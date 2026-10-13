package collectorcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	ProtocolVersion        = 1
	protocolHeader         = "X-Sherlock-Protocol-Version"
	correlationHeader      = "X-Correlation-ID"
	defaultBodyLimit       = int64(1 << 20)
	defaultRequestTimeout  = 10 * time.Second
	defaultLeaseDuration   = 2 * time.Minute
	defaultLongPoll        = 25 * time.Second
	maximumLongPoll        = 30 * time.Second
	longPollInterval       = 500 * time.Millisecond
	defaultHeartbeatPeriod = 30 * time.Second
	maxChunkEnvelopeBytes  = int64((MaxResultChunkBytes*4)/3 + 4096)
)

type IdentityOperations interface {
	Enroll(context.Context, EnrollmentRequest) (Enrollment, error)
	Renew(context.Context, domain.CollectorID, []byte) (IssuedIdentity, error)
}

type WorkLeaseOperations interface {
	ClaimWork(context.Context, domain.CollectorID, string, time.Duration) (domain.WorkLease, bool, error)
	AcknowledgeWorkStart(context.Context, domain.CollectorID, domain.WorkID, int, string) error
	RenewWorkLease(context.Context, domain.CollectorID, domain.WorkID, int, string, time.Duration) error
}

type ResultOperations interface {
	UploadResultChunk(context.Context, domain.CollectorID, ResultChunk) (ChunkOutcome, error)
	FinalizeResult(context.Context, domain.CollectorID, ResultFinalization) (FinalizeOutcome, error)
}

type Transport struct {
	identity        IdentityOperations
	authenticator   IdentityAuthenticator
	heartbeats      HeartbeatRecorder
	work            WorkLeaseOperations
	results         ResultOperations
	diagnostics     DiagnosticWorkOperations
	typedWork       TypedCollectionOperations
	credentialTests CredentialAccessTestOperations
	clock           Clock
	random          io.Reader
	randomMu        sync.Mutex
	mux             *http.ServeMux
	requestAuth     RequestAuthenticator
}

type RequestAuthenticator interface {
	Certificate(*http.Request) (*x509.Certificate, error)
	AllowEnrollment(*http.Request) bool
}

// RequestReplayStore durably consumes the signed request correlation ID for a
// certificate. A successful request must remain non-replayable across control
// process and Tunnel restarts.
type RequestReplayStore interface {
	ConsumeCollectorRequestNonce(context.Context, [32]byte, string, time.Time) error
}

type DirectMTLSAuthenticator struct{}

func (DirectMTLSAuthenticator) Certificate(r *http.Request) (*x509.Certificate, error) {
	certificate := verifiedClientCertificate(r)
	if certificate == nil {
		return nil, ErrRequestAuthentication
	}
	return certificate, nil
}
func (DirectMTLSAuthenticator) AllowEnrollment(*http.Request) bool { return true }

var ErrRequestAuthentication = errors.New("collector request authentication failed")
var ErrRequestReplay = errors.New("collector request was already observed")

func NewTransport(identity IdentityOperations, authenticator IdentityAuthenticator, heartbeats HeartbeatRecorder, work WorkLeaseOperations, results ResultOperations, clock Clock, random io.Reader) (*Transport, error) {
	if identity == nil || authenticator == nil || heartbeats == nil || work == nil || results == nil || clock == nil || random == nil {
		return nil, fmt.Errorf("collector transport dependencies are required")
	}
	return NewTransportWithRequestAuthenticator(identity, authenticator, heartbeats, work, results, clock, random, DirectMTLSAuthenticator{})
}

func NewTransportWithRequestAuthenticator(identity IdentityOperations, authenticator IdentityAuthenticator, heartbeats HeartbeatRecorder, work WorkLeaseOperations, results ResultOperations, clock Clock, random io.Reader, requestAuth RequestAuthenticator) (*Transport, error) {
	if identity == nil || authenticator == nil || heartbeats == nil || work == nil || results == nil || clock == nil || random == nil || requestAuth == nil {
		return nil, fmt.Errorf("collector transport dependencies are required")
	}
	t := &Transport{identity: identity, authenticator: authenticator, heartbeats: heartbeats, work: work, results: results, clock: clock, random: random, mux: http.NewServeMux(), requestAuth: requestAuth}
	t.mux.HandleFunc("POST /collector/v1/enroll", t.enroll)
	t.mux.HandleFunc("POST /collector/v1/identity/renew", t.renewIdentity)
	t.mux.HandleFunc("POST /collector/v1/heartbeat", t.heartbeat)
	t.mux.HandleFunc("GET /collector/v1/work/claim", t.claimWork)
	t.mux.HandleFunc("POST /collector/v1/work/{work_id}/attempts/{attempt}/start", t.startWork)
	t.mux.HandleFunc("POST /collector/v1/work/{work_id}/attempts/{attempt}/renew", t.renewLease)
	t.mux.HandleFunc("PUT /collector/v1/work/{work_id}/attempts/{attempt}/results/chunks/{index}", t.uploadResultChunk)
	t.mux.HandleFunc("POST /collector/v1/work/{work_id}/attempts/{attempt}/results/finalize", t.finalizeResult)
	t.mux.HandleFunc("GET /collector/v2/work/claim", t.claimTypedWork)
	t.mux.HandleFunc("POST /collector/v2/work/{work_id}/attempts/{attempt}/start", t.typedLease(false))
	t.mux.HandleFunc("POST /collector/v2/work/{work_id}/attempts/{attempt}/renew", t.typedLease(true))
	t.mux.HandleFunc("POST /collector/v2/work/{work_id}/attempts/{attempt}/results", t.submitTypedResult)
	return t, nil
}

func (t *Transport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	t.mux.ServeHTTP(w, r)
}

type collectorMetadataDTO struct {
	DisplayName     string `json:"display_name"`
	Version         string `json:"version"`
	BuildCommit     string `json:"build_commit"`
	ProtocolMin     int    `json:"protocol_min"`
	ProtocolMax     int    `json:"protocol_max"`
	OperatingSystem string `json:"operating_system"`
	Architecture    string `json:"architecture"`
}

type enrollRequestDTO struct {
	CSRPEM   string               `json:"csr_pem"`
	Metadata collectorMetadataDTO `json:"metadata"`
}

type identityResponseDTO struct {
	CollectorID    string    `json:"collector_id,omitempty"`
	CertificatePEM string    `json:"certificate_pem"`
	CAChainPEM     string    `json:"ca_chain_pem"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}

type renewIdentityRequestDTO struct {
	CSRPEM string `json:"csr_pem"`
}

func (t *Transport) enroll(w http.ResponseWriter, r *http.Request) {
	correlationID, ok := validateProtocol(w, r)
	if !ok {
		return
	}
	if !t.requestAuth.AllowEnrollment(r) {
		writeProblem(w, http.StatusUnauthorized, "UNAUTHORIZED", "enrollment is unavailable on this request boundary", correlationID)
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "UNAUTHORIZED", "bootstrap authorization is required", correlationID)
		return
	}
	var body enrollRequestDTO
	if !decodeJSON(w, r, &body) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "request body is invalid", correlationID)
		return
	}
	if !validEnrollmentDTO(body) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "enrollment request is invalid", correlationID)
		return
	}
	if !validCollectorCSR([]byte(body.CSRPEM)) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "certificate request is invalid", correlationID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	enrollment, err := t.identity.Enroll(ctx, EnrollmentRequest{
		BootstrapToken: token,
		CSRPEM:         []byte(body.CSRPEM),
		Metadata: CollectorMetadata{
			DisplayName: body.Metadata.DisplayName, Version: body.Metadata.Version,
			BuildCommit: body.Metadata.BuildCommit, ProtocolMin: body.Metadata.ProtocolMin,
			ProtocolMax: body.Metadata.ProtocolMax, OperatingSystem: body.Metadata.OperatingSystem,
			Architecture: body.Metadata.Architecture,
		},
	})
	if err != nil {
		if errors.Is(err, ErrBootstrapUnavailable) {
			writeProblem(w, http.StatusUnauthorized, "UNAUTHORIZED", "bootstrap authorization is invalid or unavailable", correlationID)
			return
		}
		writeOperationError(w, err, correlationID)
		return
	}
	writeJSON(w, http.StatusCreated, identityDTO(enrollment.CollectorID, enrollment.Identity))
}

func (t *Transport) renewIdentity(w http.ResponseWriter, r *http.Request) {
	correlationID, ok := validateProtocol(w, r)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, correlationID)
	if !ok {
		return
	}
	var body renewIdentityRequestDTO
	if !decodeJSON(w, r, &body) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "request body is invalid", correlationID)
		return
	}
	if len(body.CSRPEM) < 1 || len(body.CSRPEM) > 32<<10 {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "certificate request is invalid", correlationID)
		return
	}
	if !validCollectorCSR([]byte(body.CSRPEM)) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "certificate request is invalid", correlationID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	issued, err := t.identity.Renew(ctx, identity.CollectorID, []byte(body.CSRPEM))
	if err != nil {
		writeOperationError(w, err, correlationID)
		return
	}
	writeJSON(w, http.StatusOK, identityDTO("", issued))
}

type capabilityDTO struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type commandPackDTO struct {
	PackID       string `json:"pack_id"`
	Version      string `json:"version"`
	DigestSHA256 string `json:"digest_sha256"`
}

type sourceHealthDTO struct {
	SourceID     string    `json:"source_id"`
	Availability string    `json:"availability"`
	SafeMessage  string    `json:"safe_message"`
	CheckedAt    time.Time `json:"checked_at"`
}

type heartbeatRequestDTO struct {
	ProtocolMin  int               `json:"protocol_min,omitempty"`
	ProtocolMax  int               `json:"protocol_max,omitempty"`
	Version      string            `json:"version"`
	BuildCommit  string            `json:"build_commit"`
	Capabilities []capabilityDTO   `json:"capabilities"`
	CommandPacks []commandPackDTO  `json:"command_packs"`
	SourceHealth []sourceHealthDTO `json:"source_health"`
}

type heartbeatResponseDTO struct {
	ServerTime           time.Time `json:"server_time"`
	NextHeartbeatSeconds int       `json:"next_heartbeat_seconds"`
}

func (t *Transport) heartbeat(w http.ResponseWriter, r *http.Request) {
	correlationID, ok := validateProtocol(w, r)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, correlationID)
	if !ok {
		return
	}
	var body heartbeatRequestDTO
	if !decodeJSON(w, r, &body) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "request body is invalid", correlationID)
		return
	}
	reportedAt := t.clock.Now().UTC()
	report := Heartbeat{CollectorID: identity.CollectorID, Version: body.Version, BuildCommit: body.BuildCommit, ReportedAt: reportedAt, ProtocolMin: body.ProtocolMin, ProtocolMax: body.ProtocolMax}
	for _, capability := range body.Capabilities {
		report.Capabilities = append(report.Capabilities, CapabilityReport(capability))
	}
	for _, pack := range body.CommandPacks {
		report.CommandPacks = append(report.CommandPacks, CommandPackReport(pack))
	}
	for _, source := range body.SourceHealth {
		report.SourceHealth = append(report.SourceHealth, SourceHealthReport{SourceID: domain.SourceID(source.SourceID), Availability: SourceAvailability(source.Availability), SafeMessage: source.SafeMessage, CheckedAt: source.CheckedAt.UTC()})
	}
	if err := ValidateHeartbeat(report, reportedAt); err != nil {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "heartbeat report is invalid", correlationID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	if err := t.heartbeats.RecordHeartbeat(ctx, report); err != nil {
		writeOperationError(w, err, correlationID)
		return
	}
	writeJSON(w, http.StatusOK, heartbeatResponseDTO{ServerTime: reportedAt, NextHeartbeatSeconds: int(defaultHeartbeatPeriod.Seconds())})
}

type collectionRangeDTO struct {
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	StepSeconds float64   `json:"step_seconds"`
}

type collectionTaskDTO struct {
	RunID          string              `json:"run_id"`
	ClusterID      string              `json:"cluster_id"`
	SourceID       string              `json:"source_id"`
	QueryKind      string              `json:"query_kind"`
	NodeFilter     string              `json:"node_filter"`
	Range          *collectionRangeDTO `json:"range,omitempty"`
	ScheduledFor   time.Time           `json:"scheduled_for"`
	Deadline       time.Time           `json:"deadline"`
	MaxSeries      int                 `json:"max_series"`
	MaxBytes       int64               `json:"max_bytes"`
	IdempotencyKey string              `json:"idempotency_key"`
}

type claimResponseDTO struct {
	WorkID        string            `json:"work_id"`
	Attempt       int               `json:"attempt"`
	LeaseToken    string            `json:"lease_token"`
	LeaseExpires  time.Time         `json:"lease_expires_at"`
	WorkExpiresAt time.Time         `json:"work_expires_at"`
	Task          collectionTaskDTO `json:"task"`
}

func (t *Transport) claimWork(w http.ResponseWriter, r *http.Request) {
	correlationID, ok := validateProtocol(w, r)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, correlationID)
	if !ok {
		return
	}
	waitFor, err := parseWait(r.URL.Query().Get("wait_seconds"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "wait_seconds is invalid", correlationID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), waitFor+defaultRequestTimeout)
	defer cancel()
	deadline := t.clock.Now().Add(waitFor)
	for {
		token, err := t.randomToken()
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "INTERNAL", "collector control operation failed", correlationID)
			return
		}
		lease, found, err := t.work.ClaimWork(ctx, identity.CollectorID, token, defaultLeaseDuration)
		if err != nil {
			writeOperationError(w, err, correlationID)
			return
		}
		if found {
			writeJSON(w, http.StatusOK, claimDTO(lease))
			return
		}
		remaining := deadline.Sub(t.clock.Now())
		if remaining <= 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		pause := longPollInterval
		if remaining < pause {
			pause = remaining
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			writeOperationError(w, ctx.Err(), correlationID)
			return
		case <-timer.C:
		}
	}
}

type leaseRequestDTO struct {
	LeaseToken      string `json:"lease_token"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
}

func (t *Transport) startWork(w http.ResponseWriter, r *http.Request) {
	t.withLease(w, r, false)
}

func (t *Transport) renewLease(w http.ResponseWriter, r *http.Request) {
	t.withLease(w, r, true)
}

func (t *Transport) withLease(w http.ResponseWriter, r *http.Request, renew bool) {
	t.withLeaseVersion(w, r, renew, ProtocolVersion)
}

func (t *Transport) withLeaseVersion(w http.ResponseWriter, r *http.Request, renew bool, version int) {
	correlationID, ok := validateProtocolVersion(w, r, version)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, correlationID)
	if !ok {
		return
	}
	if version == domain.CollectionProtocolVersion && !t.typedAvailable(w, correlationID) {
		return
	}
	attempt, err := strconv.Atoi(r.PathValue("attempt"))
	if err != nil || attempt < 1 || !domain.ValidCollectorWorkID(r.PathValue("work_id")) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "work lease target is invalid", correlationID)
		return
	}
	var body leaseRequestDTO
	if !decodeJSON(w, r, &body) || len(body.LeaseToken) < 32 || len(body.LeaseToken) > 256 {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "work lease request is invalid", correlationID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	workID := domain.WorkID(r.PathValue("work_id"))
	if renew {
		if body.DurationSeconds < 1 || body.DurationSeconds > 300 {
			writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "lease duration is invalid", correlationID)
			return
		}
		err = t.work.RenewWorkLease(ctx, identity.CollectorID, workID, attempt, body.LeaseToken, time.Duration(body.DurationSeconds)*time.Second)
	} else {
		if body.DurationSeconds != 0 {
			writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "start request contains unsupported fields", correlationID)
			return
		}
		err = t.work.AcknowledgeWorkStart(ctx, identity.CollectorID, workID, attempt, body.LeaseToken)
	}
	if err != nil {
		writeOperationError(w, err, correlationID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type resultChunkRequestDTO struct {
	LeaseToken    string `json:"lease_token"`
	PayloadBase64 string `json:"payload_base64"`
	SHA256        string `json:"sha256"`
}

type resultChunkResponseDTO struct {
	PreviouslyUploaded bool `json:"previously_uploaded"`
}

func (t *Transport) uploadResultChunk(w http.ResponseWriter, r *http.Request) {
	correlationID, ok := validateProtocol(w, r)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, correlationID)
	if !ok {
		return
	}
	reference, ok := resultPathReference(w, r, correlationID)
	if !ok {
		return
	}
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || index < 0 || index >= MaxResultChunks {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result chunk index is invalid", correlationID)
		return
	}
	var body resultChunkRequestDTO
	if !decodeJSONLimit(w, r, &body, maxChunkEnvelopeBytes) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result chunk request is invalid", correlationID)
		return
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(body.PayloadBase64)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result chunk payload encoding is invalid", correlationID)
		return
	}
	reference.LeaseToken = body.LeaseToken
	chunk := ResultChunk{LeaseRef: reference, Index: index, Payload: payload, SHA256: body.SHA256}
	if err := ValidateResultChunk(chunk); err != nil || len(body.LeaseToken) > 256 {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result chunk metadata is invalid", correlationID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	outcome, err := t.results.UploadResultChunk(ctx, identity.CollectorID, chunk)
	if err != nil {
		writeOperationError(w, err, correlationID)
		return
	}
	status := http.StatusCreated
	if outcome.PreviouslyUploaded {
		status = http.StatusOK
	}
	writeJSON(w, status, resultChunkResponseDTO(outcome))
}

type resultFinalizationRequestDTO struct {
	LeaseToken string `json:"lease_token"`
	RunID      string `json:"run_id"`
	Status     string `json:"status"`
	ChunkCount int    `json:"chunk_count"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
}

type resultFinalizationResponseDTO struct {
	RunID               string `json:"run_id"`
	Status              string `json:"status"`
	SHA256              string `json:"sha256"`
	PreviouslyFinalized bool   `json:"previously_finalized"`
}

func (t *Transport) finalizeResult(w http.ResponseWriter, r *http.Request) {
	correlationID, ok := validateProtocol(w, r)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, correlationID)
	if !ok {
		return
	}
	reference, ok := resultPathReference(w, r, correlationID)
	if !ok {
		return
	}
	var body resultFinalizationRequestDTO
	if !decodeJSON(w, r, &body) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result finalization request is invalid", correlationID)
		return
	}
	reference.LeaseToken = body.LeaseToken
	finalization := ResultFinalization{LeaseRef: reference, RunID: domain.RunID(body.RunID), Status: domain.ResultStatus(body.Status), ChunkCount: body.ChunkCount, SHA256: body.SHA256, Bytes: body.Bytes}
	if err := ValidateResultFinalization(finalization); err != nil || len(body.LeaseToken) > 256 {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result finalization metadata is invalid", correlationID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	outcome, err := t.results.FinalizeResult(ctx, identity.CollectorID, finalization)
	if err != nil {
		writeOperationError(w, err, correlationID)
		return
	}
	writeJSON(w, http.StatusOK, resultFinalizationResponseDTO{RunID: string(outcome.RunID), Status: string(outcome.Status), SHA256: outcome.SHA256, PreviouslyFinalized: outcome.PreviouslyFinalized})
}

func resultPathReference(w http.ResponseWriter, r *http.Request, correlationID string) (LeaseRef, bool) {
	attempt, err := strconv.Atoi(r.PathValue("attempt"))
	if err != nil || attempt < 1 || !domain.ValidCollectorWorkID(r.PathValue("work_id")) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "result work lease target is invalid", correlationID)
		return LeaseRef{}, false
	}
	return LeaseRef{WorkID: domain.WorkID(r.PathValue("work_id")), Attempt: attempt}, true
}

func (t *Transport) authenticate(w http.ResponseWriter, r *http.Request, correlationID string) (AuthenticatedIdentity, bool) {
	certificate, err := t.requestAuth.Certificate(r)
	if err != nil || certificate == nil {
		writeProblem(w, http.StatusUnauthorized, "UNAUTHORIZED", "a verified collector identity is required", correlationID)
		return AuthenticatedIdentity{}, false
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	serial := hex.EncodeToString(certificate.SerialNumber.Bytes())
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	identity, err := t.authenticator.AuthenticateCollectorIdentity(ctx, serial, fingerprint)
	if err != nil {
		if observer, ok := t.requestAuth.(interface{ IdentityRejected(error) }); ok {
			observer.IdentityRejected(err)
		}
		if errors.Is(err, ErrCollectorInactive) {
			writeProblem(w, http.StatusUnauthorized, "UNAUTHORIZED", "collector identity is not active", correlationID)
		} else {
			writeProblem(w, http.StatusInternalServerError, "INTERNAL", "collector identity could not be authenticated", correlationID)
		}
		return AuthenticatedIdentity{}, false
	}
	return identity, true
}

func verifiedClientCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return nil
	}
	leaf := r.TLS.PeerCertificates[0]
	if len(r.TLS.VerifiedChains[0]) == 0 || !leaf.Equal(r.TLS.VerifiedChains[0][0]) {
		return nil
	}
	return leaf
}

func validateProtocol(w http.ResponseWriter, r *http.Request) (string, bool) {
	return validateProtocolVersion(w, r, ProtocolVersion)
}

func validateProtocolVersion(w http.ResponseWriter, r *http.Request, version int) (string, bool) {
	correlationID := r.Header.Get(correlationHeader)
	if !validCorrelationID(correlationID) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "a valid correlation identifier is required", "")
		return "", false
	}
	w.Header().Set(correlationHeader, correlationID)
	w.Header().Set(protocolHeader, strconv.Itoa(version))
	if r.Header.Get(protocolHeader) != strconv.Itoa(version) {
		writeProblem(w, http.StatusUpgradeRequired, "PROTOCOL_VERSION_UNSUPPORTED", "collector protocol version is unsupported", correlationID)
		return correlationID, false
	}
	return correlationID, true
}

func validCorrelationID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("._:-", character) {
			return false
		}
	}
	return true
}

func bearerToken(value string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	token := strings.TrimPrefix(value, prefix)
	return token, len(token) >= 32 && len(token) <= 256 && !strings.ContainsAny(token, " \t\r\n")
}

func validEnrollmentDTO(body enrollRequestDTO) bool {
	metadata := body.Metadata
	return len(body.CSRPEM) >= 1 && len(body.CSRPEM) <= 32<<10 &&
		bounded(metadata.DisplayName, 1, 128) && bounded(metadata.Version, 1, 128) &&
		bounded(metadata.BuildCommit, 0, 128) && bounded(metadata.OperatingSystem, 1, 64) &&
		bounded(metadata.Architecture, 1, 64) && metadata.ProtocolMin >= 1 &&
		metadata.ProtocolMin <= ProtocolVersion && metadata.ProtocolMax >= ProtocolVersion
}

func validCollectorCSR(value []byte) bool {
	block, rest := pem.Decode(value)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		return false
	}
	return validateCollectorPublicKey(request.PublicKey) == nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	return decodeJSONLimit(w, r, target, defaultBodyLimit)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, target any, limit int64) bool {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func parseWait(raw string) (time.Duration, error) {
	if raw == "" {
		return defaultLongPoll, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 0 || seconds > int(maximumLongPoll.Seconds()) {
		return 0, fmt.Errorf("invalid wait duration")
	}
	return time.Duration(seconds) * time.Second, nil
}

func (t *Transport) randomToken() (string, error) {
	t.randomMu.Lock()
	defer t.randomMu.Unlock()
	raw := make([]byte, 32)
	if _, err := io.ReadFull(t.random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func identityDTO(collectorID domain.CollectorID, identity IssuedIdentity) identityResponseDTO {
	return identityResponseDTO{CollectorID: string(collectorID), CertificatePEM: string(identity.CertificatePEM), CAChainPEM: string(identity.CAChainPEM), NotBefore: identity.NotBefore.UTC(), NotAfter: identity.NotAfter.UTC()}
}

func claimDTO(lease domain.WorkLease) claimResponseDTO {
	task := lease.Work.Task
	dto := claimResponseDTO{
		WorkID: string(lease.Work.WorkID), Attempt: lease.Attempt, LeaseToken: lease.LeaseToken,
		LeaseExpires: lease.LeaseExpires.UTC(), WorkExpiresAt: lease.Work.WorkExpiresAt.UTC(),
		Task: collectionTaskDTO{
			RunID: string(task.RunID), ClusterID: string(task.ClusterID), SourceID: string(task.SourceID),
			QueryKind: string(task.Query), NodeFilter: task.Node, ScheduledFor: task.ScheduledFor.UTC(),
			Deadline: task.Deadline.UTC(), MaxSeries: task.MaxSeries, MaxBytes: task.MaxBytes, IdempotencyKey: task.IdempotencyKey,
		},
	}
	if task.Range != nil {
		dto.Task.Range = &collectionRangeDTO{Start: task.Range.Start.UTC(), End: task.Range.End.UTC(), StepSeconds: task.Range.Step.Seconds()}
	}
	return dto
}

type problemDTO struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

func writeOperationError(w http.ResponseWriter, err error, correlationID string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		writeProblem(w, http.StatusGatewayTimeout, "DEADLINE_EXCEEDED", "collector control operation timed out", correlationID)
	case errors.Is(err, context.Canceled):
		writeProblem(w, http.StatusRequestTimeout, "CANCELLED", "collector control operation was cancelled", correlationID)
	case errors.Is(err, ErrCollectorInactive):
		writeProblem(w, http.StatusUnauthorized, "UNAUTHORIZED", "collector identity is not active", correlationID)
	case errors.Is(err, ErrWorkLeaseInvalid):
		writeProblem(w, http.StatusConflict, "CONFLICT", "collector work lease is invalid or expired", correlationID)
	case errors.Is(err, ErrResultConflict):
		writeProblem(w, http.StatusConflict, "CONFLICT", "collector result conflicts with current state", correlationID)
	default:
		writeProblem(w, http.StatusInternalServerError, "INTERNAL", "collector control operation failed", correlationID)
	}
}

func writeProblem(w http.ResponseWriter, status int, code, title, correlationID string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemDTO{Type: "urn:sherlock:collector:error:" + strings.ToLower(code), Title: title, Status: status, Code: code, CorrelationID: correlationID})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
