package nodegateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// Ingress must durably bind session identity and commit local ownership before
// returning a GATEWAY receipt. Collection work leases cannot implement ingress.
type Ingress interface {
	RegisterSession(context.Context, telemetry.SessionMessage) (telemetry.SessionReceipt, error)
	Accept(context.Context, telemetry.NodeBatch, []byte) (telemetry.Receipt, error)
}
type Handler struct {
	authority *Authority
	ingress   Ingress
	mux       *http.ServeMux
	slots     chan struct{}
}

func NewHandler(authority *Authority, ingress Ingress) (*Handler, error) {
	if authority == nil || ingress == nil {
		return nil, telemetry.ErrInvalid
	}
	h := &Handler{authority: authority, ingress: ingress, mux: http.NewServeMux(), slots: make(chan struct{}, 4)}
	h.mux.HandleFunc("POST /node-telemetry/v1/batches", h.batch)
	h.mux.HandleFunc("POST /node-telemetry/v1/sessions", h.session)
	if retirement, ok := ingress.(RetirementIngress); ok {
		h.configureRetirement(retirement)
	}
	return h, nil
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	h.mux.ServeHTTP(w, r)
}
func (h *Handler) request(w http.ResponseWriter, r *http.Request, limit int64) (Principal, telemetry.Grant, []byte, func(), bool) {
	if r.Header.Get("X-Sherlock-Telemetry-Version") != "1" {
		problem(w, 426, "VERSION_UNSUPPORTED")
		return Principal{}, telemetry.Grant{}, nil, nil, false
	}
	if r.URL.RawQuery != "" {
		problem(w, 400, "INVALID_INPUT")
		return Principal{}, telemetry.Grant{}, nil, nil, false
	}
	encoding := r.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" || r.Header.Get("Content-Type") != "application/json" {
		problem(w, 415, "ENCODING_UNSUPPORTED")
		return Principal{}, telemetry.Grant{}, nil, nil, false
	}
	principal, grant, err := h.authority.Authenticate(r.Context(), r)
	if err != nil {
		problem(w, 403, "AUTHORITY_UNAVAILABLE")
		return principal, grant, nil, nil, false
	}
	entry := h.authority.cache[principal.EnrollmentID]
	if !entry.busy.CompareAndSwap(false, true) {
		problem(w, 429, "BACKPRESSURE")
		return principal, grant, nil, nil, false
	}
	release := func() { entry.busy.Store(false) }
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		release()
		problem(w, 413, "BODY_LIMIT")
		return principal, grant, nil, nil, false
	}
	return principal, grant, body, release, true
}
func (h *Handler) batch(w http.ResponseWriter, r *http.Request) {
	release, ok := h.acquire(w, r)
	if !ok {
		return
	}
	defer release()
	principal, grant, body, releaseNode, ok := h.request(w, r, telemetry.MaxNodeBatchBytes)
	if !ok {
		return
	}
	defer releaseNode()
	batch, err := telemetry.DecodeNodeBatch(body, "")
	if err != nil {
		problem(w, 400, "INVALID_INPUT")
		return
	}
	if batch.Key.ClusterID != principal.ClusterID || batch.Key.NodeID != principal.NodeID || batch.Key.EnrollmentID != principal.EnrollmentID || telemetry.ValidateBatchForGrant(batch, grant, h.authority.now()) != nil {
		problem(w, 403, "IDENTITY_REJECTED")
		return
	}
	key, err := signer(grant, batch.SigningKeyID)
	if err != nil || telemetry.VerifyBatchSignature(batch, key) != nil {
		problem(w, 403, "SIGNATURE_REJECTED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	receipt, err := h.ingress.Accept(ctx, batch, body)
	if err != nil {
		operationProblem(w, err)
		return
	}
	if receipt.ProtocolVersion != 1 || receipt.Durability != "GATEWAY" || !identityID(receipt.ID) || receipt.Key != batch.Key || receipt.Digest != batch.Digest || receipt.StoredAt.IsZero() {
		problem(w, 503, "OWNERSHIP_UNAVAILABLE")
		return
	}
	respond(w, receipt)
}
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	release, ok := h.acquire(w, r)
	if !ok {
		return
	}
	defer release()
	principal, grant, body, releaseNode, ok := h.request(w, r, telemetry.MaxBatchBytes)
	if !ok {
		return
	}
	defer releaseNode()
	session, err := telemetry.DecodeSessionMessage(body, "")
	if err != nil {
		problem(w, 400, "INVALID_INPUT")
		return
	}
	if session.ClusterID != principal.ClusterID || session.NodeID != principal.NodeID || session.EnrollmentID != principal.EnrollmentID || telemetry.ValidateSessionForGrant(session, grant, h.authority.now()) != nil {
		problem(w, 403, "IDENTITY_REJECTED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	receipt, err := h.ingress.RegisterSession(ctx, session)
	if err != nil {
		operationProblem(w, err)
		return
	}
	if receipt.ProtocolVersion != 1 || receipt.Durability != "GATEWAY" || !identityID(receipt.ID) || receipt.ClusterID != session.ClusterID || receipt.NodeID != session.NodeID || receipt.EnrollmentID != session.EnrollmentID || receipt.EnrollmentRevision != session.EnrollmentRevision || receipt.SessionEpoch != session.SessionEpoch || receipt.SessionID != session.SessionID || receipt.BootID != session.BootID || receipt.Kind != session.Kind || receipt.Digest != session.Digest || receipt.StoredAt.IsZero() {
		problem(w, 503, "OWNERSHIP_UNAVAILABLE")
		return
	}
	respond(w, receipt)
}
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}{code, "telemetry request was not accepted"})
}
func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func operationProblem(w http.ResponseWriter, err error) {
	status, code := 503, "STORAGE_UNAVAILABLE"
	switch {
	case errors.Is(err, telemetry.ErrUnauthorized):
		status, code = 403, "AUTHORITY_UNAVAILABLE"
	case errors.Is(err, telemetry.ErrInvalid):
		status, code = 400, "INVALID_INPUT"
	case errors.Is(err, telemetry.ErrConflict):
		status, code = 409, "CONFLICT"
	case errors.Is(err, telemetry.ErrBackpressure):
		status, code = 429, "BACKPRESSURE"
	case errors.Is(err, telemetry.ErrReplayExpired):
		status, code = 410, "REPLAY_EXPIRED"
	}
	problem(w, status, code)
}

func signer(g telemetry.Grant, id string) (ed25519.PublicKey, error) {
	for _, k := range g.Keys {
		if k.ID == id && (k.State == "ACTIVE" || k.State == "VERIFY_ONLY") {
			return telemetry.ParseNodePublicKey(k)
		}
	}
	return nil, telemetry.ErrUnauthorized
}

func (h *Handler) acquire(w http.ResponseWriter, r *http.Request) (func(), bool) {
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, true
	default:
		problem(w, 429, "BACKPRESSURE")
		return nil, false
	}
}
