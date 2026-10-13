// Package adminapi exposes Sherlock's redacted administrative projection to
// the separately deployed admin dashboard. It is a private, service-to-service
// HTTP boundary; it does not expose repositories or database details.
package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	publicapi "github.com/verticalcomputer/sherlock/internal/api"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const maxAuditBodySize int64 = 16 << 10

const (
	clusterListLimit    = 2000
	operationsListLimit = 200
)

// SnapshotProvider is the narrow query boundary needed by the private API.
// adminview.Service satisfies this interface.
type SnapshotProvider interface {
	Snapshot(context.Context, adminview.Query) (adminview.Dashboard, error)
}

// InvestigationStarter is the existing application boundary used by the
// public API. The private admin endpoint deliberately exposes only Start.
type InvestigationStarter interface {
	StartInvestigation(context.Context, publicapi.StartInvestigationInput) (publicapi.InvestigationResource, bool, error)
}

// Management is the mutation and operational-listing boundary used by the
// private API. Implementations must record cluster mutations atomically with
// their supplied audit metadata.
type Management interface {
	ListClusters(context.Context, bool, int) ([]adminmanage.Cluster, error)
	ListOperations(context.Context, int) (adminmanage.Operations, error)
	ListClusterOperations(context.Context, string, int) (adminmanage.Operations, error)
	GetInvestigationReport(context.Context, string) (adminmanage.InvestigationReport, error)
	UpdateCluster(context.Context, string, string, []string, adminmanage.MutationAudit) error
	RemoveCluster(context.Context, string, time.Time, adminmanage.MutationAudit) error
}

type CredentialManagement interface {
	ListCredentialMetadata(context.Context, string, string) ([]adminmanage.CredentialMetadata, error)
	PutCredential(context.Context, string, string, adminmanage.CredentialInput, adminmanage.MutationAudit) (adminmanage.CredentialMetadata, error)
	RevokeCredential(context.Context, string, string, string, int64, adminmanage.MutationAudit) error
}

type HumanAuthorization interface {
	ListHumanMemberships(context.Context, auth.HumanPrincipal) ([]auth.HumanMembership, error)
	HumanMembership(context.Context, auth.HumanPrincipal, domain.ClusterID) (auth.HumanMembership, error)
	HumanPrivilege(context.Context, auth.HumanPrincipal, domain.ClusterID, auth.HumanPrivilege) (auth.HumanPrivilegeGrant, error)
	HumanPlatformAdmin(context.Context, auth.HumanPrincipal) (auth.HumanPlatformGrant, error)
}

// Clock supplies the time used to bound each dashboard snapshot.
type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// InvestigationCanceller is the public API's optimistic cancellation boundary.
// A cancelled investigation is terminal, so its investigator lease stops.
type InvestigationCanceller interface {
	CancelInvestigation(context.Context, publicapi.CancelInvestigationInput) (publicapi.InvestigationResource, error)
}

type Options struct {
	Provider    SnapshotProvider
	Management  Management
	Credentials CredentialManagement
	AccessTests CredentialAccessTesting
	// GPUMetrics is optional: without it the GPU metrics route reports
	// that the feature is not configured.
	GPUMetrics GPUMetricsProvider
	// Progress is an optional, exact-job, read-only GP-07 projection.
	Progress ProgressProvider
	// ExpectedInventory is optional: without it the expected-inventory
	// routes report that the feature is not configured.
	ExpectedInventory ExpectedInventoryManagement
	Investigations    InvestigationStarter
	Cancellations     InvestigationCanceller
	Auditor           adminui.Auditor
	ServiceToken      []byte
	// RequireHumanSession is the GP-10b private-API end-user binding gate.
	// It remains off until the UI and API are rolled out together.
	RequireHumanSession       bool
	HumanAuthorization        HumanAuthorization
	RequireHumanAuthorization bool
	Clock                     Clock
	Random                    io.Reader
}

type Server struct {
	provider                  SnapshotProvider
	management                Management
	credentials               CredentialManagement
	accessTests               CredentialAccessTesting
	expectedInventory         ExpectedInventoryManagement
	investigations            InvestigationStarter
	cancellations             InvestigationCanceller
	auditor                   adminui.Auditor
	tokenDigest               [sha256.Size]byte
	humanSessionToken         []byte
	requireHumanSession       bool
	humanAuthorization        HumanAuthorization
	requireHumanAuthorization bool
	clock                     Clock
	random                    io.Reader
	handler                   http.Handler
	gpuMetrics                GPUMetricsProvider
	progress                  ProgressProvider
}

func New(options Options) (*Server, error) {
	if options.Provider == nil {
		return nil, errors.New("admin API snapshot provider is required")
	}
	if options.Auditor == nil {
		return nil, errors.New("admin API auditor is required")
	}
	if options.Management == nil {
		return nil, errors.New("admin API management service is required")
	}
	if len(options.ServiceToken) < 32 || len(options.ServiceToken) > 512 {
		return nil, errors.New("admin API service token must contain between 32 and 512 bytes")
	}
	if strings.ContainsAny(string(options.ServiceToken), " \t\r\n,") {
		return nil, errors.New("admin API service token contains invalid characters")
	}
	if options.Clock == nil {
		options.Clock = wallClock{}
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.RequireHumanAuthorization && (!options.RequireHumanSession || options.HumanAuthorization == nil) {
		return nil, errors.New("human authorization requires a verified human session and grant store")
	}
	server := &Server{
		provider:                  options.Provider,
		management:                options.Management,
		credentials:               options.Credentials,
		accessTests:               options.AccessTests,
		expectedInventory:         options.ExpectedInventory,
		investigations:            options.Investigations,
		cancellations:             options.Cancellations,
		auditor:                   options.Auditor,
		tokenDigest:               sha256.Sum256(options.ServiceToken),
		requireHumanSession:       options.RequireHumanSession,
		humanAuthorization:        options.HumanAuthorization,
		requireHumanAuthorization: options.RequireHumanAuthorization,
		clock:                     options.Clock,
		random:                    options.Random,
		gpuMetrics:                options.GPUMetrics,
		progress:                  options.Progress,
	}
	if options.RequireHumanSession {
		server.humanSessionToken = append([]byte(nil), options.ServiceToken...)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/admin/v1/human-session", server.humanSessionStatus)
	mux.HandleFunc("GET /internal/admin/v1/human-access", server.humanAccess)
	mux.HandleFunc("GET /internal/admin/v1/dashboard", server.dashboard)
	mux.HandleFunc("POST /internal/admin/v1/audit", server.audit)
	mux.HandleFunc("GET /internal/admin/v1/clusters", server.clusters)
	mux.HandleFunc("GET /internal/admin/v1/clusters/{cluster_id}/summary", server.clusterSummary)
	mux.HandleFunc("GET /internal/admin/v1/clusters/{cluster_id}/operations", server.clusterOperations)
	mux.HandleFunc("GET /internal/admin/v1/clusters/{cluster_id}/gpu-metrics", server.clusterGPUMetrics)
	mux.HandleFunc("GET /internal/admin/v1/clusters/{cluster_id}/progress", server.clusterProgress)
	mux.HandleFunc("POST /internal/admin/v1/clusters/{cluster_id}/investigations", server.startInvestigation)
	mux.HandleFunc("PATCH /internal/admin/v1/clusters/{cluster_id}", server.updateCluster)
	mux.HandleFunc("DELETE /internal/admin/v1/clusters/{cluster_id}", server.removeCluster)
	mux.HandleFunc("GET /internal/admin/v1/clusters/{cluster_id}/credentials", server.listCredentials)
	mux.HandleFunc("POST /internal/admin/v1/clusters/{cluster_id}/credentials", server.putCredential)
	mux.HandleFunc("DELETE /internal/admin/v1/clusters/{cluster_id}/credentials/{credential_id}", server.revokeCredential)
	mux.HandleFunc("POST /internal/admin/v1/clusters/{cluster_id}/credentials/{credential_id}/access-tests", server.requestCredentialAccessTest)
	mux.HandleFunc("POST /internal/admin/v1/clusters/{cluster_id}/credentials/{credential_id}/inventory-discoveries", server.requestCredentialInventoryDiscovery)
	mux.HandleFunc("GET /internal/admin/v1/clusters/{cluster_id}/inventory-discovery/latest", server.latestCredentialInventoryDiscovery)
	mux.HandleFunc("POST /internal/admin/v1/clusters/{cluster_id}/expected-inventory/previews", server.generateExpectedInventoryPreview)
	mux.HandleFunc("GET /internal/admin/v1/clusters/{cluster_id}/expected-inventory", server.expectedInventoryState)
	mux.HandleFunc("POST /internal/admin/v1/clusters/{cluster_id}/expected-inventory/previews/{preview_id}/import", server.importExpectedInventoryPreview)
	mux.HandleFunc("GET /internal/admin/v1/clusters/{cluster_id}/credential-access-tests", server.listCredentialAccessTests)
	mux.HandleFunc("POST /internal/admin/v1/clusters/{cluster_id}/credential-access-tests/{test_id}/cancel", server.cancelCredentialAccessTest)
	mux.HandleFunc("GET /internal/admin/v1/operations", server.operations)
	mux.HandleFunc("GET /internal/admin/v1/investigations/{investigation_id}", server.investigationReport)
	mux.HandleFunc("GET /internal/admin/v1/investigations/{investigation_id}/shared", server.sharedInvestigationReport)
	mux.HandleFunc("POST /internal/admin/v1/investigations/{investigation_id}/cancel", server.cancelInvestigation)
	server.handler = server.securityHeaders(server.authenticate(mux))
	return server, nil
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.handler.ServeHTTP(writer, request)
}

func (server *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		provided, ok := bearerToken(request.Header.Get("Authorization"))
		providedDigest := sha256.Sum256(provided)
		matched := subtle.ConstantTimeCompare(providedDigest[:], server.tokenDigest[:]) == 1
		clear(provided)
		if !ok || !matched {
			writeProblem(writer, http.StatusUnauthorized, "UNAUTHORIZED", "a valid admin service credential is required")
			return
		}
		if server.requireHumanSession && request.URL.Path != "/internal/admin/v1/audit" {
			values := request.Header.Values(auth.HumanSessionHeader)
			if len(values) != 1 {
				writeProblem(writer, http.StatusUnauthorized, "UNAUTHORIZED", "a verified human session is required")
				return
			}
			session, err := auth.VerifyHumanSession(server.humanSessionToken, values[0], request.Method, request.URL.RequestURI(), server.clock.Now())
			if err != nil {
				writeProblem(writer, http.StatusUnauthorized, "UNAUTHORIZED", "a verified human session is required")
				return
			}
			request = request.WithContext(context.WithValue(request.Context(), humanSessionContextKey{}, session))
			if server.requireHumanAuthorization {
				if !server.authorizeHumanRequest(writer, request, session) {
					return
				}
			}
		}
		next.ServeHTTP(writer, request)
	})
}

type humanSessionContextKey struct{}

func verifiedHumanSession(ctx context.Context) (auth.HumanSession, bool) {
	session, ok := ctx.Value(humanSessionContextKey{}).(auth.HumanSession)
	return session, ok
}

func bearerToken(value string) ([]byte, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) || strings.Contains(value, ",") {
		return nil, false
	}
	token := strings.TrimPrefix(value, prefix)
	if len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
		return []byte(token), false
	}
	return []byte(token), true
}

func (server *Server) dashboard(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "query parameters are not accepted")
		return
	}
	var dashboard adminview.Dashboard
	if server.requireHumanAuthorization {
		scope := humanScope(request.Context())
		keys := make([]string, 0, len(scope))
		for key := range scope {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		dashboard.Clusters = make([]adminview.ClusterSummary, 0, len(keys))
		for _, key := range keys {
			snapshot, err := server.provider.Snapshot(request.Context(), adminview.Query{At: server.clock.Now().UTC(), ClusterID: key, Limit: 1})
			if err != nil {
				writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the admin dashboard is temporarily unavailable")
				return
			}
			if len(snapshot.Clusters) == 1 && snapshot.Clusters[0].ClusterID == key {
				dashboard.Clusters = append(dashboard.Clusters, snapshot.Clusters[0])
			}
			dashboard.GeneratedAt, dashboard.WindowStart, dashboard.WindowEnd = snapshot.GeneratedAt, snapshot.WindowStart, snapshot.WindowEnd
		}
	} else {
		var err error
		dashboard, err = server.provider.Snapshot(request.Context(), adminview.Query{At: server.clock.Now().UTC()})
		if err != nil {
			writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the admin dashboard is temporarily unavailable")
			return
		}
	}
	writeJSON(writer, http.StatusOK, dashboard)
}

func (server *Server) humanSessionStatus(writer http.ResponseWriter, request *http.Request) {
	if !server.requireHumanAuthorization {
		writeProblem(writer, http.StatusServiceUnavailable, "HUMAN_AUTH_DISABLED", "human authorization is not configured")
		return
	}
	if rejectQuery(writer, request) {
		return
	}
	scope := humanScope(request.Context())
	if len(scope) == 0 {
		writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "no active cluster membership")
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		ClusterCount int `json:"cluster_count"`
	}{ClusterCount: len(scope)})
}

func (server *Server) clusters(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	clusters, err := server.management.ListClusters(request.Context(), false, clusterListLimit)
	if err != nil {
		writeManagementError(writer, err, "the cluster list is temporarily unavailable")
		return
	}
	response := clustersResponse{Clusters: make([]clusterDTO, 0, len(clusters))}
	scope := humanScope(request.Context())
	for _, cluster := range clusters {
		if server.requireHumanAuthorization {
			if _, allowed := scope[cluster.ID]; !allowed {
				continue
			}
		}
		response.Clusters = append(response.Clusters, clusterDTO{
			ID: cluster.ID, DisplayName: cluster.DisplayName, ExpectedCollectors: nonNilStrings(cluster.ExpectedCollectors),
			CreatedAt: cluster.CreatedAt, RemovedAt: cluster.RemovedAt,
		})
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) clusterSummary(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	id := request.PathValue("cluster_id")
	if !validClusterIDPath(id) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	dashboard, err := server.provider.Snapshot(request.Context(), adminview.Query{
		At: server.clock.Now().UTC(), ClusterID: id, Limit: 1,
	})
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the cluster summary is temporarily unavailable")
		return
	}
	if len(dashboard.Clusters) != 1 || server.requireHumanAuthorization && dashboard.Clusters[0].ClusterID != id {
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "the cluster does not exist")
		return
	}
	writeJSON(writer, http.StatusOK, dashboard.Clusters[0])
}

func (server *Server) operations(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	var operations adminmanage.Operations
	if server.requireHumanAuthorization {
		scope := humanScope(request.Context())
		keys := make([]string, 0, len(scope))
		for key := range scope {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			chunk, err := server.management.ListClusterOperations(request.Context(), key, operationsListLimit)
			if err != nil {
				writeManagementError(writer, err, "the operations list is temporarily unavailable")
				return
			}
			for _, ticket := range chunk.Tickets {
				if ticket.ClusterID == key {
					operations.Tickets = append(operations.Tickets, ticket)
				}
			}
			for _, investigation := range chunk.Investigations {
				if investigation.ClusterID == key {
					operations.Investigations = append(operations.Investigations, investigation)
				}
			}
		}
		sort.Slice(operations.Tickets, func(i, j int) bool { return operations.Tickets[i].UpdatedAt.After(operations.Tickets[j].UpdatedAt) })
		sort.Slice(operations.Investigations, func(i, j int) bool {
			return operations.Investigations[i].UpdatedAt.After(operations.Investigations[j].UpdatedAt)
		})
		if len(operations.Tickets) > operationsListLimit {
			operations.Tickets = operations.Tickets[:operationsListLimit]
		}
		if len(operations.Investigations) > operationsListLimit {
			operations.Investigations = operations.Investigations[:operationsListLimit]
		}
	} else {
		var err error
		operations, err = server.management.ListOperations(request.Context(), operationsListLimit)
		if err != nil {
			writeManagementError(writer, err, "the operations list is temporarily unavailable")
			return
		}
	}
	server.writeOperations(writer, operations)
}

func (server *Server) clusterOperations(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	id := request.PathValue("cluster_id")
	if !validClusterIDPath(id) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	operations, err := server.management.ListClusterOperations(request.Context(), id, operationsListLimit)
	if err != nil {
		writeManagementError(writer, err, "the cluster operations list is temporarily unavailable")
		return
	}
	if server.requireHumanAuthorization {
		filtered := adminmanage.Operations{}
		for _, ticket := range operations.Tickets {
			if ticket.ClusterID == id {
				filtered.Tickets = append(filtered.Tickets, ticket)
			}
		}
		for _, investigation := range operations.Investigations {
			if investigation.ClusterID == id {
				filtered.Investigations = append(filtered.Investigations, investigation)
			}
		}
		operations = filtered
	}
	server.writeOperations(writer, operations)
}

func (server *Server) listCredentials(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	if server.credentials == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "CREDENTIALS_DISABLED", "credential onboarding is not configured")
		return
	}
	clusterID := request.PathValue("cluster_id")
	if !validClusterIDPath(clusterID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	subject := strings.TrimSpace(request.Header.Get("X-Sherlock-Access-Subject"))
	if !validAccessSubjectAPI(subject) {
		writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "the credential administrator grant was not accepted")
		return
	}
	metadata, err := server.credentials.ListCredentialMetadata(request.Context(), clusterID, subject)
	if err != nil {
		writeCredentialError(writer, err)
		return
	}
	response := credentialMetadataResponse{Credentials: make([]credentialMetadataDTO, 0, len(metadata))}
	for _, item := range metadata {
		response.Credentials = append(response.Credentials, mapCredentialMetadata(item))
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) putCredential(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	if server.credentials == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "CREDENTIALS_DISABLED", "credential onboarding is not configured")
		return
	}
	clusterID := request.PathValue("cluster_id")
	if !validClusterIDPath(clusterID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	var body putCredentialDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	if !validAccessSubjectAPI(body.ActorSubject) || !validMutationContext(mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}) || !server.humanMutationMatches(request.Context(), body.SessionFingerprint, body.ActorSubject) || body.ExpectedVersion < 0 || (body.ExpectedVersion == 0 && body.ExpectedCredentialID != "") || (body.ExpectedVersion > 0 && !validCredentialIDAPI(body.ExpectedCredentialID)) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the credential request is invalid")
		return
	}
	input := adminmanage.CredentialInput{Host: body.Host, Purpose: body.Purpose, Username: body.Username, SSHPassword: []byte(body.SSHPassword), SudoPassword: []byte(body.SudoPassword), ExpectedVersion: body.ExpectedVersion, ExpectedCredentialID: body.ExpectedCredentialID}
	defer clearCredentialBytes(input.SSHPassword, input.SudoPassword)
	audit, err := server.mutationAudit(ifCredentialReplacement(body.ExpectedVersion), "credential_write", mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID})
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the credential request could not be recorded")
		return
	}
	audit.ActorSubject = body.ActorSubject
	metadata, err := server.credentials.PutCredential(request.Context(), clusterID, body.ActorSubject, input, audit)
	if err != nil {
		writeCredentialError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, mapCredentialMetadata(metadata))
}

func (server *Server) revokeCredential(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	if server.credentials == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "CREDENTIALS_DISABLED", "credential onboarding is not configured")
		return
	}
	clusterID, credentialID := request.PathValue("cluster_id"), request.PathValue("credential_id")
	if !validClusterIDPath(clusterID) || !validCredentialIDAPI(credentialID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the credential reference is invalid")
		return
	}
	var body revokeCredentialDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	if !validAccessSubjectAPI(body.ActorSubject) || !validMutationContext(mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}) || !server.humanMutationMatches(request.Context(), body.SessionFingerprint, body.ActorSubject) || body.ExpectedVersion < 1 {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the credential revocation is invalid")
		return
	}
	audit, err := server.mutationAudit(adminmanage.EventCredentialRevoked, "credential_revoked", mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID})
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the credential revocation could not be recorded")
		return
	}
	audit.ActorSubject = body.ActorSubject
	if err := server.credentials.RevokeCredential(request.Context(), clusterID, body.ActorSubject, credentialID, body.ExpectedVersion, audit); err != nil {
		writeCredentialError(writer, err)
		return
	}
	writeJSON(writer, http.StatusNoContent, nil)
}

func ifCredentialReplacement(version int64) string {
	if version > 0 {
		return adminmanage.EventCredentialReplaced
	}
	return adminmanage.EventCredentialCreated
}

func validAccessSubjectAPI(value string) bool {
	return len(value) > 0 && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n")
}
func validCredentialIDAPI(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.HasPrefix(value, "cred_") && !strings.ContainsAny(value, "\x00\r\n/\\")
}
func clearCredentialBytes(values ...[]byte) {
	for _, value := range values {
		for i := range value {
			value[i] = 0
		}
	}
}

func writeCredentialError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, adminmanage.ErrCredentialAccessDenied):
		writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "the credential administrator grant was not accepted")
	case errors.Is(err, adminmanage.ErrInvalid):
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the credential request is invalid")
	case errors.Is(err, adminmanage.ErrConflict):
		writeProblem(writer, http.StatusConflict, "CONFLICT", "the credential version conflicts with durable state")
	case errors.Is(err, adminmanage.ErrCredentialKeyUnavailable):
		writeProblem(writer, http.StatusServiceUnavailable, "CREDENTIALS_DISABLED", "credential encryption is unavailable")
	case errors.Is(err, adminmanage.ErrNotFound):
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "the credential record was not found")
	default:
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the credential operation is temporarily unavailable")
	}
}

func (server *Server) startInvestigation(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	clusterID := request.PathValue("cluster_id")
	if !validClusterIDPath(clusterID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	if server.investigations == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "INVESTIGATIONS_UNAVAILABLE", "the investigation service is not configured")
		return
	}
	var body investigationStartDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	now := server.clock.Now().UTC()
	if !validInvestigationStart(body, now) || !server.humanMutationMatches(request.Context(), body.SessionFingerprint, "") {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the investigation request is invalid")
		return
	}
	actorID := "admin-ui-" + hex.EncodeToString(body.SessionFingerprint[:8])
	result, replayed, err := server.investigations.StartInvestigation(request.Context(), publicapi.StartInvestigationInput{
		ClusterID: domain.ClusterID(clusterID), ActorID: actorID,
		IdempotencyKey: body.IdempotencyKey, IncidentID: body.IncidentID,
		Question: body.Question, Purpose: body.Purpose, Scope: body.Scope, SuccessCriteria: body.SuccessCriteria,
		Budget: body.Budget, Deadline: body.Deadline,
	})
	if err != nil {
		writeInvestigationError(writer, err, "the investigation could not be started")
		return
	}
	status := http.StatusAccepted
	if replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, investigationStartResponse{
		ID: result.InvestigationID, Status: string(result.Status), Replayed: replayed,
	})
}

func (server *Server) writeOperations(writer http.ResponseWriter, operations adminmanage.Operations) {
	repairs := repairOverviewDTO{Available: operations.Repairs.Available, GlobalEnabled: operations.Repairs.GlobalEnabled, ActiveRequests: operations.Repairs.ActiveRequests, PendingVerification: operations.Repairs.PendingVerification, Succeeded: operations.Repairs.Succeeded, Contained: operations.Repairs.Contained, Cancelled: operations.Repairs.Cancelled, RolledBack: operations.Repairs.RolledBack, Decisions: make([]repairDecisionDTO, 0, len(operations.Repairs.Decisions))}
	for _, d := range operations.Repairs.Decisions {
		repairs.Decisions = append(repairs.Decisions, repairDecisionDTO{Code: d.Code, Count: d.Count})
	}

	response := operationsResponse{
		Repairs:        repairs,
		GeneratedAt:    server.clock.Now().UTC(),
		Tickets:        make([]ticketDTO, 0, len(operations.Tickets)),
		Investigations: make([]investigationDTO, 0, len(operations.Investigations)),
	}
	for _, ticket := range operations.Tickets {
		response.Tickets = append(response.Tickets, ticketDTO{
			ID: ticket.ID, ClusterID: ticket.ClusterID, RuleID: ticket.RuleID, Title: ticket.Title,
			Summary: ticket.Summary, Severity: ticket.Severity, Status: ticket.Status, UpdatedAt: ticket.UpdatedAt,
			LastSignalAt:    ticket.LastSignalAt,
			AutoStartStatus: ticket.AutoStartStatus, AutoStartDecision: ticket.AutoStartDecision,
			AutoStartUpdatedAt: ticket.AutoStartUpdatedAt,
		})
	}
	for _, investigation := range operations.Investigations {
		response.Investigations = append(response.Investigations, investigationDTO{
			ID: investigation.ID, ClusterID: investigation.ClusterID,
			IncidentID: investigation.IncidentID, Question: investigation.Question,
			Status: investigation.Status, EntityKind: investigation.EntityKind,
			EntityIDs: nonNilStrings(investigation.EntityIDs), AuditedTokens: investigation.AuditedTokens,
			AuditedCostMicrounits: investigation.AuditedCostMicrounits, UpdatedAt: investigation.UpdatedAt,
		})
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) investigationReport(writer http.ResponseWriter, request *http.Request) {
	server.renderInvestigationReport(writer, request, false)
}

func (server *Server) sharedInvestigationReport(writer http.ResponseWriter, request *http.Request) {
	server.renderInvestigationReport(writer, request, true)
}

func (server *Server) renderInvestigationReport(writer http.ResponseWriter, request *http.Request, shared bool) {
	if rejectQuery(writer, request) {
		return
	}
	id := request.PathValue("investigation_id")
	if !validClusterIDPath(id) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the investigation ID is invalid")
		return
	}
	report, err := server.management.GetInvestigationReport(request.Context(), id)
	if err != nil {
		writeManagementError(writer, err, "the investigation report is temporarily unavailable")
		return
	}
	if server.requireHumanAuthorization {
		session, _ := verifiedHumanSession(request.Context())
		if !server.authorizeHumanCluster(writer, request, session.Principal, report.ClusterID,
			reportReadGrant(shared)) {
			return
		}
	}
	response := investigationReportDTO{
		ID: report.ID, ClusterID: report.ClusterID, IncidentID: report.IncidentID,
		Question: report.Question, Status: report.Status, StopReason: report.StopReason,
		EntityKind: report.EntityKind, EntityIDs: nonNilStrings(report.EntityIDs),
		WindowStart: report.WindowStart, WindowEnd: report.WindowEnd,
		SuccessCriteria: nonNilStrings(report.SuccessCriteria), CreatedAt: report.CreatedAt,
		UpdatedAt: report.UpdatedAt, CompletedAt: report.CompletedAt,
		ModelUsage: reportModelUsageDTO{
			MaxTokens: report.ModelUsage.MaxTokens, AdmittedTokens: report.ModelUsage.AdmittedTokens,
			AuditedTokens: report.ModelUsage.AuditedTokens, MaxCostMicrounits: report.ModelUsage.MaxCostMicrounits,
			AdmittedCostMicrounits: report.ModelUsage.AdmittedCostMicrounits, AuditedCostMicrounits: report.ModelUsage.AuditedCostMicrounits,
		},
		Findings:         make([]reportFindingDTO, 0, len(report.Findings)),
		ReportSections:   make([]reportSectionDTO, 0, len(report.ReportSections)),
		ReportOmissions:  make([]reportOmissionDTO, 0, len(report.ReportOmissions)),
		PrimaryAction:    nil,
		Evidence:         make([]reportEvidenceDTO, 0, len(report.Evidence)),
		ModelCalls:       make([]modelCallDTO, 0, len(report.ModelCalls)),
		ContextManifests: make([]contextManifestDTO, 0, len(report.ContextManifests)),
	}
	if report.PrimaryAction != nil {
		action := report.PrimaryAction
		response.PrimaryAction = &reportActionCardDTO{
			ID: action.ID, Owner: action.Owner, Action: action.Action, Urgency: action.Urgency,
			Targets: nonNilStrings(action.Targets), Rationale: action.Rationale,
			EvidenceIDs: nonNilStrings(action.EvidenceIDs), BlockingGaps: nonNilStrings(action.BlockingGaps),
			EscalationCondition: action.EscalationCondition,
		}
	}
	for _, finding := range report.Findings {
		response.Findings = append(response.Findings, reportFindingDTO{
			ID: finding.ID, Kind: finding.Kind, Statement: finding.Statement,
			EntityIDs: nonNilStrings(finding.EntityIDs), Severity: finding.Severity,
			Confidence: finding.Confidence, EvidenceIDs: nonNilStrings(finding.EvidenceIDs),
			CounterEvidenceIDs: nonNilStrings(finding.CounterEvidenceIDs),
		})
	}
	for _, section := range report.ReportSections {
		response.ReportSections = append(response.ReportSections, reportSectionDTO{
			ID: section.ID, Kind: section.Kind, Ordinal: section.Ordinal,
			Statement: section.Statement, ObservedAt: section.ObservedAt,
			EvidenceIDs: nonNilStrings(section.EvidenceIDs),
		})
	}
	for _, omission := range report.ReportOmissions {
		response.ReportOmissions = append(response.ReportOmissions, reportOmissionDTO{
			Kind: omission.Kind, Reason: omission.Reason, Count: omission.Count,
		})
	}
	for _, evidence := range report.Evidence {
		response.Evidence = append(response.Evidence, reportEvidenceDTO{
			ID: evidence.ID, Kind: evidence.Kind, Status: evidence.Status,
			ExactScope: evidence.ExactScope, ObservedStart: evidence.ObservedStart,
			ObservedEnd: evidence.ObservedEnd, RecordedAt: evidence.RecordedAt,
		})
	}
	for _, call := range report.ModelCalls {
		response.ModelCalls = append(response.ModelCalls, modelCallDTO{
			ID: call.ID, Kind: call.Kind, Provider: call.Provider, Model: call.Model,
			ModelConfigVersion: call.ModelConfigVersion, PromptSchemaVersion: call.PromptSchemaVersion,
			ToolSchemaVersion: call.ToolSchemaVersion, InputTokens: call.InputTokens,
			OutputTokens: call.OutputTokens, CostMicrounits: call.CostMicrounits,
			LatencyMilliseconds: call.LatencyMilliseconds, Outcome: call.Outcome,
			ReasonCode: call.ReasonCode, OccurredAt: call.OccurredAt,
			Input: mapPayloadDTO(call.Input), Output: mapPayloadDTO(call.Output),
		})
	}
	for _, manifest := range report.ContextManifests {
		response.ContextManifests = append(response.ContextManifests, contextManifestDTO{CallKey: manifest.CallKey, CallKind: manifest.CallKind, EstimatorVersion: manifest.EstimatorVersion, AllowanceTokens: manifest.AllowanceTokens, EstimatedInputTokens: manifest.EstimatedInputTokens, RawEstimatedInputTokens: manifest.RawEstimatedInputTokens, CalibrationFactorMillionths: manifest.CalibrationFactorMillionths, CalibrationSampleCount: manifest.CalibrationSampleCount, FixedMarginTokens: manifest.FixedMarginTokens, MaximumOutputTokens: manifest.MaximumOutputTokens, ActualInputTokens: manifest.ActualInputTokens, EstimatorUnderrun: manifest.EstimatorUnderrun, MemoryAllowanceTokens: manifest.MemoryAllowanceTokens, MemoryCandidateCount: manifest.MemoryCandidateCount, SelectedMemoryIDs: nonNilStrings(manifest.SelectedMemoryIDs), SelectedEvidenceIDs: nonNilStrings(manifest.SelectedEvidenceIDs), ExclusionReasons: manifest.ExclusionReasons, SectionTokens: manifest.SectionTokens, RetrievalLatencyMilliseconds: manifest.RetrievalLatencyMilliseconds, IndexVersion: manifest.IndexVersion, FallbackState: manifest.FallbackState, ContextMode: manifest.ContextMode, CheckpointDigest: manifest.CheckpointDigest, DeltaFromVersion: manifest.DeltaFromVersion, ShadowOnly: manifest.ShadowOnly, CreatedAt: manifest.CreatedAt})
	}
	if shared {
		response = sharedReport(response, report.Version)
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) updateCluster(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	clusterID := request.PathValue("cluster_id")
	if !validClusterIDPath(clusterID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	var body updateClusterDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	body.DisplayName = strings.TrimSpace(body.DisplayName)
	mutationContext := body.context()
	if body.DisplayName == "" || len(body.DisplayName) > 256 || len(body.ExpectedCollectors) > 100 || !validMutationContext(mutationContext) || !server.humanMutationMatches(request.Context(), mutationContext.SessionFingerprint, "") {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster update is invalid")
		return
	}
	audit, err := server.mutationAudit(adminmanage.EventClusterUpdated, "cluster_inventory_updated", mutationContext)
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the cluster update could not be recorded")
		return
	}
	if err := server.management.UpdateCluster(request.Context(), clusterID, body.DisplayName, body.ExpectedCollectors, audit); err != nil {
		writeManagementError(writer, err, "the cluster update could not be applied")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) removeCluster(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	clusterID := request.PathValue("cluster_id")
	if !validClusterIDPath(clusterID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	var body removeClusterDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	mutationContext := body.context()
	if body.Confirmation != clusterID || !validMutationContext(mutationContext) || !server.humanMutationMatches(request.Context(), mutationContext.SessionFingerprint, "") {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster removal confirmation is invalid")
		return
	}
	now := server.clock.Now().UTC()
	audit, err := server.mutationAuditAt(adminmanage.EventClusterRemoved, "cluster_removed", mutationContext, now)
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the cluster removal could not be recorded")
		return
	}
	if err := server.management.RemoveCluster(request.Context(), clusterID, now, audit); err != nil {
		writeManagementError(writer, err, "the cluster removal could not be applied")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type clustersResponse struct {
	Clusters []clusterDTO `json:"clusters"`
}

type clusterDTO struct {
	ID                 string     `json:"cluster_id"`
	DisplayName        string     `json:"display_name"`
	ExpectedCollectors []string   `json:"expected_collectors"`
	CreatedAt          time.Time  `json:"created_at"`
	RemovedAt          *time.Time `json:"removed_at,omitempty"`
}

type operationsResponse struct {
	Repairs        repairOverviewDTO  `json:"repairs"`
	GeneratedAt    time.Time          `json:"generated_at"`
	Tickets        []ticketDTO        `json:"tickets"`
	Investigations []investigationDTO `json:"investigations"`
}

type ticketDTO struct {
	ID                 string     `json:"ticket_id"`
	ClusterID          string     `json:"cluster_id"`
	RuleID             string     `json:"rule_id,omitempty"`
	Title              string     `json:"title"`
	Summary            string     `json:"summary"`
	Severity           string     `json:"severity"`
	Status             string     `json:"status"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastSignalAt       time.Time  `json:"last_signal_at"`
	AutoStartStatus    string     `json:"auto_start_status,omitempty"`
	AutoStartDecision  string     `json:"auto_start_decision,omitempty"`
	AutoStartUpdatedAt *time.Time `json:"auto_start_updated_at,omitempty"`
}

type investigationDTO struct {
	ID                    string    `json:"investigation_id"`
	ClusterID             string    `json:"cluster_id"`
	IncidentID            string    `json:"incident_id"`
	Question              string    `json:"question"`
	Status                string    `json:"status"`
	EntityKind            string    `json:"entity_kind,omitempty"`
	EntityIDs             []string  `json:"entity_ids"`
	AuditedTokens         int64     `json:"audited_tokens"`
	AuditedCostMicrounits int64     `json:"audited_cost_microunits"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type investigationStartDTO struct {
	Purpose            string                                `json:"purpose,omitempty"`
	IncidentID         string                                `json:"incident_id"`
	Question           string                                `json:"question"`
	Scope              publicapi.InvestigationScopeResource  `json:"scope"`
	SuccessCriteria    []string                              `json:"success_criteria"`
	Budget             publicapi.InvestigationBudgetResource `json:"budget"`
	Deadline           time.Time                             `json:"deadline"`
	IdempotencyKey     string                                `json:"idempotency_key"`
	SessionFingerprint []byte                                `json:"session_fingerprint"`
	RequestID          string                                `json:"request_id"`
}

type investigationStartResponse struct {
	ID       string `json:"investigation_id"`
	Status   string `json:"status"`
	Replayed bool   `json:"replayed"`
}

type investigationReportDTO struct {
	Shared           bool                 `json:"shared,omitempty"`
	Version          int                  `json:"version,omitempty"`
	ID               string               `json:"investigation_id"`
	ClusterID        string               `json:"cluster_id"`
	IncidentID       string               `json:"incident_id,omitempty"`
	Question         string               `json:"question"`
	Status           string               `json:"status"`
	StopReason       string               `json:"stop_reason,omitempty"`
	EntityKind       string               `json:"entity_kind,omitempty"`
	EntityIDs        []string             `json:"entity_ids"`
	WindowStart      time.Time            `json:"window_start"`
	WindowEnd        time.Time            `json:"window_end"`
	SuccessCriteria  []string             `json:"success_criteria"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
	CompletedAt      *time.Time           `json:"completed_at,omitempty"`
	ModelUsage       reportModelUsageDTO  `json:"model_usage"`
	Findings         []reportFindingDTO   `json:"findings"`
	ReportSections   []reportSectionDTO   `json:"report_sections"`
	ReportOmissions  []reportOmissionDTO  `json:"report_omissions"`
	PrimaryAction    *reportActionCardDTO `json:"primary_action"`
	Evidence         []reportEvidenceDTO  `json:"evidence"`
	ModelCalls       []modelCallDTO       `json:"model_calls"`
	ContextManifests []contextManifestDTO `json:"context_manifests"`
}

type reportActionCardDTO struct {
	ID                  string   `json:"id"`
	Owner               string   `json:"owner"`
	Action              string   `json:"action"`
	Urgency             string   `json:"urgency"`
	Targets             []string `json:"targets"`
	Rationale           string   `json:"rationale"`
	EvidenceIDs         []string `json:"evidence_ids"`
	BlockingGaps        []string `json:"blocking_gaps"`
	EscalationCondition string   `json:"escalation_condition"`
}

type reportOmissionDTO struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type reportSectionDTO struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Ordinal     int        `json:"ordinal"`
	Statement   string     `json:"statement"`
	ObservedAt  *time.Time `json:"observed_at,omitempty"`
	EvidenceIDs []string   `json:"evidence_ids"`
}

type contextManifestDTO struct {
	CallKey                      string    `json:"call_key"`
	CallKind                     string    `json:"call_kind"`
	EstimatorVersion             string    `json:"estimator_version"`
	AllowanceTokens              int64     `json:"allowance_tokens"`
	EstimatedInputTokens         int64     `json:"estimated_input_tokens"`
	RawEstimatedInputTokens      int64     `json:"raw_estimated_input_tokens"`
	CalibrationFactorMillionths  int64     `json:"calibration_factor_millionths"`
	CalibrationSampleCount       int       `json:"calibration_sample_count"`
	FixedMarginTokens            int64     `json:"fixed_margin_tokens"`
	MaximumOutputTokens          int64     `json:"maximum_output_tokens"`
	ActualInputTokens            *int64    `json:"actual_input_tokens,omitempty"`
	EstimatorUnderrun            bool      `json:"estimator_underrun"`
	MemoryAllowanceTokens        int64     `json:"memory_allowance_tokens"`
	MemoryCandidateCount         int       `json:"memory_candidate_count"`
	SelectedMemoryIDs            []string  `json:"selected_memory_ids"`
	SelectedEvidenceIDs          []string  `json:"selected_evidence_ids"`
	ExclusionReasons             string    `json:"exclusion_reasons"`
	SectionTokens                string    `json:"section_tokens"`
	RetrievalLatencyMilliseconds int64     `json:"retrieval_latency_milliseconds"`
	IndexVersion                 string    `json:"index_version"`
	FallbackState                string    `json:"fallback_state"`
	ContextMode                  string    `json:"context_mode"`
	CheckpointDigest             string    `json:"checkpoint_digest"`
	DeltaFromVersion             *int      `json:"delta_from_version,omitempty"`
	ShadowOnly                   bool      `json:"shadow_only"`
	CreatedAt                    time.Time `json:"created_at"`
}

type reportModelUsageDTO struct {
	MaxTokens              int64 `json:"max_tokens"`
	AdmittedTokens         int64 `json:"admitted_tokens"`
	AuditedTokens          int64 `json:"audited_tokens"`
	MaxCostMicrounits      int64 `json:"max_cost_microunits"`
	AdmittedCostMicrounits int64 `json:"admitted_cost_microunits"`
	AuditedCostMicrounits  int64 `json:"audited_cost_microunits"`
}

type reportFindingDTO struct {
	ID                 string   `json:"finding_id"`
	Kind               string   `json:"kind"`
	Statement          string   `json:"statement"`
	EntityIDs          []string `json:"entity_ids"`
	Severity           string   `json:"severity"`
	Confidence         *float64 `json:"confidence,omitempty"`
	EvidenceIDs        []string `json:"evidence_ids"`
	CounterEvidenceIDs []string `json:"counter_evidence_ids"`
}

type reportEvidenceDTO struct {
	ID            string    `json:"evidence_id"`
	Kind          string    `json:"kind"`
	Status        string    `json:"status"`
	ExactScope    string    `json:"exact_scope"`
	ObservedStart time.Time `json:"observed_start"`
	ObservedEnd   time.Time `json:"observed_end"`
	RecordedAt    time.Time `json:"recorded_at"`
}

type modelCallDTO struct {
	ID                  string          `json:"call_id"`
	Kind                string          `json:"kind"`
	Provider            string          `json:"provider"`
	Model               string          `json:"model"`
	ModelConfigVersion  string          `json:"model_config_version"`
	PromptSchemaVersion string          `json:"prompt_schema_version"`
	ToolSchemaVersion   string          `json:"tool_schema_version"`
	InputTokens         int64           `json:"input_tokens"`
	OutputTokens        int64           `json:"output_tokens"`
	CostMicrounits      int64           `json:"cost_microunits"`
	LatencyMilliseconds int64           `json:"latency_milliseconds"`
	Outcome             string          `json:"outcome"`
	ReasonCode          string          `json:"reason_code,omitempty"`
	OccurredAt          time.Time       `json:"occurred_at"`
	Input               modelPayloadDTO `json:"input"`
	Output              modelPayloadDTO `json:"output"`
}

type modelPayloadDTO struct {
	EvidenceID   string `json:"evidence_id,omitempty"`
	Availability string `json:"availability"`
	MediaType    string `json:"media_type,omitempty"`
	Content      string `json:"content,omitempty"`
}

func mapPayloadDTO(payload adminmanage.ModelPayload) modelPayloadDTO {
	return modelPayloadDTO{EvidenceID: payload.EvidenceID, Availability: payload.Availability, MediaType: payload.MediaType, Content: payload.Content}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

type mutationContextDTO struct {
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

type updateClusterDTO struct {
	DisplayName        string   `json:"display_name"`
	ExpectedCollectors []string `json:"expected_collectors"`
	SessionFingerprint []byte   `json:"session_fingerprint"`
	RequestID          string   `json:"request_id"`
}

type removeClusterDTO struct {
	Confirmation       string `json:"confirmation"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

type credentialMetadataResponse struct {
	Credentials []credentialMetadataDTO `json:"credentials"`
}
type credentialMetadataDTO struct {
	ID         string     `json:"credential_id"`
	ClusterID  string     `json:"cluster_id"`
	Host       string     `json:"host"`
	Purpose    string     `json:"purpose"`
	Username   string     `json:"username"`
	KeyVersion string     `json:"key_version"`
	Version    int64      `json:"version"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	ReplacedBy string     `json:"replaced_by,omitempty"`
}
type putCredentialDTO struct {
	Host                 string `json:"host"`
	Purpose              string `json:"purpose"`
	Username             string `json:"username"`
	SSHPassword          string `json:"ssh_password,omitempty"`
	SudoPassword         string `json:"sudo_password"`
	ExpectedVersion      int64  `json:"expected_version"`
	ExpectedCredentialID string `json:"expected_credential_id,omitempty"`
	ActorSubject         string `json:"actor_subject"`
	SessionFingerprint   []byte `json:"session_fingerprint"`
	RequestID            string `json:"request_id"`
}
type revokeCredentialDTO struct {
	ExpectedVersion    int64  `json:"expected_version"`
	ActorSubject       string `json:"actor_subject"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

func mapCredentialMetadata(item adminmanage.CredentialMetadata) credentialMetadataDTO {
	return credentialMetadataDTO{ID: item.ID, ClusterID: item.ClusterID, Host: item.Host, Purpose: item.Purpose, Username: item.Username, KeyVersion: item.KeyVersion, Version: item.Version, Status: item.Status, CreatedAt: item.CreatedAt, RevokedAt: item.RevokedAt, ReplacedBy: item.ReplacedBy}
}

func (body updateClusterDTO) context() mutationContextDTO {
	return mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}
}

func (body removeClusterDTO) context() mutationContextDTO {
	return mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}
}

func rejectQuery(writer http.ResponseWriter, request *http.Request) bool {
	if request.URL.RawQuery == "" {
		return false
	}
	writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "query parameters are not accepted")
	return true
}

func decodeMutationBody(writer http.ResponseWriter, request *http.Request, target any) bool {
	if err := decodeJSON(writer, request, target); err != nil {
		if errors.Is(err, errUnsupportedMediaType) {
			writeProblem(writer, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "content type must be application/json")
		} else {
			writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the mutation request is invalid")
		}
		return false
	}
	return true
}

func validMutationContext(context mutationContextDTO) bool {
	return len(context.SessionFingerprint) == sha256.Size && len(context.RequestID) <= 128
}

func validClusterIDPath(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, character := range id {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validInvestigationStart(body investigationStartDTO, now time.Time) bool {
	if body.Purpose != "" && body.Purpose != domain.InvestigationPurposeRepairPlan {
		return false
	}
	if body.Purpose == domain.InvestigationPurposeRepairPlan && (body.Budget.MaxDiagnosticCalls != 0 || body.Scope.EntityKind != "cluster") {
		return false
	}
	if !validClusterIDPath(body.IncidentID) || !validClusterIDPath(body.IdempotencyKey) ||
		strings.TrimSpace(body.Question) == "" || len(body.Question) > 4096 ||
		!validMutationContext(mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}) {
		return false
	}
	if !validClusterIDPath(body.Scope.EntityKind) || len(body.Scope.EntityIDs) < 1 || len(body.Scope.EntityIDs) > 256 ||
		body.Scope.Start.IsZero() || body.Scope.End.IsZero() || body.Scope.End.Before(body.Scope.Start) {
		return false
	}
	seen := make(map[string]struct{}, len(body.Scope.EntityIDs))
	for _, id := range body.Scope.EntityIDs {
		if !validClusterIDPath(id) {
			return false
		}
		if _, exists := seen[id]; exists {
			return false
		}
		seen[id] = struct{}{}
	}
	if len(body.SuccessCriteria) < 1 || len(body.SuccessCriteria) > 32 {
		return false
	}
	for _, criterion := range body.SuccessCriteria {
		if strings.TrimSpace(criterion) == "" || len(criterion) > 512 || strings.IndexByte(criterion, 0) >= 0 {
			return false
		}
	}
	budget := body.Budget
	if budget.MaxDecisions < 1 || budget.MaxDecisions > 100 || budget.MaxToolCalls < 1 || budget.MaxToolCalls > 1000 ||
		budget.MaxDiagnosticCalls < 0 || budget.MaxDiagnosticCalls > 1000 || budget.MaxPrivilegedCalls != 0 ||
		budget.MaxFanOut < 1 || budget.MaxFanOut > 256 || budget.MaxModelTokens < 0 || budget.MaxCostMicros < 0 {
		return false
	}
	return body.Deadline.After(now) && body.Deadline.Sub(now) <= 24*time.Hour
}

func writeInvestigationError(writer http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, publicapi.ErrInvestigationInvalid):
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the investigation request is invalid")
	case errors.Is(err, publicapi.ErrInvestigationNotFound):
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "the incident or investigation was not found")
	case errors.Is(err, publicapi.ErrInvestigationConflict):
		writeProblem(writer, http.StatusConflict, "CONFLICT", "the investigation request conflicts with durable state")
	case errors.Is(err, publicapi.ErrInvestigationUnavailable):
		writeProblem(writer, http.StatusServiceUnavailable, "INVESTIGATIONS_UNAVAILABLE", "the investigation service is temporarily unavailable")
	default:
		writeProblem(writer, http.StatusInternalServerError, "INTERNAL", fallback)
	}
}

type investigationCancelDTO struct {
	ExpectedVersion    int    `json:"expected_version"`
	Reason             string `json:"reason"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

type investigationCancelResponse struct {
	ID     string `json:"investigation_id"`
	Status string `json:"status"`
}

// cancelInvestigation stops a non-terminal investigation through the same
// optimistic controller transition as the public API. The expected version
// prevents cancelling a run that advanced after the operator inspected it.
func (server *Server) cancelInvestigation(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	id := request.PathValue("investigation_id")
	if !validClusterIDPath(id) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the investigation ID is invalid")
		return
	}
	if server.requireHumanAuthorization {
		report, err := server.management.GetInvestigationReport(request.Context(), id)
		if err != nil {
			writeManagementError(writer, err, "the investigation could not be found")
			return
		}
		session, _ := verifiedHumanSession(request.Context())
		if !server.authorizeHumanCluster(writer, request, session.Principal, report.ClusterID,
			humanRouteGrant{capability: auth.CapabilityInvestigationsRun}) {
			return
		}
	}
	if server.cancellations == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "INVESTIGATIONS_UNAVAILABLE", "the investigation service is not configured")
		return
	}
	var body investigationCancelDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if body.ExpectedVersion < 1 || body.Reason == "" || len(body.Reason) > 512 ||
		!validMutationContext(mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}) ||
		!server.humanMutationMatches(request.Context(), body.SessionFingerprint, "") {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the investigation cancellation is invalid")
		return
	}
	result, err := server.cancellations.CancelInvestigation(request.Context(), publicapi.CancelInvestigationInput{
		InvestigationID: id, ActorID: "admin-ui-" + hex.EncodeToString(body.SessionFingerprint[:8]),
		ExpectedVersion: body.ExpectedVersion, Reason: body.Reason,
	})
	if err != nil {
		writeInvestigationError(writer, err, "the investigation could not be cancelled")
		return
	}
	writeJSON(writer, http.StatusOK, investigationCancelResponse{ID: result.InvestigationID, Status: string(result.Status)})
}

func (server *Server) mutationAudit(kind, reason string, context mutationContextDTO) (adminmanage.MutationAudit, error) {
	return server.mutationAuditAt(kind, reason, context, server.clock.Now().UTC())
}

func (server *Server) mutationAuditAt(kind, reason string, context mutationContextDTO, occurredAt time.Time) (adminmanage.MutationAudit, error) {
	var random [16]byte
	if _, err := io.ReadFull(server.random, random[:]); err != nil {
		return adminmanage.MutationAudit{}, err
	}
	return adminmanage.MutationAudit{
		EventID: "admin-" + hex.EncodeToString(random[:]), EventKind: kind, ReasonCode: reason,
		SessionFingerprint: append([]byte(nil), context.SessionFingerprint...),
		RequestID:          context.RequestID, OccurredAt: occurredAt,
	}, nil
}

func writeManagementError(writer http.ResponseWriter, err error, unavailableMessage string) {
	switch {
	case errors.Is(err, adminmanage.ErrInvalid):
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the management request is invalid")
	case errors.Is(err, adminmanage.ErrNotFound):
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "the requested administrative record was not found")
	case errors.Is(err, adminmanage.ErrConflict):
		writeProblem(writer, http.StatusConflict, "CONFLICT", "the cluster state conflicts with the request")
	default:
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", unavailableMessage)
	}
}

func (server *Server) audit(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "query parameters are not accepted")
		return
	}
	var body auditEventDTO
	if err := decodeJSON(writer, request, &body); err != nil {
		status := http.StatusBadRequest
		code := "INVALID_ARGUMENT"
		message := "the audit event is invalid"
		if errors.Is(err, errUnsupportedMediaType) {
			status = http.StatusUnsupportedMediaType
			code = "UNSUPPORTED_MEDIA_TYPE"
			message = "content type must be application/json"
		}
		writeProblem(writer, status, code, message)
		return
	}
	event := body.event()
	if !validAuditEvent(event) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the audit event is invalid")
		return
	}
	if event.SessionFingerprint != nil {
		event.SessionFingerprint = append([]byte(nil), event.SessionFingerprint...)
	}
	if err := server.auditor.RecordAdminEvent(request.Context(), event); err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the audit event could not be recorded")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// auditEventDTO fixes the wire format independently of the internal event
// model. This avoids accidentally expanding the private API when that model
// evolves.
type auditEventDTO struct {
	Kind               adminui.EventKind    `json:"kind"`
	Outcome            adminui.EventOutcome `json:"outcome"`
	ReasonCode         string               `json:"reason_code"`
	SessionFingerprint []byte               `json:"session_fingerprint"`
	RequestID          string               `json:"request_id"`
	OccurredAt         time.Time            `json:"occurred_at"`
}

func (body auditEventDTO) event() adminui.AuditEvent {
	return adminui.AuditEvent{
		Kind: body.Kind, Outcome: body.Outcome, ReasonCode: body.ReasonCode,
		SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID,
		OccurredAt: body.OccurredAt,
	}
}

var errUnsupportedMediaType = errors.New("unsupported media type")

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || strings.ToLower(mediaType) != "application/json" {
		return errUnsupportedMediaType
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxAuditBodySize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validAuditEvent(event adminui.AuditEvent) bool {
	switch event.Kind {
	case adminui.EventAuthentication, adminui.EventSessionStarted, adminui.EventSessionEnded,
		adminui.EventSessionExpired, adminui.EventDashboardViewed,
		adminui.EventClusterUpdated, adminui.EventClusterRemoved:
	default:
		return false
	}
	if event.Outcome != adminui.OutcomeSucceeded && event.Outcome != adminui.OutcomeRejected {
		return false
	}
	if event.OccurredAt.IsZero() || len(event.ReasonCode) > 128 || len(event.RequestID) > 128 {
		return false
	}
	return len(event.SessionFingerprint) == 0 || len(event.SessionFingerprint) == sha256.Size
}

type problem struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func writeProblem(writer http.ResponseWriter, status int, code, detail string) {
	writer.Header().Set("Content-Type", "application/problem+json")
	writeJSON(writer, status, problem{Title: http.StatusText(status), Status: status, Code: code, Detail: detail})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	if writer.Header().Get("Content-Type") == "" {
		writer.Header().Set("Content-Type", "application/json")
	}
	writer.WriteHeader(status)
	if status != http.StatusNoContent {
		_ = json.NewEncoder(writer).Encode(value)
	}
}

// Compile-time assertions keep the public boundary explicit.
var _ http.Handler = (*Server)(nil)

type repairOverviewDTO struct {
	Available           bool                `json:"available"`
	GlobalEnabled       bool                `json:"global_enabled"`
	ActiveRequests      int64               `json:"active_requests"`
	PendingVerification int64               `json:"pending_verification"`
	Succeeded           int64               `json:"succeeded"`
	Contained           int64               `json:"contained"`
	Cancelled           int64               `json:"cancelled"`
	RolledBack          int64               `json:"rolled_back"`
	Decisions           []repairDecisionDTO `json:"decisions"`
}
type repairDecisionDTO struct {
	Code  string `json:"code"`
	Count int64  `json:"count"`
}
