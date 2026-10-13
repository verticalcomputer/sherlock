package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/events"
	contract "github.com/verticalcomputer/sherlock/sdk/go"
)

const maxHeaderBytes = 64 << 10

type Authenticator interface {
	Authenticate(context.Context, []byte) (auth.Principal, error)
}

type Server struct {
	auth           Authenticator
	queries        *application.PublicQueries
	events         events.Reader
	diagnostics    *application.DiagnosticService
	diagnosticRuns *application.DiagnosticQueries
	investigations InvestigationAPI
	clock          application.Clock
	freshFor       time.Duration
	allowedOrigins map[string]struct{}
	handler        http.Handler
}

type ServerOptions struct {
	Authenticator  Authenticator
	Queries        *application.PublicQueries
	Events         events.Reader
	Diagnostics    *application.DiagnosticService
	DiagnosticRuns *application.DiagnosticQueries
	Investigations InvestigationAPI
	Clock          application.Clock
	FreshFor       time.Duration
	AllowedOrigins []string
}

// NewConfiguredServer is the composition-root constructor. Optional
// capabilities are supplied as pairs and validated once here.
func NewConfiguredServer(options ServerOptions) (*Server, error) {
	if (options.Diagnostics == nil) != (options.DiagnosticRuns == nil) {
		return nil, fmt.Errorf("diagnostic API dependencies must be configured together")
	}
	server, err := newServer(options.Authenticator, options.Queries, options.Events, options.Diagnostics, options.DiagnosticRuns, options.Clock, options.FreshFor, options.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	server.investigations = options.Investigations
	return server, nil
}

func NewServer(authenticator Authenticator, queries *application.PublicQueries, eventReader events.Reader, clock application.Clock, freshFor time.Duration, allowedOrigins []string) (*Server, error) {
	return newServer(authenticator, queries, eventReader, nil, nil, clock, freshFor, allowedOrigins)
}

func NewServerWithDiagnostics(authenticator Authenticator, queries *application.PublicQueries, eventReader events.Reader, diagnostics *application.DiagnosticService, diagnosticRuns *application.DiagnosticQueries, clock application.Clock, freshFor time.Duration, allowedOrigins []string) (*Server, error) {
	if diagnostics == nil || diagnosticRuns == nil {
		return nil, fmt.Errorf("diagnostic API dependencies are required")
	}
	return newServer(authenticator, queries, eventReader, diagnostics, diagnosticRuns, clock, freshFor, allowedOrigins)
}

func NewServerWithInvestigations(authenticator Authenticator, queries *application.PublicQueries, eventReader events.Reader, investigations InvestigationAPI, clock application.Clock, freshFor time.Duration, allowedOrigins []string) (*Server, error) {
	if investigations == nil {
		return nil, fmt.Errorf("investigation API dependency is required")
	}
	server, err := newServer(authenticator, queries, eventReader, nil, nil, clock, freshFor, allowedOrigins)
	if err != nil {
		return nil, err
	}
	server.investigations = investigations
	return server, nil
}

func NewServerWithDiagnosticsAndInvestigations(authenticator Authenticator, queries *application.PublicQueries, eventReader events.Reader, diagnostics *application.DiagnosticService, diagnosticRuns *application.DiagnosticQueries, investigations InvestigationAPI, clock application.Clock, freshFor time.Duration, allowedOrigins []string) (*Server, error) {
	if investigations == nil {
		return nil, fmt.Errorf("investigation API dependency is required")
	}
	server, err := NewServerWithDiagnostics(authenticator, queries, eventReader, diagnostics, diagnosticRuns, clock, freshFor, allowedOrigins)
	if err != nil {
		return nil, err
	}
	server.investigations = investigations
	return server, nil
}

func newServer(authenticator Authenticator, queries *application.PublicQueries, eventReader events.Reader, diagnostics *application.DiagnosticService, diagnosticRuns *application.DiagnosticQueries, clock application.Clock, freshFor time.Duration, allowedOrigins []string) (*Server, error) {
	if authenticator == nil || queries == nil || eventReader == nil || clock == nil {
		return nil, fmt.Errorf("public API dependencies are required")
	}
	if freshFor <= 0 {
		return nil, fmt.Errorf("public API freshness window must be positive")
	}
	server := &Server{auth: authenticator, queries: queries, events: eventReader, diagnostics: diagnostics, diagnosticRuns: diagnosticRuns, clock: clock, freshFor: freshFor, allowedOrigins: make(map[string]struct{})}
	for _, origin := range allowedOrigins {
		server.allowedOrigins[origin] = struct{}{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/clusters", server.listClusters)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}", server.getCluster)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/health", server.getHealth)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/sources", server.listSources)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/observations", server.listObservations)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/gpus", server.listGPUs)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/collection-runs", server.listRuns)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/evidence", server.listEvidence)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/evidence/{evidence_id}", server.getEvidence)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/events", server.streamEvents)
	mux.HandleFunc("POST /api/v1/clusters/{cluster_id}/diagnostic-runs/preview", server.previewDiagnostic)
	mux.HandleFunc("POST /api/v1/clusters/{cluster_id}/diagnostic-runs", server.startDiagnostic)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/diagnostic-runs/{run_id}", server.getDiagnosticRun)
	mux.HandleFunc("POST /api/v1/clusters/{cluster_id}/diagnostic-runs/{run_id}/approval", server.approveDiagnostic)
	mux.HandleFunc("GET /api/v1/clusters/{cluster_id}/incidents", server.listIncidents)
	mux.HandleFunc("POST /api/v1/clusters/{cluster_id}/incidents", server.createIncident)
	mux.HandleFunc("GET /api/v1/incidents/{incident_id}", server.getIncident)
	mux.HandleFunc("POST /api/v1/investigations", server.startInvestigation)
	mux.HandleFunc("GET /api/v1/investigations/{investigation_id}", server.getInvestigation)
	mux.HandleFunc("POST /api/v1/investigations/{investigation_id}/cancel", server.cancelInvestigation)
	mux.HandleFunc("POST /api/v1/investigations/{investigation_id}/approvals", server.approveInvestigation)
	mux.HandleFunc("GET /api/v1/investigations/{investigation_id}/events", server.listInvestigationEvents)
	mux.HandleFunc("GET /api/v1/investigations/{investigation_id}/evidence", server.listInvestigationEvidence)
	mux.HandleFunc("GET /api/v1/investigations/{investigation_id}/hypotheses", server.listInvestigationHypotheses)
	mux.HandleFunc("GET /api/v1/investigations/{investigation_id}/findings", server.listInvestigationFindings)
	server.handler = server.middleware(mux)
	return server, nil
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.handler.ServeHTTP(writer, request)
}

func NewHTTPServer(address string, handler http.Handler, readHeaderTimeout, readTimeout, idleTimeout time.Duration) (*http.Server, error) {
	if address == "" || handler == nil {
		return nil, fmt.Errorf("public API address and handler are required")
	}
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, WriteTimeout: 0, IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes}, nil
}

type requestKey struct{}

type requestState struct {
	ID        string
	Principal auth.Principal
}

func (server *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := newRequestID()
		writer.Header().Set("X-Request-ID", requestID)
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		if origin := request.Header.Get("Origin"); origin != "" {
			if _, allowed := server.allowedOrigins[origin]; !allowed {
				writeProblem(writer, requestID, http.StatusForbidden, "CORS_ORIGIN_DENIED", "Forbidden", "the request origin is not allowed")
				return
			}
			writer.Header().Set("Access-Control-Allow-Origin", origin)
			writer.Header().Set("Vary", "Origin")
			if request.Method == http.MethodOptions {
				writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, Last-Event-ID")
				writer.Header().Set("Access-Control-Max-Age", "600")
				writer.WriteHeader(http.StatusNoContent)
				return
			}
		}
		authorization := request.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") || strings.Contains(authorization, ",") {
			writeProblem(writer, requestID, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized", "a valid cluster API key is required")
			return
		}
		plaintext := []byte(strings.TrimPrefix(authorization, "Bearer "))
		principal, err := server.auth.Authenticate(request.Context(), plaintext)
		for index := range plaintext {
			plaintext[index] = 0
		}
		if err != nil {
			writeProblem(writer, requestID, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized", "a valid cluster API key is required")
			return
		}
		state := requestState{ID: requestID, Principal: principal}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), requestKey{}, state)))
	})
}

func (server *Server) authorize(writer http.ResponseWriter, request *http.Request, capability auth.Capability) (requestState, domain.ClusterID, bool) {
	state, ok := request.Context().Value(requestKey{}).(requestState)
	clusterID := domain.ClusterID(request.PathValue("cluster_id"))
	if !ok || clusterID == "" || state.Principal.Authorize(clusterID, capability) != nil {
		writeProblem(writer, state.ID, http.StatusForbidden, "CLUSTER_SCOPE_DENIED", "Forbidden", "the key is not authorized for this cluster")
		return state, clusterID, false
	}
	return state, clusterID, true
}

func (server *Server) listClusters(writer http.ResponseWriter, request *http.Request) {
	state := request.Context().Value(requestKey{}).(requestState)
	if !state.Principal.Has(auth.CapabilityClusterRead) {
		writeProblem(writer, state.ID, http.StatusForbidden, "CAPABILITY_DENIED", "Forbidden", "the key lacks the required capability")
		return
	}
	page, err := parsePage(request)
	if err != nil || page.Token != "" {
		if err == nil {
			err = fmt.Errorf("page_token is invalid")
		}
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	cluster, found, err := server.queries.GetCluster(request.Context(), state.Principal.ClusterID)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	data := []contract.Cluster{}
	if found {
		health, _, healthErr := server.queries.GetHealth(request.Context(), state.Principal.ClusterID)
		if healthErr != nil {
			server.queryError(writer, state.ID)
			return
		}
		data = append(data, mapCluster(cluster, health, state.Principal.Capabilities))
	}
	meta := responseMeta(state.ID, server.clock.Now(), domain.ResultSucceeded, domain.FreshnessUnknown, len(data), "")
	writeJSON(writer, http.StatusOK, contract.ClusterListResponse{Data: data, Meta: meta, Errors: []contract.CollectionError{}})
}

func (server *Server) getCluster(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityClusterRead)
	if !ok {
		return
	}
	cluster, found, err := server.queries.GetCluster(request.Context(), clusterID)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	if !found {
		writeProblem(writer, state.ID, http.StatusNotFound, "NOT_FOUND", "Not found", "the requested resource was not found")
		return
	}
	health, _, err := server.queries.GetHealth(request.Context(), clusterID)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	writeJSON(writer, http.StatusOK, mapCluster(cluster, health, state.Principal.Capabilities))
}

func (server *Server) getHealth(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityTelemetryRead)
	if !ok {
		return
	}
	health, found, err := server.queries.GetHealth(request.Context(), clusterID)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	if !found {
		writeProblem(writer, state.ID, http.StatusNotFound, "NOT_FOUND", "Not found", "the requested resource was not found")
		return
	}
	writeJSON(writer, http.StatusOK, mapHealth(health))
}

func (server *Server) listSources(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityTelemetryRead)
	if !ok {
		return
	}
	page, err := parsePage(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	filters, err := parseSourceFilters(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	items, next, err := server.queries.ListSources(request.Context(), clusterID, filters, page)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	data := make([]contract.Source, 0, len(items))
	for _, item := range items {
		data = append(data, mapSource(item))
	}
	meta := responseMeta(state.ID, server.clock.Now(), aggregateSourceStatus(items), aggregateSourceFreshness(items), len(items), next.NextToken)
	writeJSON(writer, 200, contract.SourceListResponse{Data: data, Meta: meta, Errors: []contract.CollectionError{}})
}

func (server *Server) listObservations(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityTelemetryRead)
	if !ok {
		return
	}
	page, err := parsePage(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	filters, err := parseObservationFilters(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	items, next, err := server.queries.ListObservations(request.Context(), clusterID, filters, page)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	data := make([]contract.Observation, 0, len(items))
	now := server.clock.Now()
	for _, item := range items {
		data = append(data, mapObservation(item, now, server.freshFor))
	}
	meta := responseMeta(state.ID, now, statusForCount(len(items)), freshnessForObservations(items, now, server.freshFor), len(items), next.NextToken)
	writeJSON(writer, 200, contract.ObservationListResponse{Data: data, Meta: meta, Errors: []contract.CollectionError{}})
}

func (server *Server) listGPUs(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityTelemetryRead)
	if !ok {
		return
	}
	page, err := parsePage(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	filters, err := parseGPUFilters(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	items, next, err := server.queries.ListGPUSummaries(request.Context(), clusterID, filters, page)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	data := make([]contract.GPUSummary, 0, len(items))
	for _, item := range items {
		data = append(data, mapGPU(item))
	}
	meta := responseMeta(state.ID, server.clock.Now(), statusForCount(len(items)), aggregateGPUFreshness(items), len(items), next.NextToken)
	writeJSON(writer, 200, contract.GPUSummaryListResponse{Data: data, Meta: meta, Errors: []contract.CollectionError{}})
}

func (server *Server) listRuns(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityTelemetryRead)
	if !ok {
		return
	}
	page, err := parsePage(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	filters, err := parseRunFilters(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	items, next, err := server.queries.ListCollectionRuns(request.Context(), clusterID, filters, page)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	data := make([]contract.CollectionRun, 0, len(items))
	now := server.clock.Now()
	for _, item := range items {
		data = append(data, mapRun(clusterID, item, now, server.freshFor))
	}
	meta := responseMeta(state.ID, now, aggregateRunStatus(items), freshnessForRuns(items, now, server.freshFor), len(items), next.NextToken)
	writeJSON(writer, 200, contract.CollectionRunListResponse{Data: data, Meta: meta, Errors: []contract.CollectionError{}})
}

func (server *Server) listEvidence(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityTelemetryRead)
	if !ok {
		return
	}
	page, err := parsePage(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	filters, err := parseEvidenceFilters(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	items, next, err := server.queries.ListEvidence(request.Context(), clusterID, filters, page)
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	data := make([]contract.Evidence, 0, len(items))
	for _, item := range items {
		data = append(data, mapEvidence(item))
	}
	meta := responseMeta(state.ID, server.clock.Now(), evidenceListStatus(items), domain.FreshnessUnknown, len(items), next.NextToken)
	writeJSON(writer, 200, contract.EvidenceListResponse{Data: data, Meta: meta, Errors: []contract.CollectionError{}})
}

func (server *Server) getEvidence(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityTelemetryRead)
	if !ok {
		return
	}
	item, found, err := server.queries.GetEvidence(request.Context(), clusterID, domain.EvidenceID(request.PathValue("evidence_id")))
	if err != nil {
		server.queryError(writer, state.ID)
		return
	}
	if !found {
		writeProblem(writer, state.ID, 404, "NOT_FOUND", "Not found", "the requested resource was not found")
		return
	}
	writeJSON(writer, 200, mapEvidence(item))
}

func (server *Server) streamEvents(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityTelemetryRead)
	if !ok {
		return
	}
	after, err := parseLastEventID(request.Header.Get("Last-Event-ID"))
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	requestedTypes, err := parseEventTypes(request)
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		server.queryError(writer, state.ID)
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.WriteHeader(200)
	flusher.Flush()
	for {
		page, err := server.events.WaitAfter(request.Context(), clusterID, after, events.MaxPageSize, 15*time.Second)
		if err != nil {
			return
		}
		if len(page.Events) == 0 {
			if _, err := fmt.Fprint(writer, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
			continue
		}
		for _, event := range page.Events {
			name, payload := mapEvent(event)
			after = event.ID
			if len(requestedTypes) > 0 {
				if _, included := requestedTypes[name]; !included {
					continue
				}
			}
			encoded, err := json.Marshal(payload)
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(writer, "id: evt_%d\nevent: %s\ndata: %s\n\n", event.ID, name, encoded); err != nil {
				return
			}
		}
		flusher.Flush()
	}
}

func parsePage(request *http.Request) (application.PageRequest, error) {
	page := application.PageRequest{Token: request.URL.Query().Get("page_token")}
	if raw := request.URL.Query().Get("page_size"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return page, fmt.Errorf("page_size must be an integer")
		}
		page.Size = value
	}
	if page.Size < 0 || page.Size > application.MaxPageSize {
		return page, fmt.Errorf("page_size must be between 1 and %d", application.MaxPageSize)
	}
	if len(page.Token) > 2048 {
		return page, fmt.Errorf("page_token is too long")
	}
	return page, nil
}

func parseSourceFilters(request *http.Request) (application.SourceFilters, error) {
	status := request.URL.Query().Get("status")
	switch status {
	case "", "AVAILABLE", "DEGRADED", "UNAVAILABLE", "UNKNOWN":
		return application.SourceFilters{Status: status}, nil
	default:
		return application.SourceFilters{}, fmt.Errorf("status is invalid")
	}
}

func parseObservationFilters(request *http.Request) (application.ObservationFilters, error) {
	query := request.URL.Query()
	filters := application.ObservationFilters{SourceID: query.Get("source_id"), EntityKey: query.Get("entity_key"), Kind: query.Get("kind"), Metric: query.Get("metric")}
	var err error
	if raw := query.Get("observed_after"); raw != "" {
		value, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			return filters, fmt.Errorf("observed_after must be RFC 3339")
		}
		filters.ObservedAfter = &value
	}
	if raw := query.Get("observed_before"); raw != "" {
		value, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			return filters, fmt.Errorf("observed_before must be RFC 3339")
		}
		filters.ObservedBefore = &value
	}
	if filters.ObservedAfter != nil && filters.ObservedBefore != nil && filters.ObservedAfter.After(*filters.ObservedBefore) {
		err = fmt.Errorf("observed_after must not follow observed_before")
	}
	return filters, err
}

func parseGPUFilters(request *http.Request) (application.GPUFilters, error) {
	filters := application.GPUFilters{NodeID: request.URL.Query().Get("node_id"), Health: domain.HealthSignalType(request.URL.Query().Get("health"))}
	switch filters.Health {
	case "", domain.HealthSignalNormal, domain.HealthSignalPartial, domain.HealthSignalStale, domain.HealthSignalUnavailable, domain.HealthSignalNoData, domain.HealthSignalXID, domain.HealthSignalECC, domain.HealthSignalThermal, domain.HealthSignalMemory, domain.HealthSignalPower, domain.HealthSignalUtilization:
		return filters, nil
	default:
		return filters, fmt.Errorf("health is invalid")
	}
}

func parseRunFilters(request *http.Request) (application.CollectionRunFilters, error) {
	filters := application.CollectionRunFilters{SourceID: domain.SourceID(request.URL.Query().Get("source_id")), Status: domain.ResultStatus(request.URL.Query().Get("status"))}
	switch filters.Status {
	case "", domain.ResultSucceeded, domain.ResultNoData, domain.ResultPartial, domain.ResultFailed:
		return filters, nil
	default:
		return filters, fmt.Errorf("status is invalid")
	}
}

func parseEvidenceFilters(request *http.Request) (application.EvidenceFilters, error) {
	filters := application.EvidenceFilters{Status: domain.EvidenceStatus(request.URL.Query().Get("status")), TargetID: domain.EvidenceTargetID(request.URL.Query().Get("target_id"))}
	switch filters.Status {
	case "", domain.EvidenceComplete, domain.EvidencePartial, domain.EvidenceNoData, domain.EvidenceUnavailable:
		return filters, nil
	default:
		return filters, fmt.Errorf("status is invalid")
	}
}

func parseLastEventID(value string) (events.ID, error) {
	if value == "" {
		return 0, nil
	}
	if !strings.HasPrefix(value, "evt_") {
		return 0, fmt.Errorf("Last-Event-ID must be a Sherlock event identifier")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "evt_"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Last-Event-ID must be a Sherlock event identifier")
	}
	return events.ID(parsed), nil
}

func parseEventTypes(request *http.Request) (map[contract.EventType]struct{}, error) {
	result := make(map[contract.EventType]struct{})
	for _, raw := range request.URL.Query()["event_type"] {
		value := contract.EventType(raw)
		switch value {
		case contract.EventTypeCollectionRunUpdated, contract.EventTypeSourceUpdated:
			result[value] = struct{}{}
		default:
			return nil, fmt.Errorf("event_type is invalid")
		}
	}
	return result, nil
}

func (server *Server) queryError(writer http.ResponseWriter, requestID string) {
	writeProblem(writer, requestID, 503, "SERVICE_UNAVAILABLE", "Service unavailable", "the query service is temporarily unavailable")
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	if writer.Header().Get("Content-Type") == "" {
		writer.Header().Set("Content-Type", "application/json")
	}
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeProblem(writer http.ResponseWriter, requestID string, status int, code, title, detail string) {
	if requestID == "" {
		requestID = newRequestID()
	}
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, status, contract.Problem{Type: "https://sherlock.dev/problems/" + strings.ToLower(strings.ReplaceAll(code, "_", "-")), Title: title, Status: status, Code: code, Detail: detail, RequestID: requestID})
}

func newRequestID() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(value[:])
}

var _ = errors.Is
