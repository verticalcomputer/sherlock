package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	contract "github.com/verticalcomputer/sherlock/sdk/go"
)

// InvestigationAPI is the transport-owned consumer contract for the M6
// incident and investigation workflow. Application adapters implement this
// interface; HTTP handlers do not own workflow transitions or persistence.
type InvestigationAPI interface {
	CreateIncident(context.Context, CreateIncidentInput) (IncidentResource, bool, error)
	ListIncidents(context.Context, domain.ClusterID, IncidentListOptions) ([]IncidentResource, string, error)
	GetIncident(context.Context, string) (IncidentResource, bool, error)
	StartInvestigation(context.Context, StartInvestigationInput) (InvestigationResource, bool, error)
	GetInvestigation(context.Context, string) (InvestigationResource, bool, error)
	CancelInvestigation(context.Context, CancelInvestigationInput) (InvestigationResource, error)
	ApproveInvestigation(context.Context, ApproveInvestigationInput) (InvestigationResource, error)
	ListInvestigationEvents(context.Context, string, string, int) ([]InvestigationEventResource, error)
	ListInvestigationEvidence(context.Context, string) ([]InvestigationEvidenceResource, error)
	ListInvestigationHypotheses(context.Context, string) ([]HypothesisResource, error)
	ListInvestigationFindings(context.Context, string) ([]FindingResource, error)
}

var (
	ErrInvestigationInvalid     = errors.New("invalid investigation request")
	ErrInvestigationNotFound    = errors.New("investigation not found")
	ErrInvestigationConflict    = errors.New("investigation state conflict")
	ErrInvestigationUnavailable = errors.New("investigation service unavailable")
)

type CreateIncidentInput struct {
	ClusterID      domain.ClusterID
	ActorID        string
	IdempotencyKey string
	Title          string
	Summary        string
	Severity       string
	TargetIDs      []string
	EvidenceIDs    []string
}

type IncidentListOptions struct {
	PageSize  int
	PageToken string
	Status    string
	Severity  string
}

type IncidentResource = contract.Incident

type InvestigationBudgetResource = contract.InvestigationBudget

type InvestigationScopeResource = contract.InvestigationScope

type StartInvestigationInput struct {
	Purpose         string
	ClusterID       domain.ClusterID
	ActorID         string
	IdempotencyKey  string
	IncidentID      string
	Question        string
	Scope           InvestigationScopeResource
	SuccessCriteria []string
	Budget          InvestigationBudgetResource
	Deadline        time.Time
}

type InvestigationResource = contract.Investigation

type InvestigationActionResource = contract.InvestigationAction

type InvestigationEventResource = contract.InvestigationEvent

type InvestigationEvidenceResource = contract.InvestigationEvidence

type HypothesisResource = contract.Hypothesis

type FindingResource = contract.Finding

type CancelInvestigationInput struct {
	InvestigationID string
	ActorID         string
	ExpectedVersion int
	Reason          string
}

type ApproveInvestigationInput struct {
	InvestigationID string
	ActorID         string
	ApprovalID      string
	ActionID        string
	ActionSHA256    string
	ExpectedVersion int
	ExpiresAt       time.Time
}

type incidentCreateDTO struct {
	Title       string   `json:"title"`
	Summary     string   `json:"summary"`
	Severity    string   `json:"severity"`
	TargetIDs   []string `json:"target_ids"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type investigationStartDTO struct {
	ClusterID       string                      `json:"cluster_id"`
	IncidentID      string                      `json:"incident_id"`
	Question        string                      `json:"question"`
	Scope           InvestigationScopeResource  `json:"scope"`
	SuccessCriteria []string                    `json:"success_criteria"`
	Budget          InvestigationBudgetResource `json:"budget"`
	Deadline        time.Time                   `json:"deadline"`
}

type investigationCancelDTO struct {
	ExpectedVersion int    `json:"expected_version"`
	Reason          string `json:"reason"`
}

type investigationApprovalDTO struct {
	ApprovalID      string    `json:"approval_id"`
	ActionID        string    `json:"action_id"`
	ActionSHA256    string    `json:"action_sha256"`
	ExpectedVersion int       `json:"expected_version"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type incidentListResponse struct {
	Data          []IncidentResource `json:"data"`
	NextPageToken string             `json:"next_page_token,omitempty"`
}

func (server *Server) createIncident(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityIncidentsWrite)
	if !ok {
		return
	}
	if !server.requireInvestigationAPI(writer, state.ID) {
		return
	}
	key, ok := requireIdempotencyKey(writer, request, state.ID)
	if !ok {
		return
	}
	var body incidentCreateDTO
	if err := decodeStrictJSON(request, &body); err != nil || strings.TrimSpace(body.Title) == "" || !validIncidentSeverity(body.Severity) {
		if err == nil {
			err = errors.New("title and a valid severity are required")
		}
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	incident, recorded, err := server.investigations.CreateIncident(request.Context(), CreateIncidentInput{ClusterID: clusterID, ActorID: state.Principal.KeyID, IdempotencyKey: key, Title: body.Title, Summary: body.Summary, Severity: body.Severity, TargetIDs: body.TargetIDs, EvidenceIDs: body.EvidenceIDs})
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return
	}
	writer.Header().Set("Location", "/api/v1/incidents/"+incident.IncidentID)
	status := http.StatusCreated
	if recorded {
		status = http.StatusOK
	}
	writeJSON(writer, status, incident)
}

func (server *Server) listIncidents(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityIncidentsRead)
	if !ok {
		return
	}
	if !server.requireInvestigationAPI(writer, state.ID) {
		return
	}
	page, err := parsePage(request)
	status, severity := request.URL.Query().Get("status"), request.URL.Query().Get("severity")
	if err != nil || !validOptionalIncidentStatus(status) || !validOptionalIncidentSeverity(severity) {
		if err == nil {
			err = errors.New("status or severity is invalid")
		}
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	items, next, err := server.investigations.ListIncidents(request.Context(), clusterID, IncidentListOptions{PageSize: page.Size, PageToken: page.Token, Status: status, Severity: severity})
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return
	}
	if items == nil {
		items = []IncidentResource{}
	}
	writeJSON(writer, http.StatusOK, incidentListResponse{Data: items, NextPageToken: next})
}

func (server *Server) getIncident(writer http.ResponseWriter, request *http.Request) {
	state := request.Context().Value(requestKey{}).(requestState)
	if !server.requireInvestigationAPI(writer, state.ID) {
		return
	}
	incident, found, err := server.investigations.GetIncident(request.Context(), request.PathValue("incident_id"))
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return
	}
	if !found {
		writeProblem(writer, state.ID, http.StatusNotFound, "NOT_FOUND", "Not found", "the requested resource was not found")
		return
	}
	if !authorizeResolved(writer, state, domain.ClusterID(incident.ClusterID), auth.CapabilityIncidentsRead) {
		return
	}
	writeJSON(writer, http.StatusOK, incident)
}

func (server *Server) startInvestigation(writer http.ResponseWriter, request *http.Request) {
	state := request.Context().Value(requestKey{}).(requestState)
	if !server.requireInvestigationAPI(writer, state.ID) {
		return
	}
	key, ok := requireIdempotencyKey(writer, request, state.ID)
	if !ok {
		return
	}
	var body investigationStartDTO
	if err := decodeStrictJSON(request, &body); err != nil || body.ClusterID == "" || strings.TrimSpace(body.Question) == "" || body.IncidentID == "" || !validScope(body.Scope) || len(body.SuccessCriteria) < 1 || len(body.SuccessCriteria) > 32 || !validBudget(body.Budget) || body.Deadline.IsZero() {
		if err == nil {
			err = errors.New("cluster_id, incident_id, question, scope, success_criteria, budget, and deadline are required")
		}
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	clusterID := domain.ClusterID(body.ClusterID)
	if !authorizeResolved(writer, state, clusterID, auth.CapabilityInvestigationsRun) {
		return
	}
	result, recorded, err := server.investigations.StartInvestigation(request.Context(), StartInvestigationInput{ClusterID: clusterID, ActorID: state.Principal.KeyID, IdempotencyKey: key, IncidentID: body.IncidentID, Question: body.Question, Scope: body.Scope, SuccessCriteria: body.SuccessCriteria, Budget: body.Budget, Deadline: body.Deadline})
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return
	}
	writer.Header().Set("Location", "/api/v1/investigations/"+result.InvestigationID)
	status := http.StatusAccepted
	if recorded {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (server *Server) getInvestigation(writer http.ResponseWriter, request *http.Request) {
	server.withInvestigation(writer, request, auth.CapabilityInvestigationsRead, func(state requestState, item InvestigationResource) {
		writer.Header().Set("ETag", fmt.Sprintf("\"%d\"", item.Version))
		writeJSON(writer, http.StatusOK, item)
	})
}

func (server *Server) cancelInvestigation(writer http.ResponseWriter, request *http.Request) {
	state, item, ok := server.resolveInvestigation(writer, request, auth.CapabilityInvestigationsRun)
	if !ok {
		return
	}
	var body investigationCancelDTO
	if err := decodeStrictJSON(request, &body); err != nil || body.ExpectedVersion < 1 || strings.TrimSpace(body.Reason) == "" {
		if err == nil {
			err = errors.New("expected_version and reason are required")
		}
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	result, err := server.investigations.CancelInvestigation(request.Context(), CancelInvestigationInput{InvestigationID: item.InvestigationID, ActorID: state.Principal.KeyID, ExpectedVersion: body.ExpectedVersion, Reason: body.Reason})
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (server *Server) approveInvestigation(writer http.ResponseWriter, request *http.Request) {
	state, item, ok := server.resolveInvestigation(writer, request, auth.CapabilityDiagnosticsPrivileged)
	if !ok {
		return
	}
	var body investigationApprovalDTO
	if err := decodeStrictJSON(request, &body); err != nil || body.ApprovalID == "" || body.ActionID == "" || len(body.ActionSHA256) != 64 || body.ExpectedVersion < 1 || body.ExpiresAt.IsZero() {
		if err == nil {
			err = errors.New("approval_id, action_id, action_sha256, expected_version, and expires_at are required")
		}
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	result, err := server.investigations.ApproveInvestigation(request.Context(), ApproveInvestigationInput{InvestigationID: item.InvestigationID, ActorID: state.Principal.KeyID, ApprovalID: body.ApprovalID, ActionID: body.ActionID, ActionSHA256: body.ActionSHA256, ExpectedVersion: body.ExpectedVersion, ExpiresAt: body.ExpiresAt})
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (server *Server) listInvestigationEvents(writer http.ResponseWriter, request *http.Request) {
	state, item, ok := server.resolveInvestigation(writer, request, auth.CapabilityInvestigationsRead)
	if !ok {
		return
	}
	limit, err := parseLedgerLimit(request.URL.Query().Get("limit"))
	if err != nil {
		writeProblem(writer, state.ID, 400, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	events, err := server.investigations.ListInvestigationEvents(request.Context(), item.InvestigationID, request.Header.Get("Last-Event-ID"), limit)
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return
	}
	if events == nil {
		events = []InvestigationEventResource{}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"data": events})
}

func (server *Server) listInvestigationEvidence(writer http.ResponseWriter, request *http.Request) {
	server.writeInvestigationLedger(writer, request, func(ctx context.Context, id string) (any, error) {
		values, err := server.investigations.ListInvestigationEvidence(ctx, id)
		if values == nil {
			values = []InvestigationEvidenceResource{}
		}
		return values, err
	})
}
func (server *Server) listInvestigationHypotheses(writer http.ResponseWriter, request *http.Request) {
	server.writeInvestigationLedger(writer, request, func(ctx context.Context, id string) (any, error) {
		values, err := server.investigations.ListInvestigationHypotheses(ctx, id)
		if values == nil {
			values = []HypothesisResource{}
		}
		return values, err
	})
}
func (server *Server) listInvestigationFindings(writer http.ResponseWriter, request *http.Request) {
	server.writeInvestigationLedger(writer, request, func(ctx context.Context, id string) (any, error) {
		values, err := server.investigations.ListInvestigationFindings(ctx, id)
		if values == nil {
			values = []FindingResource{}
		}
		return values, err
	})
}

func (server *Server) writeInvestigationLedger(writer http.ResponseWriter, request *http.Request, load func(context.Context, string) (any, error)) {
	state, item, ok := server.resolveInvestigation(writer, request, auth.CapabilityInvestigationsRead)
	if !ok {
		return
	}
	values, err := load(request.Context(), item.InvestigationID)
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"data": values})
}

func (server *Server) withInvestigation(writer http.ResponseWriter, request *http.Request, capability auth.Capability, fn func(requestState, InvestigationResource)) {
	state, item, ok := server.resolveInvestigation(writer, request, capability)
	if ok {
		fn(state, item)
	}
}

func (server *Server) resolveInvestigation(writer http.ResponseWriter, request *http.Request, capability auth.Capability) (requestState, InvestigationResource, bool) {
	state := request.Context().Value(requestKey{}).(requestState)
	if !server.requireInvestigationAPI(writer, state.ID) {
		return state, InvestigationResource{}, false
	}
	item, found, err := server.investigations.GetInvestigation(request.Context(), request.PathValue("investigation_id"))
	if err != nil {
		server.investigationError(writer, state.ID, err)
		return state, item, false
	}
	if !found {
		writeProblem(writer, state.ID, http.StatusNotFound, "NOT_FOUND", "Not found", "the requested resource was not found")
		return state, item, false
	}
	return state, item, authorizeResolved(writer, state, domain.ClusterID(item.ClusterID), capability)
}

func authorizeResolved(writer http.ResponseWriter, state requestState, clusterID domain.ClusterID, capability auth.Capability) bool {
	if clusterID == "" || state.Principal.Authorize(clusterID, capability) != nil {
		writeProblem(writer, state.ID, http.StatusForbidden, "CLUSTER_SCOPE_DENIED", "Forbidden", "the key is not authorized for this cluster")
		return false
	}
	return true
}

func (server *Server) requireInvestigationAPI(writer http.ResponseWriter, requestID string) bool {
	if server.investigations == nil {
		writeProblem(writer, requestID, http.StatusServiceUnavailable, "INVESTIGATIONS_UNAVAILABLE", "Service unavailable", "incident and investigation workflows are not configured")
		return false
	}
	return true
}

func (server *Server) investigationError(writer http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, ErrInvestigationInvalid):
		writeProblem(writer, requestID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", "the investigation request is invalid")
	case errors.Is(err, ErrInvestigationNotFound):
		writeProblem(writer, requestID, http.StatusNotFound, "NOT_FOUND", "Not found", "the requested investigation was not found")
	case errors.Is(err, ErrInvestigationConflict):
		writeProblem(writer, requestID, http.StatusConflict, "CONFLICT", "Conflict", "the investigation state changed")
	case errors.Is(err, ErrInvestigationUnavailable):
		writeProblem(writer, requestID, http.StatusServiceUnavailable, "INVESTIGATIONS_UNAVAILABLE", "Service unavailable", "the investigation service is temporarily unavailable")
	default:
		writeProblem(writer, requestID, http.StatusInternalServerError, "INTERNAL", "Internal error", "the investigation operation failed")
	}
}

func requireIdempotencyKey(writer http.ResponseWriter, request *http.Request, requestID string) (string, bool) {
	key := request.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		writeProblem(writer, requestID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", "Idempotency-Key is required and must not exceed 128 characters")
		return "", false
	}
	return key, true
}

func validIncidentSeverity(value string) bool {
	return value == "INFO" || value == "LOW" || value == "MEDIUM" || value == "HIGH" || value == "CRITICAL"
}
func validOptionalIncidentSeverity(value string) bool {
	return value == "" || validIncidentSeverity(value)
}
func validOptionalIncidentStatus(value string) bool {
	switch value {
	case "", "OPEN", "INVESTIGATING", "MONITORING", "RESOLVED", "CLOSED":
		return true
	default:
		return false
	}
}
func validBudget(value InvestigationBudgetResource) bool {
	return value.MaxDecisions > 0 && value.MaxDecisions <= 100 && value.MaxToolCalls > 0 && value.MaxToolCalls <= 1000 && value.MaxDiagnosticCalls >= 0 && value.MaxDiagnosticCalls <= 1000 && value.MaxPrivilegedCalls >= 0 && value.MaxPrivilegedCalls <= value.MaxToolCalls+value.MaxDiagnosticCalls && value.MaxFanOut > 0 && value.MaxFanOut <= 256 && value.MaxModelTokens >= 0 && value.MaxCostMicros >= 0
}
func validScope(value InvestigationScopeResource) bool {
	return value.EntityKind != "" && len(value.EntityIDs) > 0 && len(value.EntityIDs) <= 256 && !value.Start.IsZero() && !value.End.IsZero() && !value.End.Before(value.Start)
}
func parseLedgerLimit(raw string) (int, error) {
	if raw == "" {
		return 200, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 1000 {
		return 0, errors.New("limit must be between 1 and 1000")
	}
	return value, nil
}
