package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const maxDiagnosticBody = 64 << 10

type diagnosticDefinitionDTO struct {
	PackID            string `json:"pack_id"`
	PackVersion       string `json:"pack_version"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion string `json:"definition_version"`
	DefinitionSHA256  string `json:"definition_sha256"`
}

type diagnosticArgumentDTO struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type diagnosticRequestDTO struct {
	Definition  diagnosticDefinitionDTO `json:"definition"`
	Targets     []string                `json:"targets"`
	Arguments   []diagnosticArgumentDTO `json:"arguments"`
	Deadline    *time.Time              `json:"deadline,omitempty"`
	MaxAttempts int                     `json:"max_attempts,omitempty"`
}

type diagnosticApprovalDTO struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type diagnosticRunDTO struct {
	RunID       string                  `json:"run_id"`
	ClusterID   string                  `json:"cluster_id"`
	Definition  diagnosticDefinitionDTO `json:"definition"`
	Privilege   string                  `json:"privilege"`
	Status      string                  `json:"status"`
	RequestedBy string                  `json:"requested_by"`
	RequestedAt time.Time               `json:"requested_at"`
	Deadline    time.Time               `json:"deadline"`
	CompletedAt *time.Time              `json:"completed_at,omitempty"`
	Version     int                     `json:"version"`
	WorkID      string                  `json:"work_id,omitempty"`
	Attempts    []diagnosticAttemptDTO  `json:"attempts"`
}

type diagnosticAttemptDTO struct {
	Attempt      int                         `json:"attempt"`
	RunnerID     string                      `json:"runner_id"`
	Status       string                      `json:"status"`
	LeaseExpires time.Time                   `json:"lease_expires_at"`
	PlanSHA256   string                      `json:"plan_sha256,omitempty"`
	StartedAt    *time.Time                  `json:"started_at,omitempty"`
	CompletedAt  *time.Time                  `json:"completed_at,omitempty"`
	Targets      []diagnosticTargetResultDTO `json:"targets"`
}

type diagnosticTargetResultDTO struct {
	Target                    string `json:"target"`
	Status                    string `json:"status"`
	Retryable                 bool   `json:"retryable"`
	ExitCode                  *int   `json:"exit_code,omitempty"`
	Signal                    string `json:"signal,omitempty"`
	TimedOut                  bool   `json:"timed_out"`
	StdoutTruncated           bool   `json:"stdout_truncated"`
	StderrTruncated           bool   `json:"stderr_truncated"`
	StdoutBytes               int64  `json:"stdout_bytes"`
	StderrBytes               int64  `json:"stderr_bytes"`
	StdoutSHA256              string `json:"stdout_sha256"`
	StdoutTransformationState string `json:"stdout_transformation_state"`
	StderrSHA256              string `json:"stderr_sha256"`
	ErrorCode                 string `json:"error_code,omitempty"`
	StdoutExcerpt             string `json:"stdout_excerpt,omitempty"`
}

func (server *Server) previewDiagnostic(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityInvestigationsRun)
	if !ok {
		return
	}
	if server.diagnostics == nil {
		server.diagnosticUnavailable(writer, state.ID)
		return
	}
	input, err := decodeDiagnosticRequest(request, false)
	if err != nil {
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	decision, err := server.diagnostics.PreviewAuthorization(request.Context(), application.PreviewDiagnosticInput{ActorID: state.Principal.KeyID, ClusterID: clusterID, Definition: input.definition, Targets: input.targets, Arguments: input.arguments})
	if err != nil {
		server.diagnosticError(writer, state.ID, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"allowed": decision.Allowed, "approval_required": decision.ApprovalRequired, "reason_code": decision.ReasonCode})
}

func (server *Server) startDiagnostic(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityInvestigationsRun)
	if !ok {
		return
	}
	if server.diagnostics == nil {
		server.diagnosticUnavailable(writer, state.ID)
		return
	}
	input, err := decodeDiagnosticRequest(request, true)
	if err != nil {
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", "Idempotency-Key is required")
		return
	}
	outcome, err := server.diagnostics.Start(request.Context(), application.StartDiagnosticInput{ActorID: state.Principal.KeyID, ClusterID: clusterID, Definition: input.definition, Targets: input.targets, Arguments: input.arguments, IdempotencyKey: idempotencyKey, Deadline: *input.deadline, MaxAttempts: input.maxAttempts})
	if err != nil {
		server.diagnosticError(writer, state.ID, err)
		return
	}
	mapped := mapDiagnosticDomainRun(outcome.Run)
	writer.Header().Set("Location", "/api/v1/clusters/"+string(clusterID)+"/diagnostic-runs/"+mapped.RunID)
	status := http.StatusAccepted
	if outcome.PreviouslyRecorded {
		status = http.StatusOK
	}
	writeJSON(writer, status, mapped)
}

func (server *Server) getDiagnosticRun(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityInvestigationsRead)
	if !ok {
		return
	}
	if server.diagnosticRuns == nil {
		server.diagnosticUnavailable(writer, state.ID)
		return
	}
	runID := domain.DiagnosticRunID(request.PathValue("run_id"))
	projection, found, err := server.diagnosticRuns.GetRun(request.Context(), clusterID, runID)
	if err != nil {
		server.diagnosticError(writer, state.ID, err)
		return
	}
	if !found {
		writeProblem(writer, state.ID, http.StatusNotFound, "NOT_FOUND", "Not found", "the requested resource was not found")
		return
	}
	writeJSON(writer, http.StatusOK, mapDiagnosticProjection(projection))
}

func (server *Server) approveDiagnostic(writer http.ResponseWriter, request *http.Request) {
	state, clusterID, ok := server.authorize(writer, request, auth.CapabilityDiagnosticsPrivileged)
	if !ok {
		return
	}
	if server.diagnostics == nil {
		server.diagnosticUnavailable(writer, state.ID)
		return
	}
	var body diagnosticApprovalDTO
	if err := decodeStrictJSON(request, &body); err != nil || body.ExpiresAt.IsZero() {
		if err == nil {
			err = errors.New("expires_at is required")
		}
		writeProblem(writer, state.ID, http.StatusBadRequest, "INVALID_ARGUMENT", "Invalid request", err.Error())
		return
	}
	run, err := server.diagnostics.Approve(request.Context(), application.ApproveDiagnosticInput{ClusterID: clusterID, RunID: domain.DiagnosticRunID(request.PathValue("run_id")), ApprovedBy: state.Principal.KeyID, ExpiresAt: body.ExpiresAt})
	if err != nil {
		server.diagnosticError(writer, state.ID, err)
		return
	}
	writeJSON(writer, http.StatusOK, mapDiagnosticDomainRun(run))
}

type decodedDiagnosticRequest struct {
	definition  domain.DiagnosticDefinitionRef
	targets     []domain.DiagnosticTarget
	arguments   []domain.DiagnosticArgument
	deadline    *time.Time
	maxAttempts int
}

func decodeDiagnosticRequest(request *http.Request, requireExecution bool) (decodedDiagnosticRequest, error) {
	var body diagnosticRequestDTO
	if err := decodeStrictJSON(request, &body); err != nil {
		return decodedDiagnosticRequest{}, err
	}
	digest, err := hex.DecodeString(body.Definition.DefinitionSHA256)
	if err != nil || len(digest) != sha256.Size || body.Definition.DefinitionSHA256 != strings.ToLower(body.Definition.DefinitionSHA256) {
		return decodedDiagnosticRequest{}, errors.New("definition_sha256 must be 64 lowercase hexadecimal characters")
	}
	result := decodedDiagnosticRequest{definition: domain.DiagnosticDefinitionRef{PackID: body.Definition.PackID, PackVersion: body.Definition.PackVersion, DefinitionID: domain.DiagnosticDefinitionID(body.Definition.DefinitionID), DefinitionVersion: body.Definition.DefinitionVersion}, deadline: body.Deadline, maxAttempts: body.MaxAttempts}
	copy(result.definition.DefinitionDigest[:], digest)
	if result.definition.DefinitionDigest == (domain.SHA256{}) {
		return decodedDiagnosticRequest{}, errors.New("definition_sha256 cannot be zero")
	}
	for _, target := range body.Targets {
		result.targets = append(result.targets, domain.DiagnosticTarget(target))
	}
	for _, argument := range body.Arguments {
		result.arguments = append(result.arguments, domain.DiagnosticArgument{Name: argument.Name, Value: argument.Value})
	}
	if requireExecution {
		if result.deadline == nil {
			return decodedDiagnosticRequest{}, errors.New("deadline is required")
		}
		if result.maxAttempts == 0 {
			result.maxAttempts = 1
		}
	}
	return result, nil
}

func decodeStrictJSON(request *http.Request, destination any) error {
	contentType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])
	if contentType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maxDiagnosticBody+1))
	if err != nil {
		return errors.New("read JSON body")
	}
	if len(payload) > maxDiagnosticBody {
		return errors.New("request body exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func mapDiagnosticDomainRun(run domain.DiagnosticRun) diagnosticRunDTO {
	request := run.Request()
	return diagnosticRunDTO{RunID: string(request.RunID), ClusterID: string(request.ClusterID), Definition: mapDiagnosticDefinition(request.Definition), Privilege: string(request.Privilege), Status: string(run.Status()), RequestedBy: request.RequestedBy, RequestedAt: request.RequestedAt, Deadline: request.Deadline, Version: run.Version(), Attempts: []diagnosticAttemptDTO{}}
}

func mapDiagnosticProjection(projection application.DiagnosticRunProjection) diagnosticRunDTO {
	result := diagnosticRunDTO{RunID: string(projection.RunID), ClusterID: string(projection.ClusterID), Definition: mapDiagnosticDefinition(projection.Definition), Privilege: string(projection.Privilege), Status: string(projection.Status), RequestedBy: projection.RequestedBy, RequestedAt: projection.RequestedAt, Deadline: projection.Deadline, CompletedAt: projection.CompletedAt, Version: projection.Version, WorkID: string(projection.WorkID), Attempts: []diagnosticAttemptDTO{}}
	for _, attempt := range projection.Attempts {
		mapped := diagnosticAttemptDTO{Attempt: attempt.Attempt, RunnerID: attempt.RunnerID, Status: string(attempt.Status), LeaseExpires: attempt.LeaseExpires, StartedAt: attempt.StartedAt, CompletedAt: attempt.CompletedAt, Targets: []diagnosticTargetResultDTO{}}
		if attempt.PlanDigest != nil {
			mapped.PlanSHA256 = attempt.PlanDigest.String()
		}
		for _, target := range attempt.Targets {
			mapped.Targets = append(mapped.Targets, diagnosticTargetResultDTO{Target: string(target.Target), Status: string(target.Status), Retryable: target.Retryable, ExitCode: target.ExitCode, Signal: target.Signal, TimedOut: target.TimedOut, StdoutTruncated: target.StdoutTruncated, StderrTruncated: target.StderrTruncated, StdoutBytes: target.StdoutBytes, StderrBytes: target.StderrBytes, StdoutSHA256: target.StdoutSHA256.String(), StdoutTransformationState: string(domain.NormalizeStdoutTransformationState(string(target.StdoutTransformationState))), StderrSHA256: target.StderrSHA256.String(), ErrorCode: target.ErrorCode, StdoutExcerpt: target.StdoutExcerpt})
		}
		result.Attempts = append(result.Attempts, mapped)
	}
	return result
}

func mapDiagnosticDefinition(reference domain.DiagnosticDefinitionRef) diagnosticDefinitionDTO {
	return diagnosticDefinitionDTO{PackID: reference.PackID, PackVersion: reference.PackVersion, DefinitionID: string(reference.DefinitionID), DefinitionVersion: reference.DefinitionVersion, DefinitionSHA256: reference.DefinitionDigest.String()}
}

func (server *Server) diagnosticUnavailable(writer http.ResponseWriter, requestID string) {
	writeProblem(writer, requestID, http.StatusServiceUnavailable, "DIAGNOSTICS_UNAVAILABLE", "Service unavailable", "diagnostic execution is not configured")
}
func (server *Server) diagnosticError(writer http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, application.ErrDiagnosticNotFound):
		writeProblem(writer, requestID, http.StatusNotFound, "NOT_FOUND", "Not found", "the requested resource was not found")
	case errors.Is(err, application.ErrDiagnosticForbidden):
		writeProblem(writer, requestID, http.StatusForbidden, "CAPABILITY_DENIED", "Forbidden", "the diagnostic action is not authorized")
	case errors.Is(err, application.ErrDiagnosticConflict):
		writeProblem(writer, requestID, http.StatusConflict, "CONFLICT", "Conflict", "the diagnostic state changed")
	case errors.Is(err, application.ErrDiagnosticDefinitionInvalid):
		writeProblem(writer, requestID, http.StatusBadRequest, "INVALID_DEFINITION", "Invalid request", "the signed diagnostic definition is invalid or unavailable")
	default:
		writeProblem(writer, requestID, http.StatusInternalServerError, "INTERNAL", "Internal error", "the diagnostic operation failed")
	}
}
