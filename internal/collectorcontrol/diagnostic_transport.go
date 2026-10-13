package collectorcontrol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ErrDiagnosticExecutionNotPermitted means this collector is not authorized to
// execute commands. A collector authorized to poll metrics is not thereby
// authorized to run anything, so diagnostic claiming is a separate permission
// and refusing it is a 403 rather than a silent empty claim.
var ErrDiagnosticExecutionNotPermitted = errors.New("collector is not permitted to execute diagnostics")

// DiagnosticWorkOperations is the pull side of reviewed remote execution. It is
// a separate endpoint family from collection work because the two carry
// different results: a collection returns a series of observations, and a
// diagnostic returns per-target exit codes and output digests. Forcing the
// second through the first would lose exactly the structure evidence
// projection consumes.
type DiagnosticWorkOperations interface {
	ClaimDiagnosticWork(context.Context, domain.ClusterID, domain.CollectorID, string, time.Duration) (domain.DiagnosticWorkLease, bool, error)
	RecordDiagnosticAttempt(context.Context, domain.ClusterID, domain.CollectorID, domain.DiagnosticWorkID, int, string, domain.DiagnosticAttemptResult) (domain.DiagnosticRunStatus, bool, error)
}

// ConfigureDiagnosticWork adds the diagnostic endpoints. It is opt-in so a
// control plane that grants no cluster diagnostic capability never exposes an
// execution surface at all.
func (t *Transport) ConfigureDiagnosticWork(operations DiagnosticWorkOperations) error {
	if t == nil || operations == nil {
		return fmt.Errorf("diagnostic work operations are required")
	}
	if t.diagnostics != nil {
		return fmt.Errorf("diagnostic work operations are already configured")
	}
	t.diagnostics = operations
	t.mux.HandleFunc("GET /collector/v1/diagnostic-work/claim", t.claimDiagnosticWork)
	t.mux.HandleFunc("POST /collector/v1/diagnostic-work/{work_id}/attempts/{attempt}/results", t.recordDiagnosticAttempt)
	return nil
}

func (t *Transport) claimDiagnosticWork(w http.ResponseWriter, r *http.Request) {
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
		lease, found, err := t.diagnostics.ClaimDiagnosticWork(ctx, identity.ClusterID, identity.CollectorID, token, defaultLeaseDuration)
		if err != nil {
			writeDiagnosticOperationError(w, err, correlationID)
			return
		}
		if found {
			if lease.Work.Run.Request().ClusterID != identity.ClusterID {
				writeDiagnosticOperationError(w, ErrDiagnosticExecutionNotPermitted, correlationID)
				return
			}
			dto, err := diagnosticClaimDTO(lease)
			if err != nil {
				writeProblem(w, http.StatusInternalServerError, "INTERNAL", "collector control operation failed", correlationID)
				return
			}
			writeJSON(w, http.StatusOK, dto)
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
			writeDiagnosticOperationError(w, ctx.Err(), correlationID)
			return
		case <-timer.C:
		}
	}
}

func (t *Transport) recordDiagnosticAttempt(w http.ResponseWriter, r *http.Request) {
	correlationID, ok := validateProtocol(w, r)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, correlationID)
	if !ok {
		return
	}
	workID := r.PathValue("work_id")
	attempt, err := strconv.Atoi(r.PathValue("attempt"))
	if err != nil || attempt < 1 || workID == "" {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "diagnostic work identity is invalid", correlationID)
		return
	}
	var request diagnosticAttemptRequestDTO
	if !decodeJSON(w, r, &request) {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "diagnostic attempt body is invalid", correlationID)
		return
	}
	result, err := request.toDomain(domain.DiagnosticWorkID(workID), attempt)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "diagnostic attempt is invalid", correlationID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	status, recorded, err := t.diagnostics.RecordDiagnosticAttempt(ctx, identity.ClusterID, identity.CollectorID, domain.DiagnosticWorkID(workID), attempt, request.LeaseToken, result)
	if err != nil {
		writeDiagnosticOperationError(w, err, correlationID)
		return
	}
	writeJSON(w, http.StatusOK, diagnosticAttemptResponseDTO{RunID: request.RunID, Status: string(status), Recorded: recorded})
}

type diagnosticDefinitionRefDTO struct {
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

type diagnosticInvocationDTO struct {
	RunID       string                     `json:"run_id"`
	ClusterID   string                     `json:"cluster_id"`
	Definition  diagnosticDefinitionRefDTO `json:"definition"`
	Privilege   string                     `json:"privilege"`
	Targets     []string                   `json:"targets"`
	Arguments   []diagnosticArgumentDTO    `json:"arguments"`
	Deadline    time.Time                  `json:"deadline"`
	MaxAttempts int                        `json:"max_attempts"`
}

type diagnosticClaimResponseDTO struct {
	WorkID       string                  `json:"work_id"`
	Attempt      int                     `json:"attempt"`
	LeaseToken   string                  `json:"lease_token"`
	LeaseExpires time.Time               `json:"lease_expires_at"`
	Invocation   diagnosticInvocationDTO `json:"invocation"`
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
	// StdoutExcerpt is untrusted host output. The domain bounds and screens it;
	// nothing here interprets it.
	StdoutExcerpt string `json:"stdout_excerpt,omitempty"`
}

type diagnosticAttemptRequestDTO struct {
	LeaseToken  string                      `json:"lease_token"`
	RunID       string                      `json:"run_id"`
	RunnerID    string                      `json:"runner_id"`
	PlanSHA256  string                      `json:"plan_sha256"`
	StartedAt   time.Time                   `json:"started_at"`
	CompletedAt time.Time                   `json:"completed_at"`
	Targets     []diagnosticTargetResultDTO `json:"targets"`
}

type diagnosticAttemptResponseDTO struct {
	RunID    string `json:"run_id"`
	Status   string `json:"status"`
	Recorded bool   `json:"recorded"`
}

// diagnosticClaimDTO transmits the invocation by reference only. The argv is
// deliberately absent: the runner resolves it from the signed pack it verifies
// itself, so a compromised control plane cannot dictate a command.
func diagnosticClaimDTO(lease domain.DiagnosticWorkLease) (diagnosticClaimResponseDTO, error) {
	request := lease.Work.Run.Request()
	if err := request.Validate(); err != nil {
		return diagnosticClaimResponseDTO{}, err
	}
	targets := make([]string, 0, len(request.Targets))
	for _, target := range request.Targets {
		targets = append(targets, string(target))
	}
	arguments := make([]diagnosticArgumentDTO, 0, len(request.Arguments))
	for _, argument := range request.Arguments {
		arguments = append(arguments, diagnosticArgumentDTO{Name: argument.Name, Value: argument.Value})
	}
	return diagnosticClaimResponseDTO{
		WorkID: string(lease.Work.WorkID), Attempt: lease.Attempt, LeaseToken: lease.LeaseToken, LeaseExpires: lease.LeaseExpires.UTC(),
		Invocation: diagnosticInvocationDTO{
			RunID: string(request.RunID), ClusterID: string(request.ClusterID),
			Definition: diagnosticDefinitionRefDTO{
				PackID: request.Definition.PackID, PackVersion: request.Definition.PackVersion,
				DefinitionID: string(request.Definition.DefinitionID), DefinitionVersion: request.Definition.DefinitionVersion,
				DefinitionSHA256: request.Definition.DefinitionDigest.String(),
			},
			Privilege: string(request.Privilege), Targets: targets, Arguments: arguments,
			Deadline: request.Deadline.UTC(), MaxAttempts: request.MaxAttempts,
		},
	}, nil
}

func (request diagnosticAttemptRequestDTO) toDomain(workID domain.DiagnosticWorkID, attempt int) (domain.DiagnosticAttemptResult, error) {
	if request.LeaseToken == "" || request.RunID == "" || request.RunnerID == "" || len(request.Targets) == 0 {
		return domain.DiagnosticAttemptResult{}, fmt.Errorf("diagnostic attempt identity is incomplete")
	}
	planDigest, err := domain.ParseSHA256(request.PlanSHA256)
	if err != nil {
		return domain.DiagnosticAttemptResult{}, err
	}
	targets := make([]domain.DiagnosticTargetResult, 0, len(request.Targets))
	seen := make(map[string]struct{}, len(request.Targets))
	for _, target := range request.Targets {
		if _, duplicate := seen[target.Target]; duplicate {
			return domain.DiagnosticAttemptResult{}, fmt.Errorf("diagnostic attempt reports a target twice")
		}
		seen[target.Target] = struct{}{}
		stdout, err := domain.ParseSHA256(target.StdoutSHA256)
		if err != nil {
			return domain.DiagnosticAttemptResult{}, err
		}
		stderr, err := domain.ParseSHA256(target.StderrSHA256)
		if err != nil {
			return domain.DiagnosticAttemptResult{}, err
		}
		var exitCode *int
		if target.ExitCode != nil {
			value := *target.ExitCode
			exitCode = &value
		}
		targets = append(targets, domain.DiagnosticTargetResult{
			Target: domain.DiagnosticTarget(target.Target), Status: domain.DiagnosticTargetStatus(target.Status),
			Retryable: target.Retryable, ExitCode: exitCode, Signal: target.Signal, TimedOut: target.TimedOut,
			StdoutTruncated: target.StdoutTruncated, StderrTruncated: target.StderrTruncated,
			StdoutBytes: target.StdoutBytes, StderrBytes: target.StderrBytes,
			StdoutSHA256: stdout, StderrSHA256: stderr, ErrorCode: target.ErrorCode,
			StdoutTransformationState: domain.NormalizeStdoutTransformationState(target.StdoutTransformationState),
			StdoutExcerpt:             target.StdoutExcerpt,
		})
	}
	slices.SortFunc(targets, func(left, right domain.DiagnosticTargetResult) int {
		switch {
		case left.Target < right.Target:
			return -1
		case left.Target > right.Target:
			return 1
		default:
			return 0
		}
	})
	return domain.DiagnosticAttemptResult{
		WorkID: workID, RunID: domain.DiagnosticRunID(request.RunID), Attempt: attempt, RunnerID: request.RunnerID,
		PlanDigest: planDigest, StartedAt: request.StartedAt.UTC(), CompletedAt: request.CompletedAt.UTC(), Targets: targets,
	}, nil
}

func writeDiagnosticOperationError(w http.ResponseWriter, err error, correlationID string) {
	if errors.Is(err, ErrDiagnosticExecutionNotPermitted) {
		writeProblem(w, http.StatusForbidden, "FORBIDDEN", "collector is not permitted to execute diagnostics", correlationID)
		return
	}
	writeOperationError(w, err, correlationID)
}
