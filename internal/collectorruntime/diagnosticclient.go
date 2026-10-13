package collectorruntime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

var (
	// ErrDiagnosticExecutionForbidden means this collector holds an identity but
	// is not permitted to execute commands. Polling metrics does not imply
	// permission to run anything, so the control plane refuses explicitly rather
	// than answering with an empty queue, and a head node must report that
	// difference instead of idling as if there were no work.
	ErrDiagnosticExecutionForbidden = errors.New("collector is not permitted to execute diagnostics")
	// ErrDiagnosticWorkOutstanding means a lease is already held. A head node
	// executes one diagnostic at a time; a second concurrent claim would strand
	// the first lease until it expired, with the investigation that dispatched
	// it parked for that whole window.
	ErrDiagnosticWorkOutstanding = errors.New("a diagnostic work lease is already outstanding")
	// ErrDiagnosticLeaseUnknown means an attempt was reported against a lease
	// this client did not claim.
	ErrDiagnosticLeaseUnknown = errors.New("attempt does not match the outstanding diagnostic lease")
)

// controlPlaneRequester and the request time below fill the two fields the
// claim protocol deliberately does not carry. Who asked for a diagnostic and
// when they asked are control-plane bookkeeping; the head node needs neither to
// execute, and the protocol does not transmit them. They are reconstructed only
// because the domain request type validates as a whole, and they are never
// persisted or sent back -- the recorded attempt carries the runner's own
// identity.
const controlPlaneRequester = "control-plane"

// requestedAtFromDeadline derives a request time that is consistent with the
// transmitted deadline under the domain's one-hour bound. Using the local clock
// instead would make a claim's validity depend on head-node clock skew.
func requestedAtFromDeadline(deadline time.Time) time.Time { return deadline.Add(-time.Hour) }

type diagnosticDefinitionWire struct {
	PackID            string `json:"pack_id"`
	PackVersion       string `json:"pack_version"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion string `json:"definition_version"`
	DefinitionSHA256  string `json:"definition_sha256"`
}

type diagnosticArgumentWire struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type diagnosticInvocationWire struct {
	RunID       string                   `json:"run_id"`
	ClusterID   string                   `json:"cluster_id"`
	Definition  diagnosticDefinitionWire `json:"definition"`
	Privilege   string                   `json:"privilege"`
	Targets     []string                 `json:"targets"`
	Arguments   []diagnosticArgumentWire `json:"arguments"`
	Deadline    time.Time                `json:"deadline"`
	MaxAttempts int                      `json:"max_attempts"`
}

type diagnosticClaimWire struct {
	WorkID       string                   `json:"work_id"`
	Attempt      int                      `json:"attempt"`
	LeaseToken   string                   `json:"lease_token"`
	LeaseExpires time.Time                `json:"lease_expires_at"`
	Invocation   diagnosticInvocationWire `json:"invocation"`
}

type diagnosticTargetResultWire struct {
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

type diagnosticAttemptWire struct {
	LeaseToken  string                       `json:"lease_token"`
	RunID       string                       `json:"run_id"`
	RunnerID    string                       `json:"runner_id"`
	PlanSHA256  string                       `json:"plan_sha256"`
	StartedAt   time.Time                    `json:"started_at"`
	CompletedAt time.Time                    `json:"completed_at"`
	Targets     []diagnosticTargetResultWire `json:"targets"`
}

type diagnosticAttemptResponseWire struct {
	RunID    string `json:"run_id"`
	Status   string `json:"status"`
	Recorded bool   `json:"recorded"`
}

// claimDiagnosticWork performs one long poll. It reports no work as a nil lease
// so an empty queue stays distinguishable from a failed exchange.
func (c *HTTPClient) claimDiagnosticWork(ctx context.Context, runnerID string, wait time.Duration) (*domain.DiagnosticWorkLease, error) {
	path := "/collector/v1/diagnostic-work/claim?wait_seconds=" + strconv.Itoa(int(wait/time.Second))
	var wire diagnosticClaimWire
	status, err := c.do(ctx, http.MethodGet, path, nil, &wire, http.StatusOK, http.StatusNoContent)
	if err != nil {
		if status == http.StatusForbidden {
			return nil, errors.Join(ErrDiagnosticExecutionForbidden, err)
		}
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return diagnosticLeaseFromWire(wire, runnerID)
}

// diagnosticLeaseFromWire maps the claim onto the domain lease. The invocation
// is a reference: the definition digest and identity arrive, the argv does not,
// and the head node resolves it from the pack it verifies itself.
func diagnosticLeaseFromWire(wire diagnosticClaimWire, runnerID string) (*domain.DiagnosticWorkLease, error) {
	definitionDigest, err := domain.ParseSHA256(wire.Invocation.Definition.DefinitionSHA256)
	if err != nil {
		return nil, fmt.Errorf("claimed diagnostic definition digest is unreadable: %w", err)
	}
	targets := make([]domain.DiagnosticTarget, 0, len(wire.Invocation.Targets))
	for _, target := range wire.Invocation.Targets {
		targets = append(targets, domain.DiagnosticTarget(target))
	}
	arguments := make([]domain.DiagnosticArgument, 0, len(wire.Invocation.Arguments))
	for _, argument := range wire.Invocation.Arguments {
		arguments = append(arguments, domain.DiagnosticArgument{Name: argument.Name, Value: argument.Value})
	}
	deadline := wire.Invocation.Deadline.UTC()
	request := domain.DiagnosticRequest{
		RunID:     domain.DiagnosticRunID(wire.Invocation.RunID),
		ClusterID: domain.ClusterID(wire.Invocation.ClusterID),
		Definition: domain.DiagnosticDefinitionRef{
			PackID: wire.Invocation.Definition.PackID, PackVersion: wire.Invocation.Definition.PackVersion,
			DefinitionID:      domain.DiagnosticDefinitionID(wire.Invocation.Definition.DefinitionID),
			DefinitionVersion: wire.Invocation.Definition.DefinitionVersion, DefinitionDigest: definitionDigest,
		},
		Privilege: domain.DiagnosticPrivilege(wire.Invocation.Privilege),
		Targets:   targets, Arguments: arguments,
		RequestedBy: controlPlaneRequester,
		// The work identity is the queue's own idempotency key, so reusing it
		// keeps the reconstructed request tied to the claim it came from rather
		// than inventing a value.
		IdempotencyKey: wire.WorkID,
		RequestedAt:    requestedAtFromDeadline(deadline),
		Deadline:       deadline,
		MaxAttempts:    wire.Invocation.MaxAttempts,
	}
	// The run is already leased, so RUNNING is its honest status here. The
	// version is the control plane's and is not transmitted; this reconstruction
	// is never persisted, and recording an attempt is authenticated by the lease
	// token rather than by an optimistic version.
	run, err := domain.ReconstituteDiagnosticRun(request, domain.DiagnosticRunning, 1)
	if err != nil {
		return nil, fmt.Errorf("claimed diagnostic invocation is invalid: %w", err)
	}
	if wire.WorkID == "" || wire.Attempt < 1 || wire.LeaseToken == "" {
		return nil, fmt.Errorf("claimed diagnostic lease identity is incomplete")
	}
	return &domain.DiagnosticWorkLease{
		Work: domain.DiagnosticWork{
			WorkID: domain.DiagnosticWorkID(wire.WorkID), Run: run,
			AvailableAt: request.RequestedAt, Deadline: deadline, MaxAttempts: wire.Invocation.MaxAttempts,
		},
		Attempt: wire.Attempt, RunnerID: runnerID, LeaseToken: wire.LeaseToken, LeaseExpires: wire.LeaseExpires.UTC(),
	}, nil
}

// recordDiagnosticAttempt reports one attempt. Recording is idempotent on
// (work_id, attempt), so a replay after a lost response returns the stored
// outcome rather than executing again.
func (c *HTTPClient) recordDiagnosticAttempt(ctx context.Context, lease domain.DiagnosticWorkLease, result domain.DiagnosticAttemptResult) error {
	targets := make([]diagnosticTargetResultWire, 0, len(result.Targets))
	for _, target := range result.Targets {
		wire := diagnosticTargetResultWire{
			Target: string(target.Target), Status: string(target.Status), Retryable: target.Retryable,
			Signal: target.Signal, TimedOut: target.TimedOut,
			StdoutTruncated: target.StdoutTruncated, StderrTruncated: target.StderrTruncated,
			StdoutBytes: target.StdoutBytes, StderrBytes: target.StderrBytes,
			StdoutSHA256: target.StdoutSHA256.String(), StderrSHA256: target.StderrSHA256.String(),
			StdoutTransformationState: string(domain.NormalizeStdoutTransformationState(string(target.StdoutTransformationState))),
			ErrorCode:                 target.ErrorCode, StdoutExcerpt: target.StdoutExcerpt,
		}
		if target.ExitCode != nil {
			exitCode := *target.ExitCode
			wire.ExitCode = &exitCode
		}
		targets = append(targets, wire)
	}
	body := diagnosticAttemptWire{
		LeaseToken: lease.LeaseToken, RunID: string(result.RunID), RunnerID: result.RunnerID,
		PlanSHA256: result.PlanDigest.String(), StartedAt: result.StartedAt.UTC(), CompletedAt: result.CompletedAt.UTC(),
		Targets: targets,
	}
	path := "/collector/v1/diagnostic-work/" + url.PathEscape(string(lease.Work.WorkID)) + "/attempts/" + strconv.Itoa(lease.Attempt) + "/results"
	var response diagnosticAttemptResponseWire
	status, err := c.do(ctx, http.MethodPost, path, body, &response, http.StatusOK)
	if err != nil {
		if status == http.StatusForbidden {
			return errors.Join(ErrDiagnosticExecutionForbidden, err)
		}
		return err
	}
	return nil
}

// DiagnosticWorkClient is the collector-side pull client for reviewed
// diagnostic work, and satisfies diagnosticrunner.DiagnosticWorkSource.
//
// Its process-local slot enforces one concurrent claim only. It is not result
// authorization: the durable head journal can submit a result through a fresh
// client, and PostgreSQL reconstructs and validates that lease.
type DiagnosticWorkClient struct {
	control  *HTTPClient
	runnerID string
	wait     time.Duration
	slot     leaseSlot
}

func NewDiagnosticWorkClient(control *HTTPClient, runnerID string, wait time.Duration) (*DiagnosticWorkClient, error) {
	if control == nil || runnerID == "" {
		return nil, fmt.Errorf("diagnostic work client requires a control client and a runner identity")
	}
	if wait < time.Second || wait > 30*time.Second {
		return nil, fmt.Errorf("diagnostic claim wait must be between one and thirty seconds")
	}
	return &DiagnosticWorkClient{control: control, runnerID: runnerID, wait: wait}, nil
}

// ClaimDiagnosticWork long-polls for one unit of work. The requested wait is
// bounded by the client's configured wait, which the control plane also caps.
func (client *DiagnosticWorkClient) ClaimDiagnosticWork(ctx context.Context, wait time.Duration) (domain.DiagnosticWorkLease, bool, error) {
	if client == nil {
		return domain.DiagnosticWorkLease{}, false, fmt.Errorf("diagnostic work client is unavailable")
	}
	if wait <= 0 || wait > client.wait {
		wait = client.wait
	}
	if err := client.slot.begin(); err != nil {
		return domain.DiagnosticWorkLease{}, false, err
	}
	lease, err := client.control.claimDiagnosticWork(ctx, client.runnerID, wait)
	if err != nil || lease == nil {
		client.slot.abandon()
		return domain.DiagnosticWorkLease{}, false, err
	}
	client.slot.hold(*lease)
	return *lease, true, nil
}

// RecordDiagnosticAttempt reports a journal-reconstructed attempt. The local
// slot is concurrency bookkeeping only; PostgreSQL authenticates the lease.
// This permits a restarted claimant to replay a completed result without first
// re-claiming or re-executing it.
func (client *DiagnosticWorkClient) RecordDiagnosticAttempt(ctx context.Context, lease domain.DiagnosticWorkLease, result domain.DiagnosticAttemptResult) error {
	if client == nil {
		return fmt.Errorf("diagnostic work client is unavailable")
	}
	if lease.Work.WorkID == "" || lease.Attempt < 1 || lease.LeaseToken == "" || lease.RunnerID != client.runnerID || result.WorkID != lease.Work.WorkID || result.Attempt != lease.Attempt || result.RunnerID != client.runnerID {
		return ErrDiagnosticLeaseUnknown
	}
	defer client.slot.releaseIfMatches(lease)
	err := client.control.recordDiagnosticAttempt(ctx, lease, result)
	if errors.Is(err, ErrLeaseLost) {
		return errors.Join(err, diagnosticrunner.ErrDiagnosticLeaseLost)
	}
	return err
}

// Outstanding reports the lease currently held, for a caller that needs to see
// whether execution is in flight.
func (client *DiagnosticWorkClient) Outstanding() (domain.DiagnosticWorkLease, bool) {
	if client == nil {
		return domain.DiagnosticWorkLease{}, false
	}
	return client.slot.current()
}

// leaseSlot keeps the lock and the state it protects in one small type. It
// holds at most one lease and reserves itself for the duration of a claim, so
// concurrent claims cannot both pass an "is anything outstanding" check while a
// long poll is in flight and the slot is still empty.
type leaseSlot struct {
	mu       sync.Mutex
	claiming bool
	held     *domain.DiagnosticWorkLease
}

func (slot *leaseSlot) begin() error {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.claiming || slot.held != nil {
		return ErrDiagnosticWorkOutstanding
	}
	slot.claiming = true
	return nil
}

func (slot *leaseSlot) hold(lease domain.DiagnosticWorkLease) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	slot.claiming = false
	slot.held = &lease
}

func (slot *leaseSlot) abandon() {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	slot.claiming = false
	slot.held = nil
}

func (slot *leaseSlot) releaseIfMatches(lease domain.DiagnosticWorkLease) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.held == nil {
		return
	}
	if slot.held.Work.WorkID != lease.Work.WorkID || slot.held.Attempt != lease.Attempt || slot.held.LeaseToken != lease.LeaseToken {
		return
	}
	slot.claiming = false
	slot.held = nil
}

func (slot *leaseSlot) current() (domain.DiagnosticWorkLease, bool) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.held == nil {
		return domain.DiagnosticWorkLease{}, false
	}
	return *slot.held, true
}
