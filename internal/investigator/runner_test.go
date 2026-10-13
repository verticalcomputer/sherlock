package investigator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/contextbudget"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
)

func TestTwoRunnersCannotAdvanceSameLeaseConcurrently(t *testing.T) {
	store := &memoryLeases{available: []domain.InvestigationID{"investigation-1"}}
	advancer := &blockingAdvancer{entered: make(chan struct{}, 2), release: make(chan struct{})}
	clock := testClock{time.Now()}
	runnerA, _ := New(store, advancer, clock, Config{WorkerID: "a", PollInterval: 10 * time.Millisecond, LeaseDuration: time.Second, MaxConcurrent: 1, MaxGlobal: 2, MaxPerCluster: 1})
	runnerB, _ := New(store, advancer, clock, Config{WorkerID: "b", PollInterval: 10 * time.Millisecond, LeaseDuration: time.Second, MaxConcurrent: 1, MaxGlobal: 2, MaxPerCluster: 1})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	go func() { _ = runnerA.Run(ctx); done <- struct{}{} }()
	go func() { _ = runnerB.Run(ctx); done <- struct{}{} }()
	select {
	case <-advancer.entered:
	case <-time.After(time.Second):
		t.Fatal("investigation was not advanced")
	}
	select {
	case <-advancer.entered:
		t.Fatal("same investigation advanced concurrently")
	case <-time.After(80 * time.Millisecond):
	}
	cancel()
	close(advancer.release)
	<-done
	<-done
	advancer.mu.Lock()
	defer advancer.mu.Unlock()
	if advancer.maxActive != 1 {
		t.Fatalf("max active=%d", advancer.maxActive)
	}
}

func TestRunnerProjectsOnlyTerminalSnapshots(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	request := domain.InvestigationRequest{
		ID: "investigation-1", IncidentID: "incident-1", ClusterID: "cluster-1", Question: "why", RequestedBy: "test", IdempotencyKey: "key-1",
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now},
		SuccessCriteria: []string{"cite evidence"},
		Budget:          domain.InvestigationBudget{MaxDecisions: 1, MaxToolCalls: 1, MaxFanOut: 1, MaxModelTokens: 1000, MaxCostMicros: 1},
		RequestedAt:     now, Deadline: now.Add(time.Hour),
	}
	nonterminal, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := nonterminal.Stop(domain.InvestigationPartial, domain.StopNoUsefulAction, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		value domain.Investigation
		want  int
	}{
		{name: "nonterminal", value: nonterminal, want: 0},
		{name: "terminal", value: terminal, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			projector := &countingProjector{}
			runner, err := New(&memoryLeases{}, staticAdvancer{snapshot: application.InvestigationSnapshot{Investigation: test.value}}, testClock{now}, Config{WorkerID: "worker", PollInterval: 10 * time.Millisecond, LeaseDuration: time.Second, MaxConcurrent: 1, MaxGlobal: 1, MaxPerCluster: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err := runner.ConfigureMemoryProjection(projector); err != nil {
				t.Fatal(err)
			}
			runner.advance(t.Context(), Lease{InvestigationID: request.ID, Owner: "worker"})
			if projector.calls != test.want {
				t.Fatalf("projection calls=%d want=%d", projector.calls, test.want)
			}
		})
	}
}

func TestRunnerProjectsTerminalSnapshotRecordedAfterAdvanceFailure(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	request := domain.InvestigationRequest{
		ID: "investigation-1", IncidentID: "incident-1", ClusterID: "cluster-1", Question: "why", RequestedBy: "test", IdempotencyKey: "key-1",
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now},
		SuccessCriteria: []string{"cite evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 1, MaxToolCalls: 1, MaxFanOut: 1, MaxModelTokens: 1000, MaxCostMicros: 1},
		RequestedAt: now, Deadline: now.Add(time.Hour),
	}
	value, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := value.Stop(domain.InvestigationBlocked, domain.StopAccessUnavailable, now)
	if err != nil {
		t.Fatal(err)
	}
	projector := &countingProjector{}
	runner, err := New(&memoryLeases{}, staticAdvancer{err: errors.New("planning failed"), stopped: application.InvestigationSnapshot{Investigation: stopped}}, testClock{now}, Config{WorkerID: "worker", PollInterval: 10 * time.Millisecond, LeaseDuration: time.Second, MaxConcurrent: 1, MaxGlobal: 1, MaxPerCluster: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.ConfigureMemoryProjection(projector); err != nil {
		t.Fatal(err)
	}
	runner.advance(t.Context(), Lease{InvestigationID: request.ID, Owner: "worker"})
	if projector.calls != 1 {
		t.Fatalf("projection calls=%d want=1", projector.calls)
	}
}

type staticAdvancer struct {
	snapshot application.InvestigationSnapshot
	stopped  application.InvestigationSnapshot
	err      error
}

func (advancer staticAdvancer) Advance(context.Context, domain.InvestigationID) (application.InvestigationSnapshot, error) {
	return advancer.snapshot, advancer.err
}
func (advancer staticAdvancer) StopAfterFailure(context.Context, domain.InvestigationID, error) (application.InvestigationSnapshot, error) {
	return advancer.stopped, nil
}

type countingProjector struct{ calls int }

func (projector *countingProjector) ProjectInvestigation(context.Context, domain.InvestigationID) error {
	projector.calls++
	return nil
}

type memoryLeases struct {
	mu          sync.Mutex
	available   []domain.InvestigationID
	leased      bool
	releasedAt  time.Time
	availableAt time.Time
}

func (store *memoryLeases) Claim(_ context.Context, owner string, _ time.Time, _ time.Duration, _, _ int) (Lease, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.leased || len(store.available) == 0 {
		return Lease{}, false, nil
	}
	store.leased = true
	return Lease{InvestigationID: store.available[0], Owner: owner, Epoch: 1}, true, nil
}
func (store *memoryLeases) Heartbeat(context.Context, Lease, time.Time, time.Duration) error {
	return nil
}
func (store *memoryLeases) Release(_ context.Context, _ Lease, now, availableAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.leased = false
	store.available = nil
	store.releasedAt, store.availableAt = now, availableAt
	return nil
}

type blockingAdvancer struct {
	mu                sync.Mutex
	active, maxActive int
	entered           chan struct{}
	release           chan struct{}
}

func (a *blockingAdvancer) Advance(ctx context.Context, _ domain.InvestigationID) (application.InvestigationSnapshot, error) {
	a.mu.Lock()
	a.active++
	if a.active > a.maxActive {
		a.maxActive = a.active
	}
	a.mu.Unlock()
	a.entered <- struct{}{}
	select {
	case <-a.release:
	case <-ctx.Done():
	}
	a.mu.Lock()
	a.active--
	a.mu.Unlock()
	return application.InvestigationSnapshot{}, ctx.Err()
}
func (*blockingAdvancer) StopAfterFailure(context.Context, domain.InvestigationID, error) (application.InvestigationSnapshot, error) {
	return application.InvestigationSnapshot{}, nil
}

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

// A single ADVANCE_FAILED code cannot tell a provider outage from a budget stop,
// so the classified reason must reach the log without carrying provider detail.
func TestAdvanceFailureReasonClassifiesWithoutLeakingDetail(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "classified provider error", err: fmt.Errorf("wrapped: %w", classifiedProviderError{}), want: "PROVIDER_UNAVAILABLE"},
		{name: "budget", err: fmt.Errorf("wrapped: %w", domain.ErrInvestigationBudgetExceeded), want: "BUDGET_EXCEEDED"},
		{name: "missing investigation", err: fmt.Errorf("wrapped: %w", application.ErrInvestigationNotFound), want: "INVESTIGATION_NOT_FOUND"},
		{name: "required context", err: fmt.Errorf("plan investigation: %w", contextbudget.ErrRequiredContextExceeded), want: "REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE"},
		// Same message text, different sentinel and different fix: this one means
		// mandatory evidence outgrew the engine's evidence allowance.
		{name: "required evidence", err: fmt.Errorf("plan investigation: %w", investigationcontext.ErrRequiredContextTooLarge), want: "REQUIRED_EVIDENCE_EXCEEDS_ALLOWANCE"},
		{name: "checkpoint mismatch", err: fmt.Errorf("wrapped: %w", investigationcontext.ErrCheckpointMismatch), want: investigationcontext.ErrCheckpointMismatch.Error()},
		{name: "prospective run budget", err: fmt.Errorf("wrapped: %w", contextbudget.ErrProspectiveRunBudget), want: "PROSPECTIVE_RUN_BUDGET_EXCEEDED"},
		{name: "encoded context limit", err: fmt.Errorf("wrapped: %w", investigationcontext.ErrContextTooLarge), want: "CONTEXT_EXCEEDS_ENCODED_LIMIT"},
		{name: "unknown", err: errors.New("private store detail"), want: "UNCLASSIFIED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := advanceFailureReason(test.err); got != test.want {
				t.Fatalf("advanceFailureReason() = %q, want %q", got, test.want)
			}
		})
	}
}

type classifiedProviderError struct{}

func (classifiedProviderError) Error() string          { return "private provider detail" }
func (classifiedProviderError) SafeReasonCode() string { return "PROVIDER_UNAVAILABLE" }

// A live investigation failed three times reporting only ADVANCE_FAILED. The
// stage and durable state are already carried safely on the error and localize
// the failure without exposing its text.
func TestAdvanceFailureStageLocalizesTheTransition(t *testing.T) {
	wrapped := fmt.Errorf("plan investigation: %w", contextbudget.ErrRequiredContextExceeded)
	failure := &application.InvestigationAdvanceError{Stage: "PLANNING", State: domain.InvestigationPlanning, Err: wrapped}
	stage, state := advanceFailureStage(failure)
	if stage != "PLANNING" || state != string(domain.InvestigationPlanning) {
		t.Fatalf("stage=%q state=%q", stage, state)
	}
	if reason := advanceFailureReason(failure); reason != "REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE" {
		t.Fatalf("reason=%q", reason)
	}
	if stage, state := advanceFailureStage(errors.New("plain")); stage != "" || state != "" {
		t.Fatalf("unstructured error reported stage=%q state=%q", stage, state)
	}
}

// The two overflow sentinels share a message, so a text match would conflate
// them. They must stay distinguishable by value.
func TestOverflowSentinelsAreDistinguishableDespiteSharedText(t *testing.T) {
	if investigationcontext.ErrRequiredContextTooLarge.Error() != contextbudget.ErrRequiredContextExceeded.Error() {
		t.Skip("sentinels no longer share text; the conflation hazard is gone")
	}
	evidence := advanceFailureReason(fmt.Errorf("wrapped: %w", investigationcontext.ErrRequiredContextTooLarge))
	provider := advanceFailureReason(fmt.Errorf("wrapped: %w", contextbudget.ErrRequiredContextExceeded))
	if evidence == provider {
		t.Fatalf("both overflows report %q; the failing subsystem is unidentifiable", evidence)
	}
}

func TestRunnerPassesFixedContextClassificationToTerminalRecovery(t *testing.T) {
	now := time.Date(2026, 9, 9, 13, 10, 0, 0, time.UTC)
	advancer := &capturingFailureAdvancer{err: fmt.Errorf("planning failed: %w", contextbudget.ErrRequiredContextExceeded)}
	runner, err := New(&memoryLeases{}, advancer, testClock{now}, Config{WorkerID: "worker", PollInterval: 10 * time.Millisecond, LeaseDuration: time.Second, MaxConcurrent: 1, MaxGlobal: 1, MaxPerCluster: 1})
	if err != nil {
		t.Fatal(err)
	}
	runner.advance(t.Context(), Lease{InvestigationID: "investigation-1", Owner: "worker"})
	type safeReason interface{ SafeReasonCode() string }
	var classified safeReason
	if !errors.As(advancer.stoppedWith, &classified) || classified.SafeReasonCode() != application.FailureRequiredContext {
		t.Fatalf("terminal recovery cause=%v", advancer.stoppedWith)
	}
}

type capturingFailureAdvancer struct {
	err         error
	stopErr     error
	stoppedWith error
}

func (advancer *capturingFailureAdvancer) Advance(context.Context, domain.InvestigationID) (application.InvestigationSnapshot, error) {
	return application.InvestigationSnapshot{}, advancer.err
}

func (advancer *capturingFailureAdvancer) StopAfterFailure(_ context.Context, _ domain.InvestigationID, cause error) (application.InvestigationSnapshot, error) {
	advancer.stoppedWith = cause
	return application.InvestigationSnapshot{}, advancer.stopErr
}

func TestRunnerDefersClaimWhenFailureCannotBeRecorded(t *testing.T) {
	now := time.Date(2026, 9, 11, 18, 5, 10, 0, time.UTC)
	config := Config{WorkerID: "worker", PollInterval: 10 * time.Millisecond, LeaseDuration: time.Second, MaxConcurrent: 1, MaxGlobal: 1, MaxPerCluster: 1}
	for name, test := range map[string]struct {
		stopErr   error
		wantDelay time.Duration
	}{
		"recorded failure releases immediately": {wantDelay: 0},
		"unrecorded failure defers the claim":   {stopErr: errors.New("persist report section citation: foreign key"), wantDelay: defaultFailureRetryDelay},
		"conflicting stop releases immediately": {stopErr: application.ErrInvestigationConflict, wantDelay: 0},
	} {
		t.Run(name, func(t *testing.T) {
			leases := &memoryLeases{}
			advancer := &capturingFailureAdvancer{err: fmt.Errorf("synthesis failed: %w", investigationcontext.ErrContextTooLarge), stopErr: test.stopErr}
			runner, err := New(leases, advancer, testClock{now}, config)
			if err != nil {
				t.Fatal(err)
			}
			runner.advance(t.Context(), Lease{InvestigationID: "investigation-1", Owner: "worker"})
			if !leases.releasedAt.Equal(now) || !leases.availableAt.Equal(now.Add(test.wantDelay)) {
				t.Fatalf("released at %s, available at %s; want available after %s", leases.releasedAt, leases.availableAt, test.wantDelay)
			}
		})
	}
	for _, delay := range []time.Duration{-time.Second, time.Hour + time.Second} {
		invalid := config
		invalid.FailureRetryDelay = delay
		if _, err := New(&memoryLeases{}, &capturingFailureAdvancer{}, testClock{now}, invalid); err == nil {
			t.Fatalf("retry delay %s was accepted", delay)
		}
	}
}
