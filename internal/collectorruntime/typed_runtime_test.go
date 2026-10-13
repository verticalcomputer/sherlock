package collectorruntime

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type typedExecutorFunc func(context.Context, domain.TypedWorkLease) domain.TypedCollectorResult

func (f typedExecutorFunc) ExecuteTyped(ctx context.Context, lease domain.TypedWorkLease) domain.TypedCollectorResult {
	return f(ctx, lease)
}

type typedControl struct {
	*fakeControl
	queue       []domain.TypedWorkLease
	claimTyped  func(context.Context, ClaimRequest) (*domain.TypedWorkLease, error)
	submissions []domain.TypedCollectorResult
	failSubmit  bool
	afterSubmit func()
}

func (f *typedControl) ClaimTyped(ctx context.Context, claim ClaimRequest) (*domain.TypedWorkLease, error) {
	if f.claimTyped != nil {
		return f.claimTyped(ctx, claim)
	}
	if len(f.queue) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	lease := f.queue[0]
	f.queue = f.queue[1:]
	return &lease, nil
}

func TestMixedRuntimeDoesNotLongPollTypedQueueBeforeLegacyWork(t *testing.T) {
	clock := liveClock{}
	registry, err := application.NewTypedCollectionRegistry(2, []application.TypedCollectionSource{{ClusterID: "cluster-1", SourceID: "typed-1", Kind: domain.CollectionSourceSlurm, Operations: []domain.CollectionOperationID{domain.OperationSlurmInventory}, Executor: typedExecutorFunc(func(context.Context, domain.TypedWorkLease) domain.TypedCollectorResult {
		return domain.TypedCollectorResult{}
	})}}, clock)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "mixed.json"), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var typedWait time.Duration
	legacyClaims := 0
	client := &typedControl{fakeControl: &fakeControl{claim: func(context.Context, ClaimRequest) (*domain.WorkLease, error) {
		legacyClaims++
		cancel()
		return nil, nil
	}}, claimTyped: func(_ context.Context, claim ClaimRequest) (*domain.TypedWorkLease, error) {
		typedWait = claim.Wait
		return nil, nil
	}}
	cfg := RuntimeConfig{CollectorID: "collector-1", SourceID: "legacy-1", Version: "test", Capabilities: []string{string(domain.QueryGPUUtilization)}, HeartbeatInterval: time.Minute, ClaimWait: 25 * time.Second, RenewInterval: time.Second, BackoffMinimum: time.Millisecond, BackoffMaximum: time.Millisecond}
	runtime, err := NewRuntimeWithTyped(cfg, client, executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult { return domain.CollectionResult{} }), registry, journal, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run error = %v", err)
	}
	if typedWait != 0 || legacyClaims != 1 {
		t.Fatalf("typed wait = %v, legacy claims = %d", typedWait, legacyClaims)
	}
}

func TestTypedOnlyRuntimeKeepsLongPoll(t *testing.T) {
	clock := liveClock{}
	registry, err := application.NewTypedCollectionRegistry(2, []application.TypedCollectionSource{{ClusterID: "cluster-1", SourceID: "typed-1", Kind: domain.CollectionSourceSlurm, Operations: []domain.CollectionOperationID{domain.OperationSlurmInventory}, Executor: typedExecutorFunc(func(context.Context, domain.TypedWorkLease) domain.TypedCollectorResult {
		return domain.TypedCollectorResult{}
	})}}, clock)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "typed.json"), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var typedWait time.Duration
	client := &typedControl{fakeControl: &fakeControl{}, claimTyped: func(_ context.Context, claim ClaimRequest) (*domain.TypedWorkLease, error) {
		typedWait = claim.Wait
		cancel()
		return nil, nil
	}}
	cfg := RuntimeConfig{CollectorID: "collector-1", SourceID: "typed-1", Version: "test", HeartbeatInterval: time.Minute, ClaimWait: 25 * time.Second, RenewInterval: time.Second, BackoffMinimum: time.Millisecond, BackoffMaximum: time.Millisecond}
	runtime, err := NewRuntimeWithTyped(cfg, client, nil, registry, journal, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run error = %v", err)
	}
	if typedWait != cfg.ClaimWait {
		t.Fatalf("typed-only wait = %v, want %v", typedWait, cfg.ClaimWait)
	}
}
func (f *typedControl) StartTyped(ctx context.Context, ref LeaseRef) error { return f.Start(ctx, ref) }
func (f *typedControl) RenewTyped(ctx context.Context, ref LeaseRef) (time.Time, error) {
	return f.Renew(ctx, ref)
}
func (f *typedControl) SubmitTyped(_ context.Context, _ LeaseRef, result domain.TypedCollectorResult) error {
	f.submissions = append(f.submissions, result)
	if f.failSubmit {
		f.failSubmit = false
		return errors.New("lost response")
	}
	if f.afterSubmit != nil {
		f.afterSubmit()
	}
	return nil
}

func typedRuntimeLease(now time.Time) domain.TypedWorkLease {
	p := domain.CollectionPlan{SchemaVersion: 2, RunID: "typed-run", ClusterID: "cluster-1", SourceID: "slurm-1", SourceKind: domain.CollectionSourceSlurm,
		Operation: domain.OperationSlurmInventory, PayloadSchema: domain.CollectionInventorySchema, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}},
		Interval: &domain.CollectionInterval{Start: now.Add(-time.Minute), End: now}, ScheduledFor: now, Deadline: now.Add(time.Minute), Limits: domain.CollectionLimits{MaxRecords: 10, MaxBytes: 100000}, IdempotencyKey: "typed-key"}
	return domain.TypedWorkLease{Plan: p, Lease: domain.WorkLease{CollectorID: "collector-1", Attempt: 1, LeaseToken: strings.Repeat("a", 32), LeaseExpires: p.Deadline,
		Work: domain.CollectorWork{WorkID: "typed-work", WorkExpiresAt: p.Deadline, Task: domain.CollectionTask{RunID: p.RunID, ClusterID: p.ClusterID, SourceID: p.SourceID, IdempotencyKey: p.IdempotencyKey}}}}
}

func newTypedRuntime(t *testing.T, path string, client *typedControl, executor typedExecutorFunc) (*Runtime, *Journal) {
	t.Helper()
	clock := liveClock{}
	registry, err := application.NewTypedCollectionRegistry(2, []application.TypedCollectionSource{{ClusterID: "cluster-1", SourceID: "slurm-1", Kind: domain.CollectionSourceSlurm, Operations: []domain.CollectionOperationID{domain.OperationSlurmInventory}, Executor: executor}}, clock)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	cfg := RuntimeConfig{CollectorID: "collector-1", SourceID: "slurm-1", Version: "test", HeartbeatInterval: time.Second, ClaimWait: time.Millisecond, RenewInterval: time.Second, BackoffMinimum: time.Millisecond, BackoffMaximum: time.Millisecond}
	runtime, err := NewRuntimeWithTyped(cfg, client, nil, registry, journal, clock)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, journal
}

func TestTypedRuntimeRestartReplaysWithoutReexecutionAndRefusesV1Export(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	lease := typedRuntimeLease(time.Now().UTC())
	calls := 0
	execute := typedExecutorFunc(func(_ context.Context, lease domain.TypedWorkLease) domain.TypedCollectorResult {
		calls++
		return application.FailedTypedCollection(lease, time.Now(), domain.FailureSourceUnavailable, "fixture unavailable")
	})
	client := &typedControl{fakeControl: &fakeControl{}, failSubmit: true}
	runtime, journal := newTypedRuntime(t, path, client, execute)
	if err := runtime.processTyped(context.Background(), lease); err == nil {
		t.Fatal("lost submission should remain pending")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportJournalForRollback(path, liveClock{}); err == nil {
		t.Fatal("typed journal exported to v1")
	}
	runtime, journal = newTypedRuntime(t, path, client, execute)
	defer journal.Close()
	pending, found, err := journal.pending()
	if err != nil || !found || pending.TypedPlan == nil {
		t.Fatalf("pending typed receipt: %v %v", found, err)
	}
	if err := runtime.processTyped(context.Background(), pendingTypedLease("collector-1", pending)); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(client.submissions) != 2 {
		t.Fatalf("execution=%d submissions=%d", calls, len(client.submissions))
	}
	first, _ := domain.EncodeTypedCollectorResult(client.submissions[0])
	second, _ := domain.EncodeTypedCollectorResult(client.submissions[1])
	if string(first) != string(second) {
		t.Fatal("restart changed canonical result")
	}
	if err := runtime.processTyped(context.Background(), lease); !errors.Is(err, ErrJournalDeliveryRefused) {
		t.Fatalf("completed receipt delivered again: %v", err)
	}
}

func TestTypedRuntimeInterruptedReceiptDoesNotExecute(t *testing.T) {
	client := &typedControl{fakeControl: &fakeControl{}}
	runtime, journal := newTypedRuntime(t, filepath.Join(t.TempDir(), "journal.json"), client, func(context.Context, domain.TypedWorkLease) domain.TypedCollectorResult {
		t.Fatal("re-executed interrupted work")
		return domain.TypedCollectorResult{}
	})
	defer journal.Close()
	lease := typedRuntimeLease(time.Now().UTC())
	if _, _, err := journal.beginTyped(lease); err != nil {
		t.Fatal(err)
	}
	if err := journal.markStarted(lease.Plan.RunID); err != nil {
		t.Fatal(err)
	}
	if err := runtime.processTyped(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if len(client.submissions) != 1 || client.submissions[0].Status != domain.ResultFailed {
		t.Fatal("interruption was not durably reported")
	}
}

func TestTypedRuntimeMalformedResultDoesNotStopNextSource(t *testing.T) {
	first := typedRuntimeLease(time.Now().UTC())
	second := first
	second.Plan.RunID = "next-run"
	second.Plan.IdempotencyKey = "next-key"
	second.Plan.SourceID = "slurm-2"
	second.Lease.Work.WorkID = "next-work"
	second.Lease.Work.Task.RunID = second.Plan.RunID
	second.Lease.Work.Task.IdempotencyKey = second.Plan.IdempotencyKey
	second.Lease.Work.Task.SourceID = second.Plan.SourceID
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := &typedControl{fakeControl: &fakeControl{}, queue: []domain.TypedWorkLease{first, second}}
	client.afterSubmit = func() {
		if len(client.submissions) == 2 {
			cancel()
		}
	}
	runtime, journal := newTypedRuntime(t, filepath.Join(t.TempDir(), "journal.json"), client, func(context.Context, domain.TypedWorkLease) domain.TypedCollectorResult {
		return domain.TypedCollectorResult{}
	})
	defer journal.Close()
	registry, err := application.NewTypedCollectionRegistry(2, []application.TypedCollectionSource{
		{ClusterID: "cluster-1", SourceID: "slurm-1", Kind: domain.CollectionSourceSlurm, Operations: []domain.CollectionOperationID{domain.OperationSlurmInventory}, Executor: typedExecutorFunc(func(context.Context, domain.TypedWorkLease) domain.TypedCollectorResult {
			return domain.TypedCollectorResult{}
		})},
		{ClusterID: "cluster-1", SourceID: "slurm-2", Kind: domain.CollectionSourceSlurm, Operations: []domain.CollectionOperationID{domain.OperationSlurmInventory}, Executor: typedExecutorFunc(func(_ context.Context, l domain.TypedWorkLease) domain.TypedCollectorResult {
			return application.FailedTypedCollection(l, time.Now(), domain.FailureSourceUnavailable, "second source checked")
		})},
	}, liveClock{})
	if err != nil {
		t.Fatal(err)
	}
	runtime.typedExecutor = registry
	client.heartbeat = func(_ context.Context, h Heartbeat, _ int) error {
		if h.ProtocolMin != 1 || h.ProtocolMax != 2 || len(h.Capabilities) != 1 || h.Capabilities[0].Name != string(domain.OperationSlurmInventory) {
			t.Errorf("unexpected capability advertisement: %+v", h)
		}
		return nil
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(client.submissions) != 2 || client.submissions[1].Plan.SourceID != "slurm-2" || client.claims != 0 {
		t.Fatal("malformed source blocked unrelated source or used v1")
	}
}
