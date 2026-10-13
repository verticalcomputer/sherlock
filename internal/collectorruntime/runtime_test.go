package collectorruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type liveClock struct{}

func (liveClock) Now() time.Time { return time.Now() }

type executorFunc func(context.Context, domain.CollectionTask) domain.CollectionResult

func (f executorFunc) Execute(ctx context.Context, task domain.CollectionTask) domain.CollectionResult {
	return f(ctx, task)
}

type fakeControl struct {
	mu               sync.Mutex
	heartbeats       int
	starts           int
	renews           int
	uploads          []ResultChunk
	finalizations    int
	claims           int
	heartbeat        func(context.Context, Heartbeat, int) error
	claim            func(context.Context, ClaimRequest) (*domain.WorkLease, error)
	renew            func(context.Context, LeaseRef) (time.Time, error)
	finalizationFail error
	finalize         func()
}

func (f *fakeControl) Heartbeat(ctx context.Context, heartbeat Heartbeat) error {
	f.mu.Lock()
	f.heartbeats++
	call := f.heartbeats
	f.mu.Unlock()
	if f.heartbeat != nil {
		return f.heartbeat(ctx, heartbeat, call)
	}
	return nil
}
func (f *fakeControl) Claim(ctx context.Context, claim ClaimRequest) (*domain.WorkLease, error) {
	f.mu.Lock()
	f.claims++
	f.mu.Unlock()
	if f.claim != nil {
		return f.claim(ctx, claim)
	}
	return nil, nil
}
func (f *fakeControl) Start(context.Context, LeaseRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	return nil
}
func (f *fakeControl) Renew(ctx context.Context, ref LeaseRef) (time.Time, error) {
	f.mu.Lock()
	f.renews++
	f.mu.Unlock()
	if f.renew != nil {
		return f.renew(ctx, ref)
	}
	return time.Now().Add(time.Minute), nil
}
func (f *fakeControl) UploadChunk(_ context.Context, chunk ResultChunk) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	copyChunk := chunk
	copyChunk.Payload = append([]byte(nil), chunk.Payload...)
	f.uploads = append(f.uploads, copyChunk)
	return nil
}
func (f *fakeControl) Finalize(context.Context, Finalization) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalizations++
	if f.finalizationFail != nil {
		err := f.finalizationFail
		f.finalizationFail = nil
		return err
	}
	if f.finalize != nil {
		f.finalize()
	}
	return nil
}

func TestJournalPersistsReceiptAndRestrictsPermissions(t *testing.T) {
	clock := testClock{now: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "journal", "attempts.json")
	journal := openTestJournal(t, path, clock)
	lease := testLease(clock.now, 1)
	if _, existed, err := journal.begin(lease); err != nil || existed {
		t.Fatalf("begin: existed=%v err=%v", existed, err)
	}
	if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
		t.Fatal(err)
	}
	result := noDataResult(lease.Work.Task, clock.now)
	if err := journal.storeResult(lease.Work.Task.RunID, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, strings.TrimSuffix(path, ".json") + ".sqlite", strings.TrimSuffix(path, ".json") + ".sqlite-wal", strings.TrimSuffix(path, ".json") + ".sqlite.lock"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s permissions = %o, want 600", filepath.Base(name), info.Mode().Perm())
		}
	}
	// Exclusive locking keeps the WAL index in memory; no shared-memory file.
	assertMissing(t, strings.TrimSuffix(path, ".json")+".sqlite-shm")
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestJournal(t, path, clock)
	entry, ok := reopened.entry(lease.Work.Task.RunID)
	if !ok || entry.Result == nil || entry.State != journalReady {
		t.Fatalf("reopened entry = %+v, %v", entry, ok)
	}
}

func TestRuntimeRestartReuploadsWithoutReexecution(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	clock := testClock{now: now}
	path := filepath.Join(t.TempDir(), "attempts.json")
	journal := openTestJournal(t, path, clock)
	lease := testLease(now, 1)
	var executions atomic.Int32
	executor := executorFunc(func(_ context.Context, task domain.CollectionTask) domain.CollectionResult {
		executions.Add(1)
		return noDataResult(task, now)
	})
	firstClient := &fakeControl{finalizationFail: errors.New("connection reset")}
	first := newTestRuntime(t, firstClient, executor, journal, clock)
	if err := first.process(context.Background(), lease); err == nil {
		t.Fatal("first delivery unexpectedly finalized")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestJournal(t, path, clock)
	secondClient := &fakeControl{}
	neverExecute := executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult {
		t.Fatal("persisted result was re-executed")
		return domain.CollectionResult{}
	})
	second := newTestRuntime(t, secondClient, neverExecute, reopened, clock)
	if err := second.process(context.Background(), testLease(now, 2)); err != nil {
		t.Fatal(err)
	}
	if executions.Load() != 1 || secondClient.finalizations != 1 || len(secondClient.uploads) == 0 {
		t.Fatalf("executions=%d finalizations=%d uploads=%d", executions.Load(), secondClient.finalizations, len(secondClient.uploads))
	}
}

func TestRuntimeRestartAfterStartDoesNotReexecute(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	clock := testClock{now: now}
	path := filepath.Join(t.TempDir(), "attempts.json")
	journal := openTestJournal(t, path, clock)
	lease := testLease(now, 1)
	if _, _, err := journal.begin(lease); err != nil {
		t.Fatal(err)
	}
	if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestJournal(t, path, clock)
	client := &fakeControl{}
	runtime := newTestRuntime(t, client, executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult {
		t.Fatal("ambiguous started attempt was re-executed")
		return domain.CollectionResult{}
	}), reopened, clock)
	if err := runtime.process(context.Background(), testLease(now, 2)); err != nil {
		t.Fatal(err)
	}
	// Finalization reclaims the journaled payload, so inspect what was delivered.
	document := uploadedDocument(t, client)
	if document.Result.Status != domain.ResultFailed || len(document.Result.Failures) != 1 || document.Result.Failures[0].Code != domain.FailureInternal {
		t.Fatalf("unexpected interrupted result: %+v", document.Result)
	}
	if entry, ok := reopened.entry(lease.Work.Task.RunID); !ok || entry.State != journalFinalized || entry.Result != nil || entry.LeaseToken != "" {
		t.Fatalf("finalized receipt was not compacted: %+v %v", entry, ok)
	}
}

func TestRuntimeRunResumesPendingResultBeforeClaim(t *testing.T) {
	now := time.Now().UTC()
	clock := liveClock{}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "attempts.json"), clock)
	lease := testLease(now, 1)
	if _, _, err := journal.begin(lease); err != nil {
		t.Fatal(err)
	}
	if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
		t.Fatal(err)
	}
	if err := journal.storeResult(lease.Work.Task.RunID, noDataResult(lease.Work.Task, now)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &fakeControl{finalize: cancel}
	runtime := newTestRuntime(t, client, executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult {
		t.Fatal("pending result was re-executed")
		return domain.CollectionResult{}
	}), journal, clock)
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if client.finalizations != 1 || client.claims != 0 {
		t.Fatalf("finalizations=%d claims=%d", client.finalizations, client.claims)
	}
}

func TestRuntimeLeaseLossCancelsExecutionWithoutUpload(t *testing.T) {
	now := time.Now().UTC()
	clock := liveClock{}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "attempts.json"), clock)
	client := &fakeControl{renew: func(context.Context, LeaseRef) (time.Time, error) { return time.Time{}, ErrLeaseLost }}
	executor := executorFunc(func(ctx context.Context, task domain.CollectionTask) domain.CollectionResult {
		<-ctx.Done()
		completed := time.Now().UTC()
		return domain.CollectionResult{Task: task, Status: domain.ResultFailed, StartedAt: completed, CompletedAt: completed, Coverage: domain.Coverage{Complete: false}, Failures: []domain.CollectionFailure{{Code: domain.FailureDeadlineExceeded, Message: "execution cancelled"}}}
	})
	runtime := newTestRuntime(t, client, executor, journal, clock)
	if err := runtime.process(context.Background(), testLease(now, 1)); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("process error = %v, want lease lost", err)
	}
	if len(client.uploads) != 0 || client.finalizations != 0 {
		t.Fatal("lease-lost result was uploaded")
	}
}

func TestRuntimeReconnectsAfterHeartbeatFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &fakeControl{heartbeat: func(_ context.Context, _ Heartbeat, call int) error {
		if call == 1 {
			return errors.New("disconnected")
		}
		cancel()
		return nil
	}}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "attempts.json"), liveClock{})
	runtime := newTestRuntime(t, client, executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult { return domain.CollectionResult{} }), journal, liveClock{})
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if client.heartbeats != 2 {
		t.Fatalf("heartbeat calls = %d, want 2", client.heartbeats)
	}
}

func TestRuntimeImmediatelyReclaimsAfterNoWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var claimCalls atomic.Int32
	client := &fakeControl{claim: func(_ context.Context, _ ClaimRequest) (*domain.WorkLease, error) {
		if claimCalls.Add(1) == 2 {
			cancel()
		}
		return nil, nil
	}}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "attempts.json"), liveClock{})
	runtime, err := NewRuntime(RuntimeConfig{
		CollectorID: "collector-1", SourceID: "source-1", Version: "test", Capabilities: []string{string(domain.QuerySourceHealth)},
		HeartbeatInterval: time.Second, ClaimWait: time.Second, RenewInterval: time.Second,
		BackoffMinimum: time.Second, BackoffMaximum: time.Second,
	}, client, executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult { return domain.CollectionResult{} }), journal, liveClock{})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("empty response used reconnect backoff: elapsed=%s", elapsed)
	}
	if client.claims != 2 {
		t.Fatalf("claim calls = %d, want 2 before cancellation", client.claims)
	}
}

func TestRuntimeRefusesSameClusterSourceMismatchBeforeExecution(t *testing.T) {
	clock := liveClock{}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "attempts.json"), clock)
	client := &fakeControl{}
	executions := 0
	runtime := newTestRuntime(t, client, executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult {
		executions++
		return domain.CollectionResult{}
	}), journal, clock)
	lease := testLease(clock.Now(), 1)
	lease.Work.Task.SourceID = "other-source"
	if err := runtime.process(context.Background(), lease); err == nil {
		t.Fatal("accepted a lease for another locally configured source")
	}
	if executions != 0 || client.starts != 0 || len(client.uploads) != 0 || client.finalizations != 0 {
		t.Fatalf("source mismatch executed or published: executions=%d starts=%d uploads=%d finalizations=%d", executions, client.starts, len(client.uploads), client.finalizations)
	}
	if stats, err := journal.Stats(); err != nil || stats.Records() != 0 {
		t.Fatalf("mismatched work entered local journal: %+v %v", stats, err)
	}
}

func TestRuntimeRetriesTransientSourceFailureBeforeFinalization(t *testing.T) {
	now := time.Now().UTC()
	clock := liveClock{}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "attempts.json"), clock)
	client := &fakeControl{}
	var executions atomic.Int32
	executor := executorFunc(func(_ context.Context, task domain.CollectionTask) domain.CollectionResult {
		if executions.Add(1) == 1 {
			return domain.CollectionResult{
				Task: task, Status: domain.ResultFailed, StartedAt: now, CompletedAt: now,
				Coverage: domain.Coverage{Complete: false},
				Failures: []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Retryable: true, Message: "source temporarily unavailable"}},
			}
		}
		return noDataResult(task, now)
	})
	runtime, err := NewRuntime(RuntimeConfig{
		CollectorID: "collector-1", SourceID: "source-1", Version: "test", Capabilities: []string{string(domain.QuerySourceHealth)},
		HeartbeatInterval: time.Second, ClaimWait: time.Millisecond, RenewInterval: 100 * time.Millisecond,
		BackoffMinimum: time.Millisecond, BackoffMaximum: time.Millisecond,
		ExecutionRetries: 2, ExecutionBackoff: time.Millisecond,
	}, client, executor, journal, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.process(context.Background(), testLease(now, 1)); err != nil {
		t.Fatal(err)
	}
	if executions.Load() != 2 || client.finalizations != 1 {
		t.Fatalf("executions=%d finalizations=%d", executions.Load(), client.finalizations)
	}
}

func TestSourceHealthKeepsReachabilitySeparateFromResultValidity(t *testing.T) {
	now := time.Now().UTC()
	task := testLease(now, 1).Work.Task
	malformed := domain.CollectionResult{
		Task: task, Status: domain.ResultFailed, CompletedAt: now,
		Failures: []domain.CollectionFailure{{Code: domain.FailureMalformedResponse, Message: "source returned malformed data"}},
	}
	if health := sourceHealthFromResult(task.SourceID, malformed); health.Availability != "AVAILABLE" {
		t.Fatalf("malformed response reachability=%s", health.Availability)
	}
	unavailable := malformed
	unavailable.Failures[0].Code = domain.FailureSourceUnavailable
	if health := sourceHealthFromResult(task.SourceID, unavailable); health.Availability != "UNAVAILABLE" || health.SafeMessage == "" {
		t.Fatalf("source unavailable health=%+v", health)
	}
}

func uploadedDocument(t *testing.T, client *fakeControl) domain.CollectorResultDocument {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	var encoded []byte
	for _, chunk := range client.uploads {
		encoded = append(encoded, chunk.Payload...)
	}
	document, err := domain.DecodeCollectorResult(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func openTestJournal(t *testing.T, path string, clock Clock) *Journal {
	t.Helper()
	journal, err := OpenJournal(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

func newTestRuntime(t *testing.T, client ControlClient, executor executorFunc, journal *Journal, clock Clock) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(RuntimeConfig{
		CollectorID: "collector-1", SourceID: "source-1", Version: "test", Capabilities: []string{string(domain.QuerySourceHealth)},
		HeartbeatInterval: 10 * time.Millisecond, ClaimWait: 5 * time.Millisecond, RenewInterval: time.Millisecond,
		BackoffMinimum: time.Millisecond, BackoffMaximum: 2 * time.Millisecond,
	}, client, executor, journal, clock)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func testLease(now time.Time, attempt int) domain.WorkLease {
	task := domain.CollectionTask{
		RunID: "run-1", ClusterID: "cluster-1", SourceID: "source-1", Query: domain.QuerySourceHealth,
		ScheduledFor: now, Deadline: now.Add(time.Minute), MaxSeries: 10_000, MaxBytes: 10 << 20, IdempotencyKey: "run/run-1",
	}
	return domain.WorkLease{
		CollectorID: "collector-1", Attempt: attempt, LeaseToken: "lease-token-that-is-at-least-thirty-two-bytes", LeaseExpires: now.Add(time.Minute),
		Work: domain.CollectorWork{WorkID: "work-1", Task: task, Status: domain.WorkLeased, AvailableAt: now.Add(-time.Second), WorkExpiresAt: now.Add(time.Hour)},
	}
}

func noDataResult(task domain.CollectionTask, now time.Time) domain.CollectionResult {
	return domain.CollectionResult{Task: task, Status: domain.ResultNoData, StartedAt: now, CompletedAt: now, Coverage: domain.Coverage{Complete: true}}
}
