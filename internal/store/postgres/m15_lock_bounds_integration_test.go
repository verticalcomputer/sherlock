//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediationlive"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestM15AuthorityLockBoundsEveryLivePath(t *testing.T) {
	result := m15RunRecovery(t, m15RecoveryHooks{StopAfterRequest: true})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := m15LockPool(t, ctx)
	defer pool.Close()
	store, err := storepg.NewRemediationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	control, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	var attemptID domain.RemediationAttemptID
	if err = pool.QueryRow(ctx, `SELECT attempt_id FROM collection_repair_requests WHERE request_id=$1`, result.RepairRequestID).Scan(&attemptID); err != nil {
		t.Fatal(err)
	}
	workerClaim, found, err := store.ClaimRepairCollection(ctx, result.ClusterID, result.SourceID, "lock-test-worker", time.Minute)
	if err != nil || !found {
		t.Fatalf("claim repair fixture: found=%t err=%v", found, err)
	}
	workLease, found, err := control.ClaimWork(ctx, result.CollectorID, "lock-test-collector-token", time.Minute)
	if err != nil || !found {
		t.Fatalf("claim collector fixture: found=%t err=%v", found, err)
	}
	var supervisor storepg.RemediationSupervisorClaim
	deadline := time.Now().Add(time.Second)
	for supervisor.RunID == "" && time.Now().Before(deadline) {
		supervisor, err = store.ClaimRemediation(ctx, result.ClusterID, "lock-test-supervisor", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if supervisor.RunID == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if supervisor.RunID == "" {
		t.Fatal("claim remediation fixture timed out")
	}
	supervised := storepg.ContextWithRemediationSupervisorClaim(ctx, supervisor)

	holder, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if err = storepg.LockRepairAuthority(ctx, holder, result.ClusterID); err != nil {
		t.Fatal(err)
	}

	unit := domain.ExecutionUnit{
		RunID: domain.RemediationRunID(result.RemediationRun), AttemptID: attemptID, ClusterID: result.ClusterID,
		Targets: []domain.ResolvedTarget{{Target: domain.RemediationTarget(result.JobID), Role: domain.RoleManagedCollectionStream, ClusterID: result.ClusterID}},
	}
	invalidFinalization := collectorcontrol.ResultFinalization{
		LeaseRef: collectorcontrol.LeaseRef{WorkID: workLease.Work.WorkID, Attempt: workLease.Attempt, LeaseToken: workLease.LeaseToken},
		RunID:    workLease.Work.Task.RunID, Status: domain.ResultSucceeded, ChunkCount: 1, Bytes: 1, SHA256: strings.Repeat("0", 64),
	}
	paths := map[string]func() error{
		"operator control claim": func() error {
			_, callErr := store.ClaimRemediationControl(ctx, result.ClusterID, domain.RemediationRunID(result.RemediationRun), "lock-test-control", time.Minute)
			return callErr
		},
		"live effect": func() error {
			_, callErr := store.RequestCollection(ctx, remediationlive.Request{Unit: unit, Catalog: result.Catalog})
			return callErr
		},
		"rollback compensation": func() error {
			_, callErr := store.CancelCollection(ctx, remediationlive.Request{Unit: unit, Catalog: result.Catalog})
			return callErr
		},
		"cancellation": func() error {
			return store.RequestRemediationCancellation(ctx, result.ClusterID, domain.RemediationRunID(result.RemediationRun), "lock-test-operator")
		},
		"reconciliation": func() error {
			return store.ReconcileCollectionRequest(ctx, result.ClusterID, domain.RemediationRunID(result.RemediationRun), attemptID)
		},
		"repair worker claim": func() error {
			_, _, callErr := store.ClaimRepairCollection(ctx, result.ClusterID, result.SourceID, "lock-test-contender", time.Minute)
			return callErr
		},
		"repair worker completion": func() error {
			return store.FinishRepairCollection(ctx, workerClaim, "lock-test-worker")
		},
		"collector claim": func() error {
			_, _, callErr := control.ClaimWork(ctx, result.CollectorID, "lock-test-second-token", time.Minute)
			return callErr
		},
		"collector start": func() error {
			return control.AcknowledgeWorkStart(ctx, result.CollectorID, workLease.Work.WorkID, workLease.Attempt, workLease.LeaseToken)
		},
		"collector renewal": func() error {
			return control.RenewWorkLease(ctx, result.CollectorID, workLease.Work.WorkID, workLease.Attempt, workLease.LeaseToken, time.Minute)
		},
		"result finalization": func() error {
			_, callErr := control.FinalizeResult(ctx, result.CollectorID, invalidFinalization)
			return callErr
		},
		"committed effect recovery": func() error {
			_, _, callErr := store.RecoverCommittedLiveEffect(supervised, result.ClusterID, domain.RemediationRunID(result.RemediationRun), attemptID)
			return callErr
		},
	}
	type outcome struct {
		name    string
		elapsed time.Duration
		err     error
	}
	outcomes := make(chan outcome, len(paths))
	var wg sync.WaitGroup
	for name, call := range paths {
		wg.Add(1)
		go func(name string, call func() error) {
			defer wg.Done()
			started := time.Now()
			callErr := call()
			outcomes <- outcome{name: name, elapsed: time.Since(started), err: callErr}
		}(name, call)
	}
	wg.Wait()
	close(outcomes)
	for got := range outcomes {
		if !errors.Is(got.err, storepg.ErrRemediationAuthorityBusy) {
			t.Errorf("%s returned %v, want stable authority-busy error", got.name, got.err)
		}
		if got.elapsed > storepg.RemediationAuthorityLockTimeout+time.Second {
			t.Errorf("%s exceeded lock bound: %s", got.name, got.elapsed)
		}
	}

	shortCtx, shortCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shortCancel()
	shortTx, err := pool.BeginTx(shortCtx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = storepg.LockRepairAuthority(shortCtx, shortTx, result.ClusterID)
	_ = shortTx.Rollback(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) >= storepg.RemediationAuthorityLockTimeout {
		t.Fatalf("shorter caller deadline was not preserved: elapsed=%s err=%v", time.Since(started), err)
	}

	if err = holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	available, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = available.Rollback(context.Background()) }()
	if err = storepg.LockRepairAuthority(ctx, available, result.ClusterID); err != nil {
		t.Fatalf("authority remained unavailable after holder rollback: %v", err)
	}
}

func TestM15AuthorityLockBreaksInverseRowOrder(t *testing.T) {
	result := m15RunRecovery(t, m15RecoveryHooks{StopAfterRequest: true})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := m15LockPool(t, ctx)
	defer pool.Close()
	store, err := storepg.NewRemediationStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	rowFirst, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rowFirst.Rollback(context.Background()) }()
	if _, err = rowFirst.Exec(ctx, `SELECT request_id FROM collection_repair_requests WHERE request_id=$1 FOR UPDATE`, result.RepairRequestID); err != nil {
		t.Fatal(err)
	}

	cancellation := make(chan error, 1)
	started := time.Now()
	go func() {
		cancellation <- store.RequestRemediationCancellation(ctx, result.ClusterID, domain.RemediationRunID(result.RemediationRun), "lock-order-operator")
	}()
	// Give the correctly ordered path time to acquire authority and reach the
	// deliberately held request row, creating the historical inverse cycle.
	time.Sleep(100 * time.Millisecond)
	rowFirstErr := storepg.LockRepairAuthority(ctx, rowFirst, result.ClusterID)
	_ = rowFirst.Rollback(context.Background())
	cancelErr := <-cancellation
	if time.Since(started) > 2*storepg.RemediationAuthorityLockTimeout+time.Second {
		t.Fatalf("inverse lock order did not resolve within bounds: %s", time.Since(started))
	}
	if rowFirstErr == nil && cancelErr == nil {
		t.Fatal("inverse lock cycle unexpectedly committed both contenders")
	}
}

func TestM15RepairCompletionRejectsWrongClusterAuthority(t *testing.T) {
	result := m15RunRecovery(t, m15RecoveryHooks{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := m15LockPool(t, ctx)
	defer pool.Close()
	store, err := storepg.NewRemediationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	claim := application.RepairCollectionClaim{
		RequestID: result.RepairRequestID,
		Task: domain.CollectionTask{
			RunID:     domain.RunID(result.RepairRequestID),
			ClusterID: domain.ClusterID("wrong-" + string(result.ClusterID)),
		},
	}
	if err = store.FinishRepairCollection(ctx, claim, "wrong-cluster-worker"); err == nil {
		t.Fatal("repair completion accepted authority for another cluster")
	}
}

func m15LockPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(os.Getenv("SHERLOCK_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}
