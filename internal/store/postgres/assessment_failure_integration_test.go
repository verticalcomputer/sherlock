//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

func failureAccountingFixture(t *testing.T) (*assessmentFixture, *AssessmentStore) {
	t.Helper()
	f := newAssessmentFixture(t)
	at := time.Now().UTC().Truncate(time.Microsecond)
	f.seedRun(t, at)
	f.seedEnrollment(t, at)
	return f, &AssessmentStore{pool: f.restrictedPool(t), registry: f.registry, config: f.config}
}

func failureAccountingTotals(t *testing.T, f *assessmentFixture) (int64, int64, int64) {
	t.Helper()
	var count, coverage, overflow int64
	err := f.admin.QueryRow(context.Background(), `SELECT (SELECT coalesce(sum(count),0) FROM assessment_failures WHERE run_id=$1),coalesce((SELECT sum((v->>'count')::bigint) FROM jsonb_array_elements(convert_from(coverage,'UTF8')::jsonb) v),0),overflow_count FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&count, &coverage, &overflow)
	if err != nil {
		t.Fatal(err)
	}
	return count, coverage, overflow
}

func TestAssessmentFailureLostCommitAcknowledgement(t *testing.T) {
	f, s := failureAccountingFixture(t)
	ctx := context.Background()
	s.noteAssessmentFailure(time.Now(), errors.New("source failed"))
	err := s.flushAssessmentFailureWithCommit(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return context.DeadlineExceeded
	})
	if !errors.Is(err, errAssessmentCommitUnresolved) || !errors.Is(err, context.DeadlineExceeded) || s.pendingFailure.xid == "" {
		t.Fatalf("lost ambiguity: %v", err)
	}
	if n, c, o := failureAccountingTotals(t, f); n != 1 || c != 1 || o != 0 {
		t.Fatalf("initial totals %d/%d/%d", n, c, o)
	}
	// A fresh process cannot replay the already durable batch.
	restarted := &AssessmentStore{pool: s.pool, config: s.config}
	if err := restarted.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	s.noteAssessmentFailure(time.Now(), ErrAssessmentCapacity, "deadline_capacity")
	if s.pendingFailure.count != 1 || s.pendingFailure.capacity || s.queuedFailure.count != 1 {
		t.Fatal("frozen batch mutated")
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	if n, c, o := failureAccountingTotals(t, f); n != 2 || c != 2 || o != 0 {
		t.Fatalf("replayed totals %d/%d/%d", n, c, o)
	}
	var state string
	if err := f.admin.QueryRow(ctx, `SELECT state FROM assessment_runs WHERE run_id=$1`, f.config.RunID).Scan(&state); err != nil || state != "DRAINING" {
		t.Fatalf("capacity successor not durable: %s %v", state, err)
	}
	if s.pendingFailure != nil || s.queuedFailure != nil {
		t.Fatal("committed batches retained")
	}
}

func TestAssessmentFailureAbortedCommitReplaysOnce(t *testing.T) {
	f, s := failureAccountingFixture(t)
	ctx := context.Background()
	s.noteAssessmentFailure(time.Now(), context.DeadlineExceeded)
	err := s.flushAssessmentFailureWithCommit(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		return context.DeadlineExceeded
	})
	if !errors.Is(err, errAssessmentCommitUnresolved) {
		t.Fatal(err)
	}
	if n, c, o := failureAccountingTotals(t, f); n != 0 || c != 0 || o != 0 {
		t.Fatal("aborted write survived")
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	if n, c, o := failureAccountingTotals(t, f); n != 1 || c != 1 || o != 0 {
		t.Fatalf("retry totals %d/%d/%d", n, c, o)
	}
}

func TestAssessmentFailureUnresolvedCommitStopsRefresh(t *testing.T) {
	f, s := failureAccountingFixture(t)
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	var xid string
	if err := tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	s.noteAssessmentFailure(time.Now(), context.DeadlineExceeded)
	s.pendingFailure.xid = xid
	for range 3 {
		if err := s.Refresh(ctx); !errors.Is(err, errAssessmentCommitUnresolved) {
			t.Fatalf("refresh admitted while unresolved: %v", err)
		}
	}
	if n, c, o := failureAccountingTotals(t, f); n != 0 || c != 0 || o != 0 {
		t.Fatal("in-progress transaction replayed")
	}
	if s.pendingFailure.count != 1 || s.queuedFailure != nil {
		t.Fatal("poll failures counted as new evaluation failures")
	}
	// An unavailable lookup also retains the frozen batch.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.flushAssessmentFailure(canceled); !errors.Is(err, errAssessmentCommitUnresolved) {
		t.Fatal(err)
	}
	if s.pendingFailure.xid != xid {
		t.Fatal("lost transaction identity")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	if n, c, o := failureAccountingTotals(t, f); n != 1 || c != 1 || o != 0 {
		t.Fatalf("resolved totals %d/%d/%d", n, c, o)
	}
}

func TestAssessmentFailureOverflowLostAcknowledgement(t *testing.T) {
	f, s := failureAccountingFixture(t)
	ctx := context.Background()
	at := time.Now().UTC()
	body, _ := a.Canonical(assessmentFailureBody{Schema: 1, FactIDs: []string{}, Message: "fixture", From: at, Through: at})
	batch := &pgx.Batch{}
	for i := range 1024 {
		scope := fmt.Sprintf("fixture-%d", i)
		id, _ := a.Identity("failure", f.config.Category, map[string]any{"run": f.config.RunID, "code": "COVERAGE", "scope_key": scope})
		batch.Queue(`INSERT INTO assessment_failures(run_id,id,category,kind,code,scope_key,first_at,last_at,count,body) VALUES($1,$2,$3,'COVERAGE','COVERAGE',$4,$5,$5,1,$6)`, f.config.RunID, id, f.config.Category, scope, at, body)
	}
	if err := f.admin.SendBatch(ctx, batch).Close(); err != nil {
		t.Fatal(err)
	}
	s.noteAssessmentFailure(time.Now(), ErrAssessmentCapacity, "deadline_capacity")
	err := s.flushAssessmentFailureWithCommit(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return context.DeadlineExceeded
	})
	if !errors.Is(err, errAssessmentCommitUnresolved) {
		t.Fatal(err)
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	if n, c, o := failureAccountingTotals(t, f); n != 1024 || c != 1 || o != 1 {
		t.Fatalf("overflow replayed: %d/%d/%d", n, c, o)
	}
}

func TestAssessmentFailureTransactionDiagnostics(t *testing.T) {
	f, s := failureAccountingFixture(t)
	ctx := context.Background()
	holder, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(holder)
	if _, err := holder.Exec(ctx, `SELECT run_id FROM assessment_runs WHERE run_id=$1 FOR UPDATE`, f.config.RunID); err != nil {
		t.Fatal(err)
	}
	s.noteAssessmentFailure(time.Now(), context.DeadlineExceeded)
	err = s.flushAssessmentFailure(ctx)
	var diagnostic *assessmentTxError
	if !errors.As(err, &diagnostic) || diagnostic.diagnostic.Stage != "failure_flush.read" || diagnostic.diagnostic.SQLState != "55P03" || diagnostic.diagnostic.ElapsedMS < 1 || diagnostic.diagnostic.CommitOutcome != "not_attempted" {
		t.Fatalf("lock timeout diagnostic: %+v / %v", diagnostic, err)
	}
	if s.pendingFailure == nil || s.pendingFailure.xid != "" {
		t.Fatal("precommit failure became ambiguous")
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.flushAssessmentFailure(ctx); err != nil {
		t.Fatal(err)
	}
	// A stale repeatable-read snapshot must retain SQLSTATE through the refresh wrapper.
	tx, err := beginAssessmentTx(ctx, s.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE assessment_runs SET unknown_through=clock_timestamp() WHERE run_id=$1`, f.config.RunID)
	err = s.refreshAssessmentTx(ctx, tx, false)
	diagnostic = nil
	if !errors.As(err, &diagnostic) || diagnostic.diagnostic.Stage != "refresh.load" || diagnostic.diagnostic.SQLState != "40001" {
		t.Fatalf("serialization diagnostic: %+v / %v", diagnostic, err)
	}
}
