//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestM15RemediationOperationsProjection(t *testing.T) {
	if os.Getenv("SHERLOCK_TEST_DATABASE_URL") == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	result := m15RunRecovery(t, m15RecoveryHooks{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := m15SecurityPool(t, ctx)
	defer pool.Close()
	store, err := storepg.NewRemediationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.RemediationOperations(ctx, string(result.ClusterID), 64)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]int64{}
	for _, b := range snapshot.RunStates {
		states[b.Class] = b.Count
	}
	requests := map[string]int64{}
	for _, b := range snapshot.RequestStates {
		requests[b.Class] = b.Count
	}
	if states["SUCCEEDED"] != 1 || requests["COMPLETED"] != 1 || snapshot.RepairEffects != 1 || snapshot.TerminalRuns != 1 || snapshot.PendingVerification != 0 || snapshot.ActiveReservations != 0 {
		t.Fatalf("unexpected projection states=%v requests=%v snapshot=%+v", states, requests, snapshot)
	}
	if snapshot.EffectLatencySeconds <= 0 || snapshot.EffectLatencySeconds > 30 {
		t.Fatalf("verification latency=%f", snapshot.EffectLatencySeconds)
	}
	// Sample timestamps can precede request insertion while still following the
	// dispatch boundary. Operational latency ends at durable verification.
	var expectedLatency float64
	if err := pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM (v.recorded_at-r.created_at)) FROM collection_repair_requests r JOIN remediation_verification_evidence v ON v.cluster_id=r.cluster_id AND v.run_id=r.run_id AND v.attempt_id=r.attempt_id AND v.target=r.job_id WHERE r.request_id=$1 AND v.condition_id='stream-fresh'`, result.RepairRequestID).Scan(&expectedLatency); err != nil {
		t.Fatal(err)
	}
	if snapshot.EffectLatencySeconds != expectedLatency {
		t.Fatalf("latency=%f want durable verification latency=%f", snapshot.EffectLatencySeconds, expectedLatency)
	}
	// The public snapshot is category-only; it has no durable identifiers to leak.
	for _, b := range snapshot.RunStates {
		if b.Class == result.RepairRequestID || b.Class == result.EvidenceID {
			t.Fatalf("identifier leaked in bucket %q", b.Class)
		}
	}
	for _, b := range snapshot.RequestStates {
		if b.Class == result.RepairRequestID || b.Class == result.EvidenceID {
			t.Fatalf("identifier leaked in bucket %q", b.Class)
		}
	}
}

func TestM15OperationsRevisionFenceVisibility(t *testing.T) {
	result := m15RunRecovery(t, m15RecoveryHooks{StopAfterRequest: true})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := m15SecurityPool(t, ctx)
	defer pool.Close()
	store, err := storepg.NewRemediationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE collection_jobs SET interval_seconds=interval_seconds+1 WHERE cluster_id=$1 AND job_id=$2`, result.ClusterID, result.JobID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.RemediationOperations(ctx, string(result.ClusterID), 64)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range snapshot.FenceStates {
		if b.Class == "configuration_revision_mismatch" && b.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing actual revision mismatch: %+v", snapshot.FenceStates)
	}
}
