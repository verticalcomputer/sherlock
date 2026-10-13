//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// This test writes only controlled simulation observations. It deliberately
// does not use executor receipts as evidence for verification.
func TestRemediationObservationsUseExecutionReceiptBoundaryAndProvenance(t *testing.T) {
	f := newRemediationFixture(t)
	ctx := context.Background()
	plan := f.plan(t, domain.RemediationRunID("observation-run-"+f.suffix), f.targets[:1])
	if _, created := f.create(t, plan, "observations"); !created {
		t.Fatal("expected isolated run")
	}
	attemptID := domain.RemediationAttemptID("observation-attempt-" + f.suffix)
	target := f.targets[0]
	boundary := insertObservationAttempt(t, f, plan.RunID, attemptID, target)
	receiptAt := boundary.Add(30 * time.Second)
	insertObservationReceipt(t, f, plan.RunID, attemptID, target, receiptAt)
	q := application.RemediationObservationQuery{
		AttemptID: attemptID, Simulation: true, ClusterID: f.clusterID, RunID: plan.RunID,
		Targets: []domain.RemediationTarget{target}, Window: time.Hour,
		Conditions: []string{"stream-fresh", "schedule-restored"},
	}

	old := boundary.Add(-time.Minute)
	if _, err := f.pool.Exec(ctx, `INSERT INTO remediation_simulation_observations
		(evidence_id,cluster_id,run_id,attempt_id,target,observed_start,observed_end,complete)
		VALUES($1,$2,$3,$4,$5,$6,$7,true)`, "old-"+f.suffix, f.clusterID, plan.RunID, attemptID, target, old, old.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	observations, err := f.store.ReadRemediationObservations(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 {
		t.Fatalf("observations=%d want 2", len(observations))
	}
	for _, observation := range observations {
		if observation.Result != domain.ConditionUnobserved {
			t.Fatalf("old evidence satisfied %s", observation.ConditionID)
		}
	}
	// The attempt and receipt boundaries are derived from the database clock.
	// This sample is unambiguously after the receipt and behind the database-owned
	// read instant.
	valid := boundary.Add(time.Minute)
	if _, err = f.pool.Exec(ctx, `INSERT INTO remediation_simulation_observations
		(evidence_id,cluster_id,run_id,attempt_id,target,observed_start,observed_end,complete)
		VALUES($1,$2,$3,$4,$5,$6,$7,true)`, "new-"+f.suffix, f.clusterID, plan.RunID, attemptID, target, valid, valid.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	observations, err = f.store.ReadRemediationObservations(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if observations[0].Result != domain.ConditionSatisfied || observations[0].EvidenceID != "new-"+f.suffix || observations[0].Source != "SIMULATION_OBSERVATIONS" {
		t.Fatalf("fresh observation=%+v", observations[0])
	}
	if observations[1].Result != domain.ConditionUnobserved {
		t.Fatalf("missing schedule snapshot satisfied: %+v", observations[1])
	}
}

// Production verification accepts only a complete, successful collection run
// for the exact attempted target whose entire run and sample interval is after
// the execution receipt boundary and no later than the database read instant.
func TestRemediationRealCollectionObservationsFailClosed(t *testing.T) {
	tests := []struct {
		name           string
		status         string
		coverage       bool
		targetIndex    int
		scheduledDelta time.Duration
		startedDelta   time.Duration
		completedDelta time.Duration
		observedDelta  time.Duration
		collectedDelta time.Duration
		createdDelta   time.Duration
	}{
		{name: "failed", status: "FAILED", coverage: true, scheduledDelta: 10 * time.Second, startedDelta: 10 * time.Second, completedDelta: 20 * time.Second, observedDelta: 15 * time.Second, collectedDelta: 20 * time.Second, createdDelta: 20 * time.Second},
		{name: "partial", status: "PARTIAL", coverage: true, scheduledDelta: 10 * time.Second, startedDelta: 10 * time.Second, completedDelta: 20 * time.Second, observedDelta: 15 * time.Second, collectedDelta: 20 * time.Second, createdDelta: 20 * time.Second},
		{name: "incomplete coverage", status: "SUCCEEDED", coverage: false, scheduledDelta: 10 * time.Second, startedDelta: 10 * time.Second, completedDelta: 20 * time.Second, observedDelta: 15 * time.Second, collectedDelta: 20 * time.Second, createdDelta: 20 * time.Second},
		{name: "spans execution boundary", status: "SUCCEEDED", coverage: true, scheduledDelta: 10 * time.Second, startedDelta: -time.Second, completedDelta: 20 * time.Second, observedDelta: 15 * time.Second, collectedDelta: 20 * time.Second, createdDelta: 20 * time.Second},
		{name: "old", status: "SUCCEEDED", coverage: true, scheduledDelta: -time.Minute, startedDelta: -time.Minute, completedDelta: -30 * time.Second, observedDelta: -45 * time.Second, collectedDelta: -30 * time.Second, createdDelta: -30 * time.Second},
		{name: "future", status: "SUCCEEDED", coverage: true, scheduledDelta: 10 * time.Minute, startedDelta: 10 * time.Minute, completedDelta: 11 * time.Minute, observedDelta: 10*time.Minute + 30*time.Second, collectedDelta: 11 * time.Minute, createdDelta: 11 * time.Minute},
		{name: "wrong target", status: "SUCCEEDED", coverage: true, targetIndex: 1, scheduledDelta: 10 * time.Second, startedDelta: 10 * time.Second, completedDelta: 20 * time.Second, observedDelta: 15 * time.Second, collectedDelta: 20 * time.Second, createdDelta: 20 * time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newRemediationFixture(t)
			ctx := context.Background()
			plan := f.plan(t, domain.RemediationRunID("real-observation-run-"+f.suffix), f.targets[:1])
			if _, created := f.create(t, plan, "real-observations"); !created {
				t.Fatal("expected isolated run")
			}
			attemptID := domain.RemediationAttemptID("real-observation-attempt-" + f.suffix)
			boundary := insertObservationAttempt(t, f, plan.RunID, attemptID, f.targets[0])
			insertObservationReceipt(t, f, plan.RunID, attemptID, f.targets[0], boundary.Add(5*time.Second))
			insertCollectionEvidence(t, f, "rejected-"+f.suffix, f.targets[test.targetIndex], test.status, test.coverage,
				boundary.Add(test.scheduledDelta), boundary.Add(test.startedDelta), boundary.Add(test.completedDelta),
				boundary.Add(test.observedDelta), boundary.Add(test.collectedDelta), boundary.Add(test.createdDelta))

			observations, err := f.store.ReadRemediationObservations(ctx, application.RemediationObservationQuery{
				AttemptID: attemptID, ClusterID: f.clusterID, RunID: plan.RunID,
				Targets: []domain.RemediationTarget{f.targets[0]}, Window: time.Hour,
				Conditions: []string{"stream-fresh"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(observations) != 1 || observations[0].Result != domain.ConditionUnobserved || observations[0].EvidenceID != "" {
				t.Fatalf("rejected collection evidence satisfied verification: %+v", observations)
			}
		})
	}
}

func TestRemediationRealCollectionObservationUsesExactRunProvenance(t *testing.T) {
	f := newRemediationFixture(t)
	ctx := context.Background()
	plan := f.plan(t, domain.RemediationRunID("valid-real-observation-run-"+f.suffix), f.targets[:1])
	if _, created := f.create(t, plan, "valid-real-observations"); !created {
		t.Fatal("expected isolated run")
	}
	attemptID := domain.RemediationAttemptID("valid-real-observation-attempt-" + f.suffix)
	boundary := insertObservationAttempt(t, f, plan.RunID, attemptID, f.targets[0])
	receiptAt := boundary.Add(time.Minute)

	// A fully successful collection after attempt admission but before the
	// executor receipt is not causally downstream of the repair.
	insertCollectionEvidence(t, f, "pre-receipt-"+f.suffix, f.targets[0], "SUCCEEDED", true,
		boundary.Add(10*time.Second), boundary.Add(10*time.Second), boundary.Add(30*time.Second),
		boundary.Add(20*time.Second), boundary.Add(30*time.Second), boundary.Add(30*time.Second))
	insertObservationReceipt(t, f, plan.RunID, attemptID, f.targets[0], receiptAt)
	q := application.RemediationObservationQuery{
		AttemptID: attemptID, ClusterID: f.clusterID, RunID: plan.RunID,
		Targets: []domain.RemediationTarget{f.targets[0]}, Window: time.Hour,
		Conditions: []string{"stream-fresh"},
	}
	observations, err := f.store.ReadRemediationObservations(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Result != domain.ConditionUnobserved {
		t.Fatalf("pre-receipt collection evidence satisfied verification: %+v", observations)
	}

	runID := "accepted-" + f.suffix
	observedAt := receiptAt.Add(30 * time.Second)
	insertCollectionEvidence(t, f, runID, f.targets[0], "SUCCEEDED", true,
		receiptAt.Add(10*time.Second), receiptAt.Add(10*time.Second), receiptAt.Add(time.Minute),
		observedAt, receiptAt.Add(time.Minute), receiptAt.Add(time.Minute))

	observations, err = f.store.ReadRemediationObservations(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Result != domain.ConditionSatisfied || observations[0].EvidenceID != runID || observations[0].Source != "COLLECTION_RUNS" || !observations[0].ObservedAt.Equal(observedAt) {
		t.Fatalf("valid collection evidence=%+v", observations)
	}
}

func TestRemediationLiveScheduleRestorationRequiresExactFence(t *testing.T) {
	tests := []struct {
		name       string
		withRow    bool
		configure  func(*testing.T, remediationFixture, domain.RemediationRunID, domain.RemediationAttemptID, domain.RemediationTarget)
		wantResult domain.ConditionResult
	}{
		{name: "missing snapshot", wantResult: domain.ConditionUnobserved},
		{name: "matching values without fence", withRow: true, wantResult: domain.ConditionUnsatisfied},
		{
			name: "partial fence", withRow: true, wantResult: domain.ConditionUnsatisfied,
			configure: func(t *testing.T, f remediationFixture, runID domain.RemediationRunID, attemptID domain.RemediationAttemptID, target domain.RemediationTarget) {
				t.Helper()
				if _, err := f.pool.Exec(context.Background(), `UPDATE remediation_schedule_snapshots
					SET live_forward_revision=prior_revision+1,live_restored_attempt_id=$4
					WHERE cluster_id=$1 AND run_id=$2 AND target=$3`, f.clusterID, runID, target, attemptID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "claimed fence without schedule mutations", withRow: true, wantResult: domain.ConditionUnsatisfied,
			configure: func(t *testing.T, f remediationFixture, runID domain.RemediationRunID, attemptID domain.RemediationAttemptID, target domain.RemediationTarget) {
				t.Helper()
				if _, err := f.pool.Exec(context.Background(), `UPDATE remediation_schedule_snapshots
					SET live_forward_revision=prior_revision+1,live_restored_revision=prior_revision+2,live_restored_attempt_id=$4
					WHERE cluster_id=$1 AND run_id=$2 AND target=$3`, f.clusterID, runID, target, attemptID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "exact forward and restoration revisions", withRow: true, wantResult: domain.ConditionSatisfied,
			configure: func(t *testing.T, f remediationFixture, runID domain.RemediationRunID, attemptID domain.RemediationAttemptID, target domain.RemediationTarget) {
				t.Helper()
				ctx := context.Background()
				if _, err := f.pool.Exec(ctx, `UPDATE collection_jobs SET next_run_at=next_run_at+interval '5 minutes' WHERE cluster_id=$1 AND job_id=$2`, f.clusterID, target); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(ctx, `UPDATE collection_jobs j SET active=p.prior_active,interval_seconds=p.prior_interval,next_run_at=p.prior_next
					FROM remediation_schedule_snapshots p WHERE p.cluster_id=$1 AND p.run_id=$2 AND p.target=$3 AND j.cluster_id=p.cluster_id AND j.job_id=p.target`, f.clusterID, runID, target); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(ctx, `UPDATE remediation_schedule_snapshots
					SET live_forward_revision=prior_revision+1,live_restored_revision=prior_revision+2,live_restored_attempt_id=$4
					WHERE cluster_id=$1 AND run_id=$2 AND target=$3`, f.clusterID, runID, target, attemptID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "ABA after restoration", withRow: true, wantResult: domain.ConditionUnsatisfied,
			configure: func(t *testing.T, f remediationFixture, runID domain.RemediationRunID, attemptID domain.RemediationAttemptID, target domain.RemediationTarget) {
				t.Helper()
				ctx := context.Background()
				for index := 0; index < 2; index++ {
					if _, err := f.pool.Exec(ctx, `UPDATE collection_jobs SET next_run_at=next_run_at+interval '5 minutes' WHERE cluster_id=$1 AND job_id=$2`, f.clusterID, target); err != nil {
						t.Fatal(err)
					}
					if _, err := f.pool.Exec(ctx, `UPDATE collection_jobs j SET active=p.prior_active,interval_seconds=p.prior_interval,next_run_at=p.prior_next
						FROM remediation_schedule_snapshots p WHERE p.cluster_id=$1 AND p.run_id=$2 AND p.target=$3 AND j.cluster_id=p.cluster_id AND j.job_id=p.target`, f.clusterID, runID, target); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := f.pool.Exec(ctx, `UPDATE remediation_schedule_snapshots
					SET live_forward_revision=prior_revision+1,live_restored_revision=prior_revision+2,live_restored_attempt_id=$4
					WHERE cluster_id=$1 AND run_id=$2 AND target=$3`, f.clusterID, runID, target, attemptID); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newRemediationFixture(t)
			ctx := context.Background()
			plan := f.plan(t, domain.RemediationRunID("restoration-run-"+f.suffix), f.targets[:1])
			if _, created := f.create(t, plan, "restoration"); !created {
				t.Fatal("expected isolated run")
			}
			attemptID := domain.RemediationAttemptID("restoration-attempt-" + f.suffix)
			boundary := insertObservationAttempt(t, f, plan.RunID, attemptID, f.targets[0])
			insertObservationReceipt(t, f, plan.RunID, attemptID, f.targets[0], boundary.Add(time.Second))
			if test.withRow {
				if _, err := f.pool.Exec(ctx, `INSERT INTO remediation_schedule_snapshots
					(cluster_id,run_id,target,prior_active,prior_interval,prior_next,prior_revision)
					SELECT cluster_id,$2,job_id,active,interval_seconds,next_run_at,schedule_revision
					FROM collection_jobs WHERE cluster_id=$1 AND job_id=$3`, f.clusterID, plan.RunID, f.targets[0]); err != nil {
					t.Fatal(err)
				}
			}
			if test.configure != nil {
				test.configure(t, f, plan.RunID, attemptID, f.targets[0])
			}
			observations, err := f.store.ReadRemediationObservations(ctx, application.RemediationObservationQuery{
				AttemptID: attemptID, ClusterID: f.clusterID, RunID: plan.RunID,
				Targets: []domain.RemediationTarget{f.targets[0]}, Window: time.Hour,
				Conditions: []string{"schedule-restored"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(observations) != 1 || observations[0].Result != test.wantResult {
				t.Fatalf("restoration observation=%+v want=%s", observations, test.wantResult)
			}
		})
	}
}

func insertObservationReceipt(t *testing.T, f remediationFixture, runID domain.RemediationRunID, attemptID domain.RemediationAttemptID, target domain.RemediationTarget, observedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	receiptID := "observation-receipt-" + f.suffix
	if _, err := f.pool.Exec(ctx, `INSERT INTO remediation_receipts
		(cluster_id,receipt_id,run_id,attempt_id,idempotency_key,stage,outcome,digest,observed_at)
		SELECT a.cluster_id,$1,a.run_id,a.attempt_id,a.idempotency_key,a.stage,'EXECUTED',sha256($1::text::bytea),$4
		FROM remediation_attempts a WHERE a.cluster_id=$2 AND a.run_id=$3 AND a.attempt_id=$5`, receiptID, f.clusterID, runID, observedAt, attemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO remediation_receipt_targets(cluster_id,receipt_id,target,outcome)
		VALUES($1,$2,$3,'EXECUTED')`, f.clusterID, receiptID, target); err != nil {
		t.Fatal(err)
	}
}

func insertObservationAttempt(t *testing.T, f remediationFixture, runID domain.RemediationRunID, attemptID domain.RemediationAttemptID, target domain.RemediationTarget) time.Time {
	t.Helper()
	ctx := context.Background()
	leaseHash := sha256.Sum256([]byte("lease"))
	keyHash := sha256.Sum256([]byte("key"))
	var boundary time.Time
	if err := f.pool.QueryRow(ctx, `INSERT INTO remediation_attempts
		(cluster_id,attempt_id,run_id,stage,attempt_number,idempotency_key,wave_target_digest,lease_owner,lease_token_hash,lease_expires_at,lease_deadline_at,policy_id,policy_version,policy_code,created_at)
		VALUES($1,$2,$3,'CANARY',1,$4,$5,'test',$6,clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour',$7,1,'ALLOWED',clock_timestamp()-interval '2 minutes')
		RETURNING created_at`, f.clusterID, attemptID, runID, "observation-key-"+f.suffix, keyHash[:], leaseHash[:], "observation-policy-"+f.suffix).Scan(&boundary); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO remediation_attempt_targets(cluster_id,attempt_id,run_id,ordinal,target) VALUES($1,$2,$3,0,$4)`, f.clusterID, attemptID, runID, target); err != nil {
		t.Fatal(err)
	}
	return boundary
}

func insertCollectionEvidence(t *testing.T, f remediationFixture, runID string, target domain.RemediationTarget, status string, coverage bool, scheduledAt, startedAt, completedAt, observedAt, collectedAt, createdAt time.Time) {
	t.Helper()
	ctx := context.Background()
	idempotencyKey := "collection-key-" + runID
	if _, err := f.pool.Exec(ctx, `INSERT INTO collection_runs
		(run_id,job_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete,created_at)
		SELECT $1,j.job_id,j.cluster_id,j.source_id,j.query_kind,$2,$3,$4,$5,$6,1,1,$7,$8
		FROM collection_jobs j WHERE j.cluster_id=$9 AND j.job_id=$10`, runID, idempotencyKey, status, scheduledAt, startedAt, completedAt, coverage, createdAt, f.clusterID, target); err != nil {
		t.Fatal(err)
	}
	observationID := "observation-" + runID
	if _, err := f.pool.Exec(ctx, `INSERT INTO observations
		(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,observed_at,collected_at,source_reference,sample_fingerprint)
		SELECT $1::text,r.run_id,r.cluster_id,r.source_id,1,'TEST','test-target','up','{}'::jsonb,1,'bool',$3,$4,'integration-test',sha256($1::text::bytea)
		FROM collection_runs r WHERE r.run_id=$2`, observationID, runID, observedAt, collectedAt); err != nil {
		t.Fatal(err)
	}
}
