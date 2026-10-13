//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/remediationlive"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// TestM15LiveAuthorityRevocationBeforeEffect exercises the production
// supervisor boundary after a run is READY but before it may create collector
// work. Every mutable authority fact must fail closed without a repair request.
func TestM15LiveAuthorityRevocationBeforeEffect(t *testing.T) {
	for _, tc := range []struct {
		name             string
		expectedAttempts int
		revoke           func(t *testing.T, ctx context.Context, result m15RecoveryResult)
	}{
		{name: "policy revoked", revoke: func(t *testing.T, ctx context.Context, result m15RecoveryResult) {
			pool := m15SecurityPool(t, ctx)
			defer pool.Close()
			if _, err := pool.Exec(ctx, `UPDATE remediation_policies SET revoked_at=clock_timestamp() WHERE cluster_id=$1`, result.ClusterID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "global kill switch", revoke: func(t *testing.T, ctx context.Context, _ m15RecoveryResult) {
			pool := m15SecurityPool(t, ctx)
			defer pool.Close()
			if _, err := pool.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=false WHERE id`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "target configuration changed", expectedAttempts: 1, revoke: func(t *testing.T, ctx context.Context, result m15RecoveryResult) {
			pool := m15SecurityPool(t, ctx)
			defer pool.Close()
			if _, err := pool.Exec(ctx, `UPDATE collection_jobs SET node_filter='changed-before-effect' WHERE cluster_id=$1 AND job_id=$2`, result.ClusterID, result.JobID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "target population changed", revoke: func(t *testing.T, ctx context.Context, result m15RecoveryResult) {
			pool := m15SecurityPool(t, ctx)
			defer pool.Close()
			if _, err := pool.Exec(ctx, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,node_filter,interval_seconds,next_run_at)
				VALUES($1,$2,$3,'GPU_UTILIZATION','population-change',60,clock_timestamp()+interval '1 hour')`, "extra-"+result.JobID, result.ClusterID, result.SourceID); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := m15RunRecovery(t, m15RecoveryHooks{
				ExpectNoRequest: true,
				BeforeEffect: func(t *testing.T, ctx context.Context, _ *pgxpool.Pool, result m15RecoveryResult) {
					tc.revoke(t, ctx, result)
				},
			})
			ctx := context.Background()
			pool := m15SecurityPool(t, ctx)
			defer pool.Close()
			var state domain.RemediationState
			var attempts, requests int
			if err := pool.QueryRow(ctx, `SELECT state,total_attempts,
				(SELECT count(*) FROM collection_repair_requests WHERE cluster_id=$1 AND run_id=$2)
				FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`, result.ClusterID, result.RemediationRun).Scan(&state, &attempts, &requests); err != nil {
				t.Fatal(err)
			}
			if !state.Terminal() || attempts != tc.expectedAttempts || requests != 0 {
				t.Fatalf("revoked pre-effect authority state=%s attempts=%d requests=%d", state, attempts, requests)
			}
		})
	}
}

// TestM15CancelBeforeReservationUsesLiveService proves the authenticated
// application path, rather than a direct table mutation, cancels a READY live
// run without reserving an attempt or creating collector work.
func TestM15CancelBeforeReservationUsesLiveService(t *testing.T) {
	result := m15RunRecovery(t, m15RecoveryHooks{
		ExpectNoRequest: true,
		BeforeEffect: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult) {
			store, err := storepg.NewRemediationStore(pool)
			if err != nil {
				t.Fatal(err)
			}
			executor, err := remediationlive.New(result.Catalog, store)
			if err != nil {
				t.Fatal(err)
			}
			service, err := application.NewLiveRemediationService(store, store, result.Catalog, executor,
				m15RuntimeAuthorizer{cluster: result.ClusterID}, platform.SystemClock{}, platform.RandomIDGenerator{}, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			cancelled, err := service.CancelRemediation(ctx, result.ClusterID, domain.RemediationRunID(result.RemediationRun), "sherlock-remediator")
			if err != nil {
				t.Fatalf("cancel live remediation before reservation: %v", err)
			}
			if cancelled.State() != domain.RemediationCancelled || cancelled.Progress().TotalAttempts != 0 {
				t.Fatalf("cancelled state=%s attempts=%d", cancelled.State(), cancelled.Progress().TotalAttempts)
			}
		},
	})
	ctx := context.Background()
	pool := m15SecurityPool(t, ctx)
	defer pool.Close()
	var state domain.RemediationState
	var attempts, requests int
	if err := pool.QueryRow(ctx, `SELECT state,total_attempts,
		(SELECT count(*) FROM collection_repair_requests WHERE cluster_id=$1 AND run_id=$2)
		FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`, result.ClusterID, result.RemediationRun).Scan(&state, &attempts, &requests); err != nil {
		t.Fatal(err)
	}
	if state != domain.RemediationCancelled || attempts != 0 || requests != 0 {
		t.Fatalf("pre-reservation cancellation state=%s attempts=%d requests=%d", state, attempts, requests)
	}
}

func m15SecurityPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, os.Getenv("SHERLOCK_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

// TestM15CommittedRequestRecoveryDoesNotRepeatEffect constructs the durable
// state left by a crash after RequestCollection committed and before receipt
// ingestion. Recovery must acknowledge that exact request without inserting a
// second collector work item, and it must advance only to independent
// verification.
func TestM15CommittedRequestRecoveryDoesNotRepeatEffect(t *testing.T) {
	fixture := newRemediationFixture(t)
	ctx := context.Background()
	catalog := m15LiveCatalog(t, time.Now().UTC())
	forward, found := catalog.Lookup(remediation.RecipeEvidenceCollectionRequeue, remediation.CollectionRequestRecipeVersion)
	if !found {
		t.Fatal("live forward recipe is missing")
	}
	rollback, found := catalog.Lookup(remediation.RecipeEvidenceCollectionRestore, remediation.CollectionRequestRecipeVersion)
	if !found {
		t.Fatal("live rollback recipe is missing")
	}

	plan := fixture.plan(t, domain.RemediationRunID("live-recovery-"+fixture.suffix), fixture.targets[:1])
	plan.Recipe, plan.Rollback = forward.Ref(), rollback.Ref()
	plan.Tier, plan.Privilege, plan.Assurance = forward.Tier, forward.Privilege, domain.AssuranceLive
	plan.MaxTargets, plan.MaxConcurrency, plan.CanaryTargets, plan.MaxAttempts = 1, 1, 1, forward.MaxAttempts
	if err := plan.Validate(); err != nil {
		t.Fatalf("live recovery plan is invalid: %v", err)
	}
	run, err := domain.NewRemediationRun(plan)
	if err != nil {
		t.Fatal(err)
	}
	created, wasCreated, err := fixture.store.CreateRemediationRun(ctx, application.CreateRemediationRunInput{
		Run:              run,
		Recipe:           application.RemediationRecipeRecord{Ref: forward.Ref(), Tier: forward.Tier, Operation: string(forward.Operation), ExpiresAt: forward.ExpiresAt},
		Rollback:         &application.RemediationRecipeRecord{Ref: rollback.Ref(), Tier: rollback.Tier, Operation: string(rollback.Operation), ExpiresAt: rollback.ExpiresAt},
		PinnedPopulation: len(fixture.targets), LedgerEntryIDs: []string{fixture.ledgerEntryID}, DeadlineAt: time.Now().UTC().Add(time.Minute),
	}, fixture.audit(application.RemediationAuditProposal, plan, "live-recovery"))
	if err != nil || !wasCreated {
		t.Fatalf("create live recovery run: created=%t run=%s err=%v", wasCreated, created.State(), err)
	}

	attemptID := domain.RemediationAttemptID("live-recovery-attempt-" + fixture.suffix)
	idempotencyKey := "live-recovery-key-" + fixture.suffix
	requestID := "repair-" + string(attemptID) + "-" + string(fixture.targets[0])
	workID := "repair-work-" + string(attemptID) + "-" + string(fixture.targets[0])
	waveDigest := domain.RemediationWaveTargetDigest(fixture.targets[:1])
	tokenHash := sha256.Sum256([]byte("discarded-after-crash"))
	var sourceID, queryKind string
	if err = fixture.pool.QueryRow(ctx, `SELECT source_id,query_kind FROM collection_jobs WHERE cluster_id=$1 AND job_id=$2`, fixture.clusterID, fixture.targets[0]).Scan(&sourceID, &queryKind); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	commands := []struct {
		query string
		args  []any
	}{
		{`UPDATE remediation_runs SET state='CANARY_EXECUTING',version=2,total_attempts=1,lease_owner='lost-process',lease_expires_at=clock_timestamp()+interval '1 minute',deadline_at=clock_timestamp()+interval '1 minute' WHERE cluster_id=$1 AND run_id=$2`, []any{fixture.clusterID, plan.RunID}},
		{`INSERT INTO remediation_attempts(cluster_id,attempt_id,run_id,stage,attempt_number,idempotency_key,wave_target_digest,lease_owner,lease_token_hash,lease_expires_at,lease_deadline_at,policy_id,policy_version,policy_code) VALUES($1,$2,$3,'CANARY',1,$4,$5,'lost-process',$6,clock_timestamp()+interval '1 minute',clock_timestamp()+interval '5 minutes','policy-live-recovery',1,'ALLOWED')`, []any{fixture.clusterID, attemptID, plan.RunID, idempotencyKey, waveDigest[:], tokenHash[:]}},
		{`INSERT INTO remediation_attempt_targets(cluster_id,attempt_id,run_id,target,ordinal) VALUES($1,$2,$3,$4,0)`, []any{fixture.clusterID, attemptID, plan.RunID, fixture.targets[0]}},
		{`INSERT INTO remediation_schedule_snapshots(cluster_id,run_id,target,prior_active,prior_interval,prior_next,prior_revision,prior_configuration_revision) SELECT cluster_id,$2,job_id,active,interval_seconds,next_run_at,schedule_revision,configuration_revision FROM collection_jobs WHERE cluster_id=$1 AND job_id=$3`, []any{fixture.clusterID, plan.RunID, fixture.targets[0]}},
		{`INSERT INTO collection_run_jobs(run_id,job_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,configuration_revision,lease_generation) SELECT $1,job_id,cluster_id,source_id,query_kind,node_filter,$2,configuration_revision,1 FROM collection_jobs WHERE cluster_id=$3 AND job_id=$4`, []any{requestID, now, fixture.clusterID, fixture.targets[0]}},
		{`INSERT INTO collector_work_items(work_id,run_id,cluster_id,source_id,query_kind,node_filter,scheduled_for,deadline,max_series,max_bytes,idempotency_key,available_at,work_expires_at) VALUES($1,$2,$3,$4,$5,'',$6,(SELECT deadline_at FROM remediation_runs WHERE cluster_id=$3 AND run_id=$7),10000,10485760,$8,$6,(SELECT deadline_at FROM remediation_runs WHERE cluster_id=$3 AND run_id=$7))`, []any{workID, requestID, fixture.clusterID, sourceID, queryKind, now, plan.RunID, idempotencyKey}},
		{`INSERT INTO collection_repair_requests(request_id,cluster_id,run_id,attempt_id,job_id,operation,configuration_revision,schedule_revision,idempotency_key,status,deadline_at,effect_receipt,work_id) SELECT $1,$2,$3,$4,j.job_id,$5,j.configuration_revision,j.schedule_revision,$6,'REQUESTED',rr.deadline_at,$1,$7 FROM collection_jobs j JOIN remediation_runs rr ON rr.cluster_id=j.cluster_id AND rr.run_id=$3 WHERE j.cluster_id=$2 AND j.job_id=$8`, []any{requestID, fixture.clusterID, plan.RunID, attemptID, string(remediation.OperationEvidenceCollectionRequeue), idempotencyKey, workID, fixture.targets[0]}},
		{`UPDATE remediation_schedule_snapshots SET live_request_id=$4 WHERE cluster_id=$1 AND run_id=$2 AND target=$3`, []any{fixture.clusterID, plan.RunID, fixture.targets[0], requestID}},
	}
	for _, command := range commands {
		if _, err = fixture.pool.Exec(ctx, command.query, command.args...); err != nil {
			t.Fatalf("seed committed request crash state: %v", err)
		}
	}

	claim, err := fixture.store.ClaimRemediation(ctx, fixture.clusterID, "recovery-supervisor", time.Minute)
	if err != nil || claim.RunID != plan.RunID {
		t.Fatalf("claim recovery run: claim=%+v err=%v", claim, err)
	}
	claimCtx := storepg.ContextWithRemediationSupervisorClaim(ctx, claim)
	recovered, ok, err := fixture.store.RecoverCommittedLiveEffect(claimCtx, fixture.clusterID, plan.RunID, attemptID)
	if err != nil || !ok || recovered.State() != domain.RemediationVerifying {
		t.Fatalf("recover committed request: ok=%t state=%s err=%v", ok, recovered.State(), err)
	}
	var requests, work, receipts int
	if err = fixture.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM collection_repair_requests WHERE cluster_id=$1 AND run_id=$2),
		(SELECT count(*) FROM collector_work_items WHERE work_id=$3),
		(SELECT count(*) FROM remediation_receipts WHERE cluster_id=$1 AND attempt_id=$4)`,
		fixture.clusterID, plan.RunID, workID, attemptID).Scan(&requests, &work, &receipts); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || work != 1 || receipts != 1 {
		t.Fatalf("recovery duplicated or omitted durable state: requests=%d work=%d receipts=%d", requests, work, receipts)
	}

	// The candidate query must skip temporarily unauthorized repair work rather
	// than selecting it and letting the trigger abort the whole claim. Once the
	// exact source-health fact becomes current, the same item is claimable.
	collectorID := domain.CollectorID("live-recovery-collector-" + fixture.suffix)
	if _, err = fixture.pool.Exec(ctx, `INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture,identity_not_after,last_heartbeat_at)
		VALUES($1,$2,'recovery collector','ACTIVE','1','test',1,1,'linux','amd64',clock_timestamp()+interval '1 hour',clock_timestamp())`, collectorID, fixture.clusterID); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.pool.Exec(ctx, `INSERT INTO collector_capabilities(collector_id,capability,version) VALUES($1,$2,'1')`, collectorID, queryKind); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.pool.Exec(ctx, `INSERT INTO collector_source_health(collector_id,source_id,availability,checked_at) VALUES($1,$2,'UNAVAILABLE',clock_timestamp())`, collectorID, sourceID); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.pool.Exec(ctx, `INSERT INTO remediation_policies(cluster_id,policy_id,version,recipe_id,recipe_version,enabled,max_tier,incident_kinds,max_targets,max_concurrent_runs,cooldown_seconds,evidence_max_age_seconds,min_evidence_coverage,not_before,not_after)
		VALUES($1,'policy-live-recovery',1,$2,$3,true,1,ARRAY[$4],1,1,0,900,100,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')`, fixture.clusterID, plan.Recipe.ID, plan.Recipe.Version, remediation.IncidentKindEvidenceStreamStale); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.pool.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=true WHERE id`); err != nil {
		t.Fatal(err)
	}
	control, err := storepg.NewCollectorControlStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err = control.ClaimWork(ctx, collectorID, "unhealthy-token", time.Minute); err != nil || found {
		t.Fatalf("unhealthy repair candidate must be skipped: found=%t err=%v", found, err)
	}
	if _, err = fixture.pool.Exec(ctx, `UPDATE collector_source_health SET availability='AVAILABLE',checked_at=clock_timestamp() WHERE collector_id=$1 AND source_id=$2`, collectorID, sourceID); err != nil {
		t.Fatal(err)
	}
	lease, found, err := control.ClaimWork(ctx, collectorID, "current-token", time.Minute)
	if err != nil || !found || string(lease.Work.WorkID) != workID {
		t.Fatalf("authorized repair candidate was not claimed: found=%t work=%s err=%v", found, lease.Work.WorkID, err)
	}
	if err = fixture.store.RequestRemediationCancellation(ctx, fixture.clusterID, plan.RunID, "operator"); err != nil {
		t.Fatal(err)
	}
	if err = control.RenewWorkLease(ctx, collectorID, lease.Work.WorkID, lease.Attempt, lease.LeaseToken, time.Minute); err == nil {
		t.Fatal("repair work lease renewed after durable cancellation")
	}
	if err = control.AcknowledgeWorkStart(ctx, collectorID, lease.Work.WorkID, lease.Attempt, lease.LeaseToken); err == nil {
		t.Fatal("repair work started after durable cancellation")
	}
	if _, ok, err = fixture.store.RecoverCommittedLiveEffect(claimCtx, fixture.clusterID, plan.RunID, attemptID); err != nil || ok {
		t.Fatalf("second recovery must be a no-op: ok=%t err=%v", ok, err)
	}
}
