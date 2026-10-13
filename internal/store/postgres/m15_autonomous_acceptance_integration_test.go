//go:build integration

package postgres_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	prometheusexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/remediationlive"
	"github.com/verticalcomputer/sherlock/internal/remediationruntime"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// TestM15AutonomousSupervisorWorkerCollectorRecovery is the principal isolated
// acceptance path. It seeds only policy, inventory, and one controlled future
// schedule fault. Both the prior stale samples and recovery samples travel over
// the production remote collector protocol to a loopback Prometheus response.
func TestM15AutonomousSupervisorWorkerCollectorRecovery(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{})
}

// TestM15AutonomousRecoveryToleratesLostWorkerCompletionReply proves that a
// worker restart which retries completion after the collector has already
// terminalized its bound work cannot create a second collection occurrence.
func TestM15AutonomousRecoveryToleratesLostWorkerCompletionReply(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{AfterVerification: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult) {
		store, err := storepg.NewRemediationStore(pool)
		if err != nil {
			t.Fatal(err)
		}
		err = store.FinishRepairCollection(ctx, application.RepairCollectionClaim{
			RequestID: result.RepairRequestID,
			Task:      domain.CollectionTask{RunID: domain.RunID(result.RepairRequestID), ClusterID: result.ClusterID},
		}, "m15-lost-reply-worker")
		if err != nil {
			t.Fatalf("lost completion reply was not idempotent: %v", err)
		}
		var runs, workItems int
		if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM collection_runs WHERE run_id=$1),(SELECT count(*) FROM collector_work_items WHERE work_id=$2)`, result.RepairRequestID, result.CollectorWorkID).Scan(&runs, &workItems); err != nil {
			t.Fatal(err)
		}
		if runs != 1 || workItems != 1 {
			t.Fatalf("lost completion reply changed durable occurrence counts runs=%d work_items=%d", runs, workItems)
		}
	}})
}

// TestM15LiveVerificationRejectsInvalidEvidence starts from a real completed
// repair, then proves the live verifier fails closed when a fixture changes a
// causal or completeness fact. Each mutation is restored before the next
// assertion; the principal path is never used as a fabricated result fixture.
func TestM15LiveVerificationRejectsInvalidEvidence(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{AfterVerification: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult) {
		store, err := storepg.NewRemediationStore(pool)
		if err != nil {
			t.Fatal(err)
		}
		query := application.RemediationObservationQuery{
			ClusterID: result.ClusterID, RunID: domain.RemediationRunID(result.RemediationRun), AttemptID: domain.RemediationAttemptID(result.AttemptID),
			Targets: []domain.RemediationTarget{domain.RemediationTarget(result.JobID)}, Conditions: []string{"stream-fresh"}, Window: 15 * time.Minute,
		}
		assert := func(name string) {
			t.Helper()
			observations, readErr := store.ReadRemediationObservations(ctx, query)
			if readErr != nil {
				t.Fatalf("%s: read live verification: %v", name, readErr)
			}
			if len(observations) != 1 || observations[0].Result != domain.ConditionUnobserved {
				t.Fatalf("%s: verification=%+v, want one unobserved result", name, observations)
			}
		}

		var baseline []domain.ConditionObservation
		baseline, err = store.ReadRemediationObservations(ctx, query)
		if err != nil || len(baseline) != 1 || baseline[0].Result != domain.ConditionSatisfied || baseline[0].EvidenceID != result.EvidenceID {
			t.Fatalf("baseline exact live verification=%+v err=%v", baseline, err)
		}
		for _, tc := range []struct {
			name   string
			mutate func(*application.RemediationObservationQuery)
		}{
			{name: "wrong_cluster", mutate: func(q *application.RemediationObservationQuery) { q.ClusterID = "wrong-" + q.ClusterID }},
			{name: "wrong_attempt", mutate: func(q *application.RemediationObservationQuery) { q.AttemptID = "wrong-attempt" }},
			{name: "wrong_target", mutate: func(q *application.RemediationObservationQuery) {
				q.Targets = []domain.RemediationTarget{"wrong-target"}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				candidate := query
				tc.mutate(&candidate)
				observations, readErr := store.ReadRemediationObservations(ctx, candidate)
				if readErr != nil || len(observations) != 1 || observations[0].Result != domain.ConditionUnobserved {
					t.Fatalf("%s: verification=%+v err=%v, want unobserved", tc.name, observations, readErr)
				}
			})
		}

		t.Run("stale_after_effect_outside_window", func(t *testing.T) {
			candidate := query
			candidate.Window = time.Nanosecond
			observations, readErr := store.ReadRemediationObservations(ctx, candidate)
			if readErr != nil || len(observations) != 1 || observations[0].Result != domain.ConditionUnobserved {
				t.Fatalf("stale within effect but outside window accepted: %+v %v", observations, readErr)
			}
		})

		t.Run("old_sample_before_work", func(t *testing.T) {
			var observed time.Time
			if err := pool.QueryRow(ctx, `SELECT observed_at FROM observations WHERE run_id=$1 LIMIT 1`, result.RepairRequestID).Scan(&observed); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE observations SET observed_at=(SELECT scheduled_for-interval '96 microseconds' FROM collector_work_items WHERE work_id=$2) WHERE run_id=$1`, result.RepairRequestID, result.CollectorWorkID); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = pool.Exec(context.Background(), `UPDATE observations SET observed_at=$2 WHERE run_id=$1`, result.RepairRequestID, observed)
			}()
			assert("old_sample_before_work")
		})

		t.Run("future_sample", func(t *testing.T) {
			var observed time.Time
			if err := pool.QueryRow(ctx, `SELECT observed_at FROM observations WHERE run_id=$1 LIMIT 1`, result.RepairRequestID).Scan(&observed); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE observations SET observed_at=clock_timestamp()+interval '1 hour' WHERE run_id=$1`, result.RepairRequestID); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = pool.Exec(context.Background(), `UPDATE observations SET observed_at=$2 WHERE run_id=$1`, result.RepairRequestID, observed)
			}()
			assert("future_sample")
		})

		t.Run("future_result_ingestion", func(t *testing.T) {
			var finalized time.Time
			if err := pool.QueryRow(ctx, `SELECT finalized_at FROM collector_result_ingestions WHERE work_id=$1`, result.CollectorWorkID).Scan(&finalized); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE collector_result_ingestions SET finalized_at=clock_timestamp()+interval '1 hour' WHERE work_id=$1`, result.CollectorWorkID); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = pool.Exec(context.Background(), `UPDATE collector_result_ingestions SET finalized_at=$2 WHERE work_id=$1`, result.CollectorWorkID, finalized)
			}()
			assert("future_result_ingestion")
		})

		t.Run("failed_collection", func(t *testing.T) {
			if _, err := pool.Exec(ctx, `UPDATE collection_runs SET status='FAILED' WHERE run_id=$1`, result.RepairRequestID); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = pool.Exec(context.Background(), `UPDATE collection_runs SET status='SUCCEEDED' WHERE run_id=$1`, result.RepairRequestID)
			}()
			assert("failed_collection")
		})

		t.Run("incomplete_coverage", func(t *testing.T) {
			if _, err := pool.Exec(ctx, `UPDATE collection_runs SET coverage_complete=false WHERE run_id=$1`, result.RepairRequestID); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = pool.Exec(context.Background(), `UPDATE collection_runs SET coverage_complete=true WHERE run_id=$1`, result.RepairRequestID)
			}()
			assert("incomplete_coverage")
		})

		t.Run("partial_evidence_envelope", func(t *testing.T) {
			if _, err := pool.Exec(ctx, `UPDATE evidence_envelopes SET status='PARTIAL' WHERE evidence_id=$1`, result.EvidenceID); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = pool.Exec(context.Background(), `UPDATE evidence_envelopes SET status='COMPLETE' WHERE evidence_id=$1`, result.EvidenceID)
			}()
			assert("partial_evidence_envelope")
		})
	}})
}

// m15RecoveryHooks expose the two durable boundaries around the real repair
// delivery. Hooks are test-only and run in the same isolated database/session
// as the principal path: after the signed request exists, and after its repair
// worker has claimed it but before the collector runtime receives delivery.
type m15RecoveryHooks struct {
	// SupervisorPool is invoked after the privileged fixture has created its
	// scoped cluster/job but before detection. It lets security acceptance run
	// the detector, controller, and repair-request worker under a separate
	// restricted identity while the collector fixture retains its normal pool.
	SupervisorPool              func(t *testing.T, ctx context.Context, fixture *pgxpool.Pool, result m15RecoveryResult) (*pgxpool.Pool, error)
	BeforePreflight             func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult)
	BeforeEffect                func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult)
	AfterRequest                func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult)
	BeforeCollectorDelivery     func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult)
	AfterVerification           func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult)
	AfterRepairSourceStart      func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult)
	BeforeVerification          func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result m15RecoveryResult)
	StopAfterRequest            bool
	StopBeforeCollectorDelivery bool
	ExpectContained             bool
	ExpectNoRequest             bool
	ExpectedTerminal            domain.RemediationState
}

type m15RecoveryResult struct {
	ClusterID              domain.ClusterID
	SourceID               domain.SourceID
	CollectorID            domain.CollectorID
	JobID                  string
	IncidentID             string
	InvestigationID        string
	ActionCardID           string
	RemediationRun         string
	AttemptID              string
	RepairRequestID        string
	CollectorWorkID        string
	EvidenceID             string
	EffectCommittedAt      time.Time
	VerificationObservedAt time.Time
	RepairSampleCount      int
	Catalog                *remediation.Catalog
}

// m15RunRecovery is the package-local autonomous fixture used by the
// principal acceptance test and M15 lifecycle/performance tests. Its default
// path has no hooks and reaches verified SUCCEEDED through actual worker and
// collector delivery.
func m15RunRecovery(t *testing.T, hooks m15RecoveryHooks) m15RecoveryResult {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use a fresh migrated M15 database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	suffix := fmt.Sprintf("m15-e2e-%d", time.Now().UnixNano())
	cluster := domain.ClusterID("cluster-" + suffix)
	source := domain.SourceID("source-" + suffix)
	collectorID := domain.CollectorID("collector-" + suffix)
	jobID := "m1/" + suffix + "/dcgm_gpu_utilization"
	result := m15RecoveryResult{ClusterID: cluster, SourceID: source, CollectorID: collectorID, JobID: jobID}
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	control, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err = collections.EnsureSource(ctx, cluster, "M15 isolated cluster", source, "M15 loopback source"); err != nil {
		t.Fatal(err)
	}

	var repairSourceHook func()
	var repairSourceHookOnce sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Match Prometheus evaluation time, not wall-clock delivery time. Using
		// delivery time masked the live pilot's sub-millisecond causal mismatch.
		observed, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("time"))
		if err != nil {
			t.Errorf("invalid evaluation time: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		observed = observed.Truncate(time.Millisecond)
		query := r.URL.Query().Get("query")
		if strings.Contains(query, "count by") {
			_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"Hostname":"node-m15","UUID":"GPU-m15","gpu":"0"},"value":[%d.%03d,"1"]}]}}`, observed.Unix(), observed.Nanosecond()/int(time.Millisecond))
			return
		}
		if repairSourceHook != nil {
			repairSourceHookOnce.Do(repairSourceHook)
		}
		_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"node-m15","UUID":"GPU-m15","gpu":"0"},"value":[%d.%03d,"42"]}]}}`, observed.Unix(), observed.Nanosecond()/int(time.Millisecond))
	}))
	defer upstream.Close()

	collector, startCollector, stopCollector, closeCollector := m15CollectorRuntime(t, ctx, collections, control, cluster, source, collectorID, upstream.URL, suffix)
	defer closeCollector()
	startCollector()

	// Establish an inventory and a complete successful scheduled collection via
	// the same remote executor/collector/source path used for the repair.
	now := time.Now().UTC()
	identityTask := domain.CollectionTask{RunID: domain.RunID("identity-" + suffix), ClusterID: cluster, SourceID: source, Query: domain.QueryGPUIdentity, ScheduledFor: now.Add(-4 * time.Second), Deadline: now.Add(20 * time.Second), MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "identity/" + suffix}
	if outcome, collectErr := collector.Collect(ctx, identityTask); collectErr != nil || outcome.Result.Status != domain.ResultSucceeded {
		t.Fatalf("initial identity collection result=%+v err=%v", outcome.Result, collectErr)
	}
	if err = collections.EnsureJob(ctx, jobID, cluster, source, domain.QueryGPUUtilization, "", time.Second, now.Add(-4*time.Second)); err != nil {
		t.Fatal(err)
	}
	claimed, found, err := collections.ClaimDueSourceJob(ctx, "m15-normal-worker", 10*time.Second, source)
	if err != nil || !found || claimed.JobID != jobID {
		t.Fatalf("claim normal job found=%t job=%+v err=%v", found, claimed, err)
	}
	bound, err := collections.BindCollectionJob(ctx, claimed, "m15-normal-worker", domain.RunID("baseline-"+suffix))
	if err != nil {
		t.Fatal(err)
	}
	baselineTask := domain.CollectionTask{RunID: bound, ClusterID: cluster, SourceID: source, Query: claimed.Query, Node: claimed.Node, ScheduledFor: claimed.ScheduledFor, Deadline: time.Now().UTC().Add(20 * time.Second), MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: fmt.Sprintf("%s/%s/config/%d", jobID, claimed.ScheduledFor.Format(time.RFC3339Nano), claimed.ConfigurationRevision)}
	if outcome, collectErr := collector.Collect(ctx, baselineTask); collectErr != nil || outcome.Result.Status != domain.ResultSucceeded || !outcome.Result.Coverage.Complete {
		t.Fatalf("initial scheduled collection result=%+v err=%v", outcome.Result, collectErr)
	}
	if err = collections.CompleteJob(ctx, claimed, "m15-normal-worker"); err != nil {
		t.Fatal(err)
	}
	if err = m15Eventually(ctx, 4*time.Second, 20*time.Millisecond, func() (bool, error) {
		var available bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collector_source_health WHERE collector_id=$1 AND source_id=$2 AND availability='AVAILABLE')`, collectorID, source).Scan(&available)
		return available, err
	}); err != nil {
		t.Fatalf("collector did not heartbeat source availability: %v", err)
	}
	stopCollector()

	// Let the authentic prior sample become stale, then inject only the
	// controlled scheduling defect. No observation or repair result is inserted.
	time.Sleep(3200 * time.Millisecond)
	if _, err = pool.Exec(ctx, `UPDATE collection_jobs SET next_run_at=clock_timestamp()+interval '1 hour' WHERE cluster_id=$1 AND job_id=$2`, cluster, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=true WHERE id`); err != nil {
		t.Fatal(err)
	}
	catalog := m15LiveCatalog(t, time.Now().UTC())
	result.Catalog = catalog
	recipe, ok := catalog.Lookup(remediation.RecipeEvidenceCollectionRequeue, remediation.CollectionRequestRecipeVersion)
	if !ok {
		t.Fatal("verified live requeue recipe is missing")
	}
	if _, err = pool.Exec(ctx, `INSERT INTO remediation_policies(cluster_id,policy_id,version,recipe_id,recipe_version,enabled,max_tier,incident_kinds,max_targets,max_concurrent_runs,cooldown_seconds,evidence_max_age_seconds,min_evidence_coverage,not_before,not_after)
		VALUES($1,$2,1,$3,$4,true,1,ARRAY[$5],1,1,0,900,100,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')`, cluster, "policy-"+suffix, recipe.ID, recipe.Version, remediation.IncidentKindEvidenceStreamStale); err != nil {
		t.Fatal(err)
	}
	supervisorPool := pool
	if hooks.SupervisorPool != nil {
		supervisorPool, err = hooks.SupervisorPool(t, ctx, pool, result)
		if err != nil {
			t.Fatal(err)
		}
		if supervisorPool == nil {
			t.Fatal("restricted supervisor pool is nil")
		}
		defer supervisorPool.Close()
	}
	runtime, err := remediationruntime.New(supervisorPool, catalog, remediationruntime.Config{Enabled: true, Live: true, ClusterID: cluster, Owner: "m15-supervisor", PollInterval: 10 * time.Millisecond, Lease: 10 * time.Second, Batch: 1}, slog.New(slog.NewTextHandler(testLogWriter{t}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if hooks.BeforePreflight != nil {
		hooks.BeforePreflight(t, ctx, pool, result)
	}
	var requestID, repairRunID string
	var repairRequestedAt time.Time
	beforeEffectCalled := false
	if err = m15Eventually(ctx, 12*time.Second, 25*time.Millisecond, func() (bool, error) {
		if _, runErr := runtime.RunOnce(ctx); runErr != nil {
			return false, runErr
		}
		if err := m15AssertGeneralWorkerExcludesSchedule(ctx, pool, cluster); err != nil {
			return false, err
		}
		if hooks.BeforeEffect != nil && !beforeEffectCalled {
			var state domain.RemediationState
			var candidateRunID string
			err = pool.QueryRow(ctx, `SELECT rr.run_id,rr.state FROM schedule_repair_detections d JOIN remediation_runs rr ON rr.cluster_id=d.cluster_id AND rr.incident_id=d.incident_id AND rr.investigation_id=d.investigation_id WHERE d.cluster_id=$1 AND d.job_id=$2 ORDER BY rr.created_at DESC LIMIT 1`, cluster, jobID).Scan(&candidateRunID, &state)
			if err == nil && state == domain.RemediationReady {
				result.RemediationRun = candidateRunID
				hooks.BeforeEffect(t, ctx, pool, result)
				beforeEffectCalled = true
			} else if err != nil && !strings.Contains(err.Error(), "no rows") {
				return false, err
			}
		}
		if hooks.ExpectNoRequest {
			var state domain.RemediationState
			var candidateRunID string
			err = pool.QueryRow(ctx, `SELECT rr.run_id,rr.state FROM schedule_repair_detections d JOIN remediation_runs rr ON rr.cluster_id=d.cluster_id AND rr.incident_id=d.incident_id AND rr.investigation_id=d.investigation_id WHERE d.cluster_id=$1 AND d.job_id=$2 ORDER BY rr.created_at DESC LIMIT 1`, cluster, jobID).Scan(&candidateRunID, &state)
			if err != nil && !strings.Contains(err.Error(), "no rows") {
				return false, err
			}
			if err == nil && state.Terminal() {
				result.RemediationRun = candidateRunID
				var requests int
				err = pool.QueryRow(ctx, `SELECT count(*) FROM collection_repair_requests WHERE cluster_id=$1 AND run_id=$2`, cluster, candidateRunID).Scan(&requests)
				return err == nil && requests == 0, err
			}
			return false, nil
		}
		err := pool.QueryRow(ctx, `SELECT request_id,run_id,created_at FROM collection_repair_requests WHERE cluster_id=$1 AND job_id=$2`, cluster, jobID).Scan(&requestID, &repairRunID, &repairRequestedAt)
		if err != nil && strings.Contains(err.Error(), "no rows") {
			return false, nil
		}
		return err == nil, err
	}); err != nil {
		t.Fatalf("supervisor did not automatically create the signed repair request: %v; direct live proposal diagnostic: %v", err, m15LiveProposalDiagnostic(ctx, pool, catalog, cluster))
	}
	if hooks.ExpectNoRequest {
		return result
	}
	result.RemediationRun, result.RepairRequestID = repairRunID, requestID
	result.EffectCommittedAt = repairRequestedAt
	if hooks.AfterRequest != nil {
		hooks.AfterRequest(t, ctx, pool, result)
	}
	if hooks.StopAfterRequest {
		return result
	}
	if hooks.AfterRepairSourceStart != nil {
		repairSourceHook = func() { hooks.AfterRepairSourceStart(t, ctx, pool, result) }
	}

	// The repair worker receives the immutable pre-bound task and invokes the
	// normal remote collector protocol. The controlled source remains healthy;
	// the repairable fault is solely the deferred permanent schedule.
	remediationStore, err := storepg.NewRemediationStore(supervisorPool)
	if err != nil {
		t.Fatal(err)
	}
	repairWorker, err := application.NewRepairCollectionWorker(remediationStore, collector, cluster, source, "m15-repair-worker", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	workerDone := make(chan struct {
		progressed bool
		err        error
	}, 1)
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerFinished := false
	defer func() {
		stopWorker()
		if !workerFinished {
			<-workerDone
		}
	}()
	go func() {
		progressed, runErr := repairWorker.RunOnce(workerCtx)
		workerDone <- struct {
			progressed bool
			err        error
		}{progressed, runErr}
	}()
	if err = m15Eventually(ctx, 2*time.Second, 10*time.Millisecond, func() (bool, error) {
		var status string
		err := pool.QueryRow(ctx, `SELECT status FROM collection_repair_requests WHERE request_id=$1`, requestID).Scan(&status)
		return err == nil && status == "CLAIMED", err
	}); err != nil {
		t.Fatalf("repair worker did not claim the request before collector delivery: %v", err)
	}
	repairClaimedAt := time.Now().UTC()
	if hooks.BeforeCollectorDelivery != nil {
		hooks.BeforeCollectorDelivery(t, ctx, pool, result)
	}
	if hooks.StopBeforeCollectorDelivery {
		return result
	}
	collectorDeliveryStartedAt := time.Now().UTC()
	startCollector()
	var collectorDeliveryCompletedAt time.Time
	select {
	case outcome := <-workerDone:
		workerFinished = true
		collectorDeliveryCompletedAt = time.Now().UTC()
		if outcome.err != nil || !outcome.progressed {
			t.Fatalf("repair worker progressed=%t err=%v", outcome.progressed, outcome.err)
		}
	case <-ctx.Done():
		t.Fatalf("repair worker timed out: %v", ctx.Err())
	}
	stopCollector()
	var repairSamples int
	if err = m15Eventually(ctx, 5*time.Second, 20*time.Millisecond, func() (bool, error) {
		var runs int
		err := pool.QueryRow(ctx, `SELECT count(*), (SELECT count(*) FROM observations WHERE run_id=$1) FROM collection_runs WHERE run_id=$1`, requestID).Scan(&runs, &repairSamples)
		return err == nil && runs == 1 && repairSamples > 0, err
	}); err != nil {
		t.Fatalf("repair collection samples were not persisted: %v", err)
	}
	if hooks.BeforeVerification != nil {
		hooks.BeforeVerification(t, ctx, pool, result)
	}

	if hooks.ExpectContained {
		if err = m15Eventually(ctx, 3*time.Second, 25*time.Millisecond, func() (bool, error) {
			var status string
			err := pool.QueryRow(ctx, `SELECT status FROM collection_repair_requests WHERE request_id=$1`, requestID).Scan(&status)
			return err == nil && status == "CONTAINED", err
		}); err != nil {
			t.Fatalf("delivered cancelled repair was not CONTAINED: %v", err)
		}
		var requestStatus, workStatus string
		var evidence, samples int
		if err := pool.QueryRow(ctx, `SELECT r.status,w.status,(SELECT count(*) FROM observations WHERE run_id=r.request_id),(SELECT count(*) FROM evidence_envelopes WHERE run_id=r.request_id AND status='COMPLETE') FROM collection_repair_requests r JOIN collector_work_items w ON w.work_id=r.work_id WHERE r.request_id=$1`, requestID).Scan(&requestStatus, &workStatus, &samples, &evidence); err != nil {
			t.Fatal(err)
		}
		if requestStatus != "CONTAINED" || workStatus != string(domain.WorkSucceeded) || samples < 1 || evidence < 1 {
			t.Fatalf("contained repair did not preserve delivered evidence request=%s work=%s samples=%d evidence=%d", requestStatus, workStatus, samples, evidence)
		}
		return result
	}
	expectedTerminal := domain.RemediationSucceeded
	if hooks.ExpectedTerminal != "" {
		expectedTerminal = hooks.ExpectedTerminal
	}
	if err = m15Eventually(ctx, 8*time.Second, 25*time.Millisecond, func() (bool, error) {
		if _, runErr := runtime.RunOnce(ctx); runErr != nil {
			return false, runErr
		}
		var state domain.RemediationState
		err := pool.QueryRow(ctx, `SELECT state FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`, cluster, repairRunID).Scan(&state)
		return err == nil && state == expectedTerminal, err
	}); err != nil {
		t.Fatalf("independent remediation terminal state=%s did not arrive: %v", expectedTerminal, err)
	}
	if expectedTerminal != domain.RemediationSucceeded {
		return result
	}

	var incidentID, investigationID, actionCardID, attemptID, workID, requestStatus, workStatus, verificationSource, verificationEvidence string
	var verificationObservedAt time.Time
	err = pool.QueryRow(ctx, `SELECT d.incident_id,d.investigation_id,c.action_card_id,a.attempt_id,r.work_id,r.status,w.status,v.source,v.evidence_id,v.observed_at
		FROM schedule_repair_detections d
		JOIN investigation_action_cards c ON c.cluster_id=d.cluster_id AND c.investigation_id=d.investigation_id
		JOIN remediation_runs rr ON rr.cluster_id=d.cluster_id AND rr.incident_id=d.incident_id AND rr.investigation_id=d.investigation_id
		JOIN remediation_attempts a ON a.cluster_id=rr.cluster_id AND a.run_id=rr.run_id
		JOIN collection_repair_requests r ON r.cluster_id=rr.cluster_id AND r.run_id=rr.run_id AND r.attempt_id=a.attempt_id
		JOIN collector_work_items w ON w.work_id=r.work_id
		JOIN remediation_verification_evidence v ON v.cluster_id=rr.cluster_id AND v.run_id=rr.run_id AND v.attempt_id=a.attempt_id AND v.target=r.job_id AND v.condition_id='stream-fresh'
		JOIN evidence_envelopes e ON e.cluster_id=r.cluster_id AND e.run_id=r.request_id AND e.evidence_id=v.evidence_id AND e.status='COMPLETE' AND e.artifact_availability IN ('NONE','AVAILABLE')
		WHERE d.cluster_id=$1 AND d.job_id=$2 AND rr.run_id=$3`, cluster, jobID, repairRunID).Scan(&incidentID, &investigationID, &actionCardID, &attemptID, &workID, &requestStatus, &workStatus, &verificationSource, &verificationEvidence, &verificationObservedAt)
	if err != nil {
		t.Fatalf("load durable autonomous chain: %v", err)
	}
	if incidentID == "" || investigationID == "" || actionCardID == "" || attemptID == "" || requestID == "" || workID == "" || requestStatus != "COMPLETED" || workStatus != string(domain.WorkSucceeded) || verificationSource != "COLLECTION_REPAIR_REQUESTS" || verificationEvidence == "" {
		t.Fatalf("invalid durable chain incident=%s investigation=%s card=%s attempt=%s request=%s work=%s request_status=%s work_status=%s verification=%s/%s", incidentID, investigationID, actionCardID, attemptID, requestID, workID, requestStatus, workStatus, verificationSource, verificationEvidence)
	}
	result.IncidentID, result.InvestigationID, result.ActionCardID = incidentID, investigationID, actionCardID
	result.AttemptID, result.CollectorWorkID, result.EvidenceID = attemptID, workID, verificationEvidence
	result.VerificationObservedAt, result.RepairSampleCount = verificationObservedAt, repairSamples
	t.Logf("M15 autonomous chain incident=%s investigation=%s action_card=%s remediation_run=%s attempt=%s repair_request=%s collector_work=%s collection_run=%s verification_evidence=%s", incidentID, investigationID, actionCardID, repairRunID, attemptID, requestID, workID, requestID, verificationEvidence)
	t.Logf("M15 recovery timing request_to_claim_ms=%.3f collector_delivery_ms=%.3f request_to_recovery_ms=%.3f repair_samples=%d repair_requests=1 collector_work_items=1", float64(repairClaimedAt.Sub(repairRequestedAt).Microseconds())/1000, float64(collectorDeliveryCompletedAt.Sub(collectorDeliveryStartedAt).Microseconds())/1000, float64(collectorDeliveryCompletedAt.Sub(repairRequestedAt).Microseconds())/1000, repairSamples)
	if hooks.AfterVerification != nil {
		hooks.AfterVerification(t, ctx, pool, result)
	}
	return result
}

func m15CollectorRuntime(t *testing.T, parent context.Context, collections *storepg.CollectionStore, control *storepg.CollectorControlStore, cluster domain.ClusterID, source domain.SourceID, collectorID domain.CollectorID, upstreamURL, suffix string) (*application.Collector, func(), func(), func()) {
	t.Helper()
	now := time.Now().UTC()
	caPEM, caKey := m15TestCA(t, now)
	issuer, err := collectorcontrol.NewCAIssuer(caPEM, caKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := collectorcontrol.NewIdentityService(control, issuer, platform.SystemClock{}, &m15IDs{values: []string{"bootstrap-" + suffix, string(collectorID)}}, rand.Reader, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := identities.CreateBootstrapKey(parent, cluster, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, csr := m15CollectorCSR(t)
	enrollment, err := identities.Enroll(parent, collectorcontrol.EnrollmentRequest{BootstrapToken: bootstrap.Token, CSRPEM: csr, Metadata: collectorcontrol.CollectorMetadata{DisplayName: "M15 loopback collector", Version: "m15", BuildCommit: "test", ProtocolMin: 1, ProtocolMax: 1, OperatingSystem: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("test collector CA is invalid")
	}
	transport, err := collectorcontrol.NewTransport(identities, control, control, control, control, platform.SystemClock{}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(transport)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	server.StartTLS()
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(append(append([]byte(nil), enrollment.Identity.CertificatePEM...), enrollment.Identity.CAChainPEM...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	if err != nil {
		t.Fatal(err)
	}
	httpClient := server.Client()
	httpTransport := httpClient.Transport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = httpTransport.TLSClientConfig.Clone()
	httpTransport.TLSClientConfig.MinVersion = tls.VersionTLS13
	httpTransport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	httpClient.Transport = httpTransport
	protocol, err := collectorruntime.NewHTTPClient(server.URL, httpClient, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sourceClient, err := adapter.NewClient(adapter.Config{BaseURL: upstreamURL, Timeout: time.Second, MaxBytes: 1 << 20, MaxSeries: 100})
	if err != nil {
		t.Fatal(err)
	}
	clock := platform.SystemClock{}
	local, err := prometheusexecution.New(sourceClient, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := collectorruntime.OpenJournal(t.TempDir()+"/collector-journal.json", clock)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := collectorruntime.NewRuntime(collectorruntime.RuntimeConfig{CollectorID: collectorID, SourceID: source, Version: "m15", BuildCommit: "test", Capabilities: []string{string(domain.QueryGPUIdentity), string(domain.QueryGPUUtilization)}, HeartbeatInterval: 200 * time.Millisecond, ClaimWait: 100 * time.Millisecond, RenewInterval: 250 * time.Millisecond, BackoffMinimum: 10 * time.Millisecond, BackoffMaximum: 50 * time.Millisecond, ExecutionRetries: 0}, protocol, local, journal, clock)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := application.NewRemoteCollectionExecutor(control, clock, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := application.NewCollector(remote, collections, clock, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var stop context.CancelFunc
	var done chan error
	start := func() {
		if stop != nil {
			return
		}
		var runtimeContext context.Context
		runtimeContext, stop = context.WithCancel(parent)
		done = make(chan error, 1)
		go func() { done <- runtime.Run(runtimeContext) }()
	}
	stopRuntime := func() {
		if stop == nil {
			return
		}
		stop()
		<-done
		stop, done = nil, nil
	}
	return collector, start, stopRuntime, func() { stopRuntime(); server.Close() }
}

func m15LiveCatalog(t *testing.T, now time.Time) *remediation.Catalog {
	t.Helper()
	now = now.UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := remediation.SignRecipeRelease(remediation.CollectionRequestRecipes(now.Add(time.Hour)), "m15-root", private)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := remediation.NewRecipeTrustStore([]remediation.RecipeTrustRoot{{ID: "m15-root", Issuer: "m15-test", PublicKey: public, ActivatesAt: now.Add(-time.Minute), RetiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := trust.Verify(release, now)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

// m15LiveProposalDiagnostic runs only after the autonomous supervisor has
// already failed to create a run. It uses the same live service dependencies
// to retain the concrete admission error in the acceptance failure output.
func m15LiveProposalDiagnostic(ctx context.Context, pool *pgxpool.Pool, catalog *remediation.Catalog, cluster domain.ClusterID) error {
	store, err := storepg.NewRemediationStore(pool)
	if err != nil {
		return err
	}
	cards, err := store.DiscoverLiveRemediationCards(ctx, cluster, 1)
	if err != nil {
		return err
	}
	if len(cards) != 1 {
		return fmt.Errorf("discover live remediation cards: got %d, want 1", len(cards))
	}
	executor, err := remediationlive.New(catalog, store)
	if err != nil {
		return err
	}
	service, err := application.NewLiveRemediationService(store, store, catalog, executor, m15RuntimeAuthorizer{cluster: cluster}, platform.SystemClock{}, platform.RandomIDGenerator{}, 10*time.Second)
	if err != nil {
		return err
	}
	_, err = service.ProposeRemediation(ctx, cards[0])
	return err
}

// m15SchedulerContentionLoad is a test-only control for overlapping ordinary
// scheduler claims with a repair collection. Call m15StartSchedulerContention
// after the repair worker has claimed REQUESTED and before collector delivery.
// It uses no collector, injected result, or remediation API.
type m15SchedulerContentionLoad struct {
	done <-chan m15SchedulerContentionMetrics
}

type m15SchedulerContentionMetrics struct {
	Jobs             int
	Workers          int
	ClaimLatencies   []time.Duration
	ClaimErrors      int
	CompletionErrors int
	Elapsed          time.Duration
}

func m15StartSchedulerContention(ctx context.Context, store *storepg.CollectionStore, cluster domain.ClusterID, source domain.SourceID, prefix string, jobs, workers int) (m15SchedulerContentionLoad, error) {
	if store == nil || jobs < 1 || workers < 1 || prefix == "" {
		return m15SchedulerContentionLoad{}, fmt.Errorf("invalid M15 scheduler contention configuration")
	}
	if err := m15PreseedSchedulerContention(ctx, store, cluster, source, prefix, jobs); err != nil {
		return m15SchedulerContentionLoad{}, err
	}
	return m15StartPreseededSchedulerContention(ctx, store, source, prefix, jobs, workers), nil
}

// m15PreseedSchedulerContention establishes the same ordinary scheduler
// population before remediation preflight. Pair it with
// m15StartPreseededSchedulerContention at BeforeEffect so revalidation sees a
// stable population while claims/completions overlap the live effect.
func m15PreseedSchedulerContention(ctx context.Context, store *storepg.CollectionStore, cluster domain.ClusterID, source domain.SourceID, prefix string, jobs int) error {
	if store == nil || jobs < 1 || prefix == "" {
		return fmt.Errorf("invalid M15 scheduler contention seed")
	}
	for i := 0; i < jobs; i++ {
		jobID := fmt.Sprintf("%s-scheduler-%03d", prefix, i)
		if err := store.EnsureJob(ctx, jobID, cluster, source, domain.QueryGPUUtilization, fmt.Sprintf("%s-node-%03d", prefix, i), time.Hour, time.Now().UTC().Add(-time.Minute)); err != nil {
			return err
		}
	}
	return nil
}

func m15StartPreseededSchedulerContention(ctx context.Context, store *storepg.CollectionStore, source domain.SourceID, prefix string, jobs, workers int) m15SchedulerContentionLoad {
	done := make(chan m15SchedulerContentionMetrics, 1)
	go func() {
		started := time.Now()
		metrics := m15SchedulerContentionMetrics{Jobs: jobs, Workers: workers, ClaimLatencies: make([]time.Duration, 0, jobs)}
		var mu sync.Mutex
		var workersWG sync.WaitGroup
		for worker := 0; worker < workers; worker++ {
			workersWG.Add(1)
			go func(worker int) {
				defer workersWG.Done()
				owner := fmt.Sprintf("%s-owner-%d", prefix, worker)
				for {
					before := time.Now()
					job, found, err := store.ClaimDueSourceJob(ctx, owner, time.Minute, source)
					mu.Lock()
					if err != nil {
						metrics.ClaimErrors++
						mu.Unlock()
						return
					}
					if !found {
						mu.Unlock()
						return
					}
					metrics.ClaimLatencies = append(metrics.ClaimLatencies, time.Since(before))
					mu.Unlock()
					if err = store.CompleteJob(ctx, job, owner); err != nil {
						mu.Lock()
						metrics.CompletionErrors++
						mu.Unlock()
						return
					}
				}
			}(worker)
		}
		workersWG.Wait()
		metrics.Elapsed = time.Since(started)
		sort.Slice(metrics.ClaimLatencies, func(i, j int) bool { return metrics.ClaimLatencies[i] < metrics.ClaimLatencies[j] })
		done <- metrics
	}()
	return m15SchedulerContentionLoad{done: done}
}

func (load m15SchedulerContentionLoad) Wait(ctx context.Context) (m15SchedulerContentionMetrics, error) {
	select {
	case result := <-load.done:
		return result, nil
	case <-ctx.Done():
		return m15SchedulerContentionMetrics{}, ctx.Err()
	}
}

type m15RuntimeAuthorizer struct{ cluster domain.ClusterID }

func (a m15RuntimeAuthorizer) AuthorizeRemediation(_ context.Context, request application.RemediationAuthorizationRequest) (application.RemediationAuthorizationDecision, error) {
	return application.RemediationAuthorizationDecision{
		Allowed:    request.ClusterID == a.cluster && request.ActorID == "sherlock-remediator" && request.Tier == domain.MaxImplementedTier && request.Privilege == domain.MaxImplementedPrivilege,
		ReasonCode: "M15_DIAGNOSTIC_RUNTIME_IDENTITY",
	}, nil
}

func m15Eventually(ctx context.Context, timeout, interval time.Duration, check func() (bool, error)) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ok, err := check()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timed out after %s", timeout)
		case <-ticker.C:
		}
	}
}

type m15IDs struct {
	values []string
	next   int
}

func (ids *m15IDs) NewID() (string, error) {
	value := ids.values[ids.next]
	ids.next++
	return value, nil
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func m15TestCA(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "M15 test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func m15CollectorCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "m15"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
