//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type anomalyIntegrationClock struct{ now time.Time }

func (clock anomalyIntegrationClock) Now() time.Time { return clock.now }

type unusedInvestigationExecutor struct{}

func (unusedInvestigationExecutor) ExecuteInvestigationAction(context.Context, string, domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	return application.InvestigationExecutionResult{}, fmt.Errorf("not used")
}

func TestAnomalyBridgePostgresRestartDeduplicationAndDefaultOff(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	clusterID, sourceID := domain.ClusterID("anomaly-cluster-"+suffix), domain.SourceID("anomaly-source-"+suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, clusterID, "Anomaly cluster", sourceID, "Anomaly source"); err != nil {
		t.Fatal(err)
	}
	bridgeStore, _ := storepg.NewAnomalyBridgeStore(pool)
	investigationStore, _ := storepg.NewInvestigationStore(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	bridgeNow := now.Add(time.Minute)
	controller, err := application.NewInvestigationController(investigationStore, application.ScriptedInvestigationPlanner{}, unusedInvestigationExecutor{}, anomalyIntegrationClock{bridgeNow}, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	base := application.AutomaticInvestigationPolicy{EnabledRules: map[string]bool{application.XIDNonZeroRuleID: true}, MinimumSeverity: "HIGH", MaximumEvidenceAge: 10 * time.Minute, AllowPartialCoverage: true, Cooldown: time.Hour, MaxConcurrent: 1, DailyTokenBudget: 20_000, DailyCostBudget: 2_000_000, InvestigationBudget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxFanOut: 4, MaxModelTokens: 1_000, MaxCostMicros: 100_000}, InvestigationTTL: time.Hour, ServiceActor: "sherlock-auto-investigator"}

	recordXIDResult(t, ctx, collections, clusterID, sourceID, "one-"+suffix, now.Add(-2*time.Minute))
	disabled, err := application.NewAnomalyBridge(bridgeStore, controller, anomalyIntegrationClock{bridgeNow}, "integration-anomaly-v1", clusterID, base)
	if err != nil {
		t.Fatal(err)
	}
	drainBridge(t, ctx, disabled)
	var incidents, investigations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM anomaly_incidents WHERE cluster_id=$1`, clusterID).Scan(&incidents); err != nil || incidents != 1 {
		t.Fatalf("disabled incidents=%d err=%v", incidents, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM investigations WHERE cluster_id=$1`, clusterID).Scan(&investigations); err != nil || investigations != 0 {
		t.Fatalf("disabled investigations=%d err=%v", investigations, err)
	}

	// Explicit recovery rearms the episode detector before policy is enabled.
	recordXIDValue(t, ctx, collections, clusterID, sourceID, "two-"+suffix, now.Add(-time.Minute), 0)
	base.Enabled = true
	firstRestart, _ := application.NewAnomalyBridge(bridgeStore, controller, anomalyIntegrationClock{bridgeNow}, "integration-anomaly-v1", clusterID, base)
	secondRestart, _ := application.NewAnomalyBridge(bridgeStore, controller, anomalyIntegrationClock{bridgeNow}, "integration-anomaly-v1", clusterID, base)
	var group sync.WaitGroup
	for _, bridge := range []*application.AnomalyBridge{firstRestart, secondRestart} {
		group.Add(1)
		go func(value *application.AnomalyBridge) {
			defer group.Done()
			for range 5 {
				_, _ = value.RunOnce(ctx)
			}
		}(bridge)
	}
	group.Wait()
	drainBridge(t, ctx, firstRestart)
	recordXIDResult(t, ctx, collections, clusterID, sourceID, "three-"+suffix, now.Add(-30*time.Second))
	drainBridge(t, ctx, secondRestart)
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM anomaly_incidents WHERE cluster_id=$1`, clusterID).Scan(&incidents); err != nil || incidents != 1 {
		t.Fatalf("deduplicated incidents=%d err=%v", incidents, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM investigations WHERE cluster_id=$1 AND requested_by='sherlock-auto-investigator'`, clusterID).Scan(&investigations); err != nil || investigations != 1 {
		t.Fatalf("automatic investigations=%d err=%v", investigations, err)
	}
	var evidenceCount, signals int
	if err := pool.QueryRow(ctx, `SELECT count(*),max(signal_count) FROM incident_evidence e JOIN anomaly_incidents a ON a.incident_id=e.incident_id WHERE a.cluster_id=$1 GROUP BY a.incident_id`, clusterID).Scan(&evidenceCount, &signals); err != nil || evidenceCount != 2 || signals != 2 {
		t.Fatalf("evidence=%d signals=%d err=%v", evidenceCount, signals, err)
	}
	// A sticky non-zero gauge is one episode. An explicit zero rearms the edge,
	// so a later non-zero sample becomes a second signal without creating
	// duplicate live incidents.
	recordXIDValue(t, ctx, collections, clusterID, sourceID, "clear-"+suffix, now.Add(-20*time.Second), 0)
	drainBridge(t, ctx, firstRestart)
	recordXIDValue(t, ctx, collections, clusterID, sourceID, "recur-"+suffix, now.Add(-10*time.Second), 79)
	drainBridge(t, ctx, firstRestart)
	if err := pool.QueryRow(ctx, `SELECT count(*),max(signal_count) FROM incident_evidence e JOIN anomaly_incidents a ON a.incident_id=e.incident_id WHERE a.cluster_id=$1 GROUP BY a.incident_id`, clusterID).Scan(&evidenceCount, &signals); err != nil || evidenceCount != 3 || signals != 3 {
		t.Fatalf("rearmed evidence=%d signals=%d err=%v", evidenceCount, signals, err)
	}
	var late int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM incident_evidence ie JOIN incidents i ON i.incident_id=ie.incident_id JOIN evidence_envelopes e ON e.evidence_id=ie.evidence_id WHERE i.cluster_id=$1 AND e.created_at>ie.attached_at`, clusterID).Scan(&late); err != nil || late != 0 {
		t.Fatalf("late evidence=%d err=%v", late, err)
	}
}

func drainBridge(t *testing.T, ctx context.Context, bridge *application.AnomalyBridge) {
	t.Helper()
	for index := 0; index < 20; index++ {
		progressed, err := bridge.RunOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !progressed {
			return
		}
	}
	t.Fatal("anomaly bridge did not drain")
}

func recordXIDResult(t *testing.T, ctx context.Context, store *storepg.CollectionStore, clusterID domain.ClusterID, sourceID domain.SourceID, suffix string, observed time.Time) {
	recordXIDValue(t, ctx, store, clusterID, sourceID, suffix, observed, 79)
}

func recordXIDValue(t *testing.T, ctx context.Context, store *storepg.CollectionStore, clusterID domain.ClusterID, sourceID domain.SourceID, suffix string, observed time.Time, value float64) {
	t.Helper()
	completed := observed.Add(time.Second)
	result := domain.CollectionResult{Task: domain.CollectionTask{RunID: domain.RunID("anomaly-run-" + suffix), ClusterID: clusterID, SourceID: sourceID, Query: domain.QueryGPUXID, ScheduledFor: observed, Deadline: observed.Add(time.Minute), MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "anomaly-key-" + suffix}, Status: domain.ResultSucceeded, StartedAt: observed, CompletedAt: completed, Coverage: domain.Coverage{SeriesReturned: 1, BytesRead: 10, Complete: true}, Observations: []domain.Observation{{ID: domain.ObservationID("anomaly-observation-" + suffix), SchemaVersion: 1, ClusterID: clusterID, SourceID: sourceID, Kind: "gpu_xid", EntityKey: "node/node-1/gpu/0", Metric: "DCGM_FI_DEV_XID_ERRORS", Labels: []domain.Label{{Name: "UUID", Value: "GPU-1"}, {Name: "hostname", Value: "node-1"}}, Value: value, Unit: "xid_code", ObservedAt: observed, CollectedAt: completed, SourceReference: "prometheus:dcgm_gpu_xid"}}}
	if inserted, err := store.RecordResult(ctx, result); err != nil || !inserted {
		t.Fatalf("record XID result inserted=%t err=%v", inserted, err)
	}
}
