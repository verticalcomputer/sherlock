//go:build integration

package adminview_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminview"
)

func TestEvidenceCurrentHealthSupersedesHistoryAndSeparatesScopes(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := "admin-current-evidence-" + suffix
	sourceID := "admin-current-source-" + suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	mustExec(t, pool, `INSERT INTO clusters (cluster_id,display_name,created_at) VALUES ($1,'Evidence cluster',$2)`, clusterID, now)
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,availability,created_at) VALUES ($1,$2,'prometheus','DCGM','AVAILABLE',$3)`, sourceID, clusterID, now)
	targetGPU1 := `[{"Kind":"GPU","ID":"GPU-1"}]`
	targetGPU2 := `[{"Kind":"GPU","ID":"GPU-2"}]`
	targetBoth := `[{"Kind":"GPU","ID":"GPU-1"},{"Kind":"GPU","ID":"GPU-2"}]`
	insertEvidence := func(id, status, operation, expected, covered string, collected time.Time) {
		t.Helper()
		mustExec(t, pool, `INSERT INTO evidence_envelopes (evidence_id,schema_version,cluster_id,status,source_id,operation,definition_version,source_reference,observed_start,observed_end,collected_at,coverage_expected,coverage_covered) VALUES ($1,1,$2,$3,$4,$5,'v1','integration',$6,$6,$6,$7::jsonb,$8::jsonb)`, id, clusterID, status, sourceID, operation, collected, expected, covered)
	}
	insertEvidence("old-unavailable-"+suffix, "UNAVAILABLE", "dcgm_gpu_utilization", targetGPU1, `[]`, now.Add(-4*time.Hour))
	insertEvidence("fresh-complete-"+suffix, "COMPLETE", "dcgm_gpu_utilization", targetGPU1, targetGPU1, now.Add(-time.Hour))
	insertEvidence("scope-partial-"+suffix, "PARTIAL", "dcgm_gpu_xid", targetBoth, targetGPU1, now.Add(-30*time.Minute))
	insertEvidence("scope-complete-"+suffix, "COMPLETE", "dcgm_gpu_xid", targetGPU2, targetGPU2, now.Add(-20*time.Minute))

	store, err := adminview.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	dashboard, _, err := store.Load(ctx, adminview.Query{At: now, Window: 24 * time.Hour, FreshFor: 5 * time.Minute, Limit: 1, ClusterID: clusterID})
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboard) != 1 {
		t.Fatalf("dashboard=%+v", dashboard)
	}
	evidence := dashboard[0].Evidence
	if evidence.Total != 4 || evidence.Complete != 2 || evidence.Partial != 1 || evidence.Unavailable != 1 || evidence.CurrentTotal != 3 || evidence.CurrentComplete != 2 || evidence.CurrentPartial != 1 || evidence.CurrentUnavailable != 0 || evidence.HistoricalSuperseded != 1 {
		t.Fatalf("evidence summary=%+v", evidence)
	}
	if len(evidence.CurrentStreams) != 3 {
		t.Fatalf("current streams=%+v", evidence.CurrentStreams)
	}
	foundMissing := false
	for _, stream := range evidence.CurrentStreams {
		if stream.Operation == "dcgm_gpu_xid" && len(stream.MissingTargets) == 1 && stream.MissingTargets[0] == "GPU:GPU-2" {
			foundMissing = strings.Contains(stream.Condition, "incomplete target coverage") && strings.Contains(stream.RecommendedAction, "Restore exporter coverage")
		}
		if stream.Operation == "dcgm_gpu_utilization" && stream.Status != "COMPLETE" {
			t.Fatalf("older unavailable state still affects current health: %+v", stream)
		}
	}
	if !foundMissing {
		t.Fatalf("missing-target repair was not projected: %+v", evidence.CurrentStreams)
	}
}
