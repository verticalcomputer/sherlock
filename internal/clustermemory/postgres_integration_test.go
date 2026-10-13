//go:build integration

package clustermemory_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/clustermemory"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestProjectionRetrievalIsCitedClusterScopedAndRebuildable(t *testing.T) {
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
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	cluster := domain.ClusterID("m10-a-" + suffix)
	other := domain.ClusterID("m10-b-" + suffix)
	source := domain.SourceID("m10-source-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "M10 A", source, "M10 source"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'M10 B')`, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM investigations WHERE cluster_id=$1`, cluster)
		_, _ = pool.Exec(ctx, `DELETE FROM evidence_envelopes WHERE cluster_id=$1`, cluster)
		_, _ = pool.Exec(ctx, `DELETE FROM sources WHERE cluster_id=$1`, cluster)
		_, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE cluster_id=ANY($1::text[])`, []domain.ClusterID{cluster, other})
	})
	investigationID := domain.InvestigationID("m10-inv-" + suffix)
	evidenceID := domain.EvidenceID("m10-evidence-" + suffix)
	ledgerID := "ledger-" + suffix
	findingID := "finding-" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO evidence_envelopes(evidence_id,schema_version,cluster_id,status,source_id,operation,definition_version,source_reference,observed_start,observed_end,collected_at,coverage_expected,coverage_covered) VALUES($1,1,$2,'COMPLETE',$3,'gpu.health','v1','fixture',$4,$5,$5,'[]','[]')`, evidenceID, cluster, source, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO investigations(investigation_id,cluster_id,question,requested_by,scope,window_start,window_end,success_criteria,status,stop_reason,created_at,updated_at,completed_at) VALUES($1,$2,'why gpu fault','test','{"entity_kind":"node","entity_ids":["node-1"]}',$3,$4,'["cite"]','PARTIAL','NO_USEFUL_ACTION',$3,$4,$4)`, investigationID, cluster, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_evidence(ledger_entry_id,cluster_id,investigation_id,sequence,evidence_id,entry_kind,status,exact_scope,observed_start,observed_end,recorded_at) VALUES($1,$2,$3,1,$4,'OBSERVATION','COMPLETE','{}',$5,$6,$6)`, ledgerID, cluster, investigationID, evidenceID, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_findings(finding_id,cluster_id,investigation_id,kind,statement,scope,severity,status,validation_status,created_at,validated_at) VALUES($1,$2,$3,'OBSERVATION','GPU fault observed on node-1','{"entity_ids":["node-1"]}','WARNING','CURRENT','VALID',$4,$4)`, findingID, cluster, investigationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_finding_citations(cluster_id,investigation_id,finding_id,ledger_entry_id,relationship) VALUES($1,$2,$3,$4,'EVIDENCE')`, cluster, investigationID, findingID, ledgerID); err != nil {
		t.Fatal(err)
	}
	store, err := clustermemory.NewPostgres(pool)
	if err != nil {
		t.Fatal(err)
	}
	nonterminalID := domain.InvestigationID("m10-active-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO investigations(investigation_id,cluster_id,question,requested_by,scope,window_start,window_end,success_criteria,status,created_at,updated_at) VALUES($1,$2,'active investigation','test','{"entity_kind":"node","entity_ids":["node-1"]}',$3,$4,'["cite"]','PLANNING',$3,$4)`, nonterminalID, cluster, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := store.ProjectInvestigation(ctx, nonterminalID); err != nil {
		t.Fatalf("nonterminal projection must be a no-op: %v", err)
	}
	if err := store.ProjectInvestigation(ctx, investigationID); err != nil {
		t.Fatal(err)
	}
	result, err := store.Retrieve(ctx, clustermemory.Query{ClusterID: cluster, Text: "GPU fault", EntityIDs: []string{"node-1"}, ValidAt: now.Add(time.Minute), Limit: 12})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || len(result.Entries[0].Citations) != 1 || result.Entries[0].Citations[0].EvidenceID != evidenceID {
		t.Fatalf("result=%+v", result)
	}
	cross, err := store.Retrieve(ctx, clustermemory.Query{ClusterID: other, Text: "GPU fault", EntityIDs: []string{"node-1"}, ValidAt: now.Add(time.Minute), Limit: 12})
	if err != nil {
		t.Fatal(err)
	}
	if len(cross.Entries) != 0 {
		t.Fatalf("cross-cluster retrieval=%+v", cross)
	}
	var before []byte
	if err := pool.QueryRow(ctx, `SELECT source_digest FROM cluster_memory_projection_checkpoints WHERE cluster_id=$1`, cluster).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := store.RebuildCluster(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err := pool.QueryRow(ctx, `SELECT source_digest FROM cluster_memory_projection_checkpoints WHERE cluster_id=$1`, cluster).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("rebuild digest changed: %x != %x", before, after)
	}
}
