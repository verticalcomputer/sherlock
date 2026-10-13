//go:build integration

package investigationcontext_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
)

func TestPostgresCheckpointRoundTrip(t *testing.T) {
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
	clusterID := domain.ClusterID("m11-cluster-" + suffix)
	investigationID := domain.InvestigationID("m11-investigation-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'M11 test')`, clusterID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM investigations WHERE investigation_id=$1`, investigationID)
		_, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE cluster_id=$1`, clusterID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO investigations(investigation_id,cluster_id,question,requested_by,scope,window_start,window_end,success_criteria,status,version,created_at,updated_at) VALUES($1,$2,'why','test','{"entity_kind":"node","entity_ids":["node-1"]}',$3,$4,'["cite"]','INITIALIZING',1,$5,$5)`, investigationID, clusterID, now.Add(-time.Hour), now, now); err != nil {
		t.Fatal(err)
	}
	request := domain.InvestigationRequest{ID: investigationID, IncidentID: "incident-test", ClusterID: clusterID, Question: "why", RequestedBy: "test", IdempotencyKey: "key", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"cite"}, Budget: domain.InvestigationBudget{MaxDecisions: 1, MaxToolCalls: 1, MaxFanOut: 1, MaxModelTokens: 10000, MaxCostMicros: 100}, RequestedAt: now, Deadline: now.Add(time.Hour)}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := investigationcontext.ProjectCheckpoint(application.InvestigationSnapshot{Investigation: investigation}, investigationcontext.Input{InvestigationID: investigationID, ClusterID: clusterID, Question: "why", Scope: request.Scope, SuccessCriteria: []string{"cite"}}, "policy-v1", "tools-v1")
	if err != nil {
		t.Fatal(err)
	}
	store, err := investigationcontext.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordContextCheckpoint(ctx, investigationcontext.ContextRecord{Checkpoint: checkpoint}); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadLatestCheckpoint(ctx, string(investigationID), 2)
	if err != nil || !found {
		t.Fatalf("found=%v error=%v", found, err)
	}
	if loaded.Digest != checkpoint.Digest {
		t.Fatalf("loaded=%s want=%s", loaded.Digest, checkpoint.Digest)
	}
}
