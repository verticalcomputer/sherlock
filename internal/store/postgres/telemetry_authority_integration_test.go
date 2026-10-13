//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func TestTelemetryInventoryWriterCommitFencesBlockedIntake(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	batch := f.batch(t, 1, 1)
	writer, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	key, _ := json.Marshal([]string{"goodput-facts", "inventory", string(f.request.ClusterID), string(f.request.SourceIDs[0]), "EXPECTED"})
	if _, err = writer.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key)); err != nil {
		t.Fatal(err)
	}
	// This new immutable revision becomes effective while intake is waiting.
	// Merely changing isolation or merely refreshing the clock is insufficient.
	if _, err = writer.Exec(ctx, `INSERT INTO goodput_inventory_revisions(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at) SELECT revision_id||'-concurrent',cluster_id,source_id,inventory_class,schema_version,content_digest,clock_timestamp(),clock_timestamp()+interval '100 milliseconds',clock_timestamp() FROM goodput_inventory_revisions WHERE revision_id=$1`, f.request.InventoryRevisionID); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Exec(ctx, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid,mig_identity) SELECT cluster_id,revision_id||'-concurrent',entity_kind,stable_node_id,physical_gpu_uuid,mig_identity FROM goodput_inventory_revision_entities WHERE revision_id=$1`, f.request.InventoryRevisionID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, batch, "blocked-fixture-receipt")
		done <- err
	}()
	blocked := false
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err = f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !blocked {
		t.Fatal("did not observe actual inventory stream wait")
	}
	// Remain below the runtime's250ms lock timeout while crossing the DB-time
	// boundary using the same clock that evaluates inventory, never host skew.
	if _, err = writer.Exec(ctx, `SELECT pg_sleep(greatest(0,extract(epoch FROM ((SELECT effective_at FROM goodput_inventory_revisions WHERE revision_id=$1)-clock_timestamp()))))`, f.request.InventoryRevisionID+"-concurrent"); err != nil {
		t.Fatal(err)
	}
	if err = writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, telemetry.ErrUnauthorized) {
			t.Fatal("blocked intake used pre-writer authority", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("intake did not finish")
	}
	var receipts int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_batches WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("rejected intake persisted a receipt", err)
	}
}
