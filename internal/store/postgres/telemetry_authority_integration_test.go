//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

const inventoryLockQuery = "SELECT pg_advisory_xact_lock(hashtextextended($1,0))"

// Only the test intake connection gets a longer lock wait so the writer can
// commit even under CI scheduling delays. Production transaction limits still
// apply everywhere else.
type inventoryFenceTracer struct{ t *testing.T }

func (tracer inventoryFenceTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if data.SQL == inventoryLockQuery {
		if _, err := conn.PgConn().Exec(ctx, "SET LOCAL statement_timeout='4s'; SET LOCAL lock_timeout='4s'").ReadAll(); err != nil {
			tracer.t.Error("extend fixture inventory lock wait", err)
		}
	}
	return ctx
}

func (inventoryFenceTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestTelemetryInventoryWriterCommitFencesBlockedIntake(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	f.open(t, 1)
	batch := f.batch(t, 1, 1)

	cfg := f.pool.Config()
	cfg.ConnConfig.Tracer = inventoryFenceTracer{t}
	intakePool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(intakePool.Close)
	store := storepg.NewTelemetryStore(intakePool)

	writer, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(t.Context())
	key, _ := json.Marshal([]string{"goodput-facts", "inventory", string(f.request.ClusterID), string(f.request.SourceIDs[0]), "EXPECTED"})
	if _, err = writer.Exec(ctx, inventoryLockQuery, string(key)); err != nil {
		t.Fatal(err)
	}
	writerPID := writer.Conn().PgConn().PID()
	done := make(chan error, 1)
	go func() {
		_, err := store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, batch, "blocked-fixture-receipt")
		done <- err
	}()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err = f.pool.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted
   AND $1::integer=ANY(pg_blocking_pids(pid)))`, writerPID).Scan(&blocked)
		if err != nil {
			t.Fatal("observe inventory lock wait", err)
		}
		if blocked {
			break
		}
		select {
		case err = <-done:
			t.Fatal("intake returned before the inventory writer committed", err)
		case <-ctx.Done():
			t.Fatal("did not observe intake waiting on the inventory writer")
		case <-ticker.C:
		}
	}

	// Make the revision effective only after intake has blocked, using the
	// same database clock as intake. Seeing it requires a fresh snapshot and
	// a refreshed effective-time check after the lock is released.
	if _, err = writer.Exec(ctx, `WITH effective AS MATERIALIZED (SELECT clock_timestamp() AS at)
 INSERT INTO goodput_inventory_revisions(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at)
 SELECT revision_id||'-concurrent',cluster_id,source_id,inventory_class,schema_version,content_digest,at,at,at
 FROM goodput_inventory_revisions CROSS JOIN effective WHERE revision_id=$1`, f.request.InventoryRevisionID); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Exec(ctx, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid,mig_identity) SELECT cluster_id,revision_id||'-concurrent',entity_kind,stable_node_id,physical_gpu_uuid,mig_identity FROM goodput_inventory_revision_entities WHERE revision_id=$1`, f.request.InventoryRevisionID); err != nil {
		t.Fatal(err)
	}
	if err = writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, telemetry.ErrUnauthorized) {
			t.Fatal("intake did not reject the superseded inventory revision", err)
		}
	case <-ctx.Done():
		t.Fatal("intake did not finish after the inventory writer committed")
	}
	var receipts int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_batches WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("rejected intake persisted a receipt", err)
	}
}
