//go:build integration

package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestCoolingObservationIndexUpgrade(t *testing.T) {
	f := newAssessmentFixture(t)
	up, err := os.ReadFile("../../../migrations/000089_cooling_observation_lookup.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000089_cooling_observation_lookup.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	refused := func(migration []byte, reason string) {
		t.Helper()
		_, err := f.admin.Exec(t.Context(), string(migration))
		if err == nil || !strings.Contains(err.Error(), reason) {
			t.Fatalf("expected rejection containing %q, got %v", reason, err)
		}
	}

	// Fresh install, rerun, and down. A same-named index on another table
	// must survive even when observations is completely empty.
	f.exec(t, string(up))
	f.exec(t, string(down))
	f.exec(t, `CREATE INDEX observations_cooling_run_entity_idx ON public.collection_runs (run_id)`)
	refused(up, "unexpected definition")
	refused(down, "unexpected")
	f.exec(t, `DROP INDEX public.observations_cooling_run_entity_idx`)

	// The populated upgrade requires an online prebuild. Refuse a failed or
	// incomplete index even if its catalog definition exactly matches.
	f.seedSource(t, true)
	refused(up, "prebuild")
	const create = `CREATE INDEX CONCURRENTLY observations_cooling_run_entity_idx ON public.observations
		(run_id, entity_key) WHERE starts_with(run_id, 'prometheus-cooling-v2-')`
	// A pending writer holds the concurrent build at its first wait. The
	// timeout leaves the actual invalid index produced by PostgreSQL.
	writer, err := f.admin.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(t.Context())
	if _, err := writer.Exec(t.Context(), `LOCK TABLE public.observations IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	builder, err := f.admin.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Release()
	if _, err := builder.Exec(t.Context(), `SET statement_timeout='250ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = builder.Exec(t.Context(), create)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
		t.Fatalf("expected a cancelled concurrent build, got %v", err)
	}
	if err := writer.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	refused(up, "invalid")
	const drop = `DROP INDEX CONCURRENTLY public.observations_cooling_run_entity_idx`
	f.exec(t, drop)
	f.exec(t, create)
	f.exec(t, string(up))
	refused(down, "concurrently")
	f.exec(t, drop)
	f.exec(t, string(down))
}
