//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestRetentionBacklogStatementTimeoutPreservesRows(t *testing.T) {
	f := newRetentionFixture(t)
	old := f.now.Add(-40 * 24 * time.Hour)
	f.run(t, "slow-measurement", old)
	f.observation(t, "slow-observation", "slow-measurement", old)
	// A fixture-only view delays the observation scan beyond the method's
	// statement deadline. It changes neither the backing rows nor runtime SQL.
	f.exec(t, `ALTER TABLE observations RENAME TO observations_fixture_slow`)
	f.exec(t, `CREATE VIEW observations AS
		SELECT o.* FROM observations_fixture_slow o
		CROSS JOIN LATERAL (SELECT pg_sleep(1.2) WHERE o.observation_id IS NOT NULL) delay`)
	started := time.Now()
	result, err := f.store.MeasureRetentionBacklog(context.Background(), f.now, 7*24*time.Hour, 30*24*time.Hour)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "57014" || result != (storepg.RetentionBacklog{}) || time.Since(started) >= 2*time.Second {
		t.Fatalf("statement timeout did not fail measurement safely: elapsed=%s result=%+v err=%v", time.Since(started), result, err)
	}
	f.exec(t, `DROP VIEW observations`)
	f.exec(t, `ALTER TABLE observations_fixture_slow RENAME TO observations`)
	f.count(t, "observations", 1)
	f.count(t, "collection_runs", 1)
	f.count(t, "collection_events", 1)
	if result := f.backlog(t, f.now); result.Observations.EligibleRows != 1 {
		t.Fatalf("statement timeout did not recover: %+v", result)
	}
}
