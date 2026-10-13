//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// fixtureDatabaseTime anchors fixture business timestamps to the database
// clock. PostgreSQL compares stored availability and timestamp ordering
// against its own clock, so a host-derived base carries no safety margin when
// the two clocks disagree by even a fraction of a millisecond. Host time
// remains suitable for fixture-name suffixes and elapsed-time measurements,
// which never define database eligibility.
func fixtureDatabaseTime(t *testing.T, ctx context.Context, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatalf("read database clock: %v", err)
	}
	return now.UTC().Truncate(time.Microsecond)
}
