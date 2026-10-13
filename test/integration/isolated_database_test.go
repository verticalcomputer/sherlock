//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// isolatedDatabase provisions a private migrated database derived from
// SHERLOCK_TEST_DATABASE_URL for tests that assert database-wide effects
// such as retention counts. Other tests keep their existing shared fixtures.
// The caller owns nothing: cleanup dropping exactly the created database is
// registered immediately after successful creation, so partial setup
// failures cannot leak it. Connections close before the drop.
func isolatedDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to parent database: %v", err)
	}
	name := fmt.Sprintf("m1retention_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create isolated database: %v", err)
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated database: %v", err)
		}
		_ = admin.Close(ctx)
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse database configuration: %v", err)
	}
	cfg.ConnConfig.Database = name
	pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to isolated database: %v", err)
	}
	files, err := filepath.Glob("../../migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v", err)
	}
	sort.Strings(files)
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if _, err := pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", file, err)
		}
	}
	return ctx, pool
}
