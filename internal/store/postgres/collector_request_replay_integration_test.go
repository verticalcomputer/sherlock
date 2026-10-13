//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestCollectorRequestNonceIsDurableAndCertificateScoped(t *testing.T) {
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
	first, _ := storepg.NewCollectorControlStore(pool)
	fingerprint := sha256.Sum256([]byte("certificate-one"))
	expires := time.Now().UTC().Add(time.Minute)
	if err := first.ConsumeCollectorRequestNonce(ctx, fingerprint, "replay-integration", expires); err != nil {
		t.Fatal(err)
	}
	second, _ := storepg.NewCollectorControlStore(pool)
	if err := second.ConsumeCollectorRequestNonce(ctx, fingerprint, "replay-integration", expires); !errors.Is(err, collectorcontrol.ErrRequestReplay) {
		t.Fatalf("durable replay result = %v", err)
	}
	otherFingerprint := sha256.Sum256([]byte("certificate-two"))
	if err := second.ConsumeCollectorRequestNonce(ctx, otherFingerprint, "replay-integration", expires); err != nil {
		t.Fatalf("certificate-scoped nonce rejected: %v", err)
	}
}
