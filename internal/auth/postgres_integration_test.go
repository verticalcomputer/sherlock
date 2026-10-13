//go:build integration

package auth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
)

func TestPostgreSQLAPIKeyLifecycleAndRotation(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("api-key-cluster-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (cluster_id, display_name) VALUES ($1,$2)`, clusterID, "API-key integration cluster"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM api_keys WHERE cluster_id=$1`, clusterID)
		_, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE cluster_id=$1`, clusterID)
	}()
	store, err := auth.NewPostgreSQLStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.NewService(store, platform.SystemClock{}, rand.Reader, bytes.Repeat([]byte{0x63}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	issue := func(label string) (auth.IssuedKey, []byte) {
		issued, err := service.CreateKey(ctx, clusterID, label, []auth.Capability{auth.CapabilityClusterRead, auth.CapabilityTelemetryRead}, time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		var plaintext bytes.Buffer
		if err := issued.Plaintext.WriteOnce(&plaintext); err != nil {
			t.Fatal(err)
		}
		return issued, append([]byte(nil), plaintext.Bytes()...)
	}
	oldKey, oldPlaintext := issue("rotation old")
	newKey, newPlaintext := issue("rotation new")
	for _, plaintext := range [][]byte{oldPlaintext, newPlaintext} {
		principal, err := service.Authenticate(ctx, append([]byte(nil), plaintext...))
		if err != nil || principal.ClusterID != clusterID {
			t.Fatalf("authentication principal=%+v err=%v", principal, err)
		}
	}
	keys, err := service.ListKeys(ctx, clusterID)
	if err != nil || len(keys) != 2 {
		t.Fatalf("listed keys=%d err=%v", len(keys), err)
	}
	var hashLength int
	if err := pool.QueryRow(ctx, `SELECT octet_length(secret_hash) FROM api_keys WHERE public_key_id=$1`, oldKey.Key.PublicID).Scan(&hashLength); err != nil || hashLength != 32 {
		t.Fatalf("stored hash length=%d err=%v", hashLength, err)
	}
	if err := service.RevokeKey(ctx, clusterID, oldKey.Key.PublicID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, append([]byte(nil), oldPlaintext...)); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("revoked key err=%v", err)
	}
	if _, err := service.Authenticate(ctx, append([]byte(nil), newPlaintext...)); err != nil {
		t.Fatalf("overlapping replacement key failed: %v", err)
	}
	_ = newKey
}
