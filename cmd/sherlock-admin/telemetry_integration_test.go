//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetrylocal"
)

func TestTelemetryCLIEnrollmentRotationRevokeAndAudit(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated migrated PostgreSQL required")
	}
	t.Setenv("SHERLOCK_DATABASE_URL", dsn)
	t.Setenv("SHERLOCK_BOOTSTRAP_TTL", "30m")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("fixture pool")
	}
	defer pool.Close()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	request := storepg.EnrollmentRequest{EnrollmentID: "cli-telemetry-" + suffix, ClusterID: domain.ClusterID("cli-telemetry-c-" + suffix), NodeID: "node-a", InventoryRevisionID: "cli-telemetry-i-" + suffix, SourceIDs: []domain.SourceID{domain.SourceID("cli-telemetry-s-" + suffix)}, GatewayCollectorID: domain.CollectorID("cli-telemetry-g-" + suffix), PublicKeyBase64: base64.RawStdEncoding.EncodeToString(public), KeyID: "key-1", GatewaySPKISHA256: fmt.Sprintf("%064x", 1), AgentVersion: "fixture-v1", BuildSHA256: fmt.Sprintf("%064x", 2)}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal("synthetic setup", err)
		}
	}
	exec(`INSERT INTO clusters(cluster_id,display_name) VALUES($1,'Synthetic telemetry CLI')`, request.ClusterID)
	exec(`INSERT INTO sources(source_id,cluster_id,kind,display_name,availability) VALUES($1,$2,'prometheus','Synthetic telemetry','UNKNOWN')`, request.SourceIDs[0], request.ClusterID)
	exec(`INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture) VALUES($1,$2,'Synthetic gateway','ACTIVE','fixture','fixture',1,2,'linux','amd64')`, request.GatewayCollectorID, request.ClusterID)
	var at time.Time
	if err = pool.QueryRow(ctx, `SELECT clock_timestamp()-interval '1 hour'`).Scan(&at); err != nil {
		t.Fatal("database clock")
	}
	goodput, _ := storepg.NewGoodputStore(pool)
	if _, err = goodput.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{ID: domain.InventoryRevisionID(request.InventoryRevisionID), SchemaVersion: 1, ClusterID: request.ClusterID, SourceID: request.SourceIDs[0], SourceAt: at, ObservedAt: at, EffectiveAt: at, Entities: []domain.EntityIdentity{{ClusterID: request.ClusterID, Kind: domain.EntityNode, NodeID: request.NodeID}}}); err != nil {
		t.Fatal("expected node inventory")
	}
	path := filepath.Join(t.TempDir(), "reviewed-enrollment.json")
	body, _ := json.Marshal(request)
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func(args []string, want int) []byte {
		t.Helper()
		var out, stderr bytes.Buffer
		code := run(append([]string{"telemetry"}, args...), &out, &stderr)
		if code != want {
			t.Fatalf("CLI exit %d want %d safe error %q", code, want, stderr.String())
		}
		if strings.Contains(stderr.String(), dsn) || want != 0 && out.Len() != 0 {
			t.Fatal("unsafe failed output")
		}
		return out.Bytes()
	}
	body = invoke([]string{"enroll", "--enrollment", path, "--expected-revision", "0", "--actor", "local-fixture-operator"}, 0)
	var grant telemetry.Grant
	if json.Unmarshal(body, &grant) != nil || grant.ControlRevision != 1 || grant.EnrollmentRevision != 1 {
		t.Fatal("persisted grant")
	}
	invoke([]string{"enroll", "--enrollment", path, "--expected-revision", "0", "--actor", "local-fixture-operator"}, 0)
	statusArgs := []string{"status", "--cluster", string(request.ClusterID), "--collector", string(request.GatewayCollectorID), "--enrollment-id", request.EnrollmentID}
	body = invoke(statusArgs, 0)
	var status telemetry.EnrollmentStatus
	if json.Unmarshal(body, &status) != nil || status.Grant.EnrollmentID != request.EnrollmentID {
		t.Fatal("scoped status")
	}
	identityRequest, err := nodeidentity.NewRequest(nodeidentity.Scope{ClusterID: string(request.ClusterID), NodeID: string(request.NodeID), EnrollmentID: request.EnrollmentID, KeyID: request.KeyID}, private)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(t.TempDir(), "request.json")
	identityBody, _ := json.Marshal(identityRequest)
	if err = os.WriteFile(identityPath, identityBody, 0600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	mint := []string{"mint-node-token", "--cluster", string(request.ClusterID), "--collector", string(request.GatewayCollectorID), "--request", identityPath, "--expected-revision", "1", "--actor", "local-fixture-operator", "--token-output", tokenPath}
	minted := invoke(mint, 0)
	tokenBytes, err := telemetrylocal.ReadProtected(tokenPath, 128)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := nodeidentity.BootstrapTokenHash(string(tokenBytes))
	if err != nil || bytes.Contains(minted, tokenBytes) || string(minted) != "{\"minted\":true}\n" {
		t.Fatal("token exposed or invalid", err)
	}
	var storedHash string
	if err = pool.QueryRow(ctx, `SELECT token_hash FROM gp06f_node_bootstrap WHERE enrollment_id=$1`, request.EnrollmentID).Scan(&storedHash); err != nil || storedHash != tokenHash {
		t.Fatal("token binding", err)
	}
	invoke(mint, 1)
	preserved, err := telemetrylocal.ReadProtected(tokenPath, 128)
	if err != nil || !bytes.Equal(preserved, tokenBytes) {
		t.Fatal("token file replaced", err)
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	rotate := []string{"rotate-key", "--cluster", string(request.ClusterID), "--enrollment-id", request.EnrollmentID, "--expected-revision", "1", "--key-id", "key-2", "--public-key", base64.RawStdEncoding.EncodeToString(pub2), "--actor", "local-fixture-operator"}
	body = invoke(rotate, 0)
	if json.Unmarshal(body, &grant) != nil || grant.ControlRevision != 2 || grant.EnrollmentRevision != 1 {
		t.Fatal("rotation fences control only")
	}
	invoke(rotate, 1)
	revoke := []string{"revoke", "--cluster", string(request.ClusterID), "--enrollment-id", request.EnrollmentID, "--expected-revision", "1", "--actor", "local-fixture-operator"}
	invoke(revoke, 1)
	revoke[6] = "2"
	invoke(revoke, 0)
	invoke(statusArgs, 1)
	var audit int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_audit WHERE enrollment_id=$1 AND actor='local-fixture-operator' AND actor_kind='LOCAL_OPERATOR' AND action IN ('ENROLLED','KEY_ROTATED','REVOKED')`, request.EnrollmentID).Scan(&audit); err != nil || audit != 3 {
		t.Fatal("local attribution immutable audit", err)
	}
}
