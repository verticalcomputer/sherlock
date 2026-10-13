//go:build integration

package postgres_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func TestTelemetryRetirementUTCReceiptReplayPreservesSignedNanoseconds(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	// pgx defaults to time.Local. Force an equivalent noncanonical zero-offset
	// location per connection to reproduce UTC-host behavior on every platform,
	// without changing process-global time.Local or other tests' connections.
	location := time.FixedZone("synthetic-database-UTC", 0)
	cfg, err := pgxpool.ParseConfig(os.Getenv("SHERLOCK_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("fixture pool configuration")
	}
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		conn.TypeMap().RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID,
			Codec: &pgtype.TimestamptzCodec{ScanLocation: location}})
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("fixture pool")
	}
	t.Cleanup(pool.Close)
	var databaseTime time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseTime); err != nil || databaseTime.Location() != location {
		t.Fatal("synthetic database timezone was not exercised", err)
	}
	f.store = storepg.NewTelemetryStore(pool)
	// This sub-microsecond precision belongs to signed incoming evidence. The
	// database clock normalization must not round or rewrite any such timestamp.
	f.now = f.now.Add(123 * time.Nanosecond)
	if f.now.Nanosecond()%1000 != 123 {
		t.Fatal("signed timestamp fixture must contain nanoseconds")
	}
	f.open(t, 1)
	batch := f.batch(t, 1, 1)
	cloud := f.accept(t, batch)
	manifest := telemetryBatchManifest(batch, cloud)
	request, admission := telemetryRelease(t, f, 1, 1, 1, manifest)
	prepared, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admission)
	if err != nil {
		t.Fatal("prepare", err)
	}
	commit := telemetryCommit(t, f, request, prepared)
	final, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit)
	if err != nil {
		t.Fatal("commit", err)
	}
	completion := telemetryCompletion(t, f, request, final)
	receipt, err := f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion)
	if err != nil {
		t.Fatal("complete", err)
	}
	issued := struct {
		Prepared, Final telemetry.CloudRetirementReceipt
		Completed       telemetry.NodeCompletionReceipt
	}{prepared, final, receipt}
	body, err := json.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}
	decoded := issued
	if err := json.Unmarshal(body, &decoded); err != nil || !reflect.DeepEqual(issued, decoded) {
		t.Fatal("initial receipts must survive the persisted JSON representation exactly", err)
	}
	f.store = storepg.NewTelemetryStore(pool)
	preparedReplay, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admission)
	if err != nil || !reflect.DeepEqual(preparedReplay, prepared) {
		t.Fatal("immutable prepared replay", err)
	}
	finalReplay, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit)
	if err != nil || !reflect.DeepEqual(finalReplay, final) {
		t.Fatal("immutable final replay", err)
	}
	completionReplay, err := f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion)
	if err != nil || !reflect.DeepEqual(completionReplay, receipt) {
		t.Fatal("immutable completion replay", err)
	}
	var requestBody, admissionBody, commitBody, completionBody []byte
	if err := pool.QueryRow(ctx, `SELECT request,admission,gateway_commit,node_completion FROM gp06f_telemetry_retirements WHERE enrollment_id=$1 AND release_id=$2`, request.EnrollmentID, request.ReleaseID).
		Scan(&requestBody, &admissionBody, &commitBody, &completionBody); err != nil {
		t.Fatal("immutable incoming evidence", err)
	}
	var storedRequest telemetry.ReleaseRequest
	var storedAdmission telemetry.ReleaseAdmissionReceipt
	var storedCommit telemetry.GatewayReleaseCommit
	var storedCompletion telemetry.NodeReleaseCompletion
	for _, record := range []struct {
		body   []byte
		target any
	}{{requestBody, &storedRequest}, {admissionBody, &storedAdmission}, {commitBody, &storedCommit}, {completionBody, &storedCompletion}} {
		if err := json.Unmarshal(record.body, record.target); err != nil {
			t.Fatal(err)
		}
	}
	for _, instant := range []time.Time{storedRequest.CreatedAt, storedAdmission.StoredAt, storedCommit.CreatedAt, storedCompletion.CreatedAt} {
		if !instant.Equal(f.now) || instant.Nanosecond()%1000 != 123 {
			t.Fatal("incoming evidence timestamp precision changed")
		}
	}
	public := f.private.Public().(ed25519.PublicKey)
	if storedRequest.Digest != request.Digest || storedRequest.Signature != request.Signature || telemetry.VerifyReleaseSignature(storedRequest, public) != nil ||
		storedCompletion.Digest != completion.Digest || storedCompletion.Signature != completion.Signature || telemetry.VerifyNodeCompletionSignature(storedCompletion, public) != nil {
		t.Fatal("incoming signed evidence changed")
	}
	originalGatewayID, err := telemetry.GatewayRetirementReceiptID(final)
	if err != nil {
		t.Fatal(err)
	}
	replayedGatewayID, err := telemetry.GatewayRetirementReceiptID(finalReplay)
	if err != nil || originalGatewayID != replayedGatewayID {
		t.Fatal("canonical gateway proof changed on replay", err)
	}
}
