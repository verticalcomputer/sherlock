//go:build integration

package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type telemetryFixture struct {
	pool    *pgxpool.Pool
	store   *storepg.TelemetryStore
	request storepg.EnrollmentRequest
	private ed25519.PrivateKey
	now     time.Time
}

func newTelemetryFixture(t *testing.T) *telemetryFixture {
	t.Helper()
	url := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("isolated migrated PostgreSQL required")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal("fixture pool")
	}
	t.Cleanup(pool.Close)
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &telemetryFixture{pool: pool, store: storepg.NewTelemetryStore(pool), private: private}
	f.request = storepg.EnrollmentRequest{EnrollmentID: "telemetry-enroll-" + suffix, ClusterID: domain.ClusterID("telemetry-cluster-" + suffix), NodeID: "node-a", InventoryRevisionID: "telemetry-inventory-" + suffix, SourceIDs: []domain.SourceID{domain.SourceID("telemetry-source-" + suffix)}, GatewayCollectorID: domain.CollectorID("telemetry-gateway-" + suffix), PublicKeyBase64: base64.RawStdEncoding.EncodeToString(public), KeyID: "node-key-1", GatewaySPKISHA256: fmt.Sprintf("%064x", 1), AgentVersion: "fixture-agent-1", BuildSHA256: fmt.Sprintf("%064x", 2)}
	if err = pool.QueryRow(context.Background(), `SELECT clock_timestamp()-interval '1 second'`).Scan(&f.now); err != nil {
		t.Fatal("database clock")
	}
	f.exec(t, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'Synthetic telemetry')`, f.request.ClusterID)
	f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name,availability) VALUES($1,$2,'prometheus','Synthetic telemetry','UNKNOWN')`, f.request.SourceIDs[0], f.request.ClusterID)
	f.exec(t, `INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture) VALUES($1,$2,'Synthetic gateway','ACTIVE','fixture','fixture',1,2,'linux','amd64')`, f.request.GatewayCollectorID, f.request.ClusterID)
	goodput, _ := storepg.NewGoodputStore(pool)
	at := f.now.Add(-time.Hour)
	if _, err = goodput.RecordExpectedInventoryRevision(context.Background(), domain.InventoryRevision{ID: domain.InventoryRevisionID(f.request.InventoryRevisionID), SchemaVersion: 1, ClusterID: f.request.ClusterID, SourceID: f.request.SourceIDs[0], SourceAt: at, ObservedAt: at, EffectiveAt: at, Entities: []domain.EntityIdentity{{ClusterID: f.request.ClusterID, Kind: domain.EntityGPU, NodeID: f.request.NodeID, PhysicalGPUUUID: "GPU-a"}}}); err != nil {
		t.Fatal("expected inventory")
	}
	if _, err = f.store.CreateEnrollment(context.Background(), f.request, 0, "fixture-operator"); err != nil {
		t.Fatal("create enrollment", err)
	}
	return f
}
func (f *telemetryFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatal("synthetic fixture SQL", err)
	}
}
func (f *telemetryFixture) session(t *testing.T, epoch int, private ed25519.PrivateKey, key string) telemetry.SessionMessage {
	t.Helper()
	m := telemetry.SessionMessage{ProtocolVersion: 1, Kind: "OPEN", ClusterID: string(f.request.ClusterID), NodeID: string(f.request.NodeID), EnrollmentID: f.request.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: strconv.Itoa(epoch), SessionID: fmt.Sprintf("session-%d", epoch), BootID: fmt.Sprintf("boot-%d", epoch), SigningKeyID: key, CreatedAt: f.now}
	if err := telemetry.SignSessionMessage(&m, private); err != nil {
		t.Fatal(err)
	}
	return m
}
func (f *telemetryFixture) open(t *testing.T, epoch int) telemetry.SessionMessage {
	t.Helper()
	m := f.session(t, epoch, f.private, f.request.KeyID)
	if _, err := f.store.RegisterSession(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, m); err != nil {
		t.Fatal("open", err)
	}
	return m
}
func (f *telemetryFixture) batch(t *testing.T, epoch, sequence int) telemetry.NodeBatch {
	t.Helper()
	frame := residentFixtureFrame(t, telemetry.SourceProfile(f.request.SourceProfiles, string(f.request.SourceIDs[0])), string(f.request.SourceIDs[0]), string(f.request.ClusterID), string(f.request.NodeID), fmt.Sprintf("record-%d-%d", epoch, sequence), f.now, uint64(sequence))
	b := telemetry.NodeBatch{ProtocolVersion: 1, Key: telemetry.BatchKey{ClusterID: string(f.request.ClusterID), NodeID: string(f.request.NodeID), EnrollmentID: f.request.EnrollmentID, SessionEpoch: strconv.Itoa(epoch), SessionID: fmt.Sprintf("session-%d", epoch), Sequence: strconv.Itoa(sequence)}, EnrollmentRevision: 1, InventoryRevisionID: f.request.InventoryRevisionID, BootID: fmt.Sprintf("boot-%d", epoch), SigningKeyID: f.request.KeyID, AgentVersion: f.request.AgentVersion, BuildSHA256: f.request.BuildSHA256, CreatedAt: f.now, Sources: []telemetry.SourceFrame{frame}}
	if err := telemetry.SignBatch(&b, f.private); err != nil {
		t.Fatal(err)
	}
	return b
}
func (f *telemetryFixture) accept(t *testing.T, b telemetry.NodeBatch) telemetry.CloudReceipt {
	t.Helper()
	r, err := f.store.AcceptBatch(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, b, "gateway-"+b.Key.SessionEpoch+"-"+b.Key.Sequence)
	if err != nil {
		t.Fatal("accept", err)
	}
	return r
}

func TestTelemetryFixtureReplayScopeAndNoProjection(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	first := f.open(t, 1)
	again, err := f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, first)
	if err != nil || again.Digest != first.Digest {
		t.Fatal("lifecycle replay", err)
	}
	batch := f.batch(t, 1, 2)
	receipt := f.accept(t, batch)
	if !receipt.HistoryOnly || receipt.Durability != "CLOUD" {
		t.Fatal("synthetic boundary")
	}
	f.store = storepg.NewTelemetryStore(f.pool)
	replay, err := f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, batch, receipt.GatewayReceiptID)
	if err != nil || replay != receipt {
		t.Fatal("restart/lost response replay", err)
	}
	conflict := batch
	conflict.Sources = append([]telemetry.SourceFrame(nil), batch.Sources...)
	conflict.Sources[0].Records = append([]telemetry.Record(nil), batch.Sources[0].Records...)
	value := 99.0
	for i := range conflict.Sources[0].Records {
		if conflict.Sources[0].Records[i].Metric == "fixture.gauge" {
			conflict.Sources[0].Records[i].Value.Float = &value
		}
	}
	_ = telemetry.SignBatch(&conflict, f.private)
	if _, err = f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, conflict, receipt.GatewayReceiptID); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("conflict", err)
	}
	if _, err = f.store.AcceptBatch(ctx, "foreign", f.request.GatewayCollectorID, batch, receipt.GatewayReceiptID); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("foreign cluster", err)
	}
	status, err := f.store.Status(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.request.EnrollmentID)
	if err != nil || len(status.Receipts) != 1 || len(status.History) != 1 || status.Sessions[0].ReceivedRanges[0].From != "2" {
		t.Fatal("scoped history/gap", err)
	}
	for _, table := range []string{"observations", "collection_runs", "current_projections"} {
		var count int
		if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE cluster_id=$1`, f.request.ClusterID).Scan(&count); err != nil || count != 0 {
			t.Fatal("fixture reached ordinary health", table, err)
		}
	}
}

func TestTelemetryRejectsCarrierSelfLossWithoutPublishing(t *testing.T) {
	f := newTelemetryFixture(t)
	f.open(t, 1)
	b := f.batch(t, 1, 2)
	b.Sources[0].Loss = []telemetry.LossRange{{ID: "self-loss", AffectedKey: b.Key, ThroughSequence: "3", Reason: "SOURCE_LOSS", CountKnown: false}}
	if err := telemetry.SignBatch(&b, f.private); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptBatch(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, b, "gateway-self-loss"); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("self loss accepted", err)
	}
	for _, table := range []string{"gp06f_telemetry_batches", "gp06f_telemetry_loss", "gp06f_telemetry_intervals"} {
		var count int
		if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&count); err != nil || count != 0 {
			t.Fatal("self loss published partial evidence", table, err)
		}
	}
	// An actual previous missing sequence can be carried and replayed unchanged.
	b.Sources[0].Loss[0].AffectedKey.Sequence = "1"
	b.Sources[0].Loss[0].ThroughSequence = "1"
	if err := telemetry.SignBatch(&b, f.private); err != nil {
		t.Fatal(err)
	}
	r := f.accept(t, b)
	if replay, err := f.store.AcceptBatch(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, b, r.GatewayReceiptID); err != nil || replay != r {
		t.Fatal("previous gap replay rejected", err)
	}
}

func TestTelemetryLocalDiscardAfterLostResponseRetainsReceived(t *testing.T) {
	for _, reason := range []string{"SPOOL_EXPIRED", "SPOOL_OVERFLOW"} {
		t.Run(reason, func(t *testing.T) {
			f := newTelemetryFixture(t)
			current := f.now
			f.now = f.now.Add(-25 * time.Hour)
			open := f.open(t, 1)
			original := f.batch(t, 1, 1)
			// The store committed, but the node did not durably learn the receipt.
			_ = f.accept(t, original)
			f.now = current
			carrier := f.batch(t, 1, 2)
			carrier.Sources[0].Loss = []telemetry.LossRange{{ID: "local-discard", AffectedKey: original.Key, ThroughSequence: "1", Reason: reason, CountKnown: false}}
			if err := telemetry.SignBatch(&carrier, f.private); err != nil {
				t.Fatal(err)
			}
			receipt := f.accept(t, carrier)
			if replay, err := f.store.AcceptBatch(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, carrier, receipt.GatewayReceiptID); err != nil || replay != receipt {
				t.Fatal("discard receipt replay", err)
			}
			strict := f.batch(t, 1, 2)
			strict.Key.Sequence = "3"
			strict.Sources[0].Loss = []telemetry.LossRange{{ID: "unsupported-source-absence", AffectedKey: original.Key, ThroughSequence: "1", Reason: "SOURCE_LOSS", CountKnown: false}}
			if err := telemetry.SignBatch(&strict, f.private); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.AcceptBatch(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, strict, "strict-absence"); !errors.Is(err, telemetry.ErrConflict) {
				t.Fatal("received observation falsely declared absent", err)
			}
			final := open
			final.Kind = "FINALIZE"
			final.CreatedAt = current
			final.LastAllocatedSequence = "2"
			if err := telemetry.SignSessionMessage(&final, f.private); err != nil {
				t.Fatal(err)
			}
			finalReceipt, err := f.store.RegisterSession(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, final)
			if err != nil || !finalReceipt.Covered || finalReceipt.Retired {
				t.Fatal("actual receipt coverage lost", err)
			}
			var batches, losses int
			if err = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM gp06f_telemetry_batches WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&batches); err != nil {
				t.Fatal(err)
			}
			if err = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM gp06f_telemetry_loss WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&losses); err != nil || batches != 2 || losses != 1 {
				t.Fatal("discard fact or original receipt lost", err)
			}

		})
	}
}

func TestTelemetryConcurrentReplayRotationRevocation(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	open := f.open(t, 1)
	batch := f.batch(t, 1, 1)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, batch, "gateway-receipt-1")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, telemetry.ErrUnavailable) {
			t.Fatal("unsafe concurrent outcome", err)
		}
	}
	if success < 1 {
		t.Fatal("no commit")
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	grant, err := f.store.RotateKey(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "node-key-2", base64.RawStdEncoding.EncodeToString(public), "fixture-operator", false)
	if err != nil || grant.EnrollmentRevision != 1 || grant.ControlRevision != 2 {
		t.Fatal("rotation", err)
	}
	if _, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, open); err != nil {
		t.Fatal("old known OPEN replay", err)
	}
	if _, err = f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, batch, "gateway-receipt-1"); err != nil {
		t.Fatal("old signed receipt replay", err)
	}
	fresh := f.session(t, 2, f.private, "node-key-1")
	if _, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, fresh); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("retired key new session", err)
	}
	fresh = f.session(t, 2, private, "node-key-2")
	fresh.BootID = open.BootID
	_ = telemetry.SignSessionMessage(&fresh, private)
	if _, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, fresh); err != nil {
		t.Fatal("active rotated key session", err)
	}
	third, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = f.store.RotateKey(ctx, f.request.ClusterID, f.request.EnrollmentID, 2, "node-key-3", base64.RawStdEncoding.EncodeToString(third), "fixture-operator", false); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("unproved ownership thirdrotation", err)
	}
	if _, err = f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "fixture-operator"); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("CAS", err)
	}
	if _, err = f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 2, "fixture-operator"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, batch, "gateway-receipt-1"); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("revocation bypassed dedupe", err)
	}
}

func TestTelemetryFinalizeExplicitLossAndBoundedHistory(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	open := f.open(t, 1)
	f.accept(t, f.batch(t, 1, 2))
	finalize := open
	finalize.Kind = "FINALIZE"
	finalize.LastAllocatedSequence = "2"
	if err := telemetry.SignSessionMessage(&finalize, f.private); err != nil {
		t.Fatal(err)
	}
	r, err := f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, finalize)
	if err != nil || !r.Finalized || r.Covered || r.Retired {
		t.Fatal("unknown hole cannot retire", err)
	}
	openReplay, err := f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, open)
	if err != nil || openReplay.Finalized || openReplay.Covered || openReplay.Retired {
		t.Fatal("immutable OPEN receipt changed after FINALIZE", err)
	}
	// Later signed source loss may close coverage, but never proves gateway receipt
	// acknowledgement/ownership retirement. Immutable FINALIZE itself is replayed.
	b := f.batch(t, 1, 1)
	f.accept(t, b)
	r, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, finalize)
	if err != nil || r.Covered || r.Retired {
		t.Fatal("immutable finalization receipt changed", err)
	}
	statusAfterFill, err := f.store.Status(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.request.EnrollmentID)
	if err != nil || !statusAfterFill.Sessions[0].Covered || statusAfterFill.Sessions[0].Retired {
		t.Fatal("status coverage versus ownership", err)
	}
	f.open(t, 2)
	for i := 1; i <= 6; i++ {
		f.accept(t, f.batch(t, 2, i))
	}
	status, err := f.store.Status(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.request.EnrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	records := 0
	truncated := false
	for _, h := range status.History {
		for _, source := range h.Sources {
			records += len(source.Records)
		}
		truncated = truncated || h.RecordsTruncated
	}
	body, _ := json.Marshal(status)
	if records != 16 || !truncated || len(body) > telemetry.MaxStatusBytes {
		t.Fatal("bounded honest status")
	}
	// A different session can finalize with explicit known loss; no invented time
	// bounds/counts are required. No loss fact is promoted into received history.
	next := f.session(t, 3, f.private, f.request.KeyID)
	if _, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, next); err != nil {
		t.Fatal(err)
	}
	next.Kind = "FINALIZE"
	next.LastAllocatedSequence = "3"
	next.Loss = []telemetry.SessionLoss{{SourceID: string(f.request.SourceIDs[0]), Range: telemetry.LossRange{ID: "lost-1-3", AffectedKey: telemetry.BatchKey{ClusterID: string(f.request.ClusterID), NodeID: string(f.request.NodeID), EnrollmentID: f.request.EnrollmentID, SessionEpoch: "3", SessionID: "session-3", Sequence: "1"}, ThroughSequence: "3", Reason: "SPOOL_OVERFLOW"}}}
	_ = telemetry.SignSessionMessage(&next, f.private)
	r, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, next)
	if err != nil || !r.Covered || r.Retired {
		t.Fatal("explicit loss coverage", err)
	}
}

func TestTelemetryAuthorityCompromiseAndAtomicFailure(t *testing.T) {
	t.Run("commit failure is safe and rolls back ownership", func(t *testing.T) {
		f := newTelemetryFixture(t)
		f.open(t, 1)
		ctx := context.Background()
		name := "telemetry_failure_" + strconv.FormatInt(time.Now().UnixNano(), 10)
		f.exec(t, `CREATE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-driver-token-and-source-body'; END $$`)
		f.exec(t, `CREATE TRIGGER `+name+` BEFORE INSERT ON gp06f_telemetry_batches FOR EACH ROW EXECUTE FUNCTION `+name+`()`)
		t.Cleanup(func() {
			_, _ = f.pool.Exec(ctx, `DROP TRIGGER `+name+` ON gp06f_telemetry_batches; DROP FUNCTION `+name+`()`)
		})
		_, err := f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.batch(t, 1, 1), "gateway-1-1")
		if !errors.Is(err, telemetry.ErrUnavailable) || err.Error() != "telemetry storage unavailable" {
			t.Fatal("unsafe driver failure", err)
		}
		status, err := f.store.Status(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.request.EnrollmentID)
		if err != nil || len(status.Receipts) != 0 || len(status.Sessions[0].ReceivedRanges) != 0 || status.Sessions[0].HighestReceivedSequence != "0" {
			t.Fatal("failed commit acknowledged ownership", err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err = f.store.AcceptBatch(canceled, f.request.ClusterID, f.request.GatewayCollectorID, f.batch(t, 1, 1), "gateway-1-1"); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation ignored", err)
		}
	})
	t.Run("compromise denies matching replay", func(t *testing.T) {
		f := newTelemetryFixture(t)
		f.open(t, 1)
		b := f.batch(t, 1, 1)
		f.accept(t, b)
		public, _, _ := ed25519.GenerateKey(rand.Reader)
		if _, err := f.store.RotateKey(context.Background(), f.request.ClusterID, f.request.EnrollmentID, 1, "key-2", base64.RawStdEncoding.EncodeToString(public), "local-operator", true); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AcceptBatch(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, b, "gateway-1-1"); !errors.Is(err, telemetry.ErrUnauthorized) {
			t.Fatal("compromised key replay accepted", err)
		}
	})
	t.Run("future governing inventory rejects old receipt", func(t *testing.T) {
		f := newTelemetryFixture(t)
		f.open(t, 1)
		b := f.batch(t, 1, 1)
		f.accept(t, b)
		goodput, _ := storepg.NewGoodputStore(f.pool)
		at := f.now.Add(time.Hour)
		if _, err := goodput.RecordExpectedInventoryRevision(context.Background(), domain.InventoryRevision{ID: domain.InventoryRevisionID(f.request.InventoryRevisionID + "-future"), SchemaVersion: 1, ClusterID: f.request.ClusterID, SourceID: f.request.SourceIDs[0], SourceAt: at, EffectiveAt: f.now, ObservedAt: f.now, Entities: []domain.EntityIdentity{{ClusterID: f.request.ClusterID, Kind: domain.EntityNode, NodeID: f.request.NodeID}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AcceptBatch(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, b, "gateway-1-1"); !errors.Is(err, telemetry.ErrUnauthorized) {
			t.Fatal("future current inventory fell back to old authority", err)
		}
	})
}

func TestTelemetryMigrationRollbackPreservesHistory(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	f.accept(t, f.batch(t, 1, 1))
	down, err := os.ReadFile("../../../migrations/000077_resident_telemetry.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../migrations/000077_resident_telemetry.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, _ = tx.Exec(ctx, `SAVEPOINT rollback_probe`)
	if _, err = tx.Exec(ctx, string(down)); err == nil {
		t.Fatal("populated rollback deleted telemetry")
	}
	_, _ = tx.Exec(ctx, `ROLLBACK TO rollback_probe`)
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_batches WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&count); err != nil || count != 1 {
		t.Fatal("rollback lost receipt", err)
	}
	// Disposable transaction only: empty down/up proves schema compatibility,
	// and transaction rollback restores every fixture/history row afterwards.
	if _, err = tx.Exec(ctx, `TRUNCATE gp06f_telemetry_enrollments CASCADE`); err != nil {
		t.Fatal(err)
	}
	// The additive identity schema depends on telemetry authority and must be
	// unwound first; its own rollback independently refuses populated history.
	identityDown, err := os.ReadFile("../../../migrations/000078_node_identity.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	identityUp, err := os.ReadFile("../../../migrations/000078_node_identity.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	retirementDown, err := os.ReadFile("../../../migrations/000079_telemetry_retirement.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	retirementUp, err := os.ReadFile("../../../migrations/000079_telemetry_retirement.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(retirementDown)); err != nil {
		t.Fatal("empty retirement rollback", err)
	}
	if _, err = tx.Exec(ctx, string(identityDown)); err != nil {
		t.Fatal("empty identity rollback", err)
	}
	if _, err = tx.Exec(ctx, string(down)); err != nil {
		t.Fatal("empty rollback", err)
	}
	if _, err = tx.Exec(ctx, string(up)); err != nil {
		t.Fatal("re-expansion", err)
	}
	if _, err = tx.Exec(ctx, string(identityUp)); err != nil {
		t.Fatal("identity re-expansion", err)
	}
	if _, err = tx.Exec(ctx, string(retirementUp)); err != nil {
		t.Fatal("retirement re-expansion", err)
	}
}

func TestTelemetryMaximumLossAndUnsignedSequence(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	open := f.open(t, 1)
	batch := f.batch(t, 1, 2)
	for i := 0; i < 256; i++ {
		loss := telemetry.LossRange{ID: fmt.Sprintf("loss-%03d-", i) + strings.Repeat("x", 110), AffectedKey: batch.Key, ThroughSequence: "1", Reason: "SPOOL_EXPIRED", CountKnown: true, Count: "18446744073709551615"}
		loss.AffectedKey.Sequence = "1"
		batch.Sources[0].Loss = append(batch.Sources[0].Loss, loss)
	}
	if err := telemetry.SignBatch(&batch, f.private); err != nil {
		t.Fatal("maximum valid fixture loss", err)
	}
	body, _ := json.Marshal(batch)
	if len(body) > telemetry.MaxNodeBatchBytes {
		t.Fatal("wire bound")
	}
	f.accept(t, batch)
	var storedBytes int
	if err := f.pool.QueryRow(ctx, `SELECT octet_length(body::text) FROM gp06f_telemetry_batches WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&storedBytes); err != nil || storedBytes <= len(body) {
		t.Fatal("separate expanded JSONB representation bound", err)
	}
	// uint64's upper half cannot pass through signed bigint or floating point.
	maximum := f.batch(t, 1, 3)
	maximum.Key.Sequence = "18446744073709551615"
	maximum.Sources[0].Loss = nil
	_ = telemetry.SignBatch(&maximum, f.private)
	f.accept(t, maximum)
	terminal := open
	terminal.Kind = "FINALIZE"
	terminal.LastAllocatedSequence = "18446744073709551615"
	terminal.Loss = []telemetry.SessionLoss{{SourceID: string(f.request.SourceIDs[0]), Range: telemetry.LossRange{ID: "loss-upper-range", AffectedKey: maximum.Key, ThroughSequence: "18446744073709551614", Reason: "SOURCE_LOSS"}}}
	terminal.Loss[0].Range.AffectedKey.Sequence = "3"
	_ = telemetry.SignSessionMessage(&terminal, f.private)
	receipt, err := f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, terminal)
	if err != nil || !receipt.Covered || receipt.Retired {
		t.Fatal("uint64 terminal coverage", err)
	}
	status, err := f.store.Status(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.request.EnrollmentID)
	if err != nil || !status.Sessions[0].LossTruncated || status.Sessions[0].HighestReceivedSequence != "18446744073709551615" || status.History[1].LossCount != 256 || !status.History[1].LossTruncated {
		t.Fatal("bounded maximum loss readback", err)
	}
}
