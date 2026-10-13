//go:build integration

package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func telemetryRelease(t *testing.T, f *telemetryFixture, epoch, first, last int, manifest telemetry.ReleaseManifest) (telemetry.ReleaseRequest, telemetry.ReleaseAdmissionReceipt) {
	t.Helper()
	d, err := telemetry.CanonicalReleaseManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	request := telemetry.ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: fmt.Sprintf("release-%d-%d-%d", epoch, first, last), ClusterID: string(f.request.ClusterID), NodeID: string(f.request.NodeID), EnrollmentID: f.request.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: strconv.Itoa(epoch), SessionID: fmt.Sprintf("session-%d", epoch), SigningKeyID: f.request.KeyID, CreatedAt: f.now, FromSequence: strconv.Itoa(first), ThroughSequence: strconv.Itoa(last), ManifestDigest: hex.EncodeToString(d[:])}
	if err = telemetry.SignReleaseRequest(&request, f.private); err != nil {
		t.Fatal(err)
	}
	return request, telemetry.ReleaseAdmissionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "gateway-admit-" + request.ReleaseID, Binding: request.Binding(), StoredAt: f.now, Durability: "GATEWAY"}
}
func telemetryCommit(t *testing.T, f *telemetryFixture, request telemetry.ReleaseRequest, prepared telemetry.CloudRetirementReceipt) telemetry.GatewayReleaseCommit {
	t.Helper()
	return telemetry.GatewayReleaseCommit{ProtocolVersion: 1, ReleaseVersion: 1, ID: "gateway-commit-" + request.ReleaseID, Binding: request.Binding(), GatewayAdmissionID: prepared.GatewayAdmissionID, PreparedReceiptID: prepared.ID, CreatedAt: f.now}
}
func telemetryCompletion(t *testing.T, f *telemetryFixture, request telemetry.ReleaseRequest, final telemetry.CloudRetirementReceipt) telemetry.NodeReleaseCompletion {
	t.Helper()
	id, err := telemetry.GatewayRetirementReceiptID(final)
	if err != nil {
		t.Fatal(err)
	}
	c := telemetry.NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: "node-complete-" + request.ReleaseID, Binding: request.Binding(), CloudFinalReceiptID: final.ID, GatewayRetirementReceiptID: id, SigningKeyID: f.request.KeyID, CreatedAt: f.now}
	if err = telemetry.SignNodeCompletion(&c, f.private); err != nil {
		t.Fatal(err)
	}
	return c
}
func telemetryRetireRange(t *testing.T, f *telemetryFixture, epoch, first, last int, manifest telemetry.ReleaseManifest) (telemetry.ReleaseRequest, telemetry.ReleaseAdmissionReceipt, telemetry.CloudRetirementReceipt, telemetry.GatewayReleaseCommit, telemetry.CloudRetirementReceipt, telemetry.NodeReleaseCompletion) {
	t.Helper()
	ctx := context.Background()
	request, admit := telemetryRelease(t, f, epoch, first, last, manifest)
	prepared, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit)
	if err != nil {
		t.Fatal("prepare retirement", err)
	}
	commit := telemetryCommit(t, f, request, prepared)
	final, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit)
	if err != nil {
		t.Fatal("commit retirement", err)
	}
	completion := telemetryCompletion(t, f, request, final)
	if _, err = f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion); err != nil {
		t.Fatal("complete retirement", err)
	}
	return request, admit, prepared, commit, final, completion
}
func telemetryFinalize(t *testing.T, f *telemetryFixture, epoch, end int) telemetry.SessionReceipt {
	t.Helper()
	m := f.session(t, epoch, f.private, f.request.KeyID)
	m.Kind = "FINALIZE"
	m.LastAllocatedSequence = strconv.Itoa(end)
	if err := telemetry.SignSessionMessage(&m, f.private); err != nil {
		t.Fatal(err)
	}
	r, err := f.store.RegisterSession(context.Background(), f.request.ClusterID, f.request.GatewayCollectorID, m)
	if err != nil {
		t.Fatal("finalize", err)
	}
	return r
}
func telemetryBatchManifest(b telemetry.NodeBatch, r telemetry.CloudReceipt) telemetry.ReleaseManifest {
	return telemetry.ReleaseManifest{Batches: []telemetry.ReleaseBatchFact{{Sequence: b.Key.Sequence, Digest: b.Digest, GatewayReceiptID: r.GatewayReceiptID}}}
}

func TestTelemetryRetirementDurablePhasesAndLiveFinalize(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	batch := f.batch(t, 1, 1)
	cloud := f.accept(t, batch)
	manifest := telemetryBatchManifest(batch, cloud)
	request, admit := telemetryRelease(t, f, 1, 1, 1, manifest)
	capabilities, err := f.store.RetirementCapabilities(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.request.EnrollmentID)
	if err != nil || telemetry.ValidateRetirementCapabilities(capabilities) != nil {
		t.Fatal("capabilities", err)
	}
	prepared, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit)
	if err != nil {
		t.Fatal(err)
	}
	commit := telemetryCommit(t, f, request, prepared)
	final, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit)
	if err != nil {
		t.Fatal(err)
	}
	var completed, retired bool
	if err = f.pool.QueryRow(ctx, `SELECT node_completed_through>0,retired_at IS NOT NULL FROM gp06f_telemetry_sessions WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&completed, &retired); err != nil || completed || retired {
		t.Fatal("FINAL cannot prove node completion", err)
	}
	bad := telemetryCompletion(t, f, request, final)
	bad.GatewayRetirementReceiptID = "unbound-gateway-final"
	_ = telemetry.SignNodeCompletion(&bad, f.private)
	if _, err = f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, bad); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("unbound gateway proof", err)
	}
	completion := telemetryCompletion(t, f, request, final)
	receipt, err := f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion)
	if err != nil {
		t.Fatal(err)
	}
	// Replayed phases return the original immutable receipts after completion.
	again, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit)
	if err != nil || !reflect.DeepEqual(again, prepared) {
		t.Fatal("immutable prepared replay", err)
	}
	again, err = f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit)
	if err != nil || !reflect.DeepEqual(again, final) {
		t.Fatal("immutable final replay", err)
	}
	replay, err := f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion)
	if err != nil || !reflect.DeepEqual(replay, receipt) {
		t.Fatal("immutable completion replay", err)
	}
	if r := telemetryFinalize(t, f, 1, 1); !r.Retired {
		t.Fatal("late FINALIZE must recognize already completed terminal")
	}
	status, err := f.store.Status(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.request.EnrollmentID)
	if err != nil || !status.Sessions[0].Retired || len(status.History) != 1 {
		t.Fatal("retirement readback preserves original history", err)
	}
	if r := f.accept(t, batch); !reflect.DeepEqual(r, cloud) {
		t.Fatal("original immutable batch receipt changed")
	}
	var observations int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM observations WHERE cluster_id=$1`, f.request.ClusterID).Scan(&observations); err != nil || observations != 0 {
		t.Fatal("ownership never creates health observations", err)
	}
}

func TestTelemetryRetirementProofHolesAndPreparedFences(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	carrier := f.batch(t, 1, 2)
	loss := telemetry.LossRange{ID: "missing-first-allocation", AffectedKey: carrier.Key, ThroughSequence: "1", Reason: "SOURCE_LOSS"}
	loss.AffectedKey.Sequence = "1"
	carrier.Sources[0].Loss = []telemetry.LossRange{loss}
	_ = telemetry.SignBatch(&carrier, f.private)
	received := f.accept(t, carrier)
	hole := telemetryBatchManifest(carrier, received)
	request, admit := telemetryRelease(t, f, 1, 1, 2, hole)
	if _, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, hole, admit); err == nil {
		t.Fatal("unknown ownership hole accepted")
	}
	fact := telemetry.SessionLoss{SourceID: string(f.request.SourceIDs[0]), Range: loss}
	digest, err := telemetry.CanonicalLossDigest(fact)
	if err != nil {
		t.Fatal(err)
	}
	manifest := telemetry.ReleaseManifest{Loss: []telemetry.ReleaseLossRef{{SourceID: fact.SourceID, LossID: loss.ID, Digest: hex.EncodeToString(digest[:])}}}
	request, admit = telemetryRelease(t, f, 1, 1, 1, manifest)
	if _, err = f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.batch(t, 1, 1), "late-original"); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("prepared range accepted missing original", err)
	}
	unknown := f.batch(t, 1, 3)
	newLoss := loss
	newLoss.ID = "new-intersecting-loss"
	newLoss.Reason = "SPOOL_EXPIRED"
	unknown.Sources[0].Loss = []telemetry.LossRange{newLoss}
	_ = telemetry.SignBatch(&unknown, f.private)
	if _, err = f.store.AcceptBatch(ctx, f.request.ClusterID, f.request.GatewayCollectorID, unknown, "unknown-loss-carrier"); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("prepared range accepted new loss fact", err)
	}
	unknown.Sources[0].Loss = []telemetry.LossRange{loss}
	_ = telemetry.SignBatch(&unknown, f.private)
	f.accept(t, unknown)
	bad := admit
	bad.ID = "conflicting-admission"
	if _, err = f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, bad); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("conflicting admission replay", err)
	}
}

func TestTelemetryRetirementRecentBoundAndExpiredProof(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	var first telemetry.ReleaseRequest
	var admit telemetry.ReleaseAdmissionReceipt
	var manifest telemetry.ReleaseManifest
	var commit telemetry.GatewayReleaseCommit
	var completion telemetry.NodeReleaseCompletion
	for i := 1; i <= 9; i++ {
		batch := f.batch(t, 1, i)
		receipt := f.accept(t, batch)
		m := telemetryBatchManifest(batch, receipt)
		r, a, _, c, _, n := telemetryRetireRange(t, f, 1, i, i, m)
		if i == 1 {
			first = r
			admit = a
			manifest = m
			commit = c
			completion = n
		}
	}
	if _, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, first, manifest, admit); !errors.Is(err, telemetry.ErrReplayExpired) {
		t.Fatal("old prepared replay outcome", err)
	}
	if _, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, first, commit); !errors.Is(err, telemetry.ErrReplayExpired) {
		t.Fatal("old final replay outcome", err)
	}
	if _, err := f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion); !errors.Is(err, telemetry.ErrReplayExpired) {
		t.Fatal("old completion replay outcome", err)
	}
	var count, raw int
	var expired string
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM gp06f_telemetry_retirements WHERE enrollment_id=$1),(SELECT count(*) FROM gp06f_telemetry_batches WHERE enrollment_id=$1),retirement_receipts_expired_through::text FROM gp06f_telemetry_sessions WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&count, &raw, &expired); err != nil || count != 8 || raw != 9 || expired != "1" {
		t.Fatal("bounded proof and retained raw history", count, raw, expired, err)
	}
}

func TestTelemetryRetirementConcurrentReplayAndRevocation(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	batch := f.batch(t, 1, 1)
	r := f.accept(t, batch)
	manifest := telemetryBatchManifest(batch, r)
	request, admit := telemetryRelease(t, f, 1, 1, 1, manifest)
	var wg sync.WaitGroup
	results := make(chan telemetry.CloudRetirementReceipt, 6)
	failures := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit)
			if e != nil {
				failures <- e
			} else {
				results <- r
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal("concurrent prepare", e)
	}
	var expected *telemetry.CloudRetirementReceipt
	for r := range results {
		if expected == nil {
			copy := r
			expected = &copy
		} else if !reflect.DeepEqual(*expected, r) {
			t.Fatal("concurrent prepare changed receipt")
		}
	}
	if _, err := f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "fixture-operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("revocation bypassed on replay", err)
	}
	if _, err := f.store.RetirementCapabilities(ctx, f.request.ClusterID, f.request.GatewayCollectorID, f.request.EnrollmentID); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("revoked capability", err)
	}
}

func TestTelemetryRetirementSessionAndKeyTurnover(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	telemetryFinalize(t, f, 1, 0)
	_, _, _, _, _, _ = telemetryRetireRange(t, f, 1, 0, 0, telemetry.ReleaseManifest{})
	public, key2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.store.RotateKey(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "node-key-2", base64.RawStdEncoding.EncodeToString(public), "fixture-operator", false)
	if err != nil {
		t.Fatal(err)
	}
	nextPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.RotateKey(ctx, f.request.ClusterID, f.request.EnrollmentID, grant.ControlRevision, "node-key-3", base64.RawStdEncoding.EncodeToString(nextPublic), "fixture-operator", false); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("vacuous successor proof reclaimed key", err)
	}
	successor := f.session(t, 2, key2, "node-key-2")
	if _, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, successor); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.RotateKey(ctx, f.request.ClusterID, f.request.EnrollmentID, grant.ControlRevision, "old-material-new-id", f.request.PublicKeyBase64, "fixture-operator", false); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("archived material became new signing authority", err)
	}
	grant, err = f.store.RotateKey(ctx, f.request.ClusterID, f.request.EnrollmentID, grant.ControlRevision, "node-key-3", base64.RawStdEncoding.EncodeToString(nextPublic), "fixture-operator", false)
	if err != nil || len(grant.Keys) != 2 || grant.Keys[1].Epoch != "3" {
		t.Fatal("qualified key3", grant.Keys, err)
	}
	var archived bool
	var keys int
	if err = f.pool.QueryRow(ctx, `SELECT archived_at IS NOT NULL,(SELECT count(*) FROM gp06f_telemetry_keys WHERE enrollment_id=$1) FROM gp06f_telemetry_keys WHERE enrollment_id=$1 AND key_id=$2`, f.request.EnrollmentID, f.request.KeyID).Scan(&archived, &keys); err != nil || !archived || keys != 3 {
		t.Fatal("immutable archived identity", err)
	}
}

func TestTelemetryRetirementEightSessionsRequireNodeCompletion(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		f.open(t, i)
		telemetryFinalize(t, f, i, 0)
	}
	ninth := f.session(t, 9, f.private, f.request.KeyID)
	if _, err := f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, ninth); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("session9 without ownership proof", err)
	}
	request, admit := telemetryRelease(t, f, 1, 0, 0, telemetry.ReleaseManifest{})
	prepared, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, telemetry.ReleaseManifest{}, admit)
	if err != nil {
		t.Fatal(err)
	}
	commit := telemetryCommit(t, f, request, prepared)
	final, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, ninth); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("cloud FINAL alone reclaimed session", err)
	}
	if _, err = f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, telemetryCompletion(t, f, request, final)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.RegisterSession(ctx, f.request.ClusterID, f.request.GatewayCollectorID, ninth); err != nil {
		t.Fatal("qualified session9", err)
	}
}

func TestTelemetryRetirementAtomicFailureAndRollbackPreservesProofs(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	batch := f.batch(t, 1, 1)
	receipt := f.accept(t, batch)
	manifest := telemetryBatchManifest(batch, receipt)
	request, admit := telemetryRelease(t, f, 1, 1, 1, manifest)
	prepared, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit)
	if err != nil {
		t.Fatal(err)
	}
	// A real SQL constraint failure after proof preparation must roll back both
	// publication and prefix progress and expose only a fixed safe error.
	f.exec(t, `ALTER TABLE gp06f_telemetry_retirements ADD CONSTRAINT retirement_fixture_failure CHECK(final_at IS NULL) NOT VALID`)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `ALTER TABLE gp06f_telemetry_retirements DROP CONSTRAINT IF EXISTS retirement_fixture_failure`)
	})
	commit := telemetryCommit(t, f, request, prepared)
	if _, err = f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit); !errors.Is(err, telemetry.ErrUnavailable) {
		t.Fatal("injected transaction failure", err)
	}
	f.exec(t, `ALTER TABLE gp06f_telemetry_retirements DROP CONSTRAINT retirement_fixture_failure`)
	var final bool
	var prefix string
	if err = f.pool.QueryRow(ctx, `SELECT r.final_at IS NOT NULL,s.released_through::text FROM gp06f_telemetry_retirements r JOIN gp06f_telemetry_sessions s USING(enrollment_id,session_epoch) WHERE r.enrollment_id=$1`, f.request.EnrollmentID).Scan(&final, &prefix); err != nil || final || prefix != "0" {
		t.Fatal("failure leaked partial ownership progress", err)
	}
	finalReceipt, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, telemetryCompletion(t, f, request, finalReceipt)); err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000079_telemetry_retirement.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../migrations/000079_telemetry_retirement.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SAVEPOINT retirement_rollback_probe`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err == nil {
		t.Fatal("populated rollback removed proofs")
	}
	if _, err = tx.Exec(ctx, `ROLLBACK TO retirement_rollback_probe`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM gp06f_telemetry_retirements WHERE enrollment_id=$1`, f.request.EnrollmentID); err == nil {
		t.Fatal("receipt deleted without expiry prefix")
	}
	if _, err = tx.Exec(ctx, `ROLLBACK TO retirement_rollback_probe`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_retirements WHERE enrollment_id=$1`, f.request.EnrollmentID).Scan(&count); err != nil || count != 1 {
		t.Fatal("rollback lost proof", err)
	}
	// Empty rollback is explicitly disposable; the outer rollback restores all
	// authority and fixture history after qualifying both schema directions.
	if _, err = tx.Exec(ctx, `TRUNCATE gp06f_telemetry_enrollments CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err != nil {
		t.Fatal("empty79 down", err)
	}
	if _, err = tx.Exec(ctx, string(up)); err != nil {
		t.Fatal("empty79 up", err)
	}
}

func TestTelemetryRetirementInventoryAuthorityBeforeReplay(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	batch := f.batch(t, 1, 1)
	receipt := f.accept(t, batch)
	manifest := telemetryBatchManifest(batch, receipt)
	request, admit, _, commit, final, completion := telemetryRetireRange(t, f, 1, 1, 1, manifest)
	goodput, _ := storepg.NewGoodputStore(f.pool)
	if _, err := goodput.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{ID: domain.InventoryRevisionID(f.request.InventoryRevisionID + "-future"), SchemaVersion: 1, ClusterID: f.request.ClusterID, SourceID: f.request.SourceIDs[0], SourceAt: f.now.Add(time.Hour), EffectiveAt: f.now, ObservedAt: f.now, Entities: []domain.EntityIdentity{{ClusterID: f.request.ClusterID, Kind: domain.EntityNode, NodeID: f.request.NodeID}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("inventory bypass on prepared replay", err)
	}
	if _, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("inventory bypass on final replay", err)
	}
	if _, err := f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("inventory bypass on completion replay", err)
	}
	_ = final
}

func TestTelemetryRetirementSignerAndFutureFences(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	f.open(t, 1)
	batch := f.batch(t, 1, 1)
	receipt := f.accept(t, batch)
	manifest := telemetryBatchManifest(batch, receipt)
	request, admit := telemetryRelease(t, f, 1, 1, 1, manifest)
	future := request
	future.CreatedAt = f.now.Add(time.Hour)
	_ = telemetry.SignReleaseRequest(&future, f.private)
	futureBinding := admit
	futureBinding.Binding = future.Binding()
	if _, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, future, manifest, futureBinding); err == nil {
		t.Fatal("future signed request accepted")
	}
	futureAdmit := admit
	futureAdmit.StoredAt = f.now.Add(time.Hour)
	if _, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, futureAdmit); err == nil {
		t.Fatal("future gateway admission accepted")
	}
	prepared, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit)
	if err != nil {
		t.Fatal(err)
	}
	public, nextKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.RotateKey(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "node-key-2", base64.RawStdEncoding.EncodeToString(public), "fixture-operator", false); err != nil {
		t.Fatal(err)
	}
	if replay, err := f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, manifest, admit); err != nil || !reflect.DeepEqual(replay, prepared) {
		t.Fatal("known VERIFY_ONLY release replay", err)
	}
	introduced := request
	introduced.ReleaseID = "new-release-from-verify-only"
	_ = telemetry.SignReleaseRequest(&introduced, f.private)
	newAdmission := admit
	newAdmission.Binding = introduced.Binding()
	newAdmission.ID = "new-gateway-admission"
	if _, err = f.store.PrepareRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, introduced, manifest, newAdmission); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("VERIFY_ONLY introduced new release", err)
	}
	commit := telemetryCommit(t, f, request, prepared)
	futureCommit := commit
	futureCommit.CreatedAt = f.now.Add(time.Hour)
	if _, err = f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, futureCommit); err == nil {
		t.Fatal("future commit accepted")
	}
	final, err := f.store.CommitRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, request, commit)
	if err != nil {
		t.Fatal(err)
	}
	completion := telemetryCompletion(t, f, request, final)
	if _, err = f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("VERIFY_ONLY introduced node completion", err)
	}
	completion.SigningKeyID = "node-key-2"
	_ = telemetry.SignNodeCompletion(&completion, nextKey)
	if _, err = f.store.CompleteRetirement(ctx, f.request.ClusterID, f.request.GatewayCollectorID, completion); err != nil {
		t.Fatal("ACTIVE successor completes known old session", err)
	}
}
