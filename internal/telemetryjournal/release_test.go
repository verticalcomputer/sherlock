package telemetryjournal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type retirementFixture struct {
	*sessionFixture
	node, gateway         *Queue
	nodePath, gatewayPath string
}

func (f *retirementFixture) AuthorizeRetirement(context.Context, Scope) error {
	if f.revoked {
		return telemetry.ErrUnauthorized
	}
	return nil
}
func (f *retirementFixture) VerifyRelease(_ context.Context, e telemetry.ReleaseEnvelope) (ReleaseAuthorization, error) {
	if f.revoked {
		return ReleaseAuthorization{}, telemetry.ErrUnauthorized
	}
	k, ok := f.keys[e.Request.SigningKeyID]
	if !ok || telemetry.VerifyReleaseSignature(e.Request, k.Public().(ed25519.PublicKey)) != nil {
		return ReleaseAuthorization{}, telemetry.ErrInvalid
	}
	return ReleaseAuthorization{SignerActive: f.active[e.Request.SigningKeyID]}, nil
}
func (f *retirementFixture) VerifyCompletion(_ context.Context, c telemetry.NodeReleaseCompletion) (ReleaseAuthorization, error) {
	if f.revoked {
		return ReleaseAuthorization{}, telemetry.ErrUnauthorized
	}
	k, ok := f.keys[c.SigningKeyID]
	if !ok || telemetry.VerifyNodeCompletionSignature(c, k.Public().(ed25519.PublicKey)) != nil {
		return ReleaseAuthorization{}, telemetry.ErrInvalid
	}
	return ReleaseAuthorization{SignerActive: f.active[c.SigningKeyID]}, nil
}
func newRetirementFixture(t *testing.T) *retirementFixture {
	t.Helper()
	f := &retirementFixture{sessionFixture: newSessionFixture()}
	f.options.ReleaseVerifier = f
	f.options.PublicKeys = []telemetry.NodeKey{{ID: "key-a", Epoch: "1", State: "ACTIVE", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(f.keys["key-a"].Public().(ed25519.PublicKey))}, {ID: "key-b", Epoch: "2", State: "ACTIVE", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(f.keys["key-b"].Public().(ed25519.PublicKey))}}
	f.nodePath = filepath.Join(t.TempDir(), "node")
	f.gatewayPath = filepath.Join(t.TempDir(), "gateway")
	o := f.options
	o.Role = Node
	o.Limits = NodeLimits()
	o.Limits.MinimumFree = 0
	f.node = mustOpen(t, f.nodePath, o)
	f.gateway = mustOpen(t, f.gatewayPath, f.options)
	return f
}
func (f *retirementFixture) request(t *testing.T, m telemetry.SessionMessage, proposal ReleaseProposal, id string) telemetry.ReleaseRequest {
	t.Helper()
	d, e := telemetry.CanonicalReleaseManifestDigest(proposal.Manifest)
	if e != nil {
		t.Fatal(e)
	}
	r := telemetry.ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: id, ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: m.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, SigningKeyID: m.SigningKeyID, CreatedAt: testAt, FromSequence: proposal.FromSequence, ThroughSequence: proposal.ThroughSequence, ManifestDigest: hex.EncodeToString(d[:])}
	if e = telemetry.SignReleaseRequest(&r, f.keys[m.SigningKeyID]); e != nil {
		t.Fatal(e)
	}
	return r
}
func (f *retirementFixture) final(t *testing.T, r telemetry.ReleaseRequest, p ReleaseProposal) telemetry.GatewayRetirementReceipt {
	t.Helper()
	if e := f.node.SealRelease(ctx, r, p.Manifest); e != nil {
		t.Fatal("node seal", e)
	}
	a, e := f.gateway.AdmitRelease(ctx, r, p.Manifest)
	if e != nil {
		t.Fatal("gateway admit", e)
	}
	if _, e = f.gateway.PrepareCloudRelease(ctx, r); e != nil {
		t.Fatal("gateway prepare", e)
	}
	prepared := telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: fixtureReleaseID("prepared", r.ReleaseID), Binding: r.Binding(), Phase: "PREPARED", GatewayAdmissionID: a.ID, StoredAt: testAt, Durability: "CLOUD"}
	commit, e := f.gateway.CommitGatewayRelease(ctx, r, prepared)
	if e != nil {
		t.Fatal(e)
	}
	final := prepared
	final.ID = fixtureReleaseID("final", r.ReleaseID)
	final.Phase = "FINAL"
	final.PreparedReceiptID = prepared.ID
	final.GatewayCommitID = commit.ID
	result, e := f.gateway.ConfirmCloudRelease(ctx, r, final)
	if e != nil {
		t.Fatal(e)
	}
	return result
}
func (f *retirementFixture) complete(t *testing.T, r telemetry.ReleaseRequest, final telemetry.GatewayRetirementReceipt) {
	t.Helper()
	sum := sha256.Sum256([]byte("synthetic allocator state"))
	if e := f.node.CompleteNodeRelease(ctx, r, final, 0, func() (string, error) { return hex.EncodeToString(sum[:]), nil }); e != nil {
		t.Fatal(e)
	}
	c := telemetry.NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: fixtureReleaseID("completion", r.ReleaseID), Binding: r.Binding(), CloudFinalReceiptID: final.CloudFinalReceipt.ID, GatewayRetirementReceiptID: final.ID, SigningKeyID: r.SigningKeyID, CreatedAt: testAt}
	if e := telemetry.SignNodeCompletion(&c, f.keys[c.SigningKeyID]); e != nil {
		t.Fatal(e)
	}
	if e := f.node.SealNodeCompletion(ctx, c); e != nil {
		t.Fatal(e)
	}
	if e := f.gateway.AdmitNodeCompletion(ctx, c); e != nil {
		t.Fatal(e)
	}
	cr := telemetry.NodeCompletionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: fixtureReleaseID("completed", r.ReleaseID), Binding: r.Binding(), CompletionDigest: c.Digest, CloudFinalReceiptID: c.CloudFinalReceiptID, GatewayRetirementReceiptID: c.GatewayRetirementReceiptID, StoredAt: testAt, Durability: "CLOUD"}
	if e := f.gateway.ConfirmNodeCompletion(ctx, c, cr); e != nil {
		t.Fatal(e)
	}
	if e := f.node.ConfirmNodeCompletion(ctx, c, cr); e != nil {
		t.Fatal(e)
	}
}
func (f *retirementFixture) handoff(t *testing.T, m telemetry.SessionMessage, seq string) telemetry.Receipt {
	t.Helper()
	body := sessionBody(m, seq)
	mustPut(t, f.node, body)
	gr := mustPut(t, f.gateway, body)
	if e := f.node.Acknowledge(ctx, gr, ""); e != nil {
		t.Fatal(e)
	}
	cloud := gr
	cloud.ID = "cloud-" + seq
	cloud.Durability = "CLOUD"
	if e := f.gateway.Acknowledge(ctx, cloud, gr.ID); e != nil {
		t.Fatal(e)
	}
	return gr
}
func TestReleaseHandshakeCrashReplayAndSevenDayExpiry(t *testing.T) {
	f := newRetirementFixture(t)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, f.node, m)
	mustRegister(t, f.gateway, m)
	gr := f.handoff(t, m, "1")
	p, e := f.node.BuildReleaseManifest(ctx, "1", 4096)
	if e != nil {
		t.Fatal(e)
	}
	r := f.request(t, m, p, "release-one")
	final := f.final(t, r, p)
	crash := errors.New("synthetic allocator crash")
	f.node.opts.fault = func(s string) error {
		if s == "node_allocator_compacted" {
			return crash
		}
		return nil
	}
	calls := 0
	sum := sha256.Sum256([]byte("allocator"))
	callback := func() (string, error) { calls++; return hex.EncodeToString(sum[:]), nil }
	assertError(t, f.node.CompleteNodeRelease(ctx, r, final, 0, callback), crash)
	record, e := f.node.ReleaseStatus(ctx, r.ReleaseID)
	if e != nil || record.Phase != "FINAL_RECEIVED" || record.Final == nil {
		t.Fatal("original final proof not durable", e)
	}
	f.node.Close()
	o := f.options
	o.Role = Node
	o.Limits = NodeLimits()
	o.Limits.MinimumFree = 0
	f.node = mustOpen(t, f.nodePath, o)
	if e = f.node.CompleteNodeRelease(ctx, r, final, 0, callback); e != nil {
		t.Fatal(e)
	}
	if calls != 2 {
		t.Fatal("allocator replay missing", calls)
	}
	got, e := f.node.LookupOwnership(ctx, gr.Key)
	if e != nil || got.Disposition != OwnershipTransferred {
		t.Fatal("compacted transfer mistaken for absence", got, e)
	}
	wrong := gr.Key
	wrong.SessionID = "wrong-session"
	_, e = f.node.LookupOwnership(ctx, wrong)
	assertError(t, e, ErrConflict)
	f.complete(t, r, final)
	f.gateway.opts.Now = func() time.Time { return testAt.Add(8 * 24 * time.Hour) }
	count, e := f.gateway.PruneRetiredReceipts(ctx, testAt.Add(7*24*time.Hour-time.Nanosecond), 128)
	if e != nil || count != 0 {
		t.Fatal("receipt expired early", count, e)
	}
	if got := mustPut(t, f.gateway, sessionBody(m, "1")); got != gr {
		t.Fatal("exact replay changed")
	}
	count, e = f.gateway.PruneRetiredReceipts(ctx, testAt.Add(7*24*time.Hour), 128)
	if e != nil || count != 1 {
		t.Fatal("receipt not expired at horizon", count, e)
	}
	got, e = f.gateway.LookupOwnership(ctx, gr.Key)
	if e != nil || got.Disposition != OwnershipExpired {
		t.Fatal("expired receipt mistaken for absence", got, e)
	}
	_, e = f.gateway.Put(ctx, sessionBody(m, "1"))
	assertError(t, e, ErrReceiptExpired)
	mustPut(t, f.gateway, sessionBody(m, "2"))
	f.gateway.Close()
	f.options.Now = func() time.Time { return testAt.Add(8 * 24 * time.Hour) }
	f.gateway = mustOpen(t, f.gatewayPath, f.options)
	f.revoked = true
	_, e = f.gateway.AdmitRelease(ctx, r, p.Manifest)
	assertError(t, e, telemetry.ErrUnauthorized)
}
func TestReleaseUnknownHoleAndReceiptMismatchRemainUnsealed(t *testing.T) {
	f := newRetirementFixture(t)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, f.node, m)
	mustRegister(t, f.gateway, m)
	f.handoff(t, m, "2")
	if _, e := f.node.BuildReleaseManifest(ctx, "1", 4096); !errors.Is(e, ErrNotFound) {
		t.Fatal("unknown first hole manufactured", e)
	}
	f.handoff(t, m, "1")
	p, e := f.node.BuildReleaseManifest(ctx, "1", 4096)
	if e != nil {
		t.Fatal(e)
	}
	p.Manifest.Batches[0].GatewayReceiptID = "foreign-receipt"
	r := f.request(t, m, p, "release-bad")
	assertError(t, f.node.SealRelease(ctx, r, p.Manifest), ErrConflict)
}
func TestLookupOwnershipPreservesExactLocalLoss(t *testing.T) {
	f := newRetirementFixture(t)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, f.node, m)
	key := mustPut(t, f.node, sessionBody(m, "1")).Key
	if e := f.node.RecordLoss(ctx, key, "NODE_EXPIRED"); e != nil {
		t.Fatal(e)
	}
	got, e := f.node.LookupOwnership(ctx, key)
	if e != nil || got.Entry == nil || got.Entry.Loss == nil || got.Entry.Loss.Reason != "NODE_EXPIRED" || got.Entry.Loss.Count != nil {
		t.Fatal("local loss evidence absent or invented", got, e)
	}
}

func TestFinalizedSessionTurnoverRequiresCloudLifecycleHandoff(t *testing.T) {
	f := newRetirementFixture(t)
	for epoch := 1; epoch <= 9; epoch++ {
		m := f.message(t, "OPEN", epoch, "boot-"+strconv.Itoa(epoch), "key-a", "")
		mustRegister(t, f.node, m)
		mustRegister(t, f.gateway, m)
		final := f.message(t, "FINALIZE", epoch, m.BootID, "key-a", "0")
		nr := mustRegister(t, f.node, final)
		gr := mustRegister(t, f.gateway, final)
		if e := f.node.AcknowledgeSession(ctx, final, gr); e != nil {
			t.Fatal(e)
		}
		p, e := f.node.BuildReleaseManifest(ctx, m.SessionEpoch, 4096)
		if e != nil {
			t.Fatal(e)
		}
		r := f.request(t, m, p, "empty-"+m.SessionEpoch)
		proof := f.final(t, r, p)
		f.complete(t, r, proof)
		if e = f.gateway.CompactGatewaySessions(ctx); e != nil {
			t.Fatal(e)
		}
		base, e := f.gateway.SessionRetirementBase(ctx)
		if e != nil || base != strconv.Itoa(epoch-1) {
			t.Fatal("gateway deleted unhanded FINALIZE", base, e)
		}
		cloud := gr
		cloud.ID = "cloud-final-" + m.SessionEpoch
		cloud.Durability = "CLOUD"
		cloud.Retired = true
		cloud.Covered = true
		if e = f.gateway.AcknowledgeSession(ctx, final, cloud); e != nil {
			t.Fatal(e)
		}
		if e = f.gateway.CompactGatewaySessions(ctx); e != nil {
			t.Fatal(e)
		}
		hash := sha256.Sum256([]byte("allocator-base-" + m.SessionEpoch))
		if e = f.node.CompactFinalizedSessions(ctx, 0, func(b string) (string, error) {
			if b != m.SessionEpoch {
				t.Fatal("wrong allocator base", b)
			}
			return hex.EncodeToString(hash[:]), nil
		}); e != nil {
			t.Fatal(e)
		}
		if base, e = f.gateway.SessionRetirementBase(ctx); e != nil || base != m.SessionEpoch {
			t.Fatal("gateway base failed", base, e)
		}
		_ = nr
	}
	f.node.Close()
	o := f.options
	o.Role = Node
	o.Limits = NodeLimits()
	o.Limits.MinimumFree = 0
	f.node = mustOpen(t, f.nodePath, o)
	f.gateway.Close()
	f.gateway = mustOpen(t, f.gatewayPath, f.options)
	if base, e := f.node.SessionRetirementBase(ctx); e != nil || base != "9" {
		t.Fatal("node retired base lost", base, e)
	}
}
func TestFinalizeOnlyLossRequiresExactUpstreamHandoff(t *testing.T) {
	f := newRetirementFixture(t)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, f.node, m)
	mustRegister(t, f.gateway, m)
	final := f.message(t, "FINALIZE", 1, "boot-a", "key-a", "4")
	final.Loss = []telemetry.SessionLoss{testSourceLoss(m, "final-only-gap", "1", "4")}
	if e := telemetry.SignSessionMessage(&final, f.keys["key-a"]); e != nil {
		t.Fatal(e)
	}
	mustRegister(t, f.node, final)
	gr := mustRegister(t, f.gateway, final)
	if _, e := f.node.BuildReleaseManifest(ctx, "1", 4096); !errors.Is(e, ErrNotFound) {
		t.Fatal("unhanded final loss retired", e)
	}
	if e := f.node.AcknowledgeSession(ctx, final, gr); e != nil {
		t.Fatal(e)
	}
	p, e := f.node.BuildReleaseManifest(ctx, "1", 4096)
	if e != nil || p.ThroughSequence != "4" || len(p.Manifest.Loss) != 1 {
		t.Fatal("final-only gap unavailable", p, e)
	}
	r := f.request(t, m, p, "final-loss")
	if e = f.node.SealRelease(ctx, r, p.Manifest); e != nil {
		t.Fatal(e)
	}
	// Gateway admission can rely on its durable local FINALIZE, but this current
	// implementation conservatively awaits the exact cloud lifecycle handoff.
	_, e = f.gateway.AdmitRelease(ctx, r, p.Manifest)
	assertError(t, e, ErrRole)
	cr := gr
	cr.ID = "cloud-final-loss"
	cr.Durability = "CLOUD"
	if e = f.gateway.AcknowledgeSession(ctx, final, cr); e != nil {
		t.Fatal(e)
	}
	proof := f.final(t, r, p)
	f.complete(t, r, proof)
	got, e := f.node.LookupOwnership(ctx, sessionBatch(m, "2").Key)
	if e != nil || got.Disposition != OwnershipLoss {
		t.Fatal("explicit lost allocation became absent", got, e)
	}
	f.node.Close()
	o := f.options
	o.Role = Node
	o.Limits = NodeLimits()
	o.Limits.MinimumFree = 0
	f.node = mustOpen(t, f.nodePath, o)
}

func TestRetirementRecoveryMissingFinalFailsBeforePayloadMutation(t *testing.T) {
	f := newRetirementFixture(t)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, f.node, m)
	mustRegister(t, f.gateway, m)
	f.handoff(t, m, "1")
	p, e := f.node.BuildReleaseManifest(ctx, "1", 4096)
	if e != nil {
		t.Fatal(e)
	}
	r := f.request(t, m, p, "corrupt-final")
	proof := f.final(t, r, p)
	f.complete(t, r, proof)
	owned := mustPut(t, f.gateway, sessionBody(m, "2"))
	id, _ := keyID(owned.Key)
	ownedPath := f.gateway.path(id)
	before, e := os.ReadFile(ownedPath)
	if e != nil {
		t.Fatal(e)
	}
	record, e := f.gateway.ReleaseStatus(ctx, r.ReleaseID)
	if e != nil {
		t.Fatal(e)
	}
	record.Final = nil
	body, _ := json.Marshal(record)
	if _, e = f.gateway.db.Exec(`UPDATE release_ledger SET body=? WHERE id=?`, body, r.ReleaseID); e != nil {
		t.Fatal(e)
	}
	f.gateway.Close()
	_, e = Open(f.gatewayPath, f.options)
	assertError(t, e, ErrCorrupt)
	after, e := os.ReadFile(ownedPath)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("corrupt retirement erased owned payload")
	}
}
func TestSchemaTwoRefusalPreservesInitializedBytes(t *testing.T) {
	o := testOptions(Node)
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, o)
	mustPut(t, q, testBody(1, Data, "preserve"))
	q.Close()
	markerPath := filepath.Join(path, "identity.json")
	b, e := os.ReadFile(markerPath)
	if e != nil {
		t.Fatal(e)
	}
	b = bytes.Replace(b, []byte(`"Version":3`), []byte(`"Version":2`), 1)
	if e = os.WriteFile(markerPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	dbBefore, e := os.ReadFile(filepath.Join(path, "metadata.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = Open(path, o)
	assertError(t, e, ErrCorrupt)
	dbAfter, e := os.ReadFile(filepath.Join(path, "metadata.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadFile(markerPath)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(dbBefore, dbAfter) || !bytes.Equal(b, after) {
		t.Fatal("schema refusal mutated initialized evidence")
	}
}
func TestHistoricalPublicKeyArchiveImmutableAndIntegrityOnly(t *testing.T) {
	f := newRetirementFixture(t)
	f.node.Close()
	o := f.options
	o.Role = Node
	o.Limits = NodeLimits()
	o.Limits.MinimumFree = 0
	o.PublicKeys = []telemetry.NodeKey{{ID: "key-a", Epoch: "1", State: "ACTIVE", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(f.keys["key-a"].Public().(ed25519.PublicKey))}}
	f.node = mustOpen(t, f.nodePath, o)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, f.node, m)
	f.node.Close()
	o.PublicKeys = []telemetry.NodeKey{{ID: "key-b", Epoch: "2", State: "ACTIVE", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(f.keys["key-b"].Public().(ed25519.PublicKey))}}
	f.node = mustOpen(t, f.nodePath, o)
	keys, e := f.node.GetHistoricalPublicKeys(ctx)
	if e != nil || len(keys) != 2 {
		t.Fatal("archive lost historical identity", keys, e)
	}
	for _, k := range keys {
		if k.State != "ARCHIVED" {
			t.Fatal("archive conferred authorization", k.State)
		}
	}
	f.node.Close()
	o.PublicKeys[0].ID = "key-a"
	_, e = Open(f.nodePath, o)
	assertError(t, e, ErrConflict)
}

func TestCarrierFirstRetirementPreservesOlderSessionLossHandoff(t *testing.T) {
	f := newRetirementFixture(t)
	old := f.message(t, "OPEN", 1, "old-boot", "key-a", "")
	newer := f.message(t, "OPEN", 2, "new-boot", "key-a", "")
	for _, m := range []telemetry.SessionMessage{old, newer} {
		mustRegister(t, f.node, m)
		mustRegister(t, f.gateway, m)
	}
	loss := testSourceLoss(old, "older-gap", "1", "1")
	body := lossBody(newer, "1", loss)
	mustPut(t, f.node, body)
	gr := mustPut(t, f.gateway, body)
	if e := f.node.Acknowledge(ctx, gr, ""); e != nil {
		t.Fatal(e)
	}
	cr := gr
	cr.ID = "cloud-carrier"
	cr.Durability = "CLOUD"
	if e := f.gateway.Acknowledge(ctx, cr, gr.ID); e != nil {
		t.Fatal(e)
	}
	p, e := f.node.BuildReleaseManifest(ctx, "2", 4096)
	if e != nil {
		t.Fatal(e)
	}
	r := f.request(t, newer, p, "carrier-first")
	proof := f.final(t, r, p)
	f.complete(t, r, proof)
	f.gateway.opts.Now = func() time.Time { return testAt.Add(8 * 24 * time.Hour) }
	if n, e := f.gateway.PruneRetiredReceipts(ctx, testAt.Add(7*24*time.Hour), 128); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	f.node.Close()
	o := f.options
	o.Role = Node
	o.Limits = NodeLimits()
	o.Limits.MinimumFree = 0
	f.node = mustOpen(t, f.nodePath, o)
	f.gateway.Close()
	f.options.Now = func() time.Time { return testAt.Add(8 * 24 * time.Hour) }
	f.gateway = mustOpen(t, f.gatewayPath, f.options)
	p, e = f.node.BuildReleaseManifest(ctx, "1", 4096)
	if e != nil || len(p.Manifest.Loss) != 1 {
		t.Fatal("carrier reclamation orphaned older loss", p, e)
	}
	r = f.request(t, old, p, "older-later")
	proof = f.final(t, r, p)
	f.complete(t, r, proof)
}

func TestMaximumReleaseFactsPhysicalAdmissionAndBackpressure(t *testing.T) {
	f := newRetirementFixture(t)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, f.node, m)
	mustRegister(t, f.gateway, m)
	for i := 1; i <= 256; i++ {
		f.handoff(t, m, strconv.Itoa(i))
	}
	losses := make([]telemetry.SessionLoss, 0, 256)
	for i := 1; i <= 256; i++ {
		l := testSourceLoss(m, strings.Repeat("l", 122)+fmt.Sprintf("%06d", i), strconv.Itoa(i), strconv.Itoa(i))
		l.Range.Reason = "SPOOL_EXPIRED"
		losses = append(losses, l)
	}
	body := lossBody(m, "257", losses...)
	mustPut(t, f.node, body)
	gr := mustPut(t, f.gateway, body)
	if e := f.node.Acknowledge(ctx, gr, ""); e != nil {
		t.Fatal(e)
	}
	cloud := gr
	cloud.ID = "cloud-max-loss"
	cloud.Durability = "CLOUD"
	if e := f.gateway.Acknowledge(ctx, cloud, gr.ID); e != nil {
		t.Fatal(e)
	}
	p, e := f.node.BuildReleaseManifest(ctx, "1", 4096)
	if e != nil || len(p.Manifest.Batches) != 256 {
		t.Fatal("maximum batch facts unavailable", len(p.Manifest.Batches), e)
	}
	for _, l := range losses {
		d, e := telemetry.CanonicalLossDigest(l)
		if e != nil {
			t.Fatal(e)
		}
		p.Manifest.Loss = append(p.Manifest.Loss, telemetry.ReleaseLossRef{SourceID: l.SourceID, LossID: l.Range.ID, Digest: hex.EncodeToString(d[:])})
	}
	r := f.request(t, m, p, strings.Repeat("r", 128))
	proof := f.final(t, r, p)
	f.complete(t, r, proof)
	ns, e := f.node.Stats(ctx)
	if e != nil {
		t.Fatal(e)
	}
	gs, e := f.gateway.Stats(ctx)
	if e != nil {
		t.Fatal(e)
	}
	physicalFiles := func(q *Queue) (int64, int64) {
		var db, wal int64
		for _, name := range []string{"metadata.sqlite", "metadata.sqlite-wal"} {
			info, e := os.Stat(filepath.Join(q.root, name))
			if e == nil {
				stat := info.Sys().(*syscall.Stat_t)
				if name == "metadata.sqlite" {
					db = stat.Blocks * 512
				} else {
					wal = stat.Blocks * 512
				}
			}
		}
		return db, wal
	}
	nd, nw := physicalFiles(f.node)
	gd, gw := physicalFiles(f.gateway)
	t.Logf("selected_batch_facts=256 selected_loss_facts=256 node_physical=%d gateway_physical=%d node_sqlite_blocks_bytes=%d node_wal_blocks_bytes=%d gateway_sqlite_blocks_bytes=%d gateway_wal_blocks_bytes=%d", ns.PhysicalBytes, gs.PhysicalBytes, nd, nw, gd, gw)
	if ns.PhysicalBytes > NodeLimits().Total || gs.PhysicalBytes > GatewayLimits().Total {
		t.Fatal("physical budget exceeded")
	}
	// Lower this fixture's existing metadata category to its currently allocated
	// usage. A new mutation must backpressure without disturbing the accepted proof.
	f.gateway.opts.Limits.Metadata = gd + gw
	_, e = f.gateway.Put(ctx, sessionBody(m, "258"))
	assertError(t, e, ErrCapacity)
	current, e := f.gateway.ReleaseStatus(ctx, r.ReleaseID)
	if e != nil || current.Phase != "COMPLETE" || current.CompletionReceipt == nil {
		t.Fatal("backpressure removed accepted proof", e)
	}
}

func TestOrphanAndHistoricalIntegrityCorruptionPreserveOwnedPayload(t *testing.T) {
	for _, kind := range []string{"orphan-prefix", "orphan-range", "advanced-base", "unused-public-key", "session-signature"} {
		t.Run(kind, func(t *testing.T) {
			f := newRetirementFixture(t)
			m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
			mustRegister(t, f.gateway, m)
			receipt := mustPut(t, f.gateway, sessionBody(m, "1"))
			id, _ := keyID(receipt.Key)
			path := f.gateway.path(id)
			before, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "orphan-prefix":
				_, e = f.gateway.db.Exec(`INSERT INTO release_prefix VALUES('2','0','0','0',0)`)
			case "orphan-range":
				_, e = f.gateway.db.Exec(`INSERT INTO ownership_ranges VALUES('2','TRANSFERRED','1','1')`)
			case "advanced-base":
				_, e = f.gateway.db.Exec(`UPDATE retirement_state SET retired_epoch='1'`)
			case "unused-public-key":
				_, e = f.gateway.db.Exec(`INSERT INTO public_keys VALUES('unused','3','malformed')`)
			case "session-signature":
				m.Signature = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				b, _ := json.Marshal(m)
				_, e = f.gateway.db.Exec(`UPDATE sessions SET open=? WHERE epoch='1'`, b)
			}
			if e != nil {
				t.Fatal(e)
			}
			f.gateway.Close()
			_, e = Open(f.gatewayPath, f.options)
			assertError(t, e, ErrCorrupt)
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("corruption altered owned payload", e)
			}
		})
	}
}

func fixtureReleaseID(prefix, id string) string {
	d := sha256.Sum256([]byte(id))
	return prefix + "-" + hex.EncodeToString(d[:16])
}

func TestCompletionRetryFinishesBoundedRecentLedgerCompaction(t *testing.T) {
	f := newRetirementFixture(t)
	m := f.message(t, "OPEN", 1, "boot-a", "key-a", "")
	mustRegister(t, f.node, m)
	mustRegister(t, f.gateway, m)
	for i := 1; i <= 9; i++ {
		f.handoff(t, m, strconv.Itoa(i))
		p, e := f.node.BuildReleaseManifest(ctx, "1", 1)
		if e != nil {
			t.Fatal(e)
		}
		r := f.request(t, m, p, "prefix-"+strconv.Itoa(i))
		proof := f.final(t, r, p)
		if i < 9 {
			f.complete(t, r, proof)
			continue
		}
		sum := sha256.Sum256([]byte("allocator-nine"))
		if e = f.node.CompleteNodeRelease(ctx, r, proof, 0, func() (string, error) { return hex.EncodeToString(sum[:]), nil }); e != nil {
			t.Fatal(e)
		}
		c := telemetry.NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: "completion-nine", Binding: r.Binding(), CloudFinalReceiptID: proof.CloudFinalReceipt.ID, GatewayRetirementReceiptID: proof.ID, SigningKeyID: "key-a", CreatedAt: testAt}
		if e = telemetry.SignNodeCompletion(&c, f.keys["key-a"]); e != nil {
			t.Fatal(e)
		}
		if e = f.node.SealNodeCompletion(ctx, c); e != nil {
			t.Fatal(e)
		}
		if e = f.gateway.AdmitNodeCompletion(ctx, c); e != nil {
			t.Fatal(e)
		}
		cr := telemetry.NodeCompletionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "completed-nine", Binding: r.Binding(), CompletionDigest: c.Digest, CloudFinalReceiptID: c.CloudFinalReceiptID, GatewayRetirementReceiptID: c.GatewayRetirementReceiptID, StoredAt: testAt, Durability: "CLOUD"}
		crash := errors.New("synthetic post-completion failure")
		f.gateway.opts.fault = func(s string) error {
			if s == "node_completion_recorded" {
				return crash
			}
			return nil
		}
		assertError(t, f.gateway.ConfirmNodeCompletion(ctx, c, cr), crash)
		f.gateway.opts.fault = nil
		if e = f.gateway.ConfirmNodeCompletion(ctx, c, cr); e != nil {
			t.Fatal("exact retry failed to finish recent compaction", e)
		}
		var count int
		if e = f.gateway.db.QueryRow(`SELECT count(*) FROM release_ledger WHERE phase='COMPLETE'`).Scan(&count); e != nil || count != 8 {
			t.Fatal("recent records leaked after retry", count, e)
		}
		if e = f.node.ConfirmNodeCompletion(ctx, c, cr); e != nil {
			t.Fatal(e)
		}
	}
	f.gateway.Close()
	f.gateway = mustOpen(t, f.gatewayPath, f.options)
}
