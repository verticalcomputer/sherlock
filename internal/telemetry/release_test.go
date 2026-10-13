package telemetry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func releaseFixture(t *testing.T) (ReleaseEnvelope, ed25519.PrivateKey) {
	t.Helper()
	b := fixture()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	m := ReleaseManifest{Batches: []ReleaseBatchFact{{Sequence: "1", Digest: b.BuildSHA256, GatewayReceiptID: "gateway-receipt-1"}}}
	d, err := CanonicalReleaseManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	r := ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: "release-1", ClusterID: b.Key.ClusterID, NodeID: b.Key.NodeID, EnrollmentID: b.Key.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: b.Key.SessionEpoch, SessionID: b.Key.SessionID, SigningKeyID: b.SigningKeyID, CreatedAt: b.CreatedAt, FromSequence: "1", ThroughSequence: "1", ManifestDigest: hex.EncodeToString(d[:])}
	if err := SignReleaseRequest(&r, key); err != nil {
		t.Fatal(err)
	}
	return ReleaseEnvelope{Request: r, Manifest: m}, key
}

func resignManifest(t *testing.T, e *ReleaseEnvelope, key ed25519.PrivateKey) {
	t.Helper()
	d, err := CanonicalReleaseManifestDigest(e.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	e.Request.ManifestDigest = hex.EncodeToString(d[:])
	if err := SignReleaseRequest(&e.Request, key); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseSignatureScopeAndSeparateCompletionDomain(t *testing.T) {
	e, key := releaseFixture(t)
	if e.Request.Digest != "c55f001e70b81bddadad527b08157dc9ea2b2977f24bcc64244e2f190a713a95" || e.Request.Signature != "GMZC4hhSTDhjy/eL0hav1X962cWjDFiLiGWhKsRzH6letixT1+i4dS/cTYYZvQwGAXqUaZ+nnEBPCk4MwqBPCA" {
		t.Fatal("release v1 canonical vector changed")
	}
	pub := key.Public().(ed25519.PublicKey)
	if VerifyReleaseSignature(e.Request, pub) != nil || ValidateReleaseEnvelope(e) != nil {
		t.Fatal("valid release rejected")
	}
	for _, edit := range []func(*ReleaseRequest){
		func(r *ReleaseRequest) { r.NodeID = "foreign" },
		func(r *ReleaseRequest) { r.ReleaseID = "release-2" },
		func(r *ReleaseRequest) { r.FromSequence = "2"; r.ThroughSequence = "2" },
		func(r *ReleaseRequest) { r.SessionEpoch = "2" },
		func(r *ReleaseRequest) { r.ManifestDigest = fmt.Sprintf("%064x", 9) },
	} {
		r := e.Request
		edit(&r)
		if VerifyReleaseSignature(r, pub) == nil {
			t.Fatal("mutated release authenticated")
		}
	}
	c := NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: "completion-1", Binding: e.Request.Binding(), CloudFinalReceiptID: "cloud-final-1", GatewayRetirementReceiptID: "gateway-final-1", SigningKeyID: e.Request.SigningKeyID, CreatedAt: e.Request.CreatedAt}
	if SignNodeCompletion(&c, key) != nil || VerifyNodeCompletionSignature(c, pub) != nil {
		t.Fatal("valid completion rejected")
	}
	if c.Digest != "1bd5e9192b155bc62de71217bc18760fde54e8e8e78e65717566ef0ed95a0e9e" || c.Signature != "3Sg0voa0tzp9x++u4ZzwM7jbois/uYfVe28QN+NQbkR61wxpN6QQ97K3WB3eSX1BvDSYZF/6kNDlp23vGFpLDw" {
		t.Fatal("node completion v1 canonical vector changed")
	}
	c.Signature = e.Request.Signature
	if VerifyNodeCompletionSignature(c, pub) == nil {
		t.Fatal("release signature authenticated completion")
	}
	if SignNodeCompletion(&c, key) != nil {
		t.Fatal("sign completion")
	}
	c.CloudFinalReceiptID = "cloud-final-foreign"
	if VerifyNodeCompletionSignature(c, pub) == nil {
		t.Fatal("changed final receipt authenticated")
	}
	// Canonical instants are independent of the JSON timezone spelling.
	r := e.Request
	r.CreatedAt = r.CreatedAt.In(time.FixedZone("IST", 19800))
	if VerifyReleaseSignature(r, pub) != nil {
		t.Fatal("equivalent instant changed signature")
	}
}

func TestReleaseSelectedProofPreservesUnknownHolesAndSourceCoverage(t *testing.T) {
	e, key := releaseFixture(t)
	e.Request.ThroughSequence = "3"
	e.Manifest.Batches = append(e.Manifest.Batches, ReleaseBatchFact{Sequence: "3", Digest: e.Manifest.Batches[0].Digest, GatewayReceiptID: "gateway-receipt-3"})
	resignManifest(t, &e, key)
	if ProveReleaseCoverage(e.Request, e.Manifest, []string{"a", "b"}, nil) == nil {
		t.Fatal("highest receipt filled absent sequence")
	}
	loss := func(source string) SessionLoss {
		k := fixture().Key
		k.Sequence = "2"
		return SessionLoss{SourceID: source, Range: LossRange{ID: "loss-" + source, AffectedKey: k, ThroughSequence: "2", Reason: "SPOOL_EXPIRED", CountKnown: false}}
	}
	a, b := loss("a"), loss("b")
	add := func(l SessionLoss) {
		d, err := CanonicalLossDigest(l)
		if err != nil {
			t.Fatal(err)
		}
		e.Manifest.Loss = append(e.Manifest.Loss, ReleaseLossRef{SourceID: l.SourceID, LossID: l.Range.ID, Digest: hex.EncodeToString(d[:])})
	}
	add(a)
	resignManifest(t, &e, key)
	if ProveReleaseCoverage(e.Request, e.Manifest, []string{"a", "b"}, []SessionLoss{a}) == nil {
		t.Fatal("single source loss filled missing second source")
	}
	add(b)
	resignManifest(t, &e, key)
	if err := ProveReleaseCoverage(e.Request, e.Manifest, []string{"a", "b"}, []SessionLoss{b, a}); err != nil {
		t.Fatal(err)
	}
	b.Range.CountKnown = true
	b.Range.Count = "0"
	if ProveReleaseCoverage(e.Request, e.Manifest, []string{"a", "b"}, []SessionLoss{a, b}) == nil {
		t.Fatal("unknown count changed into known zero")
	}
	b = loss("b")
	b.Range.AffectedKey.SessionID = "foreign-session"
	if ProveReleaseCoverage(e.Request, e.Manifest, []string{"a", "b"}, []SessionLoss{a, b}) == nil {
		t.Fatal("foreign loss filled hole")
	}
	// A selected partial-source batch receipt proves ownership of that batch;
	// the proof makes no assertion about measured source coverage.
	single, _ := releaseFixture(t)
	if ProveReleaseCoverage(single.Request, single.Manifest, []string{"a", "b"}, nil) != nil {
		t.Fatal("batch transfer treated as per-source coverage")
	}
}

func TestReleaseBoundsStrictWireAndUint64End(t *testing.T) {
	e, key := releaseFixture(t)
	for _, pair := range [][2]string{{"0", "1"}, {"01", "1"}, {"2", "1"}, {"1", "4097"}, {"18446744073709551616", "18446744073709551616"}} {
		r := e.Request
		r.FromSequence, r.ThroughSequence = pair[0], pair[1]
		if ValidateReleaseRequest(r) == nil {
			t.Fatalf("invalid range accepted: %v", pair)
		}
	}
	e.Request.FromSequence, e.Request.ThroughSequence = "18446744073709551615", "18446744073709551615"
	e.Manifest.Batches[0].Sequence = e.Request.FromSequence
	resignManifest(t, &e, key)
	if ProveReleaseCoverage(e.Request, e.Manifest, []string{"a"}, nil) != nil {
		t.Fatal("exact uint64 terminal rejected")
	}
	body, _ := json.Marshal(e)
	if _, err := DecodeReleaseEnvelope(body, "identity"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(body, []byte(`"release_version":1`), []byte(`"Release_version":1`), 1),
		bytes.Replace(body, []byte(`"release_version":1`), []byte(`"release_version":1,"release_version":1`), 1),
		append(body, []byte(` {}`)...),
		bytes.Repeat([]byte{' '}, MaxReleaseBytes+1),
	} {
		if _, err := DecodeReleaseEnvelope(bad, ""); err == nil {
			t.Fatal("ambiguous/unbounded envelope accepted")
		}
	}
	if _, err := DecodeReleaseEnvelope(body, "gzip"); err == nil {
		t.Fatal("compressed input accepted")
	}
	e.Manifest.Batches = []ReleaseBatchFact{{Sequence: "2", Digest: e.Manifest.Batches[0].Digest, GatewayReceiptID: "r2"}, {Sequence: "1", Digest: e.Manifest.Batches[0].Digest, GatewayReceiptID: "r1"}}
	if ValidateReleaseManifest(e.Manifest) == nil {
		t.Fatal("nonnumeric manifest order accepted")
	}
}

func TestReleaseEmptyOwnershipProofAndReceiptPhaseBinding(t *testing.T) {
	e, key := releaseFixture(t)
	e.Request.FromSequence, e.Request.ThroughSequence = "0", "0"
	e.Manifest = ReleaseManifest{}
	resignManifest(t, &e, key)
	if ProveReleaseCoverage(e.Request, e.Manifest, []string{"a"}, nil) != nil {
		t.Fatal("empty proof rejected; caller must verify finalized terminal zero")
	}
	p := CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "prepared-1", Phase: "PREPARED", Binding: e.Request.Binding(), GatewayAdmissionID: "admission-1", StoredAt: e.Request.CreatedAt, Durability: "CLOUD"}
	if ValidateCloudRetirementReceipt(p) != nil {
		t.Fatal("prepared shape")
	}
	final := p
	final.ID = "final-1"
	final.Phase = "FINAL"
	final.PreparedReceiptID = p.ID
	final.GatewayCommitID = "commit-1"
	r := GatewayRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "gateway-final-1", Binding: e.Request.Binding(), GatewayAdmissionID: p.GatewayAdmissionID, PreparedReceiptID: p.ID, GatewayCommitID: final.GatewayCommitID, CloudFinalReceipt: final, StoredAt: e.Request.CreatedAt, Durability: "GATEWAY"}
	r.ID, _ = GatewayRetirementReceiptID(final)
	if ValidateGatewayRetirementReceipt(r) != nil {
		t.Fatal("valid final binding")
	}
	r.CloudFinalReceipt = p
	if ValidateGatewayRetirementReceipt(r) == nil {
		t.Fatal("prepared receipt retired ownership")
	}
	r.CloudFinalReceipt = final
	r.CloudFinalReceipt.Binding.SessionID = "foreign"
	if ValidateGatewayRetirementReceipt(r) == nil {
		t.Fatal("foreign final receipt retired ownership")
	}
	c := SupportedRetirementCapabilities()
	c.ReleaseVersion = 0
	if ValidateRetirementCapabilities(c) == nil {
		t.Fatal("unsupported capability permitted pruning")
	}
}
