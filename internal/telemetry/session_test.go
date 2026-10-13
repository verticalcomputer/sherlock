package telemetry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func sessionFixture() SessionMessage {
	b := fixture()
	return SessionMessage{ProtocolVersion: 1, Kind: "OPEN", ClusterID: b.Key.ClusterID, NodeID: b.Key.NodeID, EnrollmentID: b.Key.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: "1", SessionID: b.Key.SessionID, BootID: b.BootID, SigningKeyID: b.SigningKeyID, CreatedAt: b.CreatedAt}
}

func TestSessionSignedLifecycleAndOldBootLoss(t *testing.T) {
	m := sessionFixture()
	g, key := fixtureGrant(t, m.CreatedAt)
	if err := SignSessionMessage(&m, key); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSessionForGrant(m, g, m.CreatedAt); err != nil {
		t.Fatal(err)
	}
	pub, _ := ParseNodePublicKey(g.Keys[0])
	body, _ := json.Marshal(m)
	decoded, err := DecodeSessionMessage(body, "")
	if err != nil || VerifySessionSignature(decoded, pub) != nil {
		t.Fatal("signedsessiondidnotroundtrip", err)
	}
	for _, edit := range []func(*SessionMessage){func(m *SessionMessage) { m.BootID = "other-boot" }, func(m *SessionMessage) { m.SessionEpoch = "2" }, func(m *SessionMessage) { m.NodeID = "other-node" }} {
		other := m
		edit(&other)
		if VerifySessionSignature(other, pub) == nil {
			t.Fatal("sessionidentitytamperaccepted")
		}
	}
	m.Kind = "FINALIZE"
	m.CreatedAt = m.CreatedAt.Add(time.Minute)
	m.LastAllocatedSequence = "10"
	old := fixture().Key
	old.Sequence = "2"
	m.Loss = []SessionLoss{{SourceID: "fixture-gpu", Range: LossRange{ID: "loss-old-boot", AffectedKey: old, ThroughSequence: "10", Reason: "SPOOL_EXPIRED", CountKnown: false}}}
	if err := SignSessionMessage(&m, key); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSessionForGrant(m, g, m.CreatedAt); err != nil {
		t.Fatal("laterbootcouldnotfinalizeexactoldsessionloss", err)
	}
	if m.BootID != "boot-a" || m.Loss[0].Range.FromAt != nil || m.Loss[0].Range.Count != "" {
		t.Fatal("oldtargetorunknownlossmanufactured")
	}
	m.LastAllocatedSequence = "9"
	if ValidateSessionMessage(m) == nil {
		t.Fatal("lossbeyondterminalsequenceaccepted")
	}
	m.LastAllocatedSequence = ""
	if ValidateSessionMessage(m) == nil {
		t.Fatal("unknownterminalsequenceclaimedfinalization")
	}
	zero := sessionFixture()
	zero.Kind = "FINALIZE"
	zero.LastAllocatedSequence = "0"
	if ValidateSessionMessage(zero) != nil {
		t.Fatal("knownemptyterminalzerorejected")
	}
}

func TestSessionKeyRevocationAndProtocolDomainSeparation(t *testing.T) {
	m := sessionFixture()
	g, key := fixtureGrant(t, m.CreatedAt)
	if err := SignSessionMessage(&m, key); err != nil {
		t.Fatal(err)
	}
	pub, _ := ParseNodePublicKey(g.Keys[0])
	b := fixture()
	if err := SignBatch(&b, key); err != nil {
		t.Fatal(err)
	}
	m.Signature = b.Signature
	if VerifySessionSignature(m, pub) == nil {
		t.Fatal("batchsignatureauthorizedsession")
	}
	if err := SignSessionMessage(&m, key); err != nil {
		t.Fatal(err)
	}
	newKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	g.Keys[0].State = "VERIFY_ONLY"
	g.Keys = append(g.Keys, NodeKey{ID: "key-b", Epoch: "2", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(newKey.Public().(ed25519.PublicKey)), State: "ACTIVE"})
	// Pure validation permits a known OPEN replay. The mandatory store ledger
	// check rejects a new OPEN under this retired key before deduplication.
	if err := ValidateSessionForGrant(m, g, m.CreatedAt); err != nil {
		t.Fatal("knownretiredkeyreplaystructurallyrejected", err)
	}
	g.Keys[0].State = "REVOKED"
	if ValidateSessionForGrant(m, g, m.CreatedAt) == nil {
		t.Fatal("compromisedkeyreplayaccepted")
	}
}
