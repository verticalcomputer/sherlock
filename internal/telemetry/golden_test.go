package telemetry

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"testing"
)

func TestCanonicalV1GoldenVectors(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	b := fixture()
	if err := SignBatch(&b, key); err != nil {
		t.Fatal(err)
	}
	m := sessionFixture()
	if err := SignSessionMessage(&m, key); err != nil {
		t.Fatal(err)
	}
	final := sessionFixture()
	final.Kind = "FINALIZE"
	final.LastAllocatedSequence = "10"
	old := fixture().Key
	old.Sequence = "2"
	final.Loss = []SessionLoss{{SourceID: "fixture-gpu", Range: LossRange{ID: "loss-old-boot", AffectedKey: old, ThroughSequence: "10", Reason: "SPOOL_EXPIRED", CountKnown: false}}}
	if err := SignSessionMessage(&final, key); err != nil {
		t.Fatal(err)
	}
	batchWire, err := os.ReadFile("testdata/node_batch_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := DecodeNodeBatch(batchWire, "")
	if err != nil {
		t.Fatal(err)
	}
	const batchDigest = "be7f6ac3f9dfdc27d268eed7c9af298d8c95a1625eaa6df4deeceb37d8b24a57"
	const sessionDigest = "c6f6cfb7aadc50c8bcd39828b99d733668c921a0e9c5d0ca9abf19b1d1b63c99"
	if batch.Digest != batchDigest || VerifyBatchSignature(batch, key.Public().(ed25519.PublicKey)) != nil || b.Signature != batch.Signature {
		t.Fatal("batchcanonicalencoding/signaturechanged", batch.Digest)
	}
	sessionWire, err := os.ReadFile("testdata/session_open_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	session, err := DecodeSessionMessage(sessionWire, "")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := CanonicalSessionDigest(session)
	if err != nil || hex.EncodeToString(digest[:]) != sessionDigest || VerifySessionSignature(session, key.Public().(ed25519.PublicKey)) != nil || m.Signature != session.Signature {
		t.Fatal("sessioncanonicalencoding/signaturechanged", session.Digest, err)
	}
	finalWire, err := os.ReadFile("testdata/session_finalize_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	decodedFinal, err := DecodeSessionMessage(finalWire, "")
	if err != nil {
		t.Fatal(err)
	}
	const finalDigest = "3dc2f1f3e283727d1fc5a8db2bb46d1e2374d0eb78931037d359e0666c97db7f"
	if decodedFinal.Digest != finalDigest || final.Digest != finalDigest || VerifySessionSignature(decodedFinal, key.Public().(ed25519.PublicKey)) != nil || final.Signature != decodedFinal.Signature {
		t.Fatal("finalization canonical encoding/signature changed", decodedFinal.Digest)
	}
}
