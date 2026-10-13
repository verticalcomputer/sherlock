package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictWireDecodeRejectsAmbiguousOrOversizeBatch(t *testing.T) {
	body, err := json.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNodeBatch(body, "identity"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(body), `"protocol_version":1`, `"protocol_version":1,"protocol_version":1`, 1)),
		[]byte(strings.Replace(string(body), `"cluster_id":"fixture-cluster"`, `"cluster_id":"fixture-cluster","cluster_id":"foreign"`, 1)),
		[]byte(strings.Replace(string(body), `"protocol_version":1`, `"protocol_version":1,"command":"shell"`, 1)),
		append(append([]byte(nil), body...), body...),
		[]byte(strings.Repeat(" ", MaxBatchBytes+1)),
	} {
		if _, err := DecodeNodeBatch(bad, ""); err == nil {
			t.Fatal("ambiguous/oversize JSON accepted")
		}
	}
	for _, encoding := range []string{"gzip", "deflate", "identity, identity"} {
		if _, err := DecodeNodeBatch(body, encoding); err == nil {
			t.Fatal("unreviewed compression accepted")
		}
	}
}

func TestUnknownLossTimesRemainUnknownAndBindOldSession(t *testing.T) {
	b := fixture()
	old := b.Key
	old.SessionID = "old-session"
	old.Sequence = "8"
	b.Sources[0].Loss = []LossRange{{ID: "loss-a", AffectedKey: old, ThroughSequence: "10", Reason: "SPOOL_EXPIRED", CountKnown: false}}
	want, err := CanonicalDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNodeBatch(body, "")
	if err != nil {
		t.Fatal(err)
	}
	loss := decoded.Sources[0].Loss[0]
	if loss.FromAt != nil || loss.ThroughAt != nil || loss.CountKnown || loss.Count != "" || loss.AffectedKey.SessionID != "old-session" {
		t.Fatal("unknown loss facts manufactured or old session changed")
	}
	at := b.CreatedAt
	b.Sources[0].Loss[0].FromAt = &at
	if _, err := CanonicalDigest(b); err == nil {
		t.Fatal("only one loss time accepted")
	}
	b.Sources[0].Loss[0].ThroughAt = &at
	got, err := CanonicalDigest(b)
	if err != nil || got == want {
		t.Fatal("known loss times failed to change digest", err)
	}
}
