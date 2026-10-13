package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"math"
	"testing"
	"time"
)

func fixture() NodeBatch {
	at := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	value := 55.0
	flag := false
	b := NodeBatch{ProtocolVersion: 1, Key: BatchKey{ClusterID: "fixture-cluster", NodeID: "node-a", EnrollmentID: "enrollment-a", SessionEpoch: "1", SessionID: "session-a", Sequence: "1"}, EnrollmentRevision: 1, InventoryRevisionID: "inventory-a", BootID: "boot-a", SigningKeyID: "key-a", AgentVersion: "fixture.v1", BuildSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: at}
	s := SourceFrame{SourceID: "fixture-gpu", SchemaVersion: 1, AdapterVersion: FixtureProfile, ProfileID: FixtureProfile, StartedAt: at.Add(-time.Second), CompletedAt: at, Status: "SUCCEEDED", Coverage: Coverage{Expected: 4, Returned: 4, Complete: true}}
	values := []Scalar{{Kind: "float", Float: &value}, {Kind: "unsigned", Unsigned: "18446744073709551615"}, {Kind: "boolean", Boolean: &flag}, {Kind: "enum", Enum: "OK"}}
	for i, m := range fixtureMetrics {
		unit, kind, reset := "1", "gauge", "not_applicable"
		if m == "fixture.counter" {
			unit, kind, reset = "count", "counter", "session_epoch"
		}
		if m == "fixture.state" {
			kind = "state"
		}
		entity := "fixture-cluster/NODE/node-a//"
		s.Fields = append(s.Fields, FieldSupport{EntityKey: entity, Metric: m, State: "SUPPORTED", Reason: "OBSERVED"})
		s.Records = append(s.Records, Record{ID: "sample-" + m, EntityKey: entity, Metric: m, Unit: unit, Kind: kind, Reset: reset, ObservedAt: at, CollectedAt: at, Value: values[i]})
	}
	b.Sources = []SourceFrame{s}
	return b
}

func TestSignatureBindsNodeAndPayload(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	batch := fixture()
	if err := SignBatch(&batch, key); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBatchSignature(batch, pub); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*NodeBatch){func(b *NodeBatch) { b.Key.NodeID = "node-b" }, func(b *NodeBatch) { b.Key.Sequence = "2" }, func(b *NodeBatch) { b.EnrollmentRevision++ }, func(b *NodeBatch) { b.Sources[0].SourceID = "foreign" }, func(b *NodeBatch) { b.Sources[0].Coverage.Complete = false }, func(b *NodeBatch) { b.Sources[0].Records[0].Metric = "foreign" }} {
		other := fixture()
		other.Digest = batch.Digest
		other.Signature = batch.Signature
		change(&other)
		if err := VerifyBatchSignature(other, pub); err == nil {
			t.Fatal("tampered batch signature accepted")
		}
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyBatchSignature(batch, otherPub); err == nil {
		t.Fatal("foreign node key accepted")
	}
}

func TestCanonicalOrderDoesNotMutateInput(t *testing.T) {
	batch := fixture()
	second := batch.Sources[0]
	second.SourceID = "alpha"
	second.Records = append([]Record(nil), second.Records...)
	for i := range second.Records {
		second.Records[i].ID = "other-" + second.Records[i].ID
	}
	batch.Sources = append(batch.Sources, second)
	want, err := CanonicalDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Sources[0].SourceID != "fixture-gpu" {
		t.Fatal("canonicalization mutated input")
	}
	batch.Sources[0], batch.Sources[1] = batch.Sources[1], batch.Sources[0]
	got, err := CanonicalDigest(batch)
	if err != nil || got != want {
		t.Fatal("source order changed digest", err)
	}
	batch.CreatedAt = batch.CreatedAt.In(time.FixedZone("same-instant", 3600))
	got, err = CanonicalDigest(batch)
	if err != nil || got != want {
		t.Fatal("timezone representation changed digest", err)
	}
}

func TestExactScalarsAndMalformedEvidence(t *testing.T) {
	batch := fixture()
	batch.Sources[0].Records[1].Value = Scalar{Kind: "unsigned", Unsigned: "18446744073709551615"}
	before, err := CanonicalDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	batch.Sources[0].Records[1].Value.Unsigned = "18446744073709551614"
	after, err := CanonicalDigest(batch)
	if err != nil || before == after {
		t.Fatal("large counters lost exactness", err)
	}
	for _, change := range []func(*NodeBatch){func(b *NodeBatch) { b.Key.Sequence = "01" }, func(b *NodeBatch) { b.Key.SessionEpoch = "0" }, func(b *NodeBatch) { b.Sources = append(b.Sources, b.Sources[0]) }, func(b *NodeBatch) { b.Sources[0].Records = append(b.Sources[0].Records, b.Sources[0].Records[0]) }, func(b *NodeBatch) { b.Sources[0].Records[0].ObservedAt = b.CreatedAt.Add(time.Nanosecond) }, func(b *NodeBatch) { n := math.NaN(); b.Sources[0].Records[0].Value.Float = &n }, func(b *NodeBatch) { b.Sources[0].Records[0].Value.Unsigned = "1" }} {
		b := fixture()
		change(&b)
		if _, err := CanonicalDigest(b); err == nil {
			t.Fatal("malformed canonical input accepted")
		}
	}
}

func TestNegativeZeroCanonicalizes(t *testing.T) {
	b := fixture()
	zero := 0.0
	b.Sources[0].Records[0].Value.Float = &zero
	want, err := CanonicalDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	negative := math.Copysign(0, -1)
	b.Sources[0].Records[0].Value.Float = &negative
	got, err := CanonicalDigest(b)
	if err != nil || want != got {
		t.Fatal("negative zero changed canonical digest", err)
	}
}
