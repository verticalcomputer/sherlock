package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixtureGrant(t *testing.T, at time.Time) (Grant, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Grant{ProtocolVersion: 1, EnrollmentID: "enrollment-a", EnrollmentRevision: 1, ControlRevision: 1, Status: "ACTIVE", ClusterID: "fixture-cluster", NodeID: "node-a", InventoryRevisionID: "inventory-a", GatewayCollectorID: "gateway-a", Sources: []SourceGrant{{SourceID: "fixture-gpu", SchemaVersion: 1, ProfileID: FixtureProfile}}, AgentVersion: "fixture.v1", BuildSHA256: strings.Repeat("a", 64), GatewaySPKISHA256: strings.Repeat("b", 64), Keys: []NodeKey{{ID: "key-a", Epoch: "1", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pub), State: "ACTIVE"}}, NotBefore: at.Add(-time.Second), NotAfter: at.Add(299 * time.Second)}, key
}

func TestGrantClosedScopeKeysAndLease(t *testing.T) {
	at := fixture().CreatedAt
	g, _ := fixtureGrant(t, at)
	if err := ValidateGrant(g, at); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*Grant)
	}{
		{"revoked", func(g *Grant) { g.Status = "REVOKED" }},
		{"expired_exact", func(g *Grant) { g.NotAfter = at }},
		{"future_lease", func(g *Grant) { g.NotBefore = at.Add(time.Nanosecond) }},
		{"overlong_lease", func(g *Grant) { g.NotAfter = g.NotBefore.Add(GrantLease + time.Nanosecond) }},
		{"foreign_profile", func(g *Grant) { g.Sources[0].ProfileID = "gpu.nvml.v1" }},
		{"duplicate_source", func(g *Grant) { g.Sources = append(g.Sources, g.Sources[0]) }},
		{"unknown_schema", func(g *Grant) { g.Sources[0].SchemaVersion = 2 }},
		{"noncanonical_epoch", func(g *Grant) { g.Keys[0].Epoch = "01" }},
		{"invalid_publickey", func(g *Grant) { g.Keys[0].PublicKeyBase64 = "not-key" }},
		{"duplicate_key", func(g *Grant) { g.Keys = append(g.Keys, g.Keys[0]) }},
		{"no_active_key", func(g *Grant) { g.Keys[0].State = "VERIFY_ONLY" }},
		{"three_epochs", func(g *Grant) { g.Keys = append(g.Keys, g.Keys[0], g.Keys[0]) }},
		{"uppercase_hash", func(g *Grant) { g.BuildSHA256 = strings.Repeat("A", 64) }},
		{"invalid_pin", func(g *Grant) { g.GatewaySPKISHA256 = "pin" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := g
			copy.Keys = append([]NodeKey(nil), g.Keys...)
			copy.Sources = append([]SourceGrant(nil), g.Sources...)
			test.edit(&copy)
			if err := ValidateGrant(copy, at); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
}

func TestHistoricalOwnedBatchDoesNotUseFreshLeaseAsSourceTime(t *testing.T) {
	b := fixture()
	at := b.CreatedAt.Add(30 * 24 * time.Hour)
	g, key := fixtureGrant(t, at)
	if err := SignBatch(&b, key); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBatchForGrant(b, g, at); err != nil {
		t.Fatal("old owned history rejected by fresh response lease", err)
	}
	pub, _ := ParseNodePublicKey(g.Keys[0])
	if err := VerifyBatchSignature(b, pub); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*NodeBatch)
	}{
		{"foreign_node", func(b *NodeBatch) { b.Key.NodeID = "node-b" }},
		{"foreign_inventory", func(b *NodeBatch) { b.InventoryRevisionID = "inventory-b" }},
		{"foreign_version", func(b *NodeBatch) { b.AgentVersion = "unapproved" }},
		{"foreign_build", func(b *NodeBatch) { b.BuildSHA256 = strings.Repeat("c", 64) }},
		{"foreign_source", func(b *NodeBatch) { b.Sources[0].SourceID = "unapproved" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			other := fixture()
			test.edit(&other)
			if ValidateBatchForGrant(other, g, at) == nil {
				t.Fatal("foreign authority accepted")
			}
		})
	}
	for _, offset := range []time.Duration{FutureSkew, FutureSkew + time.Nanosecond} {
		future := fixture()
		future.CreatedAt = at.Add(offset)
		future.Sources[0].StartedAt = future.CreatedAt
		future.Sources[0].CompletedAt = future.CreatedAt
		for i := range future.Sources[0].Records {
			future.Sources[0].Records[i].ObservedAt = future.CreatedAt
			future.Sources[0].Records[i].CollectedAt = future.CreatedAt
		}
		err := ValidateBatchForGrant(future, g, at)
		if (err == nil) != (offset == FutureSkew) {
			t.Fatal("future skew boundary wrong", offset, err)
		}
	}
}

func TestFixtureSupportMissingAndFailedRemainDistinct(t *testing.T) {
	b := fixture()
	s := &b.Sources[0]
	s.Status = "PARTIAL"
	s.Coverage.Complete = false
	s.Coverage.Returned = 1
	s.Records = s.Records[:1]
	for i := 1; i < len(s.Fields); i++ {
		s.Fields[i].State = "UNKNOWN"
		s.Fields[i].Reason = "MISSING"
	}
	if err := ValidateNodeBatch(b); err != nil {
		t.Fatal(err)
	}
	s.Fields[1].State = "NOT_SUPPORTED"
	s.Fields[1].Reason = "UNSUPPORTED"
	if err := ValidateNodeBatch(b); err != nil {
		t.Fatal("explicit unsupported rejected", err)
	}
	s.Status = "SUCCEEDED"
	if ValidateNodeBatch(b) == nil {
		t.Fatal("partial coverage claimed complete success")
	}
	s.Status = "FAILED"
	s.Records = nil
	s.Coverage.Returned = 0
	for i := range s.Fields {
		s.Fields[i].State = "UNKNOWN"
		s.Fields[i].Reason = "SOURCE_FAILED"
	}
	if err := ValidateNodeBatch(b); err != nil {
		t.Fatal("failedsource lost explicitunknownfieldassessments", err)
	}
	for _, edit := range []func(*NodeBatch){func(b *NodeBatch) { b.Sources[0].Records[0].EntityKey = "fixture-cluster/GPU/node-a/GPU-a/" }, func(b *NodeBatch) { b.Sources[0].Records[0].Metric = "DCGM_FI_DEV_GPU_TEMP" }, func(b *NodeBatch) { b.Sources[0].Records[1].Value.Unsigned = "9007199254740993.0" }, func(b *NodeBatch) { b.Sources[0].Records[3].Value.Enum = "HEALTHY" }, func(b *NodeBatch) { b.Sources[0].Fields = nil }} {
		other := fixture()
		edit(&other)
		if ValidateNodeBatch(other) == nil {
			t.Fatal("unreviewedfixture/hardwareclaimaccepted")
		}
	}
}

func TestStrictDecoderRejectsCaseAliasesNullScalarsAndEnvelopeOverflow(t *testing.T) {
	body, _ := json.Marshal(fixture())
	for _, bad := range []string{strings.Replace(string(body), `"node_id"`, `"Node_ID"`, 1), strings.Replace(string(body), `"protocol_version":1`, `"protocol_version":null`, 1), strings.Replace(string(body), `"protocol_version":1`, `"protocol_version":1,"Protocol_Version":1`, 1)} {
		if _, err := DecodeNodeBatch([]byte(bad), ""); err == nil {
			t.Fatal("ambiguous identity or nullscalar accepted")
		}
	}
	var envelope CloudBatchEnvelope
	large := []byte(`{"batch":` + string(body) + `,"gateway_receipt_id":"` + strings.Repeat("x", MaxBatchBytes) + `"}`)
	if DecodeStrictJSON(large, "", &envelope) == nil {
		t.Fatal("outer envelope bypassed body limit")
	}
	if DecodeStrictJSON(body, "", nil) == nil {
		t.Fatal("nil destination accepted")
	}
}

func TestNewFixtureFrameHasExactNodeAndCounter(t *testing.T) {
	f, err := NewFixtureFrame("fixture-gpu", "fixture-cluster", "node-a", "sample", fixture().CreatedAt, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Records) != 4 || f.Records[1].Value.Unsigned != "18446744073709551615" {
		t.Fatal("fixturecounterrounded")
	}
	for _, r := range f.Records {
		if r.EntityKey != "fixture-cluster/NODE/node-a//" {
			t.Fatal("fixtureinferredhardwareidentity")
		}
	}
}

func TestLossBudgetAppliesAcrossSources(t *testing.T) {
	b := fixture()
	for i := 0; i < MaxLossRanges; i++ {
		key := b.Key
		key.Sequence = "2"
		b.Sources[0].Loss = append(b.Sources[0].Loss, LossRange{ID: fmt.Sprintf("loss-%03d", i), AffectedKey: key, ThroughSequence: "2", Reason: "SPOOL_EXPIRED", CountKnown: false})
	}
	if err := ValidateNodeBatch(b); err != nil {
		t.Fatal("exact loss budget rejected", err)
	}
	second, err := NewFixtureFrame("fixture-other", b.Key.ClusterID, b.Key.NodeID, "other", b.CreatedAt, 1)
	if err != nil {
		t.Fatal(err)
	}
	key := b.Key
	key.Sequence = "3"
	second.Loss = []LossRange{{ID: "loss-overflow", AffectedKey: key, ThroughSequence: "3", Reason: "SPOOL_EXPIRED", CountKnown: false}}
	b.Sources = append(b.Sources, second)
	if ValidateNodeBatch(b) == nil {
		t.Fatal("per-source limits bypassed total loss bound")
	}
}

func TestSharedIdentifierAndPublicKeyBounds(t *testing.T) {
	for _, id := range []string{"node-a", "node_a", "scope:fixture.v1", strings.Repeat("x", 128)} {
		if !ValidIdentifier(id) {
			t.Fatal("reviewed identifier rejected", id)
		}
	}
	for _, id := range []string{"", "node/alias", "node alias", "node\n", "nödé", strings.Repeat("x", 129)} {
		if ValidIdentifier(id) {
			t.Fatal("noncanonical identifier accepted")
		}
	}
	if _, err := ParseNodePublicKey(NodeKey{PublicKeyBase64: strings.Repeat("A", MaxBatchBytes)}); err == nil {
		t.Fatal("unbounded key input accepted")
	}
}
