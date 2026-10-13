package telemetry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"math"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const FixtureProfile = "fixture.v1"
const FutureSkew = 30 * time.Second
const GrantLease = 5 * time.Minute

func validID(v string) bool {
	if len(v) < 1 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

// ValidIdentifier is the shared exact wire grammar for protected operator input,
// gateway receipts and immutable telemetry IDs. It grants no authority.
func ValidIdentifier(value string) bool { return validID(value) }
func validDigest(v string) bool {
	p, err := hex.DecodeString(v)
	return err == nil && len(p) == 32 && hex.EncodeToString(p) == v
}
func decimal(v string, zero bool) (uint64, bool) {
	n, err := strconv.ParseUint(v, 10, 64)
	return n, err == nil && strconv.FormatUint(n, 10) == v && (zero || n != 0)
}
func validInstant(v time.Time) bool { return !v.IsZero() && v.Year() >= 2020 && v.Year() <= 2200 }
func validKey(k BatchKey) bool {
	_, epoch := decimal(k.SessionEpoch, false)
	_, seq := decimal(k.Sequence, false)
	return validID(k.ClusterID) && validID(k.NodeID) && validID(k.EnrollmentID) && validID(k.SessionID) && epoch && seq
}

// ValidateGrant checks a currently issued response lease and its closed source
// and key contracts. It does not prove that inventory/membership remain current;
// the authenticated store must establish those facts before issuing the lease.
func ValidateGrant(g Grant, at time.Time) error {
	if g.ProtocolVersion != ProtocolVersion || !validID(g.EnrollmentID) || g.EnrollmentRevision != 1 || g.ControlRevision < 1 || g.Status != "ACTIVE" || !validID(g.ClusterID) || !validID(g.NodeID) || !validID(g.InventoryRevisionID) || !validID(g.GatewayCollectorID) || !validID(g.AgentVersion) || !validDigest(g.BuildSHA256) || !validDigest(g.GatewaySPKISHA256) || !validInstant(at) || !validInstant(g.NotBefore) || !validInstant(g.NotAfter) || at.Before(g.NotBefore) || !at.Before(g.NotAfter) || !g.NotAfter.After(g.NotBefore) || g.NotAfter.Sub(g.NotBefore) > GrantLease {
		return ErrInvalidBatch
	}
	if len(g.Sources) < 1 || len(g.Sources) > MaxSources || len(g.Keys) < 1 || len(g.Keys) > 2 {
		return ErrInvalidBatch
	}
	sources := map[string]bool{}
	for _, s := range g.Sources {
		if !validID(s.SourceID) || sources[s.SourceID] || s.SchemaVersion != 1 || !KnownProfile(s.ProfileID) {
			return ErrInvalidBatch
		}
		sources[s.SourceID] = true
	}
	ids, epochs, pubs := map[string]bool{}, map[uint64]bool{}, map[string]bool{}
	active := 0
	var activeEpoch uint64
	for _, k := range g.Keys {
		epoch, ok := decimal(k.Epoch, false)
		_, err := ParseNodePublicKey(k)
		if !validID(k.ID) || ids[k.ID] || !ok || epochs[epoch] || err != nil || pubs[k.PublicKeyBase64] {
			return ErrInvalidBatch
		}
		ids[k.ID] = true
		epochs[epoch] = true
		pubs[k.PublicKeyBase64] = true
		switch k.State {
		case "ACTIVE":
			active++
			activeEpoch = epoch
		case "VERIFY_ONLY", "REVOKED":
		default:
			return ErrInvalidBatch
		}
	}
	if active != 1 {
		return ErrInvalidBatch
	}
	for _, k := range g.Keys {
		epoch, _ := decimal(k.Epoch, false)
		if k.State != "ACTIVE" && epoch >= activeEpoch {
			return ErrInvalidBatch
		}
	}
	return nil
}

var fixtureMetrics = []string{"fixture.gauge", "fixture.counter", "fixture.flag", "fixture.state"}

// ValidateNodeBatch checks closed source schemas, not authentication or live
// qualification. Intake history is separate from ordinary health projections.
func ValidateNodeBatch(b NodeBatch) error {
	if b.ProtocolVersion != ProtocolVersion || !validKey(b.Key) || b.EnrollmentRevision != 1 || !validID(b.InventoryRevisionID) || !validID(b.BootID) || !validID(b.SigningKeyID) || !validID(b.AgentVersion) || !validDigest(b.BuildSHA256) || !validInstant(b.CreatedAt) || len(b.Sources) < 1 || len(b.Sources) > MaxSources {
		return ErrInvalidBatch
	}
	identity, err := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: domain.ClusterID(b.Key.ClusterID), Kind: domain.EntityNode, NodeID: domain.StableNodeID(b.Key.NodeID)})
	if err != nil {
		return ErrInvalidBatch
	}
	entity := identity.Key()
	sources, recordIDs, lossIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	total, lossTotal := 0, 0
	for _, s := range b.Sources {
		if !validID(s.SourceID) || sources[s.SourceID] || s.SchemaVersion != 1 || s.AdapterVersion != s.ProfileID || !KnownProfile(s.ProfileID) || !validInstant(s.StartedAt) || !validInstant(s.CompletedAt) || s.CompletedAt.Before(s.StartedAt) || s.CompletedAt.After(b.CreatedAt) || len(s.Fields) != len(ProfileFields(s.ProfileID)) || s.Coverage.Expected != int64(len(s.Fields)) || s.Coverage.Returned != int64(len(s.Records)) || len(s.Records) > len(s.Fields) || len(s.Loss) > MaxLossRanges {
			return ErrInvalidBatch
		}
		sources[s.SourceID] = true
		fields := map[string]FieldSupport{}
		for _, f := range s.Fields {
			if f.EntityKey != entity || fields[f.Metric].Metric != "" || !profileMetric(s.ProfileID, f.Metric) || !supportState(f.State) || !supportReason(f.Reason) {
				return ErrInvalidBatch
			}
			if f.State == "SUPPORTED" && f.Reason != "OBSERVED" || f.State == "NOT_SUPPORTED" && f.Reason != "UNSUPPORTED" || f.State == "UNKNOWN" && (f.Reason == "OBSERVED" || f.Reason == "UNSUPPORTED") {
				return ErrInvalid
			}
			fields[f.Metric] = f
		}
		metrics := map[string]bool{}
		for _, r := range s.Records {
			if !validID(r.ID) || recordIDs[r.ID] || metrics[r.Metric] || r.EntityKey != entity || fields[r.Metric].State != "SUPPORTED" || !validInstant(r.ObservedAt) || !r.CollectedAt.Equal(s.CompletedAt) || r.ObservedAt.After(r.CollectedAt) || !profileRecord(s.ProfileID, r) {
				return ErrInvalidBatch
			}
			recordIDs[r.ID] = true
			metrics[r.Metric] = true
			total++
		}
		if total > MaxRecords {
			return ErrInvalidBatch
		}
		for metric, field := range fields {
			if (field.State == "SUPPORTED") != metrics[metric] {
				return ErrInvalid
			}
		}
		switch s.Status {
		case "SUCCEEDED":
			if len(s.Records) != len(s.Fields) || !s.Coverage.Complete {
				return ErrInvalidBatch
			}
		case "PARTIAL":
			if len(s.Records) < 1 || len(s.Records) >= len(s.Fields) || s.Coverage.Complete {
				return ErrInvalidBatch
			}
		case "FAILED", "NO_DATA":
			if len(s.Records) != 0 || s.Coverage.Complete {
				return ErrInvalidBatch
			}
		default:
			return ErrInvalidBatch
		}
		for _, l := range s.Loss {
			lossTotal++
			if lossTotal > MaxLossRanges {
				return ErrInvalid
			}
			if lossIDs[l.ID] || validateLoss(l, b.Key.ClusterID, b.Key.NodeID, b.Key.EnrollmentID) != nil || l.ThroughAt != nil && l.ThroughAt.After(b.CreatedAt) {
				return ErrInvalidBatch
			}
			lossIDs[l.ID] = true
		}
	}
	return nil
}

func supportState(v string) bool { return v == "SUPPORTED" || v == "UNKNOWN" || v == "NOT_SUPPORTED" }
func supportReason(v string) bool {
	switch v {
	case "OBSERVED", "MISSING", "SOURCE_FAILED", "ACCESS_DENIED", "TIMEOUT", "UNSUPPORTED":
		return true
	}
	return false
}
func fixtureRecord(r Record) bool {
	if r.ResetObserved && r.Metric != "fixture.counter" {
		return false
	}
	switch r.Metric {
	case "fixture.gauge":
		return r.Unit == "1" && r.Kind == "gauge" && r.Reset == "not_applicable" && r.Value.Kind == "float" && r.Value.Float != nil && !math.IsNaN(*r.Value.Float) && !math.IsInf(*r.Value.Float, 0) && r.Value.Unsigned == "" && r.Value.Boolean == nil && r.Value.Enum == ""
	case "fixture.counter":
		_, ok := decimal(r.Value.Unsigned, true)
		return r.Unit == "count" && r.Kind == "counter" && r.Reset == "session_epoch" && r.Value.Kind == "unsigned" && ok && r.Value.Float == nil && r.Value.Boolean == nil && r.Value.Enum == ""
	case "fixture.flag":
		return r.Unit == "1" && r.Kind == "gauge" && r.Reset == "not_applicable" && r.Value.Kind == "boolean" && r.Value.Boolean != nil && r.Value.Float == nil && r.Value.Unsigned == "" && r.Value.Enum == ""
	case "fixture.state":
		return r.Unit == "1" && r.Kind == "state" && r.Reset == "not_applicable" && r.Value.Kind == "enum" && (r.Value.Enum == "OK" || r.Value.Enum == "FAULT" || r.Value.Enum == "UNKNOWN") && r.Value.Float == nil && r.Value.Unsigned == "" && r.Value.Boolean == nil
	}
	return false
}

func validateLoss(l LossRange, cluster, node, enrollment string) error {
	from, ok := decimal(l.AffectedKey.Sequence, false)
	through, ok2 := decimal(l.ThroughSequence, false)
	if !validID(l.ID) || !validKey(l.AffectedKey) || l.AffectedKey.ClusterID != cluster || l.AffectedKey.NodeID != node || l.AffectedKey.EnrollmentID != enrollment || !ok || !ok2 || through < from || (l.FromAt == nil) != (l.ThroughAt == nil) || l.FromAt != nil && (!validInstant(*l.FromAt) || !validInstant(*l.ThroughAt) || l.ThroughAt.Before(*l.FromAt)) {
		return ErrInvalidBatch
	}
	switch l.Reason {
	case "SPOOL_OVERFLOW", "SPOOL_EXPIRED", "SOURCE_LOSS", "STORAGE_CORRUPTION":
	default:
		return ErrInvalidBatch
	}
	if l.CountKnown {
		if _, ok := decimal(l.Count, true); !ok {
			return ErrInvalidBatch
		}
	} else if l.Count != "" {
		return ErrInvalidBatch
	}
	return nil
}

// ValidateBatchForGrant checks immutable scope, source ownership, typed schema,
// source time and current lease. It intentionally imposes no maximum age: owned
// gateway history survives long disconnects. Session/key/signature checks are a
// separate mandatory step using independently persisted session authority.
func ValidateBatchForGrant(b NodeBatch, g Grant, at time.Time) error {
	if ValidateGrant(g, at) != nil || ValidateNodeBatch(b) != nil || b.Key.ClusterID != g.ClusterID || b.Key.NodeID != g.NodeID || b.Key.EnrollmentID != g.EnrollmentID || b.EnrollmentRevision != g.EnrollmentRevision || b.InventoryRevisionID != g.InventoryRevisionID || b.AgentVersion != g.AgentVersion || b.BuildSHA256 != g.BuildSHA256 || b.CreatedAt.After(at.Add(FutureSkew)) {
		return ErrInvalidBatch
	}
	allowed := map[string]SourceGrant{}
	for _, s := range g.Sources {
		allowed[s.SourceID] = s
	}
	for _, s := range b.Sources {
		a, ok := allowed[s.SourceID]
		if !ok || a.SchemaVersion != s.SchemaVersion || a.ProfileID != s.ProfileID {
			return ErrInvalidBatch
		}
		for _, l := range s.Loss {
			if l.ThroughAt != nil && l.ThroughAt.After(at.Add(FutureSkew)) {
				return ErrInvalidBatch
			}
		}
	}
	return nil
}

// ParseNodePublicKey validates the canonical unpadded base64 wire representation.
func ParseNodePublicKey(k NodeKey) (ed25519.PublicKey, error) {
	if len(k.PublicKeyBase64) != base64.RawStdEncoding.EncodedLen(ed25519.PublicKeySize) {
		return nil, ErrSignature
	}
	p, err := base64.RawStdEncoding.DecodeString(k.PublicKeyBase64)
	if err != nil || len(p) != ed25519.PublicKeySize || base64.RawStdEncoding.EncodeToString(p) != k.PublicKeyBase64 {
		return nil, ErrSignature
	}
	return ed25519.PublicKey(p), nil
}
