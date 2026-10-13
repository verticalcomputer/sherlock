package nodetelemetry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

type localVerifier struct {
	scope      LocalScope
	keys       map[string]telemetry.NodeKey
	historical map[string]telemetry.NodeKey
}

func newLocalVerifier(scope LocalScope, keyID string, key ed25519.PrivateKey) (*localVerifier, error) {
	// Validate only the closed structure using an explicitly temporary syntax
	// fixture. These times never enter local state or assert remote authority.
	at := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	g := telemetry.Grant{ProtocolVersion: 1, EnrollmentID: scope.EnrollmentID, EnrollmentRevision: 1, ControlRevision: 1, Status: "ACTIVE", ClusterID: scope.ClusterID, NodeID: scope.NodeID, InventoryRevisionID: scope.InventoryRevisionID, GatewayCollectorID: "local-structure-only", AgentVersion: scope.AgentVersion, BuildSHA256: scope.BuildSHA256, GatewaySPKISHA256: scope.GatewaySPKISHA256, Keys: scope.Keys, NotBefore: at, NotAfter: at.Add(time.Minute)}
	for _, id := range scope.SourceIDs {
		g.Sources = append(g.Sources, telemetry.SourceGrant{SourceID: id, SchemaVersion: 1, ProfileID: telemetry.SourceProfile(scope.SourceProfiles, id)})
	}
	if !telemetry.ValidSourceProfiles(scope.SourceIDs, scope.SourceProfiles) || telemetry.ValidateGrant(g, at) != nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	v := &localVerifier{scope: scope, keys: map[string]telemetry.NodeKey{}, historical: map[string]telemetry.NodeKey{}}
	for _, k := range scope.Keys {
		v.keys[k.ID] = k
	}
	k, ok := v.keys[keyID]
	pub, e := telemetry.ParseNodePublicKey(k)
	if !ok || e != nil || k.State != "ACTIVE" || !bytes.Equal(pub, key.Public().(ed25519.PublicKey)) {
		return nil, ErrInvalid
	}
	return v, nil
}

func (v *localVerifier) historicalKey(id string) (ed25519.PublicKey, error) {
	if key, ok := v.historical[id]; ok {
		return telemetry.ParseNodePublicKey(key)
	}
	return v.key(id)
}

func (v *localVerifier) verifyHistoricalSession(m telemetry.SessionMessage) error {
	key, err := v.historicalKey(m.SigningKeyID)
	if err != nil || !v.bound(m.ClusterID, m.NodeID, m.EnrollmentID) || telemetry.VerifySessionSignature(m, key) != nil {
		return ErrInvalid
	}
	for _, loss := range m.Loss {
		if !v.allowed(loss.SourceID) {
			return ErrInvalid
		}
	}
	return nil
}

func (v *localVerifier) AuthorizeRetirement(ctx context.Context, scope telemetryjournal.Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !v.bound(scope.ClusterID, scope.NodeID, scope.EnrollmentID) {
		return ErrInvalid
	}
	return nil
}
func (v *localVerifier) VerifyRelease(_ context.Context, e telemetry.ReleaseEnvelope) (telemetryjournal.ReleaseAuthorization, error) {
	pub, err := v.key(e.Request.SigningKeyID)
	// This seam authenticates the signed request. Queue separately validates
	// the manifest/proof on admission; completed records may compact manifests.
	if err != nil || !v.bound(e.Request.ClusterID, e.Request.NodeID, e.Request.EnrollmentID) || telemetry.ValidateReleaseRequest(e.Request) != nil || telemetry.VerifyReleaseSignature(e.Request, pub) != nil {
		return telemetryjournal.ReleaseAuthorization{}, ErrInvalid
	}
	return telemetryjournal.ReleaseAuthorization{SignerActive: v.keys[e.Request.SigningKeyID].State == "ACTIVE"}, nil
}
func (v *localVerifier) VerifyCompletion(_ context.Context, c telemetry.NodeReleaseCompletion) (telemetryjournal.ReleaseAuthorization, error) {
	pub, err := v.key(c.SigningKeyID)
	if err != nil || !v.bound(c.Binding.ClusterID, c.Binding.NodeID, c.Binding.EnrollmentID) || telemetry.VerifyNodeCompletionSignature(c, pub) != nil {
		return telemetryjournal.ReleaseAuthorization{}, ErrInvalid
	}
	return telemetryjournal.ReleaseAuthorization{SignerActive: v.keys[c.SigningKeyID].State == "ACTIVE"}, nil
}
func (v *localVerifier) key(id string) (ed25519.PublicKey, error) {
	k, ok := v.keys[id]
	if !ok || k.State == "REVOKED" {
		return nil, ErrInvalid
	}
	return telemetry.ParseNodePublicKey(k)
}
func (v *localVerifier) bound(cluster, node, enrollment string) bool {
	return cluster == v.scope.ClusterID && node == v.scope.NodeID && enrollment == v.scope.EnrollmentID
}
func (v *localVerifier) allowed(id string) bool {
	for _, s := range v.scope.SourceIDs {
		if s == id {
			return true
		}
	}
	return false
}
func (v *localVerifier) Verify(_ context.Context, wire []byte) (telemetryjournal.Envelope, error) {
	b, e := telemetry.DecodeNodeBatch(wire, "")
	if e != nil {
		return telemetryjournal.Envelope{}, ErrInvalid
	}
	pub, e := v.key(b.SigningKeyID)
	if e != nil || !v.bound(b.Key.ClusterID, b.Key.NodeID, b.Key.EnrollmentID) || b.InventoryRevisionID != v.scope.InventoryRevisionID || b.AgentVersion != v.scope.AgentVersion || b.BuildSHA256 != v.scope.BuildSHA256 || telemetry.VerifyBatchSignature(b, pub) != nil {
		return telemetryjournal.Envelope{}, ErrInvalid
	}
	env := telemetryjournal.Envelope{Key: b.Key, Digest: b.Digest, CreatedAt: b.CreatedAt, Lane: telemetryjournal.Data, BootID: b.BootID, SigningKeyID: b.SigningKeyID, EnrollmentRevision: b.EnrollmentRevision}
	for _, s := range b.Sources {
		if !v.allowed(s.SourceID) || s.ProfileID != telemetry.SourceProfile(v.scope.SourceProfiles, s.SourceID) {
			return telemetryjournal.Envelope{}, ErrInvalid
		}
		env.Sources = append(env.Sources, s.SourceID)
		for _, l := range s.Loss {
			env.Loss = append(env.Loss, telemetry.SessionLoss{SourceID: s.SourceID, Range: l})
		}
	}
	if len(env.Loss) > 0 {
		env.Lane = telemetryjournal.Loss
	}
	return env, nil
}
func (v *localVerifier) VerifySession(_ context.Context, m telemetry.SessionMessage) (telemetryjournal.SessionAuthorization, error) {
	pub, e := v.key(m.SigningKeyID)
	if e != nil || !v.bound(m.ClusterID, m.NodeID, m.EnrollmentID) || telemetry.VerifySessionSignature(m, pub) != nil {
		return telemetryjournal.SessionAuthorization{}, ErrInvalid
	}
	for _, l := range m.Loss {
		if !v.allowed(l.SourceID) {
			return telemetryjournal.SessionAuthorization{}, ErrInvalid
		}
	}
	return telemetryjournal.SessionAuthorization{SignerActive: v.keys[m.SigningKeyID].State == "ACTIVE"}, nil
}
func scopeDigest(s LocalScope) string {
	s.Keys = nil
	s.SourceIDs = append([]string(nil), s.SourceIDs...)
	sort.Strings(s.SourceIDs)
	body, _ := json.Marshal(s)
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}
func gapBytes(g signedGap) []byte {
	g.Digest = ""
	g.Signature = ""
	g.Carrier = nil
	b, _ := json.Marshal(g)
	return append([]byte("sherlock.node-telemetry.local-gap.v1\x00"), b...)
}
func signGap(g *signedGap, key ed25519.PrivateKey) {
	h := sha256.Sum256(gapBytes(*g))
	g.Digest = hex.EncodeToString(h[:])
	g.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("sherlock.node-telemetry.local-gap.signature.v1\x00"), h[:]...)))
}
func verifyGap(g signedGap, pub ed25519.PublicKey) bool {
	h := sha256.Sum256(gapBytes(g))
	sig, e := base64.RawStdEncoding.DecodeString(g.Signature)
	return e == nil && g.Digest == hex.EncodeToString(h[:]) && ed25519.Verify(pub, append([]byte("sherlock.node-telemetry.local-gap.signature.v1\x00"), h[:]...), sig)
}
