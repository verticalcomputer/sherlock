package telemetry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

func validReleaseRange(from, through string) bool {
	a, ok := decimal(from, true)
	b, valid := decimal(through, true)
	return ok && valid && (a == 0 && b == 0 || a > 0 && b >= a && b-a < MaxReleaseSpan)
}
func ValidateReleaseRequest(r ReleaseRequest) error {
	_, epoch := decimal(r.SessionEpoch, false)
	if r.ProtocolVersion != ProtocolVersion || r.ReleaseVersion != ReleaseVersion || !validID(r.ReleaseID) || !validID(r.ClusterID) || !validID(r.NodeID) || !validID(r.EnrollmentID) || r.EnrollmentRevision != 1 || !epoch || !validID(r.SessionID) || !validID(r.SigningKeyID) || !validInstant(r.CreatedAt) || !validReleaseRange(r.FromSequence, r.ThroughSequence) || !validDigest(r.ManifestDigest) {
		return ErrInvalid
	}
	return nil
}
func ValidateReleaseBinding(b ReleaseBinding) error {
	r := ReleaseRequest{ProtocolVersion: ProtocolVersion, ReleaseVersion: ReleaseVersion, ReleaseID: b.ReleaseID, ClusterID: b.ClusterID, NodeID: b.NodeID, EnrollmentID: b.EnrollmentID, EnrollmentRevision: b.EnrollmentRevision, SessionEpoch: b.SessionEpoch, SessionID: b.SessionID, SigningKeyID: "shape-only", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), FromSequence: b.FromSequence, ThroughSequence: b.ThroughSequence, ManifestDigest: b.ManifestDigest}
	if ValidateReleaseRequest(r) != nil || !validDigest(b.ReleaseDigest) {
		return ErrInvalid
	}
	return nil
}
func ValidateReleaseManifest(m ReleaseManifest) error {
	if len(m.Batches) > MaxReleaseFacts || len(m.Loss) > MaxReleaseFacts {
		return ErrInvalid
	}
	var prior uint64
	for _, b := range m.Batches {
		n, ok := decimal(b.Sequence, false)
		if !ok || n <= prior || !validDigest(b.Digest) || !validID(b.GatewayReceiptID) {
			return ErrInvalid
		}
		prior = n
	}
	priorSource, priorID := "", ""
	seenLossIDs := map[string]bool{}
	for _, l := range m.Loss {
		if !validID(l.SourceID) || !validID(l.LossID) || seenLossIDs[l.LossID] || !validDigest(l.Digest) || l.SourceID < priorSource || l.SourceID == priorSource && l.LossID <= priorID {
			return ErrInvalid
		}
		seenLossIDs[l.LossID] = true
		priorSource, priorID = l.SourceID, l.LossID
	}
	return nil
}
func CanonicalReleaseManifestDigest(m ReleaseManifest) ([32]byte, error) {
	if ValidateReleaseManifest(m) != nil {
		return [32]byte{}, ErrInvalid
	}
	w := new(canonicalWriter)
	w.WriteString("sherlock.node-telemetry.release-manifest.digest.v1\x00")
	w.n(len(m.Batches))
	for _, b := range m.Batches {
		w.decimal(b.Sequence, false)
		w.s(b.Digest)
		w.s(b.GatewayReceiptID)
	}
	w.n(len(m.Loss))
	for _, l := range m.Loss {
		w.s(l.SourceID)
		w.s(l.LossID)
		w.s(l.Digest)
	}
	return sha256.Sum256(w.Bytes()), w.err
}
func writeReleaseBinding(w *canonicalWriter, b ReleaseBinding) {
	w.s(b.ReleaseID)
	w.s(b.ClusterID)
	w.s(b.NodeID)
	w.s(b.EnrollmentID)
	w.u(uint64(b.EnrollmentRevision))
	w.decimal(b.SessionEpoch, false)
	w.s(b.SessionID)
	w.decimal(b.FromSequence, true)
	w.decimal(b.ThroughSequence, true)
	w.s(b.ReleaseDigest)
	w.s(b.ManifestDigest)
}
func CanonicalReleaseDigest(r ReleaseRequest) ([32]byte, error) {
	if ValidateReleaseRequest(r) != nil {
		return [32]byte{}, ErrInvalid
	}
	w := new(canonicalWriter)
	w.WriteString("sherlock.node-telemetry.release.digest.v1\x00")
	w.u(uint64(r.ProtocolVersion))
	w.u(uint64(r.ReleaseVersion))
	b := r.Binding()
	b.ReleaseDigest = ""
	writeReleaseBinding(w, b)
	w.s(r.SigningKeyID)
	w.t(r.CreatedAt)
	return sha256.Sum256(w.Bytes()), w.err
}
func releaseSignatureBytes(d [32]byte) []byte {
	return append([]byte("sherlock.node-telemetry.release.signature.v1\x00"), d[:]...)
}
func SignReleaseRequest(r *ReleaseRequest, key ed25519.PrivateKey) error {
	if r == nil || len(key) != ed25519.PrivateKeySize {
		return ErrSignature
	}
	d, e := CanonicalReleaseDigest(*r)
	if e != nil {
		return e
	}
	signed := *r
	signed.Digest = hex.EncodeToString(d[:])
	signed.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, releaseSignatureBytes(d)))
	wire, e := json.Marshal(signed)
	if e != nil || len(wire) > MaxReleaseBytes {
		return ErrInvalid
	}
	*r = signed
	return nil
}
func VerifyReleaseSignature(r ReleaseRequest, key ed25519.PublicKey) error {
	d, e := CanonicalReleaseDigest(r)
	if e != nil {
		return e
	}
	return verifyReleaseSignature(d, r.Digest, r.Signature, key, releaseSignatureBytes(d))
}
func verifyReleaseSignature(d [32]byte, digest, signature string, key ed25519.PublicKey, message []byte) error {
	if len(key) != ed25519.PublicKeySize || digest != hex.EncodeToString(d[:]) || len(signature) != base64.RawStdEncoding.EncodedLen(ed25519.SignatureSize) {
		return ErrSignature
	}
	sig, e := base64.RawStdEncoding.DecodeString(signature)
	if e != nil || len(sig) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(sig) != signature || !ed25519.Verify(key, message, sig) {
		return ErrSignature
	}
	return nil
}
func ValidateReleaseEnvelope(e ReleaseEnvelope) error {
	if ValidateReleaseRequest(e.Request) != nil || ValidateReleaseManifest(e.Manifest) != nil {
		return ErrInvalid
	}
	d, err := CanonicalReleaseManifestDigest(e.Manifest)
	if err != nil || e.Request.ManifestDigest != hex.EncodeToString(d[:]) {
		return ErrConflict
	}
	from, _ := decimal(e.Request.FromSequence, true)
	through, _ := decimal(e.Request.ThroughSequence, true)
	if from == 0 && (len(e.Manifest.Batches) > 0 || len(e.Manifest.Loss) > 0) {
		return ErrInvalid
	}
	for _, b := range e.Manifest.Batches {
		n, _ := decimal(b.Sequence, false)
		if n < from || n > through {
			return ErrInvalid
		}
	}
	body, err := json.Marshal(e)
	if err != nil || len(body) > MaxReleaseBytes {
		return ErrInvalid
	}
	return nil
}
func DecodeReleaseEnvelope(body []byte, encoding string) (ReleaseEnvelope, error) {
	var e ReleaseEnvelope
	if len(body) > MaxReleaseBytes || DecodeStrictJSON(body, encoding, &e) != nil {
		return e, ErrInvalid
	}
	if err := ValidateReleaseEnvelope(e); err != nil {
		return ReleaseEnvelope{}, err
	}
	return e, nil
}

// CanonicalLossDigest is deliberately separate from storage-specific JSON
// indexes. Instants compare canonically across equivalent time zones.
func CanonicalLossDigest(l SessionLoss) ([32]byte, error) {
	k := l.Range.AffectedKey
	if !validID(l.SourceID) || validateLoss(l.Range, k.ClusterID, k.NodeID, k.EnrollmentID) != nil {
		return [32]byte{}, ErrInvalid
	}
	w := new(canonicalWriter)
	w.WriteString("sherlock.node-telemetry.release-loss.digest.v1\x00")
	w.s(l.SourceID)
	w.s(l.Range.ID)
	w.key(k)
	w.decimal(l.Range.ThroughSequence, false)
	w.b(l.Range.FromAt != nil)
	if l.Range.FromAt != nil {
		w.t(*l.Range.FromAt)
		w.t(*l.Range.ThroughAt)
	}
	w.s(l.Range.Reason)
	w.b(l.Range.CountKnown)
	if l.Range.CountKnown {
		w.decimal(l.Range.Count, true)
	}
	return sha256.Sum256(w.Bytes()), w.err
}
func releasePublicKey(g Grant, cluster, node, enrollment string, revision int64, key string, created, at time.Time) (ed25519.PublicKey, error) {
	if ValidateGrant(g, at) != nil || cluster != g.ClusterID || node != g.NodeID || enrollment != g.EnrollmentID || revision != g.EnrollmentRevision || created.After(at.Add(FutureSkew)) {
		return nil, ErrUnauthorized
	}
	for _, k := range g.Keys {
		if k.ID == key && k.State != "REVOKED" {
			return ParseNodePublicKey(k)
		}
	}
	return nil, ErrUnauthorized
}

// ValidateReleaseForGrant authenticates current nonrevoked signing authority.
// Store/journal must additionally enforce ACTIVE for a new release and allow
// VERIFY_ONLY solely for its own exact previously admitted replay.
func ValidateReleaseForGrant(r ReleaseRequest, g Grant, at time.Time) error {
	if ValidateReleaseRequest(r) != nil {
		return ErrInvalid
	}
	key, e := releasePublicKey(g, r.ClusterID, r.NodeID, r.EnrollmentID, r.EnrollmentRevision, r.SigningKeyID, r.CreatedAt, at)
	if e != nil {
		return e
	}
	return VerifyReleaseSignature(r, key)
}

// ProveReleaseCoverage proves ownership disposition using only selected,
// independently verified facts. It does not authenticate external batch receipt
// IDs or assert per-source observation coverage. Callers verify those receipt
// facts against their own durable ledger before using this proof.
func ProveReleaseCoverage(r ReleaseRequest, m ReleaseManifest, sourceIDs []string, lossFacts []SessionLoss) error {
	if ValidateReleaseEnvelope(ReleaseEnvelope{Request: r, Manifest: m}) != nil || len(sourceIDs) < 1 || len(sourceIDs) > MaxSources || len(lossFacts) != len(m.Loss) {
		return ErrInvalid
	}
	allowed := map[string]bool{}
	for _, s := range sourceIDs {
		if !validID(s) || allowed[s] {
			return ErrInvalid
		}
		allowed[s] = true
	}
	facts := map[string]SessionLoss{}
	for _, l := range lossFacts {
		d, e := CanonicalLossDigest(l)
		if e != nil || !allowed[l.SourceID] {
			return ErrInvalid
		}
		id := l.SourceID + "\x00" + l.Range.ID
		if _, exists := facts[id]; exists {
			return ErrConflict
		}
		facts[id] = l
		found := false
		for _, ref := range m.Loss {
			if ref.SourceID == l.SourceID && ref.LossID == l.Range.ID && ref.Digest == hex.EncodeToString(d[:]) {
				found = true
				break
			}
		}
		if !found {
			return ErrConflict
		}
		k := l.Range.AffectedKey
		if k.ClusterID != r.ClusterID || k.NodeID != r.NodeID || k.EnrollmentID != r.EnrollmentID || k.SessionEpoch != r.SessionEpoch || k.SessionID != r.SessionID {
			return ErrConflict
		}
	}
	from, _ := decimal(r.FromSequence, true)
	through, _ := decimal(r.ThroughSequence, true)
	if from == 0 {
		return nil
	} // Caller must separately prove finalized terminal 0.
	type interval struct{ from, through uint64 }
	batches := make([]interval, 0, len(m.Batches))
	for _, b := range m.Batches {
		n, _ := decimal(b.Sequence, false)
		batches = append(batches, interval{n, n})
	}
	for source := range allowed {
		ranges := append([]interval(nil), batches...)
		for _, l := range lossFacts {
			if l.SourceID != source {
				continue
			}
			a, _ := decimal(l.Range.AffectedKey.Sequence, false)
			b, _ := decimal(l.Range.ThroughSequence, false)
			if b < from || a > through {
				return ErrInvalid
			}
			if a < from {
				a = from
			}
			if b > through {
				b = through
			}
			ranges = append(ranges, interval{a, b})
		}
		sort.Slice(ranges, func(i, j int) bool {
			if ranges[i].from == ranges[j].from {
				return ranges[i].through < ranges[j].through
			}
			return ranges[i].from < ranges[j].from
		})
		next := from
		covered := false
		for _, x := range ranges {
			if x.from > next {
				break
			}
			if x.through < next {
				continue
			}
			if x.through >= through {
				covered = true
				break
			}
			next = x.through + 1
		}
		if !covered {
			return ErrConflict
		}
	}
	return nil
}

func ValidateReleaseAdmissionReceipt(r ReleaseAdmissionReceipt) error {
	if r.ProtocolVersion != ProtocolVersion || r.ReleaseVersion != ReleaseVersion || !validID(r.ID) || ValidateReleaseBinding(r.Binding) != nil || !validInstant(r.StoredAt) || r.Durability != "GATEWAY" {
		return ErrInvalid
	}
	return nil
}
func ValidateCloudRetirementReceipt(r CloudRetirementReceipt) error {
	if r.ProtocolVersion != ProtocolVersion || r.ReleaseVersion != ReleaseVersion || !validID(r.ID) || ValidateReleaseBinding(r.Binding) != nil || !validID(r.GatewayAdmissionID) || !validInstant(r.StoredAt) || r.Durability != "CLOUD" {
		return ErrInvalid
	}
	switch r.Phase {
	case "PREPARED":
		if r.PreparedReceiptID != "" || r.GatewayCommitID != "" {
			return ErrInvalid
		}
	case "FINAL":
		if !validID(r.PreparedReceiptID) || !validID(r.GatewayCommitID) || r.ID == r.PreparedReceiptID {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func ValidateGatewayReleaseCommit(c GatewayReleaseCommit) error {
	if c.ProtocolVersion != ProtocolVersion || c.ReleaseVersion != ReleaseVersion || !validID(c.ID) || ValidateReleaseBinding(c.Binding) != nil || !validID(c.GatewayAdmissionID) || !validID(c.PreparedReceiptID) || !validInstant(c.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

// GatewayRetirementReceiptID binds the node's completion proof to the exact
// durable cloud final and gateway commit. The ID alone does not prove local
// persistence; gateway and node must still perform their durable transitions.
func GatewayRetirementReceiptID(c CloudRetirementReceipt) (string, error) {
	if ValidateCloudRetirementReceipt(c) != nil || c.Phase != "FINAL" {
		return "", ErrInvalid
	}
	w := new(canonicalWriter)
	w.WriteString("sherlock.node-telemetry.gateway-retirement-id.v1\x00")
	w.u(uint64(c.ProtocolVersion))
	w.u(uint64(c.ReleaseVersion))
	w.s(c.ID)
	w.s(c.Phase)
	writeReleaseBinding(w, c.Binding)
	w.s(c.GatewayAdmissionID)
	w.s(c.PreparedReceiptID)
	w.s(c.GatewayCommitID)
	w.t(c.StoredAt)
	w.s(c.Durability)
	if w.err != nil {
		return "", w.err
	}
	d := sha256.Sum256(w.Bytes())
	return "gateway-retirement-" + hex.EncodeToString(d[:]), nil
}

func ValidateGatewayRetirementReceipt(r GatewayRetirementReceipt) error {
	c := r.CloudFinalReceipt
	if r.ProtocolVersion != ProtocolVersion || r.ReleaseVersion != ReleaseVersion || !validID(r.ID) || ValidateReleaseBinding(r.Binding) != nil || !validID(r.GatewayAdmissionID) || !validID(r.PreparedReceiptID) || !validID(r.GatewayCommitID) || !validInstant(r.StoredAt) || r.Durability != "GATEWAY" || ValidateCloudRetirementReceipt(c) != nil || c.Phase != "FINAL" || c.Binding != r.Binding || c.GatewayAdmissionID != r.GatewayAdmissionID || c.PreparedReceiptID != r.PreparedReceiptID || c.GatewayCommitID != r.GatewayCommitID {
		return ErrInvalid
	}
	id, err := GatewayRetirementReceiptID(c)
	if err != nil || r.ID != id {
		return ErrInvalid
	}
	return nil
}
func ValidateNodeReleaseCompletion(c NodeReleaseCompletion) error {
	if c.ProtocolVersion != ProtocolVersion || c.ReleaseVersion != ReleaseVersion || !validID(c.ID) || ValidateReleaseBinding(c.Binding) != nil || !validID(c.CloudFinalReceiptID) || !validID(c.GatewayRetirementReceiptID) || !validID(c.SigningKeyID) || !validInstant(c.CreatedAt) {
		return ErrInvalid
	}
	return nil
}
func CanonicalNodeCompletionDigest(c NodeReleaseCompletion) ([32]byte, error) {
	if ValidateNodeReleaseCompletion(c) != nil {
		return [32]byte{}, ErrInvalid
	}
	w := new(canonicalWriter)
	w.WriteString("sherlock.node-telemetry.node-completion.digest.v1\x00")
	w.u(uint64(c.ProtocolVersion))
	w.u(uint64(c.ReleaseVersion))
	w.s(c.ID)
	writeReleaseBinding(w, c.Binding)
	w.s(c.CloudFinalReceiptID)
	w.s(c.GatewayRetirementReceiptID)
	w.s(c.SigningKeyID)
	w.t(c.CreatedAt)
	return sha256.Sum256(w.Bytes()), w.err
}
func completionSignatureBytes(d [32]byte) []byte {
	return append([]byte("sherlock.node-telemetry.node-completion.signature.v1\x00"), d[:]...)
}
func SignNodeCompletion(c *NodeReleaseCompletion, key ed25519.PrivateKey) error {
	if c == nil || len(key) != ed25519.PrivateKeySize {
		return ErrSignature
	}
	d, e := CanonicalNodeCompletionDigest(*c)
	if e != nil {
		return e
	}
	signed := *c
	signed.Digest = hex.EncodeToString(d[:])
	signed.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, completionSignatureBytes(d)))
	*c = signed
	return nil
}
func VerifyNodeCompletionSignature(c NodeReleaseCompletion, key ed25519.PublicKey) error {
	d, e := CanonicalNodeCompletionDigest(c)
	if e != nil {
		return e
	}
	return verifyReleaseSignature(d, c.Digest, c.Signature, key, completionSignatureBytes(d))
}
func ValidateNodeCompletionForGrant(c NodeReleaseCompletion, g Grant, at time.Time) error {
	if ValidateNodeReleaseCompletion(c) != nil {
		return ErrInvalid
	}
	b := c.Binding
	key, e := releasePublicKey(g, b.ClusterID, b.NodeID, b.EnrollmentID, b.EnrollmentRevision, c.SigningKeyID, c.CreatedAt, at)
	if e != nil {
		return e
	}
	return VerifyNodeCompletionSignature(c, key)
}
func ValidateNodeCompletionReceipt(r NodeCompletionReceipt) error {
	if r.ProtocolVersion != ProtocolVersion || r.ReleaseVersion != ReleaseVersion || !validID(r.ID) || ValidateReleaseBinding(r.Binding) != nil || !validDigest(r.CompletionDigest) || !validID(r.CloudFinalReceiptID) || !validID(r.GatewayRetirementReceiptID) || !validInstant(r.StoredAt) || r.Durability != "CLOUD" {
		return ErrInvalid
	}
	return nil
}
