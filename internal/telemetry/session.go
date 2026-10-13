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

// ValidateSessionMessage checks a signed lifecycle fact's closed schema. A
// finalize names the target old session/boot; CreatedAt is its current signing
// time, not a claim that the prior boot is still running.
func ValidateSessionMessage(m SessionMessage) error {
	if m.ProtocolVersion != ProtocolVersion || !validID(m.ClusterID) || !validID(m.NodeID) || !validID(m.EnrollmentID) || m.EnrollmentRevision != 1 || !validID(m.SessionID) || !validID(m.BootID) || !validID(m.SigningKeyID) || !validInstant(m.CreatedAt) || len(m.Loss) > MaxLossRanges {
		return ErrInvalid
	}
	if _, ok := decimal(m.SessionEpoch, false); !ok {
		return ErrInvalid
	}
	switch m.Kind {
	case "OPEN":
		if m.LastAllocatedSequence != "" || len(m.Loss) != 0 {
			return ErrInvalid
		}
	case "FINALIZE":
		last, ok := decimal(m.LastAllocatedSequence, true)
		if !ok {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, l := range m.Loss {
			end, _ := decimal(l.Range.ThroughSequence, false)
			if !validID(l.SourceID) || seen[l.Range.ID] || validateLoss(l.Range, m.ClusterID, m.NodeID, m.EnrollmentID) != nil || l.Range.AffectedKey.SessionEpoch != m.SessionEpoch || l.Range.AffectedKey.SessionID != m.SessionID || end > last || l.Range.ThroughAt != nil && l.Range.ThroughAt.After(m.CreatedAt) {
				return ErrInvalid
			}
			seen[l.Range.ID] = true
		}
	default:
		return ErrInvalid
	}
	return nil
}

func DecodeSessionMessage(body []byte, contentEncoding string) (SessionMessage, error) {
	var m SessionMessage
	if err := DecodeStrictJSON(body, contentEncoding, &m); err != nil {
		return m, err
	}
	if err := ValidateSessionMessage(m); err != nil {
		return SessionMessage{}, err
	}
	return m, nil
}

func CanonicalSessionDigest(m SessionMessage) ([32]byte, error) {
	var empty [32]byte
	if err := ValidateSessionMessage(m); err != nil {
		return empty, err
	}
	w := new(canonicalWriter)
	w.WriteString("sherlock.node-telemetry.session.digest.v1\x00")
	w.u(uint64(m.ProtocolVersion))
	w.s(m.Kind)
	w.s(m.ClusterID)
	w.s(m.NodeID)
	w.s(m.EnrollmentID)
	w.u(uint64(m.EnrollmentRevision))
	w.decimal(m.SessionEpoch, false)
	w.s(m.SessionID)
	w.s(m.BootID)
	w.s(m.SigningKeyID)
	w.t(m.CreatedAt)
	w.b(m.Kind == "FINALIZE")
	if m.Kind == "FINALIZE" {
		w.decimal(m.LastAllocatedSequence, true)
	}
	loss := append([]SessionLoss(nil), m.Loss...)
	sort.Slice(loss, func(i, j int) bool {
		if loss[i].SourceID == loss[j].SourceID {
			return loss[i].Range.ID < loss[j].Range.ID
		}
		return loss[i].SourceID < loss[j].SourceID
	})
	w.n(len(loss))
	for _, s := range loss {
		l := s.Range
		w.s(s.SourceID)
		w.s(l.ID)
		w.key(l.AffectedKey)
		w.decimal(l.ThroughSequence, false)
		w.b(l.FromAt != nil)
		if l.FromAt != nil {
			w.t(*l.FromAt)
			w.t(*l.ThroughAt)
		}
		w.s(l.Reason)
		w.b(l.CountKnown)
		if l.CountKnown {
			w.decimal(l.Count, true)
		}
	}
	if w.err != nil || w.Len() > MaxBatchBytes {
		return empty, ErrInvalid
	}
	return sha256.Sum256(w.Bytes()), nil
}

func sessionSignatureBytes(digest [32]byte) []byte {
	return append([]byte("sherlock.node-telemetry.session.signature.v1\x00"), digest[:]...)
}

func SignSessionMessage(m *SessionMessage, key ed25519.PrivateKey) error {
	if m == nil || len(key) != ed25519.PrivateKeySize {
		return ErrSignature
	}
	digest, err := CanonicalSessionDigest(*m)
	if err != nil {
		return err
	}
	signed := *m
	signed.Digest = hex.EncodeToString(digest[:])
	signed.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, sessionSignatureBytes(digest)))
	body, err := json.Marshal(signed)
	if err != nil || len(body) > MaxBatchBytes {
		return ErrInvalid
	}
	*m = signed
	return nil
}

func VerifySessionSignature(m SessionMessage, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return ErrSignature
	}
	digest, err := CanonicalSessionDigest(m)
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(m.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != m.Signature || m.Digest != hex.EncodeToString(digest[:]) || !ed25519.Verify(key, sessionSignatureBytes(digest), signature) {
		return ErrSignature
	}
	return nil
}

// ValidateSessionForGrant checks the current lease, immutable scope, allowed
// sources and signer state. The caller must independently prove the persisted
// session ledger: exactly-next OPEN under ACTIVE key, known FINALIZE, boot/key
// binding and terminal range coverage. VERIFY_ONLY may authenticate a matching
// known OPEN replay; it never authorizes opening a new session. The store checks
// this distinction before receipt lookup. A signature cannot grant authority.
func ValidateSessionForGrant(m SessionMessage, g Grant, at time.Time) error {
	if err := ValidateGrant(g, at); err != nil {
		return err
	}
	if err := ValidateSessionMessage(m); err != nil {
		return err
	}
	if m.ClusterID != g.ClusterID || m.NodeID != g.NodeID || m.EnrollmentID != g.EnrollmentID || m.EnrollmentRevision != g.EnrollmentRevision || m.CreatedAt.After(at.Add(FutureSkew)) {
		return ErrUnauthorized
	}
	allowed := map[string]bool{}
	for _, s := range g.Sources {
		allowed[s.SourceID] = true
	}
	for _, l := range m.Loss {
		if !allowed[l.SourceID] || l.Range.ThroughAt != nil && l.Range.ThroughAt.After(at.Add(FutureSkew)) {
			return ErrUnauthorized
		}
	}
	for _, k := range g.Keys {
		if k.ID != m.SigningKeyID {
			continue
		}
		if k.State == "REVOKED" {
			return ErrUnauthorized
		}
		pub, err := ParseNodePublicKey(k)
		if err != nil {
			return err
		}
		return VerifySessionSignature(m, pub)
	}
	return ErrUnauthorized
}
