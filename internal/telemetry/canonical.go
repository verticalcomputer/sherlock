package telemetry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"time"
)

var ErrInvalid = errors.New("invalid telemetry input")
var ErrInvalidBatch = ErrInvalid
var ErrUnauthorized = errors.New("telemetry authority unavailable")
var ErrConflict = errors.New("telemetry immutable identity conflict")
var ErrBackpressure = errors.New("telemetry bounded capacity exhausted")
var ErrReplayExpired = errors.New("telemetry replay receipt expired")
var ErrUnavailable = errors.New("telemetry storage unavailable")
var ErrSignature = ErrUnauthorized

// canonicalWriter writes an explicitly versioned binary format: string/array
// lengths are uint32 big-endian; integer fields uint64 big-endian; times signed
// Unix nanoseconds; booleans one byte. Schema validation precedes canonical use.
// This is not RFC8785 JSON canonicalization.
type canonicalWriter struct {
	bytes.Buffer
	err error
}

func (w *canonicalWriter) u(n uint64) {
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], n)
	w.Write(p[:])
}
func (w *canonicalWriter) n(n int) {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(n))
	w.Write(p[:])
}
func (w *canonicalWriter) s(v string) {
	if len(v) > 256 {
		w.err = ErrInvalidBatch
	}
	w.n(len(v))
	w.WriteString(v)
}
func (w *canonicalWriter) b(v bool) {
	if v {
		w.WriteByte(1)
	} else {
		w.WriteByte(0)
	}
}
func (w *canonicalWriter) t(v time.Time) {
	if v.IsZero() || v.Year() < 2020 || v.Year() > 2200 {
		w.err = ErrInvalidBatch
	}
	w.u(uint64(v.UnixNano()))
}
func (w *canonicalWriter) decimal(v string, zero bool) {
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != v || (!zero && n == 0) {
		w.err = ErrInvalidBatch
	}
	w.u(n)
}
func (w *canonicalWriter) key(v BatchKey) {
	w.s(v.ClusterID)
	w.s(v.NodeID)
	w.s(v.EnrollmentID)
	w.decimal(v.SessionEpoch, false)
	w.s(v.SessionID)
	w.decimal(v.Sequence, false)
}

func CanonicalDigest(batch NodeBatch) ([32]byte, error) {
	var empty [32]byte
	if err := ValidateNodeBatch(batch); err != nil {
		return empty, err
	}
	if batch.ProtocolVersion != ProtocolVersion || batch.EnrollmentRevision < 1 || len(batch.Sources) < 1 || len(batch.Sources) > MaxSources {
		return empty, ErrInvalidBatch
	}
	w := new(canonicalWriter)
	w.WriteString("sherlock.node-telemetry.digest.v1\x00")
	w.u(uint64(batch.ProtocolVersion))
	w.key(batch.Key)
	w.u(uint64(batch.EnrollmentRevision))
	w.s(batch.InventoryRevisionID)
	w.s(batch.BootID)
	w.s(batch.SigningKeyID)
	w.s(batch.AgentVersion)
	w.s(batch.BuildSHA256)
	w.t(batch.CreatedAt)
	sources := append([]SourceFrame(nil), batch.Sources...)
	sort.Slice(sources, func(i, j int) bool { return sources[i].SourceID < sources[j].SourceID })
	w.n(len(sources))
	total := 0
	for i, s := range sources {
		if i > 0 && s.SourceID == sources[i-1].SourceID {
			return empty, ErrInvalidBatch
		}
		if s.SchemaVersion < 1 || len(s.Fields) > MaxRecords || len(s.Loss) > 256 || s.CompletedAt.Before(s.StartedAt) || s.CompletedAt.After(batch.CreatedAt) || s.Coverage.Expected < 0 || s.Coverage.Returned < 0 {
			return empty, ErrInvalidBatch
		}
		w.s(s.SourceID)
		w.u(uint64(s.SchemaVersion))
		w.s(s.AdapterVersion)
		w.s(s.ProfileID)
		w.t(s.StartedAt)
		w.t(s.CompletedAt)
		w.s(s.Status)
		w.u(uint64(s.Coverage.Expected))
		w.u(uint64(s.Coverage.Returned))
		w.b(s.Coverage.Complete)
		fields := append([]FieldSupport(nil), s.Fields...)
		sort.Slice(fields, func(i, j int) bool {
			if fields[i].EntityKey == fields[j].EntityKey {
				return fields[i].Metric < fields[j].Metric
			}
			return fields[i].EntityKey < fields[j].EntityKey
		})
		w.n(len(fields))
		for i, f := range fields {
			if i > 0 && f.EntityKey == fields[i-1].EntityKey && f.Metric == fields[i-1].Metric {
				return empty, ErrInvalidBatch
			}
			w.s(f.EntityKey)
			w.s(f.Metric)
			w.s(f.State)
			w.s(f.Reason)
		}
		records := append([]Record(nil), s.Records...)
		sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
		total += len(records)
		if total > MaxRecords {
			return empty, ErrInvalidBatch
		}
		w.n(len(records))
		for i, r := range records {
			if i > 0 && r.ID == records[i-1].ID {
				return empty, ErrInvalidBatch
			}
			if r.ObservedAt.After(r.CollectedAt) || !r.CollectedAt.Equal(s.CompletedAt) {
				return empty, ErrInvalidBatch
			}
			w.s(r.ID)
			w.s(r.EntityKey)
			w.s(r.Metric)
			w.s(r.Unit)
			w.s(r.Kind)
			w.s(r.Reset)
			w.b(r.ResetObserved)
			w.t(r.ObservedAt)
			w.t(r.CollectedAt)
			if err := w.scalar(r.Value); err != nil {
				return empty, err
			}
		}
		loss := append([]LossRange(nil), s.Loss...)
		sort.Slice(loss, func(i, j int) bool { return loss[i].ID < loss[j].ID })
		w.n(len(loss))
		for i, l := range loss {
			if i > 0 && l.ID == loss[i-1].ID {
				return empty, ErrInvalidBatch
			}
			if (l.FromAt == nil) != (l.ThroughAt == nil) || l.FromAt != nil && l.ThroughAt.Before(*l.FromAt) || (l.CountKnown && l.Count == "") || (!l.CountKnown && l.Count != "") {
				return empty, ErrInvalidBatch
			}
			from, e1 := strconv.ParseUint(l.AffectedKey.Sequence, 10, 64)
			through, e2 := strconv.ParseUint(l.ThroughSequence, 10, 64)
			if e1 != nil || e2 != nil || through < from || l.AffectedKey.ClusterID != batch.Key.ClusterID || l.AffectedKey.NodeID != batch.Key.NodeID || l.AffectedKey.EnrollmentID != batch.Key.EnrollmentID {
				return empty, ErrInvalidBatch
			}
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
	}
	if w.err != nil || w.Len() > MaxBatchBytes {
		return empty, ErrInvalidBatch
	}
	return sha256.Sum256(w.Bytes()), nil
}

func (w *canonicalWriter) scalar(s Scalar) error {
	w.s(s.Kind)
	switch s.Kind {
	case "float":
		if s.Float == nil || s.Unsigned != "" || s.Boolean != nil || s.Enum != "" || math.IsNaN(*s.Float) || math.IsInf(*s.Float, 0) {
			return ErrInvalidBatch
		}
		v := *s.Float
		if v == 0 {
			v = 0
		}
		w.u(math.Float64bits(v))
	case "unsigned":
		if s.Float != nil || s.Boolean != nil || s.Enum != "" {
			return ErrInvalidBatch
		}
		w.decimal(s.Unsigned, true)
	case "boolean":
		if s.Boolean == nil || s.Float != nil || s.Unsigned != "" || s.Enum != "" {
			return ErrInvalidBatch
		}
		w.b(*s.Boolean)
	case "enum":
		if s.Enum == "" || s.Float != nil || s.Unsigned != "" || s.Boolean != nil {
			return ErrInvalidBatch
		}
		w.s(s.Enum)
	default:
		return ErrInvalidBatch
	}
	return nil
}

func signatureBytes(digest [32]byte) []byte {
	return append([]byte("sherlock.node-telemetry.signature.v1\x00"), digest[:]...)
}

// SignBatch signs all identity/source/payload fields through their canonical
// digest. Admission independently binds the key to the enrolled node; a valid
// signature alone never grants enrollment, source or inventory authority.
func SignBatch(batch *NodeBatch, private ed25519.PrivateKey) error {
	if batch == nil || len(private) != ed25519.PrivateKeySize {
		return ErrSignature
	}
	digest, err := CanonicalDigest(*batch)
	if err != nil {
		return err
	}
	signed := *batch
	signed.Digest = hex.EncodeToString(digest[:])
	signed.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, signatureBytes(digest)))
	body, err := json.Marshal(signed)
	if err != nil || len(body) > MaxNodeBatchBytes {
		return ErrInvalid
	}
	*batch = signed
	return nil
}

func VerifyBatchSignature(batch NodeBatch, public ed25519.PublicKey) error {
	if len(public) != ed25519.PublicKeySize {
		return ErrSignature
	}
	digest, err := CanonicalDigest(batch)
	if err != nil {
		return err
	}
	if batch.Digest != hex.EncodeToString(digest[:]) {
		return ErrSignature
	}
	sig, err := base64.RawStdEncoding.DecodeString(batch.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(sig) != batch.Signature || !ed25519.Verify(public, signatureBytes(digest), sig) {
		return ErrSignature
	}
	return nil
}
