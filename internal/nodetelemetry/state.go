package nodetelemetry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"golang.org/x/sys/unix"
)

const allocatorLimit = 1 << 20
const allocatorName = "node-allocator.json"
const allocatorVersion = 2

func sessionIndex(s allocator, epoch string) (int, bool) {
	n, ok := decimal(epoch, false)
	if !ok || n <= s.BaseEpoch || n-s.BaseEpoch > uint64(len(s.Sessions)) {
		return 0, false
	}
	return int(n - s.BaseEpoch - 1), true
}

func decimal(s string, zero bool) (uint64, bool) {
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil && strconv.FormatUint(n, 10) == s && (zero || n > 0)
}
func checksum(s allocator) string {
	s.Checksum = ""
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func clone(s allocator) allocator {
	b, _ := json.Marshal(s)
	var c allocator
	_ = json.Unmarshal(b, &c)
	return c
}
func randomID(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrState
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func readOwnerFile(path string, limit int) ([]byte, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "node-owned-file")
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > int64(limit) {
		return nil, ErrState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Size() == 0 {
		return nil, ErrState
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(b) > limit {
		return nil, ErrState
	}
	return b, nil
}

func (r *Runtime) load(ctx context.Context, v *localVerifier) error {
	b, e := readOwnerFile(filepath.Join(r.config.Root, allocatorName), allocatorLimit)
	if errors.Is(e, os.ErrNotExist) {
		messages, err := r.q.SessionMessages(ctx)
		if err != nil {
			return ErrState
		}
		stats, err := r.q.Stats(ctx)
		if err != nil || len(messages) > 0 || stats.Owned+stats.Transferred+stats.Lost > 0 {
			return ErrState
		}
		s := allocator{Version: allocatorVersion, ScopeDigest: scopeDigest(r.config.Scope), Sessions: []sessionState{}, Gaps: []signedGap{}}
		return r.save(ctx, s)
	}
	if e != nil {
		return ErrState
	}
	var s allocator
	if telemetry.DecodeStrictJSON(b, "", &s) != nil || s.Version != allocatorVersion || s.ScopeDigest != scopeDigest(r.config.Scope) || s.Checksum != checksum(s) || len(s.Sessions) > 8 || len(s.Gaps) > 256 || s.BaseEpoch > ^uint64(0)-uint64(len(s.Sessions)) {
		return ErrState
	}
	for i, x := range s.Sessions {
		epoch, ok := decimal(x.Open.SessionEpoch, false)
		last, valid := decimal(x.LastAllocated, true)
		released, releaseValid := decimal(x.ReleasedThrough, true)
		if !ok || !valid || epoch != s.BaseEpoch+uint64(i+1) || x.Open.Kind != "OPEN" || !releaseValid || released > last || x.EmptyReleased && (x.Final == nil || last != 0) {
			return ErrState
		}
		if _, e := v.key(x.Open.SigningKeyID); e != nil || v.verifyHistoricalSession(x.Open) != nil {
			return ErrState
		}
		for j := 0; j < i; j++ {
			prior := s.Sessions[j]
			if prior.Open.SessionID == x.Open.SessionID || prior.Open.BootID == x.Open.BootID && prior.Open.SigningKeyID == x.Open.SigningKeyID {
				return ErrState
			}
		}
		if x.Final != nil {
			if x.Final.Kind != "FINALIZE" || x.Final.SessionEpoch != x.Open.SessionEpoch || x.Final.SessionID != x.Open.SessionID || x.Final.BootID != x.Open.BootID || x.Final.LastAllocatedSequence != strconv.FormatUint(last, 10) {
				return ErrState
			}
			if _, e := v.key(x.Final.SigningKeyID); e != nil || v.verifyHistoricalSession(*x.Final) != nil {
				return ErrState
			}
		} else if i != len(s.Sessions)-1 {
			return ErrState
		}
		if x.OpenAck != nil && !validSessionReceipt(*x.OpenAck, x.Open) {
			return ErrState
		}
		if x.FinalAck != nil && (x.Final == nil || !validSessionReceipt(*x.FinalAck, *x.Final)) {
			return ErrState
		}
	}
	bound := func(k telemetry.BatchKey) bool {
		index, ok := sessionIndex(s, k.SessionEpoch)
		seq, valid := decimal(k.Sequence, false)
		if !ok || !valid || !v.bound(k.ClusterID, k.NodeID, k.EnrollmentID) {
			return false
		}
		x := s.Sessions[index]
		last, _ := decimal(x.LastAllocated, true)
		return k.SessionID == x.Open.SessionID && seq <= last
	}
	if s.Pending != nil && !bound(s.Pending.Key) {
		return ErrState
	}
	seen := map[telemetry.BatchKey]bool{}
	gapFacts := 0
	for _, g := range s.Gaps {
		gapFacts += len(g.SourceIDs)
		if gapFacts > telemetry.MaxLossRanges {
			return ErrState
		}
		pub, e := v.key(g.SigningKeyID)
		if e != nil || !bound(g.Key) || seen[g.Key] || !verifyGap(g, pub) || len(g.SourceIDs) == 0 || len(g.SourceIDs) > 16 || wireReason(g.Reason) == "" {
			return ErrState
		}
		seen[g.Key] = true
		for i, id := range g.SourceIDs {
			if !v.allowed(id) || i > 0 && g.SourceIDs[i-1] >= id {
				return ErrState
			}
		}
		if g.Carrier != nil && (g.Carrier.Key != g.Carrier.Receipt.Key || g.Carrier.Digest != g.Carrier.Receipt.Digest || !validBatchReceipt(g.Carrier.Receipt, g.Carrier.Key, g.Carrier.Digest)) {
			return ErrState
		}
	}
	r.state = s
	return nil
}
func allocatorBody(s allocator) (allocator, []byte, error) {
	s.Checksum = checksum(s)
	body, e := json.Marshal(s)
	if e != nil || len(body) > allocatorLimit {
		return allocator{}, nil, ErrCapacity
	}
	return s, body, nil
}
func (r *Runtime) save(ctx context.Context, s allocator) error {
	s, body, e := allocatorBody(s)
	if e != nil {
		return e
	}
	e = r.q.WithMetadataWrite(ctx, int64(len(body)), func() error { return r.writeAllocator(s, body) })
	if e != nil {
		return ErrState
	}
	return nil
}

// writeAllocator performs only bounded local metadata I/O. Retirement invokes
// it under the journal's existing budget/mutex, so it must never call Queue.
// The exact target checksum makes callback replay after rename/SQL interruption
// idempotent without recreating observations, gaps, sessions or network facts.
func (r *Runtime) writeAllocator(s allocator, body []byte) error {
	existing, readErr := readOwnerFile(filepath.Join(r.config.Root, allocatorName), allocatorLimit)
	if r.state.Version == 0 {
		if !errors.Is(readErr, os.ErrNotExist) {
			return ErrState
		}
	} else {
		var current allocator
		if readErr != nil || telemetry.DecodeStrictJSON(existing, "", &current) != nil || current.Checksum != checksum(current) {
			return ErrState
		}
		if current.Checksum == s.Checksum {
			r.state = s
			return nil
		}
		if current.Checksum != r.state.Checksum {
			return ErrState
		}
	}
	id, e := randomID("allocator-")
	if e != nil {
		return e
	}
	tmp := filepath.Join(r.config.Root, id+".tmp")
	fd, e := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "node-allocator")
	defer os.Remove(tmp)
	_, e = f.Write(body)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = r.fail("allocator_file_synced"); e != nil {
		return e
	}
	if e = os.Rename(tmp, filepath.Join(r.config.Root, allocatorName)); e != nil {
		return e
	}
	if e = r.fail("allocator_renamed"); e != nil {
		return e
	}
	d, e := os.Open(r.config.Root)
	if e != nil {
		return e
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return e
	}
	r.state = s
	return nil
}
func (r *Runtime) fail(point string) error {
	if r.config.fault != nil {
		return r.config.fault(point)
	}
	return nil
}
func validSessionReceipt(x telemetry.SessionReceipt, m telemetry.SessionMessage) bool {
	return x.ProtocolVersion == 1 && telemetry.ValidIdentifier(x.ID) && x.Durability == "GATEWAY" && x.ClusterID == m.ClusterID && x.NodeID == m.NodeID && x.EnrollmentID == m.EnrollmentID && x.EnrollmentRevision == m.EnrollmentRevision && x.SessionEpoch == m.SessionEpoch && x.SessionID == m.SessionID && x.BootID == m.BootID && x.Kind == m.Kind && x.Digest == m.Digest && !x.StoredAt.IsZero() && x.Finalized == (m.Kind == "FINALIZE") && !x.Covered && (!x.Retired || m.Kind == "FINALIZE")
}
func validBatchReceipt(x telemetry.Receipt, k telemetry.BatchKey, digest string) bool {
	return x.ProtocolVersion == 1 && telemetry.ValidIdentifier(x.ID) && x.Durability == "GATEWAY" && x.Key == k && x.Digest == digest && !x.StoredAt.IsZero()
}
func wireReason(reason string) string {
	switch reason {
	case "LOCAL_COMMIT_INTERRUPTED":
		return "SOURCE_LOSS"
	case "NODE_EXPIRED":
		return "SPOOL_EXPIRED"
	case "NODE_CAPACITY":
		return "SPOOL_OVERFLOW"
	}
	return ""
}
