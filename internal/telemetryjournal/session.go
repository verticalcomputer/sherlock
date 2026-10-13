package telemetryjournal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// SessionAuthorization comes from authenticated current-grant and signature
// validation. Only ACTIVE signers may create a new session. A matching known
// session replay may authenticate with its VERIFY_ONLY key until ownership is
// retired. Revocation must fail in the verifier before any receipt lookup.
type SessionAuthorization struct{ SignerActive bool }
type SessionVerifier interface {
	VerifySession(context.Context, telemetry.SessionMessage) (SessionAuthorization, error)
}

const sessionSchema = `CREATE TABLE IF NOT EXISTS sessions(epoch TEXT PRIMARY KEY,id TEXT NOT NULL UNIQUE,boot TEXT NOT NULL,signing_key TEXT NOT NULL,open BLOB NOT NULL,open_receipt BLOB NOT NULL,final BLOB,final_receipt BLOB,UNIQUE(boot,signing_key)) STRICT`

// RegisterSession durably records a signed lifecycle message before returning
// its immutable receipt. It never infers coverage or retires a session. At most
// eight sessions may be retained; ownership retirement is a separate future gate.
func (q *Queue) RegisterSession(ctx context.Context, m telemetry.SessionMessage) (telemetry.SessionReceipt, error) {
	if q.opts.SessionVerifier == nil {
		return telemetry.SessionReceipt{}, ErrInvalid
	}
	auth, e := q.opts.SessionVerifier.VerifySession(ctx, m)
	if e != nil {
		return telemetry.SessionReceipt{}, ErrInvalid
	}
	digest, e := telemetry.CanonicalSessionDigest(m)
	if e != nil || m.Digest != hex.EncodeToString(digest[:]) {
		return telemetry.SessionReceipt{}, ErrInvalid
	}
	unlock, budgetErr := q.beginBudget()
	if budgetErr != nil {
		return telemetry.SessionReceipt{}, budgetErr
	}
	defer unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if e = q.check(); e != nil {
		return telemetry.SessionReceipt{}, e
	}
	if e = q.verifyKnownSessionSigner(ctx, m); e != nil {
		return telemetry.SessionReceipt{}, e
	}
	if m.ClusterID != q.opts.Scope.ClusterID || m.NodeID != q.opts.Scope.NodeID || m.EnrollmentID != q.opts.Scope.EnrollmentID {
		return telemetry.SessionReceipt{}, ErrInvalid
	}
	base, baseErr := q.retirementBase(ctx)
	if baseErr != nil {
		return telemetry.SessionReceipt{}, baseErr
	}
	if releaseNumber(m.SessionEpoch) <= releaseNumber(base) {
		return telemetry.SessionReceipt{}, telemetry.ErrReplayExpired
	}
	var openBody, openReceipt, finalBody, finalReceipt []byte
	e = q.db.QueryRowContext(ctx, `SELECT open,open_receipt,final,final_receipt FROM sessions WHERE epoch=?`, m.SessionEpoch).Scan(&openBody, &openReceipt, &finalBody, &finalReceipt)
	if e == nil {
		var original telemetry.SessionMessage
		if json.Unmarshal(openBody, &original) != nil {
			return telemetry.SessionReceipt{}, q.markCorrupt()
		}
		if original.SessionID != m.SessionID || original.BootID != m.BootID {
			return telemetry.SessionReceipt{}, ErrConflict
		}
		if m.Kind == "FINALIZE" && !auth.SignerActive && m.SigningKeyID != original.SigningKeyID {
			return telemetry.SessionReceipt{}, ErrInvalid
		}
		if m.Kind == "OPEN" {
			if original.Digest != m.Digest {
				return telemetry.SessionReceipt{}, ErrConflict
			}
			var r telemetry.SessionReceipt
			if json.Unmarshal(openReceipt, &r) != nil {
				return r, q.markCorrupt()
			}
			return r, nil
		}
		if len(finalBody) > 0 {
			var prior telemetry.SessionMessage
			var r telemetry.SessionReceipt
			if json.Unmarshal(finalBody, &prior) != nil || json.Unmarshal(finalReceipt, &r) != nil {
				return r, q.markCorrupt()
			}
			if prior.Digest != m.Digest {
				return r, ErrConflict
			}
			return r, nil
		}
		if e = q.validateSourceLosses(ctx, telemetry.BatchKey{}, m.Loss, true); e != nil {
			return telemetry.SessionReceipt{}, e
		}
		if e = q.validateTerminal(ctx, m, false); e != nil {
			return telemetry.SessionReceipt{}, e
		}
	} else if errors.Is(e, sql.ErrNoRows) {
		if m.Kind != "OPEN" || !auth.SignerActive {
			return telemetry.SessionReceipt{}, ErrInvalid
		}
		rows, err := q.db.QueryContext(ctx, `SELECT epoch,id,boot,signing_key FROM sessions`)
		if err != nil {
			return telemetry.SessionReceipt{}, q.markCorrupt()
		}
		highest := releaseNumber(base)
		count := 0
		for rows.Next() {
			var epoch, id, boot, key string
			if rows.Scan(&epoch, &id, &boot, &key) != nil {
				rows.Close()
				return telemetry.SessionReceipt{}, q.markCorrupt()
			}
			n, err := strconv.ParseUint(epoch, 10, 64)
			if err != nil {
				rows.Close()
				return telemetry.SessionReceipt{}, q.markCorrupt()
			}
			if n > highest {
				highest = n
			}
			if id == m.SessionID || boot == m.BootID && key == m.SigningKeyID {
				rows.Close()
				return telemetry.SessionReceipt{}, ErrConflict
			}
			count++
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return telemetry.SessionReceipt{}, q.markCorrupt()
		}
		next, err := strconv.ParseUint(m.SessionEpoch, 10, 64)
		if err != nil || highest == ^uint64(0) || next != highest+1 {
			return telemetry.SessionReceipt{}, ErrConflict
		}
		if count >= 8 {
			return telemetry.SessionReceipt{}, ErrCapacity
		}
	} else {
		return telemetry.SessionReceipt{}, q.markCorrupt()
	}
	body, _ := json.Marshal(m)
	var raw [16]byte
	if _, e = rand.Read(raw[:]); e != nil {
		return telemetry.SessionReceipt{}, ErrCapacity
	}
	r := telemetry.SessionReceipt{ProtocolVersion: telemetry.ProtocolVersion, ID: "session-receipt-" + hex.EncodeToString(raw[:]), ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: m.EnrollmentID, EnrollmentRevision: m.EnrollmentRevision, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, BootID: m.BootID, Kind: m.Kind, Digest: m.Digest, StoredAt: q.opts.Now().UTC(), Durability: string(q.opts.Role), Finalized: m.Kind == "FINALIZE", Covered: false, Retired: false}
	receipt, _ := json.Marshal(r)
	if e = q.mutationCapacity(ctx, int64(3*len(body)+len(receipt))); e != nil {
		return telemetry.SessionReceipt{}, e
	}
	if m.Kind == "OPEN" {
		_, e = q.db.ExecContext(ctx, `INSERT INTO sessions(epoch,id,boot,signing_key,open,open_receipt)VALUES(?,?,?,?,?,?)`, m.SessionEpoch, m.SessionID, m.BootID, m.SigningKeyID, body, receipt)
	} else {
		e = q.persistSessionFinal(ctx, m, body, receipt)
	}
	if e != nil {
		return telemetry.SessionReceipt{}, ErrCapacity
	}
	if e = q.fail("session_committed"); e != nil {
		return telemetry.SessionReceipt{}, e
	}
	return r, nil
}

// CheckBatchSession checks immutable mapping and declared terminal/loss bounds.
// Known older epochs may still deliver historical bytes. This method grants no
// current-health authority and performs no signature/current-grant validation.
func (q *Queue) CheckBatchSession(ctx context.Context, b telemetry.NodeBatch) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return e
	}
	sources := make([]string, 0, len(b.Sources))
	for _, s := range b.Sources {
		sources = append(sources, s.SourceID)
	}
	return q.checkBatchSession(ctx, b.Key, b.BootID, b.SigningKeyID, b.EnrollmentRevision, sources...)
}
func (q *Queue) checkBatchSession(ctx context.Context, k telemetry.BatchKey, boot, key string, revision int64, sources ...string) error {
	if !validKey(k) || revision != 1 || !validID(boot) || !validID(key) || k.ClusterID != q.opts.Scope.ClusterID || k.NodeID != q.opts.Scope.NodeID || k.EnrollmentID != q.opts.Scope.EnrollmentID {
		return ErrInvalid
	}
	var expectedID, expectedBoot, expectedKey string
	var final []byte
	if e := q.db.QueryRowContext(ctx, `SELECT id,boot,signing_key,final FROM sessions WHERE epoch=?`, k.SessionEpoch).Scan(&expectedID, &expectedBoot, &expectedKey, &final); errors.Is(e, sql.ErrNoRows) {
		return ErrInvalid
	} else if e != nil {
		return q.markCorrupt()
	}
	if k.SessionID != expectedID || boot != expectedBoot || key != expectedKey {
		return ErrConflict
	}
	if len(final) > 0 {
		var m telemetry.SessionMessage
		if json.Unmarshal(final, &m) != nil {
			return q.markCorrupt()
		}
		last, _ := strconv.ParseUint(m.LastAllocatedSequence, 10, 64)
		sequence, _ := strconv.ParseUint(k.Sequence, 10, 64)
		if sequence > last {
			return ErrConflict
		}

	}
	return nil
}
func (q *Queue) validateTerminal(ctx context.Context, m telemetry.SessionMessage, recovering bool) error {
	terminal, _ := strconv.ParseUint(m.LastAllocatedSequence, 10, 64)
	rows, e := q.db.QueryContext(ctx, `SELECT key,sources,state FROM items`)
	if e != nil {
		return q.markCorrupt()
	}
	defer rows.Close()
	for rows.Next() {
		var key, sources []byte
		var state string
		var k telemetry.BatchKey
		var names []string
		if rows.Scan(&key, &sources, &state) != nil || json.Unmarshal(key, &k) != nil || json.Unmarshal(sources, &names) != nil {
			return q.markCorrupt()
		}
		if k.SessionEpoch != m.SessionEpoch || k.SessionID != m.SessionID {
			continue
		}
		sequence, e := strconv.ParseUint(k.Sequence, 10, 64)
		if e != nil {
			return q.markCorrupt()
		}
		if sequence > terminal {
			return ErrConflict
		}
		if state == "OWNED" || state == "TRANSFERRED" {
			for _, l := range m.Loss {
				if recovering || l.Range.Reason == "SPOOL_EXPIRED" || l.Range.Reason == "SPOOL_OVERFLOW" {
					continue
				}
				from, _ := strconv.ParseUint(l.Range.AffectedKey.Sequence, 10, 64)
				through, _ := strconv.ParseUint(l.Range.ThroughSequence, 10, 64)
				if sequence >= from && sequence <= through {
					for _, source := range names {
						if source == l.SourceID {
							return ErrConflict
						}
					}
				}
			}
		}
	}
	if rows.Err() != nil {
		return q.markCorrupt()
	}
	return nil
}

func (q *Queue) recoverSessions(ctx context.Context) error {
	base, e := q.retirementBase(ctx)
	if e != nil {
		return e
	}

	rows, e := q.db.QueryContext(ctx, `SELECT epoch,id,boot,signing_key,open,open_receipt,final,final_receipt FROM sessions`)
	if e != nil {
		return ErrCorrupt
	}
	type row struct {
		epoch, id, boot, key               string
		open, receipt, final, finalReceipt []byte
	}
	all := []row{}
	for rows.Next() {
		var r row
		if rows.Scan(&r.epoch, &r.id, &r.boot, &r.key, &r.open, &r.receipt, &r.final, &r.finalReceipt) != nil {
			rows.Close()
			return ErrCorrupt
		}
		all = append(all, r)
		if len(all) > 8 {
			rows.Close()
			return ErrCorrupt
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrCorrupt
	}
	seen := map[uint64]bool{}
	for _, r := range all {
		var open telemetry.SessionMessage
		var receipt telemetry.SessionReceipt
		if json.Unmarshal(r.open, &open) != nil || json.Unmarshal(r.receipt, &receipt) != nil {
			return ErrCorrupt
		}
		epoch, e := strconv.ParseUint(r.epoch, 10, 64)
		if e != nil || epoch <= releaseNumber(base) || epoch-releaseNumber(base) > 8 || seen[epoch] {
			return ErrCorrupt
		}
		seen[epoch] = true
		if !q.validSessionRecord(open, receipt) || open.Kind != "OPEN" || open.SessionEpoch != r.epoch || open.SessionID != r.id || open.BootID != r.boot || open.SigningKeyID != r.key {
			return ErrCorrupt
		}
		if len(r.final) > 0 {
			var final telemetry.SessionMessage
			var finalReceipt telemetry.SessionReceipt
			if json.Unmarshal(r.final, &final) != nil || json.Unmarshal(r.finalReceipt, &finalReceipt) != nil || !q.validSessionRecord(final, finalReceipt) || final.Kind != "FINALIZE" || final.SessionEpoch != open.SessionEpoch || final.SessionID != open.SessionID || final.BootID != open.BootID {
				return ErrCorrupt
			}
			if e = q.validateTerminal(ctx, final, true); e != nil {
				return ErrCorrupt
			}
		} else if len(r.finalReceipt) > 0 {
			return ErrCorrupt
		}
	}
	for n := uint64(1); n <= uint64(len(all)); n++ {
		if !seen[releaseNumber(base)+n] {
			return ErrCorrupt
		}
	}
	return nil
}
func (q *Queue) validSessionRecord(m telemetry.SessionMessage, r telemetry.SessionReceipt) bool {
	key, archived, keyErr := q.historicalPublicKey(context.Background(), m.SigningKeyID)
	if keyErr != nil {
		return false
	}
	if archived {
		public, err := telemetry.ParseNodePublicKey(key)
		if err != nil || telemetry.VerifySessionSignature(m, public) != nil {
			return false
		}
	}
	digest, e := telemetry.CanonicalSessionDigest(m)
	return e == nil && m.Digest == hex.EncodeToString(digest[:]) && m.ClusterID == q.opts.Scope.ClusterID && m.NodeID == q.opts.Scope.NodeID && m.EnrollmentID == q.opts.Scope.EnrollmentID && r.ProtocolVersion == telemetry.ProtocolVersion && validID(r.ID) && r.ClusterID == m.ClusterID && r.NodeID == m.NodeID && r.EnrollmentID == m.EnrollmentID && r.EnrollmentRevision == m.EnrollmentRevision && r.SessionEpoch == m.SessionEpoch && r.SessionID == m.SessionID && r.BootID == m.BootID && r.Kind == m.Kind && r.Digest == m.Digest && r.StoredAt.Year() >= 2020 && r.StoredAt.Year() <= 2200 && r.Durability == string(q.opts.Role) && !r.Retired && !r.Covered && r.Finalized == (m.Kind == "FINALIZE")
}
