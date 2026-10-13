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

var releaseSchema = []string{
	`CREATE TABLE IF NOT EXISTS source_loss_handoff(loss_id TEXT PRIMARY KEY REFERENCES source_loss(id),receipt BLOB NOT NULL,ack BLOB NOT NULL) STRICT,WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS retirement_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),retired_epoch TEXT NOT NULL) STRICT`,
	`INSERT OR IGNORE INTO retirement_state VALUES(1,'0')`,
	`CREATE TABLE IF NOT EXISTS release_prefix(epoch TEXT PRIMARY KEY,through TEXT NOT NULL,completed TEXT NOT NULL,expired TEXT NOT NULL,empty_completed INTEGER NOT NULL DEFAULT 0) STRICT,WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS release_ledger(id TEXT PRIMARY KEY,epoch TEXT NOT NULL,range_id TEXT NOT NULL,digest TEXT NOT NULL,phase TEXT NOT NULL,body BLOB NOT NULL) STRICT,WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS release_pending ON release_ledger(epoch,phase,range_id)`,
	`CREATE TABLE IF NOT EXISTS release_loss(release_id TEXT NOT NULL REFERENCES release_ledger(id),loss_id TEXT NOT NULL REFERENCES source_loss(id),PRIMARY KEY(release_id,loss_id)) STRICT,WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS ownership_ranges(epoch TEXT NOT NULL,kind TEXT NOT NULL,first TEXT NOT NULL,last TEXT NOT NULL,PRIMARY KEY(epoch,kind,first)) STRICT,WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS loss_release_anchor(id TEXT PRIMARY KEY REFERENCES source_loss(id),epoch TEXT NOT NULL,through TEXT NOT NULL) STRICT,WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS session_handoffs(epoch TEXT NOT NULL,kind TEXT NOT NULL,body BLOB NOT NULL,PRIMARY KEY(epoch,kind)) STRICT,WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS final_loss(epoch TEXT NOT NULL,loss_id TEXT NOT NULL REFERENCES source_loss(id),PRIMARY KEY(epoch,loss_id)) STRICT,WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS public_keys(id TEXT PRIMARY KEY,epoch TEXT NOT NULL UNIQUE,public TEXT NOT NULL) STRICT,WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS retained_sessions(epoch TEXT PRIMARY KEY,id TEXT NOT NULL,boot TEXT NOT NULL,signing_key TEXT NOT NULL,terminal TEXT NOT NULL) STRICT,WITHOUT ROWID`,
}

func safeReleaseError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, telemetry.ErrUnauthorized):
		return telemetry.ErrUnauthorized
	case errors.Is(e, telemetry.ErrReplayExpired):
		return telemetry.ErrReplayExpired
	case errors.Is(e, telemetry.ErrConflict):
		return ErrConflict
	default:
		return ErrInvalid
	}
}
func (q *Queue) authorizeRelease(ctx context.Context, env telemetry.ReleaseEnvelope) (ReleaseAuthorization, error) {
	if q.opts.ReleaseVerifier == nil {
		return ReleaseAuthorization{}, ErrInvalid
	}
	if e := q.opts.ReleaseVerifier.AuthorizeRetirement(ctx, q.opts.Scope); e != nil {
		return ReleaseAuthorization{}, safeReleaseError(e)
	}
	auth, e := q.opts.ReleaseVerifier.VerifyRelease(ctx, env)
	if e != nil {
		return auth, safeReleaseError(e)
	}
	d, e := telemetry.CanonicalReleaseDigest(env.Request)
	if telemetry.ValidateReleaseEnvelope(env) != nil || e != nil || env.Request.Digest != hex.EncodeToString(d[:]) || !q.boundRelease(env.Request.Binding()) {
		return auth, ErrInvalid
	}
	return auth, nil
}
func (q *Queue) boundRelease(b telemetry.ReleaseBinding) bool {
	return b.ClusterID == q.opts.Scope.ClusterID && b.NodeID == q.opts.Scope.NodeID && b.EnrollmentID == q.opts.Scope.EnrollmentID
}
func (q *Queue) lockRelease() (func(), error) {
	release, e := q.beginBudget()
	if e != nil {
		return nil, e
	}
	q.mu.Lock()
	if e = q.check(); e != nil {
		q.mu.Unlock()
		release()
		return nil, e
	}
	return func() { q.mu.Unlock(); release() }, nil
}
func (q *Queue) loadRelease(ctx context.Context, id string) (ReleaseRecord, error) {
	var body []byte
	var r ReleaseRecord
	e := q.db.QueryRowContext(ctx, `SELECT body FROM release_ledger WHERE id=?`, id).Scan(&body)
	if errors.Is(e, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if e != nil || len(body) > telemetry.MaxReleaseBytes+(64<<10) || json.Unmarshal(body, &r) != nil {
		return r, q.markCorrupt()
	}
	return r, nil
}
func (q *Queue) saveRelease(ctx context.Context, r ReleaseRecord) error {
	body, e := json.Marshal(r)
	if e != nil || len(body) > telemetry.MaxReleaseBytes+(64<<10) {
		return ErrCapacity
	}
	if e = q.mutationCapacity(ctx, int64(4*len(body))); e != nil {
		return e
	}
	key := telemetry.BatchKey{SessionEpoch: r.Request.SessionEpoch, Sequence: r.Request.FromSequence}
	rangeID, _ := keyID(key)
	_, e = q.db.ExecContext(ctx, `INSERT INTO release_ledger(id,epoch,range_id,digest,phase,body)VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET phase=excluded.phase,body=excluded.body`, r.Request.ReleaseID, r.Request.SessionEpoch, rangeID, r.Request.Digest, r.Phase, body)
	if e != nil {
		return ErrCapacity
	}
	return nil
}
func (q *Queue) ReleaseStatus(ctx context.Context, id string) (ReleaseRecord, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return ReleaseRecord{}, e
	}
	if !validID(id) {
		return ReleaseRecord{}, ErrInvalid
	}
	return q.loadRelease(ctx, id)
}
func (q *Queue) PendingReleases(ctx context.Context, afterID string, limit int) ([]ReleaseRecord, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return nil, false, e
	}
	if limit < 1 || limit > 8 || afterID != "" && !validID(afterID) {
		return nil, false, ErrInvalid
	}
	rows, e := q.db.QueryContext(ctx, `SELECT body FROM release_ledger WHERE phase<>'COMPLETE' AND id>? ORDER BY id LIMIT ?`, afterID, limit+1)
	if e != nil {
		return nil, false, q.markCorrupt()
	}
	defer rows.Close()
	out := []ReleaseRecord{}
	for rows.Next() {
		var b []byte
		var r ReleaseRecord
		if rows.Scan(&b) != nil || len(b) > telemetry.MaxReleaseBytes+(64<<10) || json.Unmarshal(b, &r) != nil {
			return nil, false, q.markCorrupt()
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, false, q.markCorrupt()
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}
func releaseNumber(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }
func (q *Queue) prefix(ctx context.Context, epoch string) (through, completed, expired string, empty bool, e error) {
	var n int
	e = q.db.QueryRowContext(ctx, `SELECT through,completed,expired,empty_completed FROM release_prefix WHERE epoch=?`, epoch).Scan(&through, &completed, &expired, &n)
	if errors.Is(e, sql.ErrNoRows) {
		return "0", "0", "0", false, nil
	}
	if e != nil {
		return "", "", "", false, q.markCorrupt()
	}
	return through, completed, expired, n == 1, nil
}
func (q *Queue) newRelease(ctx context.Context, env telemetry.ReleaseEnvelope, auth ReleaseAuthorization, phase string) (ReleaseRecord, error) {
	req := env.Request
	if e := q.verifyHistoricalRelease(ctx, ReleaseRecord{Request: req}); e != nil {
		return ReleaseRecord{}, ErrInvalid
	}
	prior, e := q.loadRelease(ctx, req.ReleaseID)
	if e == nil {
		if prior.Request.Digest != req.Digest || prior.Request.ManifestDigest != req.ManifestDigest || prior.Request.SigningKeyID != req.SigningKeyID {
			return prior, ErrConflict
		}
		return prior, nil
	}
	if e != ErrNotFound {
		return prior, e
	}
	if !auth.SignerActive {
		return prior, telemetry.ErrUnauthorized
	}
	var completedRecords int
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM release_ledger WHERE epoch=? AND phase='COMPLETE'`, req.SessionEpoch).Scan(&completedRecords) != nil {
		return prior, q.markCorrupt()
	}
	if completedRecords > 8 {
		if e = q.trimCompletedReleases(ctx, req.SessionEpoch); e != nil {
			return prior, e
		}
	}
	through, _, expired, empty, e := q.prefix(ctx, req.SessionEpoch)
	if e != nil {
		return prior, e
	}
	if empty {
		return prior, telemetry.ErrReplayExpired
	}
	if req.ThroughSequence != "0" && releaseNumber(req.ThroughSequence) <= releaseNumber(expired) {
		return prior, telemetry.ErrReplayExpired
	}
	var pending int
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM release_ledger WHERE phase<>'COMPLETE' AND epoch=?`, req.SessionEpoch).Scan(&pending) != nil {
		return prior, q.markCorrupt()
	}
	if pending > 0 {
		return prior, ErrConflict
	}
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM release_ledger WHERE phase<>'COMPLETE'`).Scan(&pending) != nil {
		return prior, q.markCorrupt()
	}
	if pending >= 8 {
		return prior, ErrCapacity
	}
	var openBody, finalBody []byte
	e = q.db.QueryRowContext(ctx, `SELECT open,final FROM sessions WHERE epoch=?`, req.SessionEpoch).Scan(&openBody, &finalBody)
	if errors.Is(e, sql.ErrNoRows) {
		return prior, ErrInvalid
	}
	if e != nil {
		return prior, q.markCorrupt()
	}
	var open telemetry.SessionMessage
	if json.Unmarshal(openBody, &open) != nil {
		return prior, q.markCorrupt()
	}
	if open.SessionID != req.SessionID {
		return prior, ErrConflict
	}
	if req.FromSequence == "0" {
		var final telemetry.SessionMessage
		if len(finalBody) == 0 || json.Unmarshal(finalBody, &final) != nil || final.LastAllocatedSequence != "0" || through != "0" {
			return prior, ErrConflict
		}
	} else {
		n := releaseNumber(through)
		if n == ^uint64(0) || releaseNumber(req.FromSequence) != n+1 {
			return prior, ErrConflict
		}
		if len(finalBody) > 0 {
			var final telemetry.SessionMessage
			if json.Unmarshal(finalBody, &final) != nil {
				return prior, q.markCorrupt()
			}
			if releaseNumber(req.ThroughSequence) > releaseNumber(final.LastAllocatedSequence) {
				return prior, ErrConflict
			}
		}
	}
	if e = q.proveRelease(ctx, env, false); e != nil {
		return prior, e
	}
	prior = ReleaseRecord{Request: req, Manifest: env.Manifest, Phase: phase}
	return prior, nil
}
func (q *Queue) SealRelease(ctx context.Context, req telemetry.ReleaseRequest, manifest telemetry.ReleaseManifest) error {
	if q.opts.Role != Node {
		return ErrRole
	}
	env := telemetry.ReleaseEnvelope{Request: req, Manifest: manifest}
	auth, e := q.authorizeRelease(ctx, env)
	if e != nil {
		return e
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return e
	}
	defer unlock()
	r, e := q.newRelease(ctx, env, auth, "SEALED")
	if e != nil {
		return e
	}
	return q.persistNewRelease(ctx, r)
}
func (q *Queue) AdmitRelease(ctx context.Context, req telemetry.ReleaseRequest, manifest telemetry.ReleaseManifest) (telemetry.ReleaseAdmissionReceipt, error) {
	if q.opts.Role != Gateway {
		return telemetry.ReleaseAdmissionReceipt{}, ErrRole
	}
	env := telemetry.ReleaseEnvelope{Request: req, Manifest: manifest}
	auth, e := q.authorizeRelease(ctx, env)
	if e != nil {
		return telemetry.ReleaseAdmissionReceipt{}, e
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return telemetry.ReleaseAdmissionReceipt{}, e
	}
	defer unlock()
	r, e := q.newRelease(ctx, env, auth, "RELEASING")
	if e != nil {
		return telemetry.ReleaseAdmissionReceipt{}, e
	}
	if r.Admission != nil {
		return *r.Admission, nil
	}
	r.Admission = &telemetry.ReleaseAdmissionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: randomReleaseID("admission"), Binding: req.Binding(), StoredAt: q.opts.Now().UTC(), Durability: "GATEWAY"}
	if r.Admission.ID == "" {
		return telemetry.ReleaseAdmissionReceipt{}, ErrCapacity
	}
	if e = q.persistNewRelease(ctx, r); e != nil {
		return telemetry.ReleaseAdmissionReceipt{}, e
	}
	return *r.Admission, nil
}
func randomReleaseID(prefix string) string {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return ""
	}
	return prefix + "-" + hex.EncodeToString(raw[:])
}
func (q *Queue) persistNewRelease(ctx context.Context, r ReleaseRecord) error {
	if prior, e := q.loadRelease(ctx, r.Request.ReleaseID); e == nil {
		if prior.Request.Digest != r.Request.Digest {
			return ErrConflict
		}
		return nil
	} else if e != ErrNotFound {
		return e
	}
	body, _ := json.Marshal(r)
	if e := q.mutationCapacity(ctx, int64(4*len(body))); e != nil {
		return e
	}
	tx, e := q.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrCapacity
	}
	defer tx.Rollback()
	rangeID, _ := keyID(telemetry.BatchKey{SessionEpoch: r.Request.SessionEpoch, Sequence: r.Request.FromSequence})
	if _, e = tx.ExecContext(ctx, `INSERT INTO release_ledger VALUES(?,?,?,?,?,?)`, r.Request.ReleaseID, r.Request.SessionEpoch, rangeID, r.Request.Digest, r.Phase, body); e != nil {
		return ErrCapacity
	}
	for _, ref := range r.Manifest.Loss {
		if _, e = tx.ExecContext(ctx, `INSERT INTO release_loss VALUES(?,?)`, r.Request.ReleaseID, ref.LossID); e != nil {
			return ErrCapacity
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO release_prefix(epoch,through,completed,expired)VALUES(?,'0','0','0')`, r.Request.SessionEpoch); e != nil {
		return ErrCapacity
	}
	if e = q.fail("release_sealed"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return ErrCapacity
	}
	return nil
}
