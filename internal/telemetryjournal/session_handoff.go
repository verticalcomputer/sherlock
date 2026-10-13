package telemetryjournal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (q *Queue) lossSession(ctx context.Context, epoch string) (telemetry.SessionMessage, []byte, error) {
	var open, final []byte
	e := q.db.QueryRowContext(ctx, `SELECT open,final FROM sessions WHERE epoch=?`, epoch).Scan(&open, &final)
	var m telemetry.SessionMessage
	if e == nil {
		if json.Unmarshal(open, &m) != nil {
			return m, nil, q.markCorrupt()
		}
		return m, final, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return m, nil, q.markCorrupt()
	}
	var id, boot, key, terminal string
	e = q.db.QueryRowContext(ctx, `SELECT id,boot,signing_key,terminal FROM retained_sessions WHERE epoch=?`, epoch).Scan(&id, &boot, &key, &terminal)
	if e == sql.ErrNoRows {
		return m, nil, ErrInvalid
	}
	if e != nil {
		return m, nil, q.markCorrupt()
	}
	m = telemetry.SessionMessage{ProtocolVersion: 1, Kind: "OPEN", ClusterID: q.opts.Scope.ClusterID, NodeID: q.opts.Scope.NodeID, EnrollmentID: q.opts.Scope.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: epoch, SessionID: id, BootID: boot, SigningKeyID: key, CreatedAt: q.opts.Now().UTC()}
	f := m
	f.Kind = "FINALIZE"
	f.LastAllocatedSequence = terminal
	final, _ = json.Marshal(f)
	return m, final, nil
}
func (q *Queue) persistSessionFinal(ctx context.Context, m telemetry.SessionMessage, body, receipt []byte) error {
	tx, e := q.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrCapacity
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `UPDATE sessions SET final=?,final_receipt=? WHERE epoch=? AND final IS NULL`, body, receipt, m.SessionEpoch); e != nil {
		return ErrCapacity
	}
	for _, l := range m.Loss {
		b, d := sourceLossBody(l)
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO source_loss VALUES(?,?,?,?,?)`, l.Range.ID, l.Range.AffectedKey.SessionEpoch, l.SourceID, d, b); e != nil {
			return ErrCapacity
		}
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO final_loss VALUES(?,?)`, m.SessionEpoch, l.Range.ID); e != nil {
			return ErrCapacity
		}
	}
	if e = q.fail("session_losses_inserted"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return ErrCapacity
	}
	return nil
}

// AcknowledgeSession records the exact upstream durable lifecycle handoff.
// Internal NODE/GATEWAY receipt alone never proves delivery to its peer.
func (q *Queue) AcknowledgeSession(ctx context.Context, m telemetry.SessionMessage, receipt telemetry.SessionReceipt) error {
	if q.opts.SessionVerifier == nil {
		return ErrInvalid
	}
	if _, e := q.opts.SessionVerifier.VerifySession(ctx, m); e != nil {
		return safeReleaseError(e)
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return e
	}
	defer unlock()
	expected := "GATEWAY"
	if q.opts.Role == Gateway {
		expected = "CLOUD"
	}
	if receipt.ProtocolVersion != 1 || !validID(receipt.ID) || receipt.Durability != expected || receipt.ClusterID != m.ClusterID || receipt.NodeID != m.NodeID || receipt.EnrollmentID != m.EnrollmentID || receipt.EnrollmentRevision != m.EnrollmentRevision || receipt.SessionEpoch != m.SessionEpoch || receipt.SessionID != m.SessionID || receipt.BootID != m.BootID || receipt.Kind != m.Kind || receipt.Digest != m.Digest || receipt.StoredAt.Year() < 2020 || receipt.StoredAt.Year() > 2200 || receipt.Finalized != (m.Kind == "FINALIZE") || m.Kind == "OPEN" && (receipt.Retired || receipt.Covered) {
		return ErrInvalid
	}
	column := "open"
	if m.Kind == "FINALIZE" {
		column = "final"
	}
	var body []byte
	if q.db.QueryRowContext(ctx, `SELECT `+column+` FROM sessions WHERE epoch=?`, m.SessionEpoch).Scan(&body) != nil {
		return ErrInvalid
	}
	var stored telemetry.SessionMessage
	if json.Unmarshal(body, &stored) != nil {
		return q.markCorrupt()
	}
	if stored.Digest != m.Digest {
		return ErrConflict
	}
	receipt.StoredAt = receipt.StoredAt.UTC()
	body, _ = json.Marshal(receipt)
	var prior []byte
	e = q.db.QueryRowContext(ctx, `SELECT body FROM session_handoffs WHERE epoch=? AND kind=?`, m.SessionEpoch, m.Kind).Scan(&prior)
	if e == nil {
		if string(prior) != string(body) {
			return ErrConflict
		}
		return nil
	}
	if e != sql.ErrNoRows {
		return q.markCorrupt()
	}
	if e = q.mutationCapacity(ctx, int64(4*len(body))); e != nil {
		return e
	}
	if _, e = q.db.ExecContext(ctx, `INSERT INTO session_handoffs VALUES(?,?,?)`, m.SessionEpoch, m.Kind, body); e != nil {
		return ErrCapacity
	}
	return nil
}
