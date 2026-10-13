package telemetryjournal

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func canonicalNumber(s string, positive bool) bool {
	n, e := strconv.ParseUint(s, 10, 64)
	return e == nil && strconv.FormatUint(n, 10) == s && (!positive || n > 0)
}
func (q *Queue) recoverRetirementIndexes(ctx context.Context) error {
	var orphan int
	for _, query := range []string{
		`SELECT 1 FROM release_prefix p LEFT JOIN sessions s ON s.epoch=p.epoch LEFT JOIN retained_sessions r ON r.epoch=p.epoch WHERE s.epoch IS NULL AND r.epoch IS NULL LIMIT 1`,
		`SELECT 1 FROM ownership_ranges p LEFT JOIN sessions s ON s.epoch=p.epoch LEFT JOIN retained_sessions r ON r.epoch=p.epoch WHERE s.epoch IS NULL AND r.epoch IS NULL LIMIT 1`,
	} {
		if e := q.db.QueryRowContext(ctx, query).Scan(&orphan); e != sql.ErrNoRows {
			return ErrCorrupt
		}
	}
	base, e := q.retirementBase(ctx)
	if e != nil {
		return e
	}
	var retainedCount int
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM retained_sessions`).Scan(&retainedCount) != nil || uint64(retainedCount) != releaseNumber(base) {
		return ErrCorrupt
	}
	// Cursor/prefix identities are small bounded facts, never a reason to reset.
	rows, e := q.db.QueryContext(ctx, `SELECT epoch,through,completed,expired,empty_completed FROM release_prefix`)
	if e != nil {
		return ErrCorrupt
	}
	count := 0
	for rows.Next() {
		var epoch, a, b, c string
		var empty int
		if rows.Scan(&epoch, &a, &b, &c, &empty) != nil || !canonicalNumber(epoch, true) || !canonicalNumber(a, false) || !canonicalNumber(b, false) || !canonicalNumber(c, false) || empty < 0 || empty > 1 || empty == 1 && (a != "0" || b != "0") {
			rows.Close()
			return ErrCorrupt
		}
		count++
		if count > MaxRetainedReceiptSessions+8 {
			rows.Close()
			return ErrCapacity
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrCorrupt
	}
	// Stream sorted interval facts instead of materializing the lifetime ledger.
	rows, e = q.db.QueryContext(ctx, `SELECT epoch,kind,first,last FROM ownership_ranges ORDER BY length(epoch),epoch,kind,length(first),first`)
	if e != nil {
		return ErrCorrupt
	}
	priorEpoch, priorKind := "", ""
	var priorLast uint64
	perGroup := 0
	total := 0
	for rows.Next() {
		var epoch, kind, a, b string
		if rows.Scan(&epoch, &kind, &a, &b) != nil || !canonicalNumber(epoch, true) || !canonicalNumber(a, true) || !canonicalNumber(b, true) || releaseNumber(a) > releaseNumber(b) || (kind != "TRANSFERRED" && kind != "LOSS" && kind != "EXPIRED") {
			rows.Close()
			return ErrCorrupt
		}
		if epoch == priorEpoch && kind == priorKind {
			if priorLast == ^uint64(0) || releaseNumber(a) <= priorLast+1 {
				rows.Close()
				return ErrCorrupt
			}
			perGroup++
		} else {
			perGroup = 1
		}
		if perGroup > 256 {
			rows.Close()
			return ErrCapacity
		}
		priorEpoch, priorKind, priorLast = epoch, kind, releaseNumber(b)
		total++
		if total > (MaxRetainedReceiptSessions+8)*3*256 {
			rows.Close()
			return ErrCapacity
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrCorrupt
	}
	rows, e = q.db.QueryContext(ctx, `SELECT epoch,id,boot,signing_key,terminal FROM retained_sessions`)
	if e != nil {
		return ErrCorrupt
	}
	count = 0
	for rows.Next() {
		var epoch, id, boot, key, last string
		if rows.Scan(&epoch, &id, &boot, &key, &last) != nil || !canonicalNumber(epoch, true) || !validID(id) || !validID(boot) || !validID(key) || !canonicalNumber(last, false) || releaseNumber(epoch) > releaseNumber(base) {
			rows.Close()
			return ErrCorrupt
		}
		count++
		if count > MaxRetainedReceiptSessions {
			rows.Close()
			return ErrCapacity
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrCorrupt
	}
	if e := q.recoverLossHandoffs(ctx); e != nil {
		return e
	}
	return q.recoverSessionHandoffs(ctx)
}
func (q *Queue) recoverSessionHandoffs(ctx context.Context) error {
	afterEpoch, afterKind := "", ""
	total := 0
	for {
		rows, e := q.db.QueryContext(ctx, `SELECT epoch,kind,body FROM session_handoffs WHERE epoch>? OR epoch=? AND kind>? ORDER BY epoch,kind LIMIT 64`, afterEpoch, afterEpoch, afterKind)
		if e != nil {
			return ErrCorrupt
		}
		type row struct {
			epoch, kind string
			body        []byte
		}
		page := []row{}
		for rows.Next() {
			var r row
			if rows.Scan(&r.epoch, &r.kind, &r.body) != nil || len(r.body) > 4096 {
				rows.Close()
				return ErrCorrupt
			}
			page = append(page, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return ErrCorrupt
		}
		for _, r := range page {
			var receipt telemetry.SessionReceipt
			if json.Unmarshal(r.body, &receipt) != nil {
				return ErrCorrupt
			}
			open, final, e := q.lossSession(ctx, r.epoch)
			if e != nil {
				return ErrCorrupt
			}
			m := open
			if r.kind == "FINALIZE" {
				if json.Unmarshal(final, &m) != nil {
					return ErrCorrupt
				}
			} else if r.kind != "OPEN" {
				return ErrCorrupt
			}
			durability := "GATEWAY"
			if q.opts.Role == Gateway {
				durability = "CLOUD"
			}
			if receipt.ProtocolVersion != 1 || !validID(receipt.ID) || receipt.Durability != durability || receipt.SessionEpoch != r.epoch || receipt.Kind != r.kind || receipt.ClusterID != m.ClusterID || receipt.NodeID != m.NodeID || receipt.EnrollmentID != m.EnrollmentID || receipt.EnrollmentRevision != m.EnrollmentRevision || receipt.SessionID != m.SessionID || receipt.BootID != m.BootID || receipt.StoredAt.Year() < 2020 || receipt.StoredAt.Year() > 2200 || receipt.Finalized != (r.kind == "FINALIZE") {
				return ErrCorrupt
			}
			// Retained compact identities omit original lifecycle bodies. Active bodies
			// must match exactly; retained receipts retain their original immutable digest.
			var active int
			e = q.db.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE epoch=?`, r.epoch).Scan(&active)
			if e == nil && receipt.Digest != m.Digest {
				return ErrCorrupt
			}
			if e != nil && e != sql.ErrNoRows {
				return ErrCorrupt
			}
			if !validDigest(receipt.Digest) {
				return ErrCorrupt
			}
			total++
			if total > (MaxRetainedReceiptSessions+8)*2 {
				return ErrCapacity
			}
			afterEpoch, afterKind = r.epoch, r.kind
		}
		if len(page) < 64 {
			return nil
		}
	}
}

func (q *Queue) recoverLossHandoffs(ctx context.Context) error {
	after := ""
	for {
		rows, e := q.db.QueryContext(ctx, `SELECT h.loss_id,h.receipt,h.ack,l.id FROM source_loss_handoff h LEFT JOIN source_loss l ON l.id=h.loss_id WHERE h.loss_id>? ORDER BY h.loss_id LIMIT 64`, after)
		if e != nil {
			return ErrCorrupt
		}
		type fact struct {
			id           string
			receipt, ack []byte
			known        sql.NullString
		}
		page := []fact{}
		for rows.Next() {
			var f fact
			if rows.Scan(&f.id, &f.receipt, &f.ack, &f.known) != nil || len(f.receipt) > 4096 || len(f.ack) > 4096 || !f.known.Valid {
				rows.Close()
				return ErrCorrupt
			}
			page = append(page, f)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return ErrCorrupt
		}
		for _, f := range page {
			var original, ack telemetry.Receipt
			if json.Unmarshal(f.receipt, &original) != nil || json.Unmarshal(f.ack, &ack) != nil {
				return ErrCorrupt
			}
			upstream := "GATEWAY"
			if q.opts.Role == Gateway {
				upstream = "CLOUD"
			}
			if original.ProtocolVersion != 1 || ack.ProtocolVersion != 1 || !validID(original.ID) || !validID(ack.ID) || original.Durability != string(q.opts.Role) || ack.Durability != upstream || !q.boundKey(original.Key) || ack.Key != original.Key || !validDigest(original.Digest) || ack.Digest != original.Digest || original.StoredAt.Year() < 2020 || original.StoredAt.Year() > 2200 || ack.StoredAt.Year() < 2020 || ack.StoredAt.Year() > 2200 {
				return ErrCorrupt
			}
			m, _, e := q.lossSession(ctx, original.Key.SessionEpoch)
			if e != nil || m.SessionID != original.Key.SessionID {
				return ErrCorrupt
			}
			after = f.id
		}
		if len(page) < 64 {
			return nil
		}
	}
}
