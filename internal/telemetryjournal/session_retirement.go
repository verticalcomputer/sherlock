package telemetryjournal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (q *Queue) SessionRetirementBase(ctx context.Context) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return "", e
	}
	return q.retirementBase(ctx)
}
func (q *Queue) retirementBase(ctx context.Context) (string, error) {
	var base string
	if q.db.QueryRowContext(ctx, `SELECT retired_epoch FROM retirement_state WHERE singleton=1`).Scan(&base) != nil {
		return "", q.markCorrupt()
	}
	return base, nil
}

// CompactFinalizedSessions advances only a contiguous fully completed terminal
// prefix. Callback changes the allocator before the SQL record; restart repeats
// against unchanged immutable terminal/completion proof if the SQL commit failed.
func (q *Queue) CompactFinalizedSessions(ctx context.Context, growthBytes int64, compactAllocator func(base string) (string, error)) error {
	if growthBytes < 0 || growthBytes > 1<<20 || compactAllocator == nil {
		return ErrInvalid
	}
	if _, e := q.RetirementCapabilities(ctx); e != nil {
		return e
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return e
	}
	defer unlock()
	base, e := q.retirementBase(ctx)
	if e != nil {
		return e
	}
	next := releaseNumber(base)
	type retiredSession struct{ epoch, id, boot, key, terminal string }
	done := []retiredSession{}
	for len(done) < 8 && next < ^uint64(0) {
		epoch := strconv.FormatUint(next+1, 10)
		var id, boot, key string
		var finalBody []byte
		e = q.db.QueryRowContext(ctx, `SELECT id,boot,signing_key,final FROM sessions WHERE epoch=?`, epoch).Scan(&id, &boot, &key, &finalBody)
		if e == sql.ErrNoRows {
			break
		}
		if e != nil {
			return q.markCorrupt()
		}
		if len(finalBody) == 0 {
			break
		}
		if q.opts.Role == Gateway {
			var acknowledged int
			if q.db.QueryRowContext(ctx, `SELECT count(*) FROM session_handoffs WHERE epoch=? AND kind='FINALIZE'`, epoch).Scan(&acknowledged) != nil {
				return q.markCorrupt()
			}
			if acknowledged != 1 {
				break
			}
		}
		var final telemetry.SessionMessage
		if json.Unmarshal(finalBody, &final) != nil {
			return q.markCorrupt()
		}
		_, completed, _, empty, e := q.prefix(ctx, epoch)
		if e != nil {
			return e
		}
		if final.LastAllocatedSequence == "0" {
			if !empty {
				break
			}
		} else if completed != final.LastAllocatedSequence {
			break
		}
		var pending int
		if q.db.QueryRowContext(ctx, `SELECT count(*) FROM release_ledger WHERE epoch=? AND phase<>'COMPLETE'`, epoch).Scan(&pending) != nil {
			return q.markCorrupt()
		}
		if pending != 0 {
			break
		}
		if q.db.QueryRowContext(ctx, `SELECT count(*)FROM item_rows WHERE epoch=? AND state IN(0,1)`, epoch).Scan(&pending) != nil {
			return q.markCorrupt()
		}
		if pending != 0 {
			break
		}
		done = append(done, retiredSession{epoch, id, boot, key, final.LastAllocatedSequence})
		next++
	}
	if len(done) == 0 {
		return nil
	}
	var retained int
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM retained_sessions`).Scan(&retained) != nil {
		return q.markCorrupt()
	}
	if retained > MaxRetainedReceiptSessions-len(done) {
		return ErrCapacity
	}
	if e = q.mutationCapacity(ctx, growthBytes+(256<<10)); e != nil {
		return e
	}
	newBase := strconv.FormatUint(next, 10)
	checksum, e := compactAllocator(newBase)
	if e != nil {
		return ErrCapacity
	}
	if !validDigest(checksum) {
		return ErrInvalid
	}
	if e = q.fail("session_allocator_compacted"); e != nil {
		return e
	}
	tx, e := q.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrCapacity
	}
	defer tx.Rollback()
	for _, s := range done {
		var total int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM retained_sessions`).Scan(&total) != nil {
			return ErrCorrupt
		}
		if total >= MaxRetainedReceiptSessions {
			return ErrCapacity
		}
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO retained_sessions VALUES(?,?,?,?,?)`, s.epoch, s.id, s.boot, s.key, s.terminal); e != nil {
			return ErrCapacity
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM sessions WHERE epoch=?`, s.epoch); e != nil {
			return ErrCapacity
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE retirement_state SET retired_epoch=? WHERE singleton=1`, newBase); e != nil {
		return ErrCapacity
	}
	if e = tx.Commit(); e != nil {
		return ErrCapacity
	}
	return q.fail("session_queue_compacted")
}

// CompactGatewaySessions has no external allocator: this gateway's durable SQL
// base is its complete local lifecycle state. The domain hash identifies that
// state transition; it is not a claim that an allocator file was fsynced.
func (q *Queue) CompactGatewaySessions(ctx context.Context) error {
	if q.opts.Role != Gateway {
		return ErrRole
	}
	return q.CompactFinalizedSessions(ctx, 0, func(base string) (string, error) {
		b, _ := json.Marshal(struct {
			Domain string
			Scope  Scope
			Base   string
		}{"sherlock.gateway-session-base.v1", q.opts.Scope, base})
		digest := sha256.Sum256(b)
		return hex.EncodeToString(digest[:]), nil
	})
}
