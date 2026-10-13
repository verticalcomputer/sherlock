package telemetryjournal

import (
	"context"
	"encoding/json"
	"math"
)

type JournalLoss struct {
	Ordinal uint64
	Loss    LocalLoss
}

// LocalLosses pages the monotonically allocated durable loss ordinal. The
// cursor is independent of source time/session/sequence, so a late old-session
// expiry cannot fall behind a previously delivered cursor. No loss is pruned.
func (q *Queue) LocalLosses(ctx context.Context, after uint64, limit int) ([]JournalLoss, uint64, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return nil, after, false, e
	}
	if after > math.MaxInt64 || limit < 1 || limit > 128 {
		return nil, after, false, ErrInvalid
	}
	rows, e := q.db.QueryContext(ctx, `SELECT o.ordinal,i.loss FROM loss_order o JOIN item_rows i ON i.id=o.item_id WHERE o.ordinal>? ORDER BY o.ordinal LIMIT ?`, int64(after), limit+1)
	if e != nil {
		return nil, after, false, q.markCorrupt()
	}
	defer rows.Close()
	out := make([]JournalLoss, 0, limit)
	next := after
	more := false
	for rows.Next() {
		var ordinal int64
		var body []byte
		var loss LocalLoss
		if rows.Scan(&ordinal, &body) != nil || ordinal < 1 || json.Unmarshal(body, &loss) != nil || !q.boundKey(loss.AffectedKey) || !validSources(loss.Sources) {
			return nil, after, false, q.markCorrupt()
		}
		if len(out) == limit {
			more = true
			break
		}
		out = append(out, JournalLoss{uint64(ordinal), loss})
		next = uint64(ordinal)
	}
	if rows.Err() != nil {
		return nil, after, false, q.markCorrupt()
	}
	return out, next, more, nil
}
