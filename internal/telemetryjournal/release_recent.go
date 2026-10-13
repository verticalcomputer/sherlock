package telemetryjournal

import (
	"context"
	"encoding/json"
)

func (q *Queue) trimCompletedReleases(ctx context.Context, epoch string) error {
	rows, e := q.db.QueryContext(ctx, `SELECT body FROM release_ledger WHERE epoch=? AND phase='COMPLETE' ORDER BY range_id DESC LIMIT 10`, epoch)
	if e != nil {
		return q.markCorrupt()
	}
	records := []ReleaseRecord{}
	for rows.Next() {
		var b []byte
		var r ReleaseRecord
		if rows.Scan(&b) != nil || json.Unmarshal(b, &r) != nil {
			rows.Close()
			return q.markCorrupt()
		}
		records = append(records, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(records) > 9 {
		return q.markCorrupt()
	}
	if e = q.mutationCapacity(ctx, 256<<10); e != nil {
		return e
	}
	tx, e := q.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrCapacity
	}
	defer tx.Rollback()
	for i, r := range records {
		if i < 8 {
			// Digests and exact phase receipts suffice for completed replay; the
			// original selected manifest is unnecessary once node completion is durable.
			r.Manifest.Batches = nil
			r.Manifest.Loss = nil
			b, _ := json.Marshal(r)
			if _, e = tx.ExecContext(ctx, `UPDATE release_ledger SET body=? WHERE id=?`, b, r.Request.ReleaseID); e != nil {
				return ErrCapacity
			}
		} else {
			if _, e = tx.ExecContext(ctx, `UPDATE release_prefix SET expired=? WHERE epoch=?`, r.Request.ThroughSequence, epoch); e != nil {
				return ErrCapacity
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM release_loss WHERE release_id=?`, r.Request.ReleaseID); e != nil {
				return ErrCapacity
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM release_ledger WHERE id=?`, r.Request.ReleaseID); e != nil {
				return ErrCapacity
			}
		}
	}
	if e = tx.Commit(); e != nil {
		return ErrCapacity
	}
	return nil
}
