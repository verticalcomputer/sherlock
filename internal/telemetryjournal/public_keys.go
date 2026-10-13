package telemetryjournal

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strconv"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// registerPublicKeys preserves identity only. Stored keys never confer current
// admission/signing authority and are not merged into an authenticated grant.
func (q *Queue) registerPublicKeys(ctx context.Context) error {
	if len(q.opts.PublicKeys) > 2 {
		return ErrInvalid
	}
	keys := append([]telemetry.NodeKey(nil), q.opts.PublicKeys...)
	sort.Slice(keys, func(i, j int) bool { return releaseNumber(keys[i].Epoch) < releaseNumber(keys[j].Epoch) })
	var high string
	if q.db.QueryRowContext(ctx, `SELECT coalesce((SELECT epoch FROM public_keys ORDER BY length(epoch) DESC,epoch DESC LIMIT 1),'0')`).Scan(&high) != nil {
		return ErrCorrupt
	}
	for _, key := range keys {
		epoch, e := strconv.ParseUint(key.Epoch, 10, 64)
		if e != nil || epoch == 0 || strconv.FormatUint(epoch, 10) != key.Epoch || !validID(key.ID) {
			return ErrInvalid
		}
		if _, e = telemetry.ParseNodePublicKey(key); e != nil {
			return ErrInvalid
		}
		var storedEpoch, pub string
		e = q.db.QueryRowContext(ctx, `SELECT epoch,public FROM public_keys WHERE id=?`, key.ID).Scan(&storedEpoch, &pub)
		if e == nil {
			if storedEpoch != key.Epoch || pub != key.PublicKeyBase64 {
				return ErrConflict
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return ErrCorrupt
		}
		if epoch <= releaseNumber(high) {
			return ErrConflict
		}
		var count int
		if q.db.QueryRowContext(ctx, `SELECT count(*) FROM public_keys`).Scan(&count) != nil {
			return ErrCorrupt
		}
		if count >= 4096 {
			return ErrCapacity
		}
		if e = q.mutationCapacity(ctx, 4096); e != nil {
			return e
		}
		if _, e = q.db.ExecContext(ctx, `INSERT INTO public_keys VALUES(?,?,?)`, key.ID, key.Epoch, key.PublicKeyBase64); e != nil {
			return ErrConflict
		}
		high = key.Epoch
	}
	return nil
}
func (q *Queue) GetHistoricalPublicKeys(ctx context.Context) ([]telemetry.NodeKey, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return nil, e
	}
	out := make([]telemetry.NodeKey, 0)
	after := ""
	for {
		rows, e := q.db.QueryContext(ctx, `SELECT id,epoch,public FROM public_keys WHERE id>? ORDER BY id LIMIT 256`, after)
		if e != nil {
			return nil, q.markCorrupt()
		}
		page := 0
		for rows.Next() {
			var key telemetry.NodeKey
			if rows.Scan(&key.ID, &key.Epoch, &key.PublicKeyBase64) != nil {
				rows.Close()
				return nil, q.markCorrupt()
			}
			key.State = "ARCHIVED"
			if _, e = telemetry.ParseNodePublicKey(key); e != nil {
				rows.Close()
				return nil, q.markCorrupt()
			}
			out = append(out, key)
			after = key.ID
			page++
			if len(out) > 4096 {
				rows.Close()
				return nil, ErrCapacity
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, q.markCorrupt()
		}
		if page < 256 {
			return out, nil
		}
	}
}
