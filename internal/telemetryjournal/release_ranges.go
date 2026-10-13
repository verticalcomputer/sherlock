package telemetryjournal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (q *Queue) RetirementCapabilities(ctx context.Context) (telemetry.RetirementCapabilities, error) {
	if q.opts.ReleaseVerifier == nil {
		return telemetry.RetirementCapabilities{}, ErrInvalid
	}
	if e := q.opts.ReleaseVerifier.AuthorizeRetirement(ctx, q.opts.Scope); e != nil {
		return telemetry.RetirementCapabilities{}, safeReleaseError(e)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return telemetry.RetirementCapabilities{}, e
	}
	return telemetry.SupportedRetirementCapabilities(), nil
}
func (q *Queue) AdmitNodeCompletion(ctx context.Context, c telemetry.NodeReleaseCompletion) error {
	if q.opts.Role != Gateway {
		return ErrRole
	}
	auth, e := q.authorizeCompletion(ctx, c)
	if e != nil {
		return e
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return e
	}
	defer unlock()
	if e = q.verifyHistoricalCompletion(ctx, c); e != nil {
		return ErrInvalid
	}
	r, e := q.loadRelease(ctx, c.Binding.ReleaseID)
	if e != nil {
		return e
	}
	if !completionMatches(c, r) {
		return ErrConflict
	}
	if r.Completion != nil {
		if !sameJSON(r.Completion, &c) {
			return ErrConflict
		}
		return nil
	}
	if !auth.SignerActive {
		return telemetry.ErrUnauthorized
	}
	if r.Phase != "FINAL_RECEIVED" {
		return ErrRole
	}
	r.Completion = &c
	r.Phase = "NODE_COMPLETION_PENDING"
	return q.saveRelease(ctx, r)
}
func (q *Queue) saveReleaseAndPrefix(ctx context.Context, r ReleaseRecord, complete bool) error {
	through, completed, _, empty, e := q.prefix(ctx, r.Request.SessionEpoch)
	if e != nil {
		return e
	}
	prior := through
	if complete {
		prior = completed
	}
	if r.Request.FromSequence == "0" {
		if empty {
			return telemetry.ErrReplayExpired
		}
	} else if releaseNumber(prior) == ^uint64(0) || releaseNumber(r.Request.FromSequence) != releaseNumber(prior)+1 {
		return ErrConflict
	}
	body, _ := json.Marshal(r)
	if e = q.mutationCapacity(ctx, int64(4*len(body))+(128<<10)); e != nil {
		return e
	}
	tx, e := q.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrCapacity
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `UPDATE release_ledger SET body=?,phase=? WHERE id=?`, body, r.Phase, r.Request.ReleaseID); e != nil {
		return ErrCapacity
	}
	column := "through"
	if complete {
		column = "completed"
	}
	if _, e = tx.ExecContext(ctx, `UPDATE release_prefix SET `+column+`=? WHERE epoch=?`, r.Request.ThroughSequence, r.Request.SessionEpoch); e != nil {
		return ErrCapacity
	}
	if complete {
		if r.Request.FromSequence == "0" {
			if _, e = tx.ExecContext(ctx, `UPDATE release_prefix SET empty_completed=1 WHERE epoch=?`, r.Request.SessionEpoch); e != nil {
				return ErrCapacity
			}
		}
		for _, ref := range r.Manifest.Loss {
			if _, e = tx.ExecContext(ctx, `INSERT OR REPLACE INTO loss_release_anchor VALUES(?,?,?)`, ref.LossID, r.Request.SessionEpoch, r.Request.ThroughSequence); e != nil {
				return ErrCapacity
			}
		}
	}
	if e = tx.Commit(); e != nil {
		return ErrCapacity
	}
	return nil
}

type ownedInterval struct{ first, last uint64 }

func addOwnershipRange(ctx context.Context, tx *sql.Tx, epoch, kind string, first, last uint64) error {
	rows, e := tx.QueryContext(ctx, `SELECT first,last FROM ownership_ranges WHERE epoch=? AND kind=?`, epoch, kind)
	if e != nil {
		return ErrCorrupt
	}
	intervals := []ownedInterval{{first, last}}
	for rows.Next() {
		var a, b string
		if rows.Scan(&a, &b) != nil {
			rows.Close()
			return ErrCorrupt
		}
		intervals = append(intervals, ownedInterval{releaseNumber(a), releaseNumber(b)})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrCorrupt
	}
	if len(intervals) > 257 {
		return ErrCapacity
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].first < intervals[j].first })
	merged := []ownedInterval{}
	for _, r := range intervals {
		n := len(merged)
		if n > 0 && (r.first <= merged[n-1].last || merged[n-1].last != ^uint64(0) && r.first == merged[n-1].last+1) {
			if r.last > merged[n-1].last {
				merged[n-1].last = r.last
			}
		} else {
			merged = append(merged, r)
		}
	}
	if len(merged) > 256 {
		return ErrCapacity
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM ownership_ranges WHERE epoch=? AND kind=?`, epoch, kind); e != nil {
		return ErrCapacity
	}
	for _, r := range merged {
		if _, e = tx.ExecContext(ctx, `INSERT INTO ownership_ranges VALUES(?,?,?,?)`, epoch, kind, strconv.FormatUint(r.first, 10), strconv.FormatUint(r.last, 10)); e != nil {
			return ErrCapacity
		}
	}
	return nil
}
func (q *Queue) compactNodeRange(ctx context.Context, r ReleaseRecord) error {
	a, _ := keyID(releaseKey(r.Request, r.Request.FromSequence))
	b, _ := keyID(releaseKey(r.Request, r.Request.ThroughSequence))
	rows, e := q.db.QueryContext(ctx, `SELECT id,key,state FROM items WHERE id>=? AND id<=? ORDER BY id LIMIT 4097`, a, b)
	if e != nil {
		return q.markCorrupt()
	}
	type item struct {
		id    string
		key   telemetry.BatchKey
		state string
	}
	items := []item{}
	for rows.Next() {
		var x item
		var body []byte
		if rows.Scan(&x.id, &body, &x.state) != nil || json.Unmarshal(body, &x.key) != nil {
			rows.Close()
			return q.markCorrupt()
		}
		if x.state != "TRANSFERRED" && x.state != "LOST" {
			rows.Close()
			return ErrRole
		}
		items = append(items, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return q.markCorrupt()
	}
	if len(items) > 4096 {
		return ErrCapacity
	}
	body, _ := json.Marshal(r)
	var handoffBytes int64
	for _, x := range items {
		growth, err := q.lossHandoffGrowth(ctx, x.id)
		if err != nil {
			return err
		}
		handoffBytes += growth
	}
	if e = q.mutationCapacity(ctx, int64(4*len(body))+4*handoffBytes+(256<<10)); e != nil {
		return e
	}
	tx, e := q.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrCapacity
	}
	defer tx.Rollback()
	for _, x := range items {
		kind := "TRANSFERRED"
		if x.state == "LOST" {
			kind = "LOSS"
		}
		n := releaseNumber(x.key.Sequence)
		if e = addOwnershipRange(ctx, tx, x.key.SessionEpoch, kind, n, n); e != nil {
			return e
		}
		if e = deleteItem(ctx, tx, x.id); e != nil {
			return e
		}
	}
	// Explicitly lost allocations may never have had a local item row.
	for _, l := range r.Manifest.Loss {
		var lossBody []byte
		if e = tx.QueryRowContext(ctx, `SELECT body FROM source_loss WHERE id=?`, l.LossID).Scan(&lossBody); e != nil {
			return ErrCorrupt
		}
		var loss telemetry.SessionLoss
		if json.Unmarshal(lossBody, &loss) != nil {
			return ErrCorrupt
		}
		from, through := releaseNumber(loss.Range.AffectedKey.Sequence), releaseNumber(loss.Range.ThroughSequence)
		if from < releaseNumber(r.Request.FromSequence) {
			from = releaseNumber(r.Request.FromSequence)
		}
		if through > releaseNumber(r.Request.ThroughSequence) {
			through = releaseNumber(r.Request.ThroughSequence)
		}
		if e = addOwnershipRange(ctx, tx, r.Request.SessionEpoch, "LOSS", from, through); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT OR REPLACE INTO loss_release_anchor VALUES(?,?,?)`, l.LossID, r.Request.SessionEpoch, r.Request.ThroughSequence); e != nil {
			return ErrCapacity
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE release_ledger SET body=?,phase=? WHERE id=?`, body, r.Phase, r.Request.ReleaseID); e != nil {
		return ErrCapacity
	}
	if _, e = tx.ExecContext(ctx, `UPDATE release_prefix SET through=? WHERE epoch=?`, r.Request.ThroughSequence, r.Request.SessionEpoch); e != nil {
		return ErrCapacity
	}
	if e = tx.Commit(); e != nil {
		return ErrCapacity
	}
	return nil
}
func deleteItem(ctx context.Context, tx *sql.Tx, id string) error {
	// Preserve the exact carrier handoff before removing its association, even
	// when the affected older session has not yet released its own range.
	if _, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO source_loss_handoff(loss_id,receipt,ack) SELECT l.loss_id,i.receipt,i.ack FROM batch_loss l JOIN items i ON i.id=l.item_id WHERE l.item_id=? AND i.state='TRANSFERRED' AND i.ack IS NOT NULL`, id); e != nil {
		return ErrCapacity
	}
	for _, s := range []string{`DELETE FROM batch_loss WHERE item_id=?`, `DELETE FROM loss_order WHERE item_id=?`, `DELETE FROM item_rows WHERE id=?`} {
		if _, e := tx.ExecContext(ctx, s, id); e != nil {
			return ErrCapacity
		}
	}
	return nil
}
func (q *Queue) checkReleaseFence(ctx context.Context, key telemetry.BatchKey) error {
	var retired string
	if q.db.QueryRowContext(ctx, `SELECT retired_epoch FROM retirement_state WHERE singleton=1`).Scan(&retired) != nil {
		return q.markCorrupt()
	}
	if releaseNumber(key.SessionEpoch) <= releaseNumber(retired) {
		return ErrReceiptExpired
	}
	through, _, _, _, e := q.prefix(ctx, key.SessionEpoch)
	if e != nil {
		return e
	}
	if releaseNumber(key.Sequence) <= releaseNumber(through) {
		return ErrReceiptExpired
	}
	rows, e := q.db.QueryContext(ctx, `SELECT body FROM release_ledger WHERE epoch=? AND phase<>'COMPLETE' LIMIT 9`, key.SessionEpoch)
	if e != nil {
		return q.markCorrupt()
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var r ReleaseRecord
		if rows.Scan(&b) != nil || json.Unmarshal(b, &r) != nil {
			return q.markCorrupt()
		}
		n := releaseNumber(key.Sequence)
		if n >= releaseNumber(r.Request.FromSequence) && n <= releaseNumber(r.Request.ThroughSequence) {
			return ErrReleaseSealed
		}
	}
	if rows.Err() != nil {
		return q.markCorrupt()
	}
	return nil
}
func (q *Queue) checkLossFence(ctx context.Context, key telemetry.BatchKey, through string) error {
	first, last := releaseNumber(key.Sequence), releaseNumber(through)
	var retired string
	if q.db.QueryRowContext(ctx, `SELECT retired_epoch FROM retirement_state WHERE singleton=1`).Scan(&retired) != nil {
		return q.markCorrupt()
	}
	if releaseNumber(key.SessionEpoch) <= releaseNumber(retired) {
		return ErrReleaseSealed
	}
	prefix, _, _, _, e := q.prefix(ctx, key.SessionEpoch)
	if e != nil {
		return e
	}
	if first <= releaseNumber(prefix) {
		return ErrReleaseSealed
	}
	rows, e := q.db.QueryContext(ctx, `SELECT body FROM release_ledger WHERE epoch=? AND phase<>'COMPLETE' LIMIT 9`, key.SessionEpoch)
	if e != nil {
		return q.markCorrupt()
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var r ReleaseRecord
		if rows.Scan(&b) != nil || json.Unmarshal(b, &r) != nil {
			return q.markCorrupt()
		}
		if first <= releaseNumber(r.Request.ThroughSequence) && last >= releaseNumber(r.Request.FromSequence) {
			return ErrReleaseSealed
		}
	}
	if rows.Err() != nil {
		return q.markCorrupt()
	}
	return nil
}
func (q *Queue) LookupOwnership(ctx context.Context, key telemetry.BatchKey) (OwnershipLookup, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return OwnershipLookup{}, e
	}
	if !q.boundKey(key) {
		return OwnershipLookup{}, ErrInvalid
	}
	id, _ := keyID(key)
	entry, e := scanEntry(q.db.QueryRowContext(ctx, `SELECT `+columns+` FROM items WHERE id=?`, id))
	if e == nil {
		if entry.Key != key {
			return OwnershipLookup{}, ErrConflict
		}
		if entry.State == "LOST" {
			var body, sourceBody []byte
			var names []string
			var loss LocalLoss
			if q.db.QueryRowContext(ctx, `SELECT loss,sources FROM items WHERE id=?`, id).Scan(&body, &sourceBody) != nil || json.Unmarshal(sourceBody, &names) != nil || json.Unmarshal(body, &loss) != nil || loss.AffectedKey != entry.Key || !equalStrings(loss.Sources, names) || loss.Count != nil || loss.FromAt != nil || loss.ThroughAt != nil || (loss.Reason != "NODE_CAPACITY" && loss.Reason != "NODE_EXPIRED" && loss.Reason != "LOCAL_COMMIT_INTERRUPTED") {
				return OwnershipLookup{}, q.markCorrupt()
			}
			entry.Loss = &loss
		}
		return OwnershipLookup{Disposition: OwnershipExact, Entry: &entry}, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return OwnershipLookup{}, q.markCorrupt()
	}
	// Sparse disposition ranges are meaningful only for the exact immutable
	// session mapping. An epoch alone is never proof of a caller's session ID.
	var sessionID string
	e = q.db.QueryRowContext(ctx, `SELECT id FROM session_identity WHERE epoch=?`, key.SessionEpoch).Scan(&sessionID)
	if errors.Is(e, sql.ErrNoRows) {
		e = q.db.QueryRowContext(ctx, `SELECT id FROM sessions WHERE epoch=?`, key.SessionEpoch).Scan(&sessionID)
	}
	if errors.Is(e, sql.ErrNoRows) {
		e = q.db.QueryRowContext(ctx, `SELECT id FROM retained_sessions WHERE epoch=?`, key.SessionEpoch).Scan(&sessionID)
	}
	if e == nil && sessionID != key.SessionID {
		return OwnershipLookup{}, ErrConflict
	}
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return OwnershipLookup{}, q.markCorrupt()
	}
	knownSession := e == nil
	rows, e := q.db.QueryContext(ctx, `SELECT kind,first,last FROM ownership_ranges WHERE epoch=? LIMIT 1025`, key.SessionEpoch)
	if e != nil {
		return OwnershipLookup{}, q.markCorrupt()
	}
	kind := ""
	count := 0
	for rows.Next() {
		count++
		var k, a, b string
		if rows.Scan(&k, &a, &b) != nil {
			rows.Close()
			return OwnershipLookup{}, q.markCorrupt()
		}
		n := releaseNumber(key.Sequence)
		if n >= releaseNumber(a) && n <= releaseNumber(b) {
			if k == "EXPIRED" {
				kind = OwnershipExpired
			} else if k == "TRANSFERRED" && kind != OwnershipExpired {
				kind = OwnershipTransferred
			} else if kind == "" && k == "LOSS" {
				kind = OwnershipLoss
			} else if kind == "" && k == "EXPIRED" {
				kind = OwnershipExpired
			}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil || count > 1024 {
		return OwnershipLookup{}, q.markCorrupt()
	}
	if kind != "" {
		if !knownSession {
			return OwnershipLookup{}, q.markCorrupt()
		}
		return OwnershipLookup{Disposition: kind}, nil
	}
	if e = q.checkReleaseFence(ctx, key); e != nil {
		return OwnershipLookup{}, e
	}
	return OwnershipLookup{}, ErrNotFound
}
func (q *Queue) PruneRetiredReceipts(ctx context.Context, at time.Time, limit int) (int, error) {
	if q.opts.Role != Gateway {
		return 0, ErrRole
	}
	if limit < 1 || limit > 128 || at.After(q.opts.Now().Add(telemetry.FutureSkew)) {
		return 0, ErrInvalid
	}
	if _, e := q.RetirementCapabilities(ctx); e != nil {
		return 0, e
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return 0, e
	}
	defer unlock()
	rows, e := q.db.QueryContext(ctx, `SELECT id,key FROM items i WHERE state='TRANSFERRED' AND acked<=? AND EXISTS(SELECT 1 FROM release_prefix p WHERE p.epoch=json_extract(i.key,'$.session_epoch') AND (length(p.completed)>length(json_extract(i.key,'$.sequence')) OR length(p.completed)=length(json_extract(i.key,'$.sequence')) AND p.completed>=json_extract(i.key,'$.sequence'))) ORDER BY id LIMIT ?`, at.Add(-telemetry.ReleaseReceiptHorizon).UnixNano(), limit)
	if e != nil {
		return 0, q.markCorrupt()
	}
	type item struct {
		id  string
		key telemetry.BatchKey
	}
	items := []item{}
	for rows.Next() {
		var x item
		var b []byte
		if rows.Scan(&x.id, &b) != nil || json.Unmarshal(b, &x.key) != nil {
			rows.Close()
			return 0, q.markCorrupt()
		}
		items = append(items, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, q.markCorrupt()
	}
	if len(items) == 0 {
		return 0, nil
	}
	var handoffBytes int64
	for _, x := range items {
		growth, err := q.lossHandoffGrowth(ctx, x.id)
		if err != nil {
			return 0, err
		}
		handoffBytes += growth
	}
	if e = q.mutationCapacity(ctx, 4*handoffBytes+(256<<10)); e != nil {
		return 0, e
	}
	tx, e := q.db.BeginTx(ctx, nil)
	if e != nil {
		return 0, ErrCapacity
	}
	defer tx.Rollback()
	for _, x := range items {
		n := releaseNumber(x.key.Sequence)
		if e = addOwnershipRange(ctx, tx, x.key.SessionEpoch, "EXPIRED", n, n); e != nil {
			return 0, e
		}
		if e = deleteItem(ctx, tx, x.id); e != nil {
			return 0, e
		}
	}
	if e = tx.Commit(); e != nil {
		return 0, ErrCapacity
	}
	return len(items), nil
}

func (q *Queue) lossHandoffGrowth(ctx context.Context, id string) (int64, error) {
	var bytes int64
	if q.db.QueryRowContext(ctx, `SELECT coalesce(sum(length(i.receipt)+length(i.ack)+256),0) FROM batch_loss l JOIN items i ON i.id=l.item_id LEFT JOIN source_loss_handoff h ON h.loss_id=l.loss_id WHERE l.item_id=? AND i.state='TRANSFERRED' AND h.loss_id IS NULL`, id).Scan(&bytes) != nil {
		return 0, q.markCorrupt()
	}
	return bytes, nil
}
