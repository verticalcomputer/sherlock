package telemetryjournal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

var ErrNotFound = errors.New("telemetry journal entry unavailable")

// Lookup reports durable ownership independently of payload retirement. Only
// ErrNotFound proves absence; corruption/capacity/closed errors never do.
func (q *Queue) Lookup(ctx context.Context, key telemetry.BatchKey) (Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return Entry{}, e
	}
	if !q.boundKey(key) {
		return Entry{}, ErrInvalid
	}
	id, _ := keyID(key)
	entry, e := scanEntry(q.db.QueryRowContext(ctx, `SELECT `+columns+` FROM items WHERE id=?`, id))
	if errors.Is(e, sql.ErrNoRows) {
		if fence := q.checkReleaseFence(ctx, key); fence != nil {
			return Entry{}, fence
		}
		return Entry{}, ErrNotFound
	}
	if e != nil {
		return Entry{}, q.markCorrupt()
	}
	if entry.Key != key {
		return Entry{}, ErrConflict
	}
	if entry.State == "LOST" {
		var body []byte
		var loss LocalLoss
		if q.db.QueryRowContext(ctx, `SELECT loss FROM items WHERE id=?`, id).Scan(&body) != nil || json.Unmarshal(body, &loss) != nil {
			return Entry{}, q.markCorrupt()
		}
		entry.Loss = &loss
	}
	return entry, nil
}
func (q *Queue) boundKey(key telemetry.BatchKey) bool {
	return validKey(key) && key.ClusterID == q.opts.Scope.ClusterID && key.NodeID == q.opts.Scope.NodeID && key.EnrollmentID == q.opts.Scope.EnrollmentID
}

// SessionOpen returns the exact immutable signed OPEN for idempotent upstream
// replay before dependent batches. The receipt does not imply cloud acceptance.
func (q *Queue) SessionOpen(ctx context.Context, epoch string) (telemetry.SessionMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return telemetry.SessionMessage{}, e
	}
	n, e := strconv.ParseUint(epoch, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != epoch {
		return telemetry.SessionMessage{}, ErrInvalid
	}
	var body []byte
	if e = q.db.QueryRowContext(ctx, `SELECT open FROM sessions WHERE epoch=?`, epoch).Scan(&body); errors.Is(e, sql.ErrNoRows) {
		return telemetry.SessionMessage{}, ErrNotFound
	} else if e != nil {
		return telemetry.SessionMessage{}, q.markCorrupt()
	}
	var m telemetry.SessionMessage
	if json.Unmarshal(body, &m) != nil {
		return m, q.markCorrupt()
	}
	return m, nil
}
func (q *Queue) SessionMessages(ctx context.Context) ([]telemetry.SessionMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return nil, e
	}
	rows, e := q.db.QueryContext(ctx, `SELECT open,final FROM sessions`)
	if e != nil {
		return nil, q.markCorrupt()
	}
	defer rows.Close()
	out := []telemetry.SessionMessage{}
	for rows.Next() {
		var open, final []byte
		if rows.Scan(&open, &final) != nil {
			return nil, q.markCorrupt()
		}
		for _, body := range [][]byte{open, final} {
			if len(body) == 0 {
				continue
			}
			var m telemetry.SessionMessage
			if json.Unmarshal(body, &m) != nil {
				return nil, q.markCorrupt()
			}
			out = append(out, m)
			if len(out) > 16 {
				return nil, q.markCorrupt()
			}
		}
	}
	if rows.Err() != nil {
		return nil, q.markCorrupt()
	}
	return out, nil
}

// NextForDrain reserves every fifth turn for control/loss; data turns use one
// newest ingress for every three oldest ingress turns. Ordering uses the local
// durable ingress timestamp, never mutable upload time or source-clock age.
func (q *Queue) NextForDrain(ctx context.Context, turn uint64) (Entry, bool, error) {
	return q.NextForDrainExcludingSessions(ctx, turn, nil)
}

// NextForDrainExcludingSessions filters a caller's bounded temporary quarantine
// before LIMIT. It preserves the weighted drain policy and all owned bytes.
// Exclusion is not a durable loss, retirement, authority or freshness assertion.
func (q *Queue) NextForDrainExcludingSessions(ctx context.Context, turn uint64, excludedEpochs []string) (Entry, bool, error) {
	if len(excludedEpochs) > 8 {
		return Entry{}, false, ErrInvalid
	}
	seen := map[string]bool{}
	args := make([]any, 0, len(excludedEpochs))
	for _, epoch := range excludedEpochs {
		n, e := strconv.ParseUint(epoch, 10, 64)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != epoch || seen[epoch] {
			return Entry{}, false, ErrInvalid
		}
		seen[epoch] = true
		args = append(args, epoch)
	}
	filter := ""
	if len(args) > 0 {
		filter = " AND json_extract(key,'$.session_epoch') NOT IN(" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ")"
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return Entry{}, false, e
	}
	control := turn%5 == 4
	dataTurn := turn - turn/5
	order := "ASC"
	if dataTurn%4 == 0 {
		order = "DESC"
	}
	predicate := "lane='DATA'"
	if control {
		predicate = "lane<>'DATA'"
		order = "ASC"
	}
	entry, e := scanEntry(q.db.QueryRowContext(ctx, `SELECT `+columns+` FROM items WHERE state='OWNED' AND `+predicate+filter+` ORDER BY stored `+order+`,id `+order+` LIMIT 1`, args...))
	if errors.Is(e, sql.ErrNoRows) {
		entry, e = scanEntry(q.db.QueryRowContext(ctx, `SELECT `+columns+` FROM items WHERE state='OWNED'`+filter+` ORDER BY stored ASC,id ASC LIMIT 1`, args...))
	}
	if errors.Is(e, sql.ErrNoRows) {
		return Entry{}, false, nil
	}
	if e != nil {
		return Entry{}, false, q.markCorrupt()
	}
	return entry, true, nil
}

// WithMetadataWrite holds physical/WAL capacity through an owner-only fsynced
// allocator write. The callback must not call back into Queue or perform I/O
// beyond bounded local metadata. A failure preserves its pending evidence.
func (q *Queue) WithMetadataWrite(ctx context.Context, growthBytes int64, write func() error) error {
	if growthBytes < 0 || growthBytes > 1<<20 || write == nil {
		return ErrInvalid
	}
	unlock, e := q.beginBudget()
	if e != nil {
		return e
	}
	defer unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if e = q.check(); e != nil {
		return e
	}
	s, physicalErr := aggregatePhysical(q.root)
	charge, _, chargeErr := q.allocationCharge(growthBytes)
	if physicalErr != nil {
		return q.markCorrupt()
	}
	if chargeErr != nil {
		return chargeErr
	}
	if s.Staging > q.opts.Limits.Staging-charge {
		return ErrCapacity
	}
	if q.opts.GatewayBudget != nil {
		if e = q.opts.GatewayBudget.reserve(0, 0, charge, 0, 0); e != nil {
			return e
		}
	}
	if e = q.mutationCapacity(ctx, growthBytes); e != nil {
		return e
	}
	if e = write(); e != nil {
		return ErrCapacity
	}
	return q.checkPhysicalLimits()
}

func (q *Queue) checkPhysicalLimits() error {
	s, e := aggregatePhysical(q.root)
	if e != nil {
		return q.markCorrupt()
	}
	if s.Total > q.opts.Limits.Total || s.Payload > q.opts.Limits.Payload || s.Metadata > q.opts.Limits.Metadata || s.LossContact > q.opts.Limits.LossContact || s.Staging > q.opts.Limits.Staging {
		return ErrCapacity
	}
	return nil
}
