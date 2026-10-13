package telemetryjournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (q *Queue) allowedSources(sources []string) bool {
	for _, source := range sources {
		i := sort.SearchStrings(q.opts.SourceIDs, source)
		if i == len(q.opts.SourceIDs) || q.opts.SourceIDs[i] != source {
			return false
		}
	}
	return true
}
func sourceLossBody(loss telemetry.SessionLoss) ([]byte, []byte) {
	if loss.Range.FromAt != nil {
		v := loss.Range.FromAt.UTC()
		loss.Range.FromAt = &v
	}
	if loss.Range.ThroughAt != nil {
		v := loss.Range.ThroughAt.UTC()
		loss.Range.ThroughAt = &v
	}
	body, _ := json.Marshal(loss)
	digest := sha256.Sum256(body)
	return body, digest[:]
}
func (q *Queue) validateSourceLosses(ctx context.Context, containing telemetry.BatchKey, losses []telemetry.SessionLoss, current bool) error {
	if len(losses) > 256 {
		return ErrCapacity
	}
	seen := map[string]bool{}
	newPerSession := map[string]int{}
	for _, loss := range losses {
		k := loss.Range.AffectedKey
		if !q.boundKey(k) || !q.allowedSources([]string{loss.SourceID}) || seen[loss.Range.ID] {
			return ErrInvalid
		}
		seen[loss.Range.ID] = true
		original, final, e := q.lossSession(ctx, k.SessionEpoch)
		if e != nil {
			return e
		}
		if original.SessionID != k.SessionID {
			return ErrConflict
		}
		shape := original
		shape.Kind = "FINALIZE"
		shape.LastAllocatedSequence = loss.Range.ThroughSequence
		shape.Loss = []telemetry.SessionLoss{loss}
		shape.CreatedAt = q.opts.Now().UTC()
		// Persisted source instants do not become corrupt after wall-clock rollback.
		if !current && loss.Range.ThroughAt != nil && loss.Range.ThroughAt.After(shape.CreatedAt) {
			shape.CreatedAt = loss.Range.ThroughAt.UTC()
		}
		if telemetry.ValidateSessionMessage(shape) != nil {
			return ErrInvalid
		}
		if current && loss.Range.ThroughAt != nil && loss.Range.ThroughAt.After(q.opts.Now().Add(telemetry.FutureSkew)) {
			return ErrInvalid
		}
		from, _ := strconv.ParseUint(k.Sequence, 10, 64)
		through, _ := strconv.ParseUint(loss.Range.ThroughSequence, 10, 64)
		if k.SessionEpoch == containing.SessionEpoch && k.SessionID == containing.SessionID {
			sequence, _ := strconv.ParseUint(containing.Sequence, 10, 64)
			if sequence >= from && sequence <= through {
				return ErrConflict
			}
		}
		if len(final) > 0 {
			var m telemetry.SessionMessage
			if json.Unmarshal(final, &m) != nil {
				return q.markCorrupt()
			}
			terminal, _ := strconv.ParseUint(m.LastAllocatedSequence, 10, 64)
			if through > terminal {
				return ErrConflict
			}
		}
		_, digest := sourceLossBody(loss)
		var prior []byte
		e = q.db.QueryRowContext(ctx, `SELECT digest FROM source_loss WHERE id=?`, loss.Range.ID).Scan(&prior)
		if e == nil {
			if !bytes.Equal(prior, digest) {
				return ErrConflict
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return q.markCorrupt()
		}
		if e = q.checkLossFence(ctx, k, loss.Range.ThroughSequence); e != nil {
			return e
		}
		newPerSession[k.SessionEpoch]++
		// Local spool loss describes node discard, not remote absence: a lost
		// acknowledgement followed by expiry must not strand the next carrier.
		// Retain the fact; received evidence remains authoritative coverage.
		if loss.Range.Reason == "SPOOL_EXPIRED" || loss.Range.Reason == "SPOOL_OVERFLOW" {
			continue
		}
		// Source loss/corruption cannot contradict known received evidence.
		slot := sort.SearchStrings(q.opts.SourceIDs, loss.SourceID)
		startID, _ := keyID(k)
		endKey := k
		endKey.Sequence = loss.Range.ThroughSequence
		endID, _ := keyID(endKey)
		// The compact epoch+sequence primary key bounds this check to the exact
		// range; a weekly receipt ledger never needs a full JSON scan per fact.
		var present int
		e = q.db.QueryRowContext(ctx, `SELECT 1 FROM item_rows WHERE id>=? AND id<=? AND state IN(1,2) AND (source_mask & ?)<>0 LIMIT 1`, startID, endID, 1<<slot).Scan(&present)
		if e == nil {
			return ErrConflict
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return q.markCorrupt()
		}

	}
	for epoch, extra := range newPerSession {
		var count int
		if q.db.QueryRowContext(ctx, `SELECT count(*) FROM source_loss WHERE epoch=?`, epoch).Scan(&count) != nil {
			return q.markCorrupt()
		}
		if count+extra > 256 {
			return ErrCapacity
		}
	}
	return nil
}

// recoverSourceLosses validates immutable facts and links before any startup
// payload retirement. Historical received fills do not erase earlier loss facts.
func (q *Queue) recoverSourceLosses(ctx context.Context) error {
	var invalid int
	e := q.db.QueryRowContext(ctx, `SELECT 1 FROM batch_loss b LEFT JOIN item_rows i ON i.id=b.item_id LEFT JOIN source_loss l ON l.id=b.loss_id WHERE i.id IS NULL OR i.state NOT IN(1,2,3) OR l.id IS NULL LIMIT 1`).Scan(&invalid)
	if e != sql.ErrNoRows {
		return ErrCorrupt
	}
	e = q.db.QueryRowContext(ctx, `SELECT 1 FROM source_loss l WHERE NOT EXISTS(SELECT 1 FROM batch_loss b WHERE b.loss_id=l.id) AND NOT EXISTS(SELECT 1 FROM final_loss f WHERE f.loss_id=l.id) AND NOT EXISTS(SELECT 1 FROM release_loss r WHERE r.loss_id=l.id) AND NOT EXISTS(SELECT 1 FROM loss_release_anchor a WHERE a.id=l.id) AND NOT EXISTS(SELECT 1 FROM source_loss_handoff h WHERE h.loss_id=l.id) LIMIT 1`).Scan(&invalid)
	if e != sql.ErrNoRows {
		return ErrCorrupt
	}
	e = q.db.QueryRowContext(ctx, `SELECT 1 FROM source_loss GROUP BY epoch HAVING count(*)>256 LIMIT 1`).Scan(&invalid)
	if e != sql.ErrNoRows {
		return ErrCorrupt
	}
	after := ""
	for {
		rows, e := q.db.QueryContext(ctx, `SELECT id,epoch,source,digest,body FROM source_loss WHERE id>? ORDER BY id LIMIT 256`, after)
		if e != nil {
			return ErrCorrupt
		}
		type fact struct {
			id, epoch, source string
			digest, body      []byte
		}
		facts := make([]fact, 0, 256)
		for rows.Next() {
			var f fact
			if rows.Scan(&f.id, &f.epoch, &f.source, &f.digest, &f.body) != nil || len(f.body) > 8192 {
				rows.Close()
				return ErrCorrupt
			}
			facts = append(facts, f)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return ErrCorrupt
		}
		for _, f := range facts {
			var loss telemetry.SessionLoss
			if json.Unmarshal(f.body, &loss) != nil || loss.Range.ID != f.id || loss.Range.AffectedKey.SessionEpoch != f.epoch || loss.SourceID != f.source {
				return ErrCorrupt
			}
			body, digest := sourceLossBody(loss)
			if !bytes.Equal(body, f.body) || !bytes.Equal(digest, f.digest) || q.validateSourceLosses(ctx, telemetry.BatchKey{}, []telemetry.SessionLoss{loss}, false) != nil {
				return ErrCorrupt
			}
			after = f.id
		}
		if len(facts) < 256 {
			return nil
		}
	}
}
