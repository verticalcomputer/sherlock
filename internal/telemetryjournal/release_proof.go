package telemetryjournal

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func releaseKey(r telemetry.ReleaseRequest, seq string) telemetry.BatchKey {
	return telemetry.BatchKey{ClusterID: r.ClusterID, NodeID: r.NodeID, EnrollmentID: r.EnrollmentID, SessionEpoch: r.SessionEpoch, SessionID: r.SessionID, Sequence: seq}
}
func (q *Queue) releaseLoss(ctx context.Context, ref telemetry.ReleaseLossRef) (telemetry.SessionLoss, error) {
	var body []byte
	var loss telemetry.SessionLoss
	e := q.db.QueryRowContext(ctx, `SELECT body FROM source_loss WHERE id=? AND source=?`, ref.LossID, ref.SourceID).Scan(&body)
	if errors.Is(e, sql.ErrNoRows) {
		return loss, ErrInvalid
	}
	if e != nil || len(body) > 8192 || json.Unmarshal(body, &loss) != nil {
		return loss, q.markCorrupt()
	}
	d, e := telemetry.CanonicalLossDigest(loss)
	if e != nil || hex.EncodeToString(d[:]) != ref.Digest {
		return loss, ErrConflict
	}
	return loss, nil
}
func (q *Queue) proveRelease(ctx context.Context, env telemetry.ReleaseEnvelope, cloud bool) error {
	req := env.Request
	var remaining int
	a, _ := keyID(releaseKey(req, req.FromSequence))
	b, _ := keyID(releaseKey(req, req.ThroughSequence))
	states := "('OWNED','STAGING')"
	if q.opts.Role == Gateway && !cloud {
		states = "('STAGING')"
	}
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM items WHERE id>=? AND id<=? AND state IN `+states, a, b).Scan(&remaining) != nil {
		return q.markCorrupt()
	}
	if remaining > 0 {
		return ErrRole
	}
	for _, fact := range env.Manifest.Batches {
		key := releaseKey(req, fact.Sequence)
		id, _ := keyID(key)
		entry, e := scanEntry(q.db.QueryRowContext(ctx, `SELECT `+columns+` FROM items WHERE id=?`, id))
		if errors.Is(e, sql.ErrNoRows) {
			return ErrInvalid
		}
		if e != nil {
			return q.markCorrupt()
		}
		if entry.Key != key || entry.Digest != fact.Digest {
			return ErrConflict
		}
		expected := entry.Receipt.ID
		if q.opts.Role == Node {
			if entry.State != "TRANSFERRED" {
				return ErrRole
			}
			var body []byte
			var ack telemetry.Receipt
			if q.db.QueryRowContext(ctx, `SELECT ack FROM items WHERE id=?`, id).Scan(&body) != nil || json.Unmarshal(body, &ack) != nil {
				return q.markCorrupt()
			}
			if ack.Key != key || ack.Digest != fact.Digest || ack.Durability != "GATEWAY" {
				return q.markCorrupt()
			}
			expected = ack.ID
		} else if entry.State != "OWNED" && entry.State != "TRANSFERRED" {
			return ErrRole
		}
		if expected != fact.GatewayReceiptID {
			return ErrConflict
		}
		if cloud && entry.State != "TRANSFERRED" {
			return ErrRole
		}
	}
	losses := make([]telemetry.SessionLoss, 0, len(env.Manifest.Loss))
	for _, ref := range env.Manifest.Loss {
		loss, e := q.releaseLoss(ctx, ref)
		if e != nil {
			return e
		}
		// A selected loss must itself have a durable handoff. FINALIZE-only facts
		// are also admitted through their exact acknowledged lifecycle receipt.
		var delivered int
		state := "('OWNED','TRANSFERRED')"
		if q.opts.Role == Node || cloud {
			state = "('TRANSFERRED')"
		}
		e = q.db.QueryRowContext(ctx, `SELECT 1 WHERE EXISTS(SELECT 1 FROM batch_loss l JOIN item_rows i ON i.id=l.item_id WHERE l.loss_id=? AND i.state IN `+compactStates(state)+`) OR EXISTS(SELECT 1 FROM final_loss f JOIN session_handoffs h ON h.epoch=f.epoch AND h.kind='FINALIZE' WHERE f.loss_id=?) OR EXISTS(SELECT 1 FROM loss_release_anchor a WHERE a.id=?) OR EXISTS(SELECT 1 FROM source_loss_handoff h WHERE h.loss_id=?)`, ref.LossID, ref.LossID, ref.LossID, ref.LossID).Scan(&delivered)
		if e == sql.ErrNoRows {
			return ErrRole
		}
		if e != nil {
			return q.markCorrupt()
		}
		losses = append(losses, loss)
	}
	if telemetry.ProveReleaseCoverage(req, env.Manifest, q.opts.SourceIDs, losses) != nil {
		return ErrInvalid
	}
	return nil
}
func compactStates(states string) string {
	if states == "('TRANSFERRED')" {
		return "(2)"
	}
	return "(1,2)"
}

// BuildReleaseManifest selects independently verified local handoff facts for
// the next contiguous ownership prefix. It never invents a digest for loss.
func (q *Queue) BuildReleaseManifest(ctx context.Context, epoch string, maxSpan int) (ReleaseProposal, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return ReleaseProposal{}, e
	}
	if q.opts.Role != Node {
		return ReleaseProposal{}, ErrRole
	}
	n, e := strconv.ParseUint(epoch, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != epoch || maxSpan < 1 || maxSpan > telemetry.MaxReleaseSpan {
		return ReleaseProposal{}, ErrInvalid
	}
	through, _, _, empty, e := q.prefix(ctx, epoch)
	if e != nil {
		return ReleaseProposal{}, e
	}
	if empty {
		return ReleaseProposal{}, telemetry.ErrReplayExpired
	}
	var body, finalBody []byte
	if q.db.QueryRowContext(ctx, `SELECT open,final FROM sessions WHERE epoch=?`, epoch).Scan(&body, &finalBody) != nil {
		return ReleaseProposal{}, ErrInvalid
	}
	var open, final telemetry.SessionMessage
	if json.Unmarshal(body, &open) != nil {
		return ReleaseProposal{}, q.markCorrupt()
	}
	if len(finalBody) > 0 {
		if json.Unmarshal(finalBody, &final) != nil {
			return ReleaseProposal{}, q.markCorrupt()
		}
		if final.LastAllocatedSequence == "0" && through == "0" {
			return ReleaseProposal{FromSequence: "0", ThroughSequence: "0", Manifest: telemetry.ReleaseManifest{Batches: []telemetry.ReleaseBatchFact{}, Loss: []telemetry.ReleaseLossRef{}}}, nil
		}
	}
	from := releaseNumber(through) + 1
	if from == 0 {
		return ReleaseProposal{}, ErrCapacity
	}
	end := from + uint64(maxSpan) - 1
	if end < from {
		end = ^uint64(0)
	}
	if len(finalBody) > 0 && end > releaseNumber(final.LastAllocatedSequence) {
		end = releaseNumber(final.LastAllocatedSequence)
	}
	req := telemetry.ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: "local-proposal", ClusterID: q.opts.Scope.ClusterID, NodeID: q.opts.Scope.NodeID, EnrollmentID: q.opts.Scope.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: epoch, SessionID: open.SessionID, SigningKeyID: open.SigningKeyID, CreatedAt: q.opts.Now().UTC(), FromSequence: strconv.FormatUint(from, 10)}
	manifest := telemetry.ReleaseManifest{Batches: []telemetry.ReleaseBatchFact{}, Loss: []telemetry.ReleaseLossRef{}}
	// Loss facts are bounded to256/session. Selection includes only handed-off
	// carriers; unacknowledged gaps stop the proposed prefix.
	rows, e := q.db.QueryContext(ctx, `SELECT l.body FROM source_loss l WHERE l.epoch=? AND (EXISTS(SELECT 1 FROM batch_loss b JOIN item_rows i ON i.id=b.item_id WHERE b.loss_id=l.id AND i.state=2) OR EXISTS(SELECT 1 FROM final_loss f JOIN session_handoffs h ON h.epoch=f.epoch AND h.kind='FINALIZE' WHERE f.loss_id=l.id) OR EXISTS(SELECT 1 FROM loss_release_anchor a WHERE a.id=l.id) OR EXISTS(SELECT 1 FROM source_loss_handoff h WHERE h.loss_id=l.id)) ORDER BY l.source,l.id LIMIT 257`, epoch)
	if e != nil {
		return ReleaseProposal{}, q.markCorrupt()
	}
	losses := []telemetry.SessionLoss{}
	for rows.Next() {
		var b []byte
		var l telemetry.SessionLoss
		if rows.Scan(&b) != nil || json.Unmarshal(b, &l) != nil {
			rows.Close()
			return ReleaseProposal{}, q.markCorrupt()
		}
		losses = append(losses, l)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ReleaseProposal{}, q.markCorrupt()
	}
	if len(losses) > 256 {
		return ReleaseProposal{}, ErrCapacity
	}
	selected := map[string]bool{}
	last := from - 1
	for seq := from; seq <= end; seq++ {
		key := releaseKey(req, strconv.FormatUint(seq, 10))
		id, _ := keyID(key)
		entry, e := scanEntry(q.db.QueryRowContext(ctx, `SELECT `+columns+` FROM items WHERE id=?`, id))
		if e == nil && entry.Key == key && entry.State == "TRANSFERRED" {
			if len(manifest.Batches) >= telemetry.MaxReleaseFacts {
				break
			}
			var b []byte
			var ack telemetry.Receipt
			if q.db.QueryRowContext(ctx, `SELECT ack FROM items WHERE id=?`, id).Scan(&b) != nil || json.Unmarshal(b, &ack) != nil {
				return ReleaseProposal{}, q.markCorrupt()
			}
			manifest.Batches = append(manifest.Batches, telemetry.ReleaseBatchFact{Sequence: key.Sequence, Digest: entry.Digest, GatewayReceiptID: ack.ID})
		} else {
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return ReleaseProposal{}, q.markCorrupt()
			}
			if e == nil && entry.State != "LOST" {
				break
			}
			covered := map[string]bool{}
			candidate := []telemetry.SessionLoss{}
			for _, l := range losses {
				if l.Range.AffectedKey.SessionID == open.SessionID && releaseNumber(l.Range.AffectedKey.Sequence) <= seq && releaseNumber(l.Range.ThroughSequence) >= seq {
					covered[l.SourceID] = true
					candidate = append(candidate, l)
				}
			}
			if len(covered) != len(q.opts.SourceIDs) {
				break
			}
			for _, l := range candidate {
				if selected[l.Range.ID] {
					continue
				}
				d, e := telemetry.CanonicalLossDigest(l)
				if e != nil {
					return ReleaseProposal{}, q.markCorrupt()
				}
				selected[l.Range.ID] = true
				manifest.Loss = append(manifest.Loss, telemetry.ReleaseLossRef{SourceID: l.SourceID, LossID: l.Range.ID, Digest: hex.EncodeToString(d[:])})
			}
		}
		last = seq
		if seq == ^uint64(0) {
			break
		}
	}
	if last < from {
		return ReleaseProposal{}, ErrNotFound
	}
	sort.Slice(manifest.Loss, func(i, j int) bool {
		if manifest.Loss[i].SourceID == manifest.Loss[j].SourceID {
			return manifest.Loss[i].LossID < manifest.Loss[j].LossID
		}
		return manifest.Loss[i].SourceID < manifest.Loss[j].SourceID
	})
	return ReleaseProposal{FromSequence: strconv.FormatUint(from, 10), ThroughSequence: strconv.FormatUint(last, 10), Manifest: manifest}, nil
}
