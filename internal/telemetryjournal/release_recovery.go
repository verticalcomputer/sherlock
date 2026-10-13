package telemetryjournal

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (q *Queue) recoverReleases(ctx context.Context) error {
	if e := q.recoverPublicKeys(ctx); e != nil {
		return e
	}
	base, e := q.retirementBase(ctx)
	if e != nil {
		return e
	}
	n, e := strconv.ParseUint(base, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != base {
		return ErrCorrupt
	}
	var count int
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM retained_sessions`).Scan(&count) != nil || count > MaxRetainedReceiptSessions {
		return ErrCapacity
	}
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM release_ledger WHERE phase<>'COMPLETE'`).Scan(&count) != nil || count > 8 {
		return ErrCorrupt
	}
	after := ""
	for {
		rows, e := q.db.QueryContext(ctx, `SELECT id,epoch,range_id,digest,phase,body FROM release_ledger WHERE id>? ORDER BY id LIMIT 64`, after)
		if e != nil {
			return ErrCorrupt
		}
		type fact struct {
			id, epoch, rangeID, digest, phase string
			body                              []byte
		}
		page := []fact{}
		for rows.Next() {
			var f fact
			if rows.Scan(&f.id, &f.epoch, &f.rangeID, &f.digest, &f.phase, &f.body) != nil || len(f.body) > telemetry.MaxReleaseBytes+(64<<10) {
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
			var r ReleaseRecord
			if json.Unmarshal(f.body, &r) != nil || r.Request.ReleaseID != f.id || r.Request.SessionEpoch != f.epoch || r.Request.Digest != f.digest || r.Phase != f.phase || !q.boundRelease(r.Request.Binding()) {
				return ErrCorrupt
			}
			rangeID, _ := keyID(releaseKey(r.Request, r.Request.FromSequence))
			if f.rangeID != rangeID {
				return ErrCorrupt
			}
			digest, e := telemetry.CanonicalReleaseDigest(r.Request)
			if e != nil || r.Request.Digest != hex.EncodeToString(digest[:]) {
				return ErrCorrupt
			}
			if r.Phase != "COMPLETE" && telemetry.ValidateReleaseEnvelope(telemetry.ReleaseEnvelope{Request: r.Request, Manifest: r.Manifest}) != nil {
				return ErrCorrupt
			}
			switch r.Phase {
			case "SEALED", "RELEASING", "RELEASED", "FINAL_RECEIVED", "NODE_COMPACTED", "COMPLETION_SEALED", "NODE_COMPLETION_PENDING", "COMPLETE":
			default:
				return ErrCorrupt
			}
			if r.Admission != nil && (telemetry.ValidateReleaseAdmissionReceipt(*r.Admission) != nil || r.Admission.Binding != r.Request.Binding()) {
				return ErrCorrupt
			}
			if r.Prepared != nil && (telemetry.ValidateCloudRetirementReceipt(*r.Prepared) != nil || r.Prepared.Phase != "PREPARED" || r.Prepared.Binding != r.Request.Binding() || r.Admission == nil || r.Prepared.GatewayAdmissionID != r.Admission.ID) {
				return ErrCorrupt
			}
			if r.Commit != nil && (telemetry.ValidateGatewayReleaseCommit(*r.Commit) != nil || r.Commit.Binding != r.Request.Binding() || r.Prepared == nil || r.Commit.PreparedReceiptID != r.Prepared.ID || r.Admission == nil || r.Commit.GatewayAdmissionID != r.Admission.ID) {
				return ErrCorrupt
			}
			if r.Final != nil && (telemetry.ValidateGatewayRetirementReceipt(*r.Final) != nil || r.Final.Binding != r.Request.Binding()) {
				return ErrCorrupt
			}
			if r.Completion != nil && (telemetry.ValidateNodeReleaseCompletion(*r.Completion) != nil || !completionMatches(*r.Completion, r)) {
				return ErrCorrupt
			}
			if r.CompletionReceipt != nil && (r.Completion == nil || telemetry.ValidateNodeCompletionReceipt(*r.CompletionReceipt) != nil || r.CompletionReceipt.Binding != r.Request.Binding() || r.CompletionReceipt.CompletionDigest != r.Completion.Digest || r.CompletionReceipt.CloudFinalReceiptID != r.Completion.CloudFinalReceiptID || r.CompletionReceipt.GatewayRetirementReceiptID != r.Completion.GatewayRetirementReceiptID) {
				return ErrCorrupt
			}
			if q.opts.Role == Node {
				if r.Phase == "RELEASING" || r.Phase == "RELEASED" || r.Phase == "NODE_COMPLETION_PENDING" {
					return ErrCorrupt
				}
				if (r.Phase == "NODE_COMPACTED" || r.Phase == "COMPLETION_SEALED" || r.Phase == "COMPLETE") && !validDigest(r.AllocatorSHA256) {
					return ErrCorrupt
				}
			} else if r.Phase == "SEALED" || r.Phase == "NODE_COMPACTED" || r.Phase == "COMPLETION_SEALED" {
				return ErrCorrupt
			}
			if r.Phase == "COMPLETE" && r.CompletionReceipt == nil {
				return ErrCorrupt
			}
			// Each phase must carry the durable prerequisite proof. Missing proof
			// fails before payload recovery is allowed to unlink anything.
			if q.opts.Role == Gateway && r.Admission == nil {
				return ErrCorrupt
			}
			if q.opts.Role == Gateway && r.Phase != "RELEASING" && (r.Prepared == nil || r.Commit == nil) {
				return ErrCorrupt
			}
			if r.Phase != "SEALED" && r.Phase != "RELEASING" && r.Phase != "RELEASED" && r.Final == nil {
				return ErrCorrupt
			}
			if (r.Phase == "COMPLETION_SEALED" || r.Phase == "NODE_COMPLETION_PENDING" || r.Phase == "COMPLETE") && r.Completion == nil {
				return ErrCorrupt
			}
			if r.Final != nil && q.opts.Role == Gateway && (r.Final.GatewayAdmissionID != r.Admission.ID || r.Final.PreparedReceiptID != r.Prepared.ID || r.Final.GatewayCommitID != r.Commit.ID) {
				return ErrCorrupt
			}
			if e = q.verifyHistoricalRelease(ctx, r); e != nil {
				return e
			}

			after = f.id
		}
		if len(page) < 64 {
			break
		}
	}
	// Limits and canonical uint64 interval shape are checked without unbounded
	// materialization. Adjacent intervals must have been coalesced on mutation.
	rows, e := q.db.QueryContext(ctx, `SELECT epoch,kind,count(*) FROM ownership_ranges GROUP BY epoch,kind HAVING count(*)>256`)
	if e != nil {
		return ErrCorrupt
	}
	if rows.Next() {
		rows.Close()
		return ErrCorrupt
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrCorrupt
	}
	var bad int
	e = q.db.QueryRowContext(ctx, `SELECT 1 FROM release_prefix p WHERE (length(completed)>length(through) OR length(completed)=length(through) AND completed>through) OR (length(expired)>length(completed) OR length(expired)=length(completed) AND expired>completed) LIMIT 1`).Scan(&bad)
	if e != sql.ErrNoRows {
		return ErrCorrupt
	}
	return q.recoverRetirementIndexes(ctx)
}
