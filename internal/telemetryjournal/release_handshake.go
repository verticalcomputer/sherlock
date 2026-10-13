package telemetryjournal

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (q *Queue) authorizeStoredRelease(ctx context.Context, req telemetry.ReleaseRequest) (ReleaseRecord, ReleaseAuthorization, error) {
	var r ReleaseRecord
	if q.opts.ReleaseVerifier == nil {
		return r, ReleaseAuthorization{}, ErrInvalid
	}
	if e := q.opts.ReleaseVerifier.AuthorizeRetirement(ctx, q.opts.Scope); e != nil {
		return r, ReleaseAuthorization{}, safeReleaseError(e)
	}
	auth, e := q.opts.ReleaseVerifier.VerifyRelease(ctx, telemetry.ReleaseEnvelope{Request: req})
	if e != nil {
		return r, auth, safeReleaseError(e)
	}
	d, e := telemetry.CanonicalReleaseDigest(req)
	if e != nil || req.Digest != hex.EncodeToString(d[:]) || !q.boundRelease(req.Binding()) {
		return r, auth, ErrInvalid
	}
	r, e = q.ReleaseStatus(ctx, req.ReleaseID)
	if e != nil {
		return r, auth, e
	}
	if r.Request.Digest != req.Digest {
		return r, auth, ErrConflict
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if e = q.check(); e != nil {
		return r, auth, e
	}
	if e = q.verifyHistoricalRelease(ctx, r); e != nil {
		return r, auth, ErrInvalid
	}
	return r, auth, nil
}
func (q *Queue) PrepareCloudRelease(ctx context.Context, req telemetry.ReleaseRequest) (telemetry.ReleasePrepareEnvelope, error) {
	if q.opts.Role != Gateway {
		return telemetry.ReleasePrepareEnvelope{}, ErrRole
	}
	_, _, e := q.authorizeStoredRelease(ctx, req)
	if e != nil {
		return telemetry.ReleasePrepareEnvelope{}, e
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return telemetry.ReleasePrepareEnvelope{}, e
	}
	defer unlock()
	r, e := q.loadRelease(ctx, req.ReleaseID)
	if e != nil {
		return telemetry.ReleasePrepareEnvelope{}, e
	}
	if r.Admission == nil {
		return telemetry.ReleasePrepareEnvelope{}, ErrRole
	}
	if r.Phase == "COMPLETE" {
		return telemetry.ReleasePrepareEnvelope{}, telemetry.ErrReplayExpired
	}
	if e = q.proveRelease(ctx, telemetry.ReleaseEnvelope{Request: r.Request, Manifest: r.Manifest}, true); e != nil {
		return telemetry.ReleasePrepareEnvelope{}, e
	}
	return telemetry.ReleasePrepareEnvelope{Release: telemetry.ReleaseEnvelope{Request: r.Request, Manifest: r.Manifest}, Admission: *r.Admission}, nil
}
func (q *Queue) CommitGatewayRelease(ctx context.Context, req telemetry.ReleaseRequest, prepared telemetry.CloudRetirementReceipt) (telemetry.GatewayReleaseCommit, error) {
	if q.opts.Role != Gateway {
		return telemetry.GatewayReleaseCommit{}, ErrRole
	}
	_, _, e := q.authorizeStoredRelease(ctx, req)
	if e != nil {
		return telemetry.GatewayReleaseCommit{}, e
	}
	if telemetry.ValidateCloudRetirementReceipt(prepared) != nil || prepared.Phase != "PREPARED" || prepared.Binding != req.Binding() {
		return telemetry.GatewayReleaseCommit{}, ErrInvalid
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return telemetry.GatewayReleaseCommit{}, e
	}
	defer unlock()
	r, e := q.loadRelease(ctx, req.ReleaseID)
	if e != nil {
		return telemetry.GatewayReleaseCommit{}, e
	}
	if r.Admission == nil || prepared.GatewayAdmissionID != r.Admission.ID {
		return telemetry.GatewayReleaseCommit{}, ErrConflict
	}
	if r.Commit != nil {
		if !sameJSON(r.Prepared, &prepared) {
			return telemetry.GatewayReleaseCommit{}, ErrConflict
		}
		return *r.Commit, nil
	}
	if e = q.proveRelease(ctx, telemetry.ReleaseEnvelope{Request: req, Manifest: r.Manifest}, true); e != nil {
		return telemetry.GatewayReleaseCommit{}, e
	}
	r.Prepared = &prepared
	r.Commit = &telemetry.GatewayReleaseCommit{ProtocolVersion: 1, ReleaseVersion: 1, ID: randomReleaseID("commit"), Binding: req.Binding(), GatewayAdmissionID: r.Admission.ID, PreparedReceiptID: prepared.ID, CreatedAt: q.opts.Now().UTC()}
	if r.Commit.ID == "" {
		return telemetry.GatewayReleaseCommit{}, ErrCapacity
	}
	r.Phase = "RELEASED"
	if e = q.saveRelease(ctx, r); e != nil {
		return telemetry.GatewayReleaseCommit{}, e
	}
	if e = q.fail("gateway_release_committed"); e != nil {
		return telemetry.GatewayReleaseCommit{}, e
	}
	return *r.Commit, nil
}
func (q *Queue) ConfirmCloudRelease(ctx context.Context, req telemetry.ReleaseRequest, final telemetry.CloudRetirementReceipt) (telemetry.GatewayRetirementReceipt, error) {
	if q.opts.Role != Gateway {
		return telemetry.GatewayRetirementReceipt{}, ErrRole
	}
	_, _, e := q.authorizeStoredRelease(ctx, req)
	if e != nil {
		return telemetry.GatewayRetirementReceipt{}, e
	}
	if telemetry.ValidateCloudRetirementReceipt(final) != nil || final.Phase != "FINAL" || final.Binding != req.Binding() {
		return telemetry.GatewayRetirementReceipt{}, ErrInvalid
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return telemetry.GatewayRetirementReceipt{}, e
	}
	defer unlock()
	r, e := q.loadRelease(ctx, req.ReleaseID)
	if e != nil {
		return telemetry.GatewayRetirementReceipt{}, e
	}
	if r.Commit == nil || r.Prepared == nil || r.Admission == nil || final.GatewayCommitID != r.Commit.ID || final.PreparedReceiptID != r.Prepared.ID || final.GatewayAdmissionID != r.Admission.ID {
		return telemetry.GatewayRetirementReceipt{}, ErrConflict
	}
	if r.Final != nil {
		if !sameJSON(&r.Final.CloudFinalReceipt, &final) {
			return telemetry.GatewayRetirementReceipt{}, ErrConflict
		}
		return *r.Final, nil
	}
	id, e := telemetry.GatewayRetirementReceiptID(final)
	if e != nil {
		return telemetry.GatewayRetirementReceipt{}, ErrInvalid
	}
	r.Final = &telemetry.GatewayRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: id, Binding: req.Binding(), GatewayAdmissionID: r.Admission.ID, PreparedReceiptID: r.Prepared.ID, GatewayCommitID: r.Commit.ID, CloudFinalReceipt: final, StoredAt: q.opts.Now().UTC(), Durability: "GATEWAY"}
	r.Phase = "FINAL_RECEIVED"
	if e = q.saveReleaseAndPrefix(ctx, r, false); e != nil {
		return telemetry.GatewayRetirementReceipt{}, e
	}
	return *r.Final, nil
}

// CompleteNodeRelease persists the exact final proof before the idempotent
// allocator callback. The callback fsyncs its file and directory and never calls
// Queue. If SQL fails afterwards the same callback is replayed against this proof.
func (q *Queue) CompleteNodeRelease(ctx context.Context, req telemetry.ReleaseRequest, final telemetry.GatewayRetirementReceipt, growthBytes int64, compactAllocator func() (string, error)) error {
	if q.opts.Role != Node {
		return ErrRole
	}
	if growthBytes < 0 || growthBytes > 1<<20 || compactAllocator == nil {
		return ErrInvalid
	}
	_, _, e := q.authorizeStoredRelease(ctx, req)
	if e != nil {
		return e
	}
	if telemetry.ValidateGatewayRetirementReceipt(final) != nil || final.Binding != req.Binding() {
		return ErrInvalid
	}
	unlock, e := q.lockRelease()
	if e != nil {
		return e
	}
	defer unlock()
	r, e := q.loadRelease(ctx, req.ReleaseID)
	if e != nil {
		return e
	}
	if r.Final != nil && !sameJSON(r.Final, &final) {
		return ErrConflict
	}
	if r.Phase == "NODE_COMPACTED" || r.Phase == "COMPLETION_SEALED" || r.Phase == "COMPLETE" {
		return nil
	}
	if e = q.proveRelease(ctx, telemetry.ReleaseEnvelope{Request: req, Manifest: r.Manifest}, false); e != nil {
		return e
	}
	if r.Final == nil {
		r.Final = &final
		r.Phase = "FINAL_RECEIVED"
		if e = q.saveRelease(ctx, r); e != nil {
			return e
		}
	}
	if e = q.fail("node_final_recorded"); e != nil {
		return e
	}
	if e = q.mutationCapacity(ctx, growthBytes+(256<<10)); e != nil {
		return e
	}
	checksum, e := compactAllocator()
	if e != nil {
		return ErrCapacity
	}
	if !validDigest(checksum) {
		return ErrInvalid
	}
	if e = q.fail("node_allocator_compacted"); e != nil {
		return e
	}
	r.AllocatorSHA256 = checksum
	r.Phase = "NODE_COMPACTED"
	if e = q.compactNodeRange(ctx, r); e != nil {
		return e
	}
	return q.fail("node_queue_compacted")
}
func (q *Queue) SealNodeCompletion(ctx context.Context, c telemetry.NodeReleaseCompletion) error {
	if q.opts.Role != Node {
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
	if r.Completion != nil {
		if !sameJSON(r.Completion, &c) {
			return ErrConflict
		}
		return nil
	}
	if !auth.SignerActive {
		return telemetry.ErrUnauthorized
	}
	if r.Phase != "NODE_COMPACTED" || !validDigest(r.AllocatorSHA256) || !completionMatches(c, r) {
		return ErrConflict
	}
	r.Completion = &c
	r.Phase = "COMPLETION_SEALED"
	return q.saveRelease(ctx, r)
}
func (q *Queue) authorizeCompletion(ctx context.Context, c telemetry.NodeReleaseCompletion) (ReleaseAuthorization, error) {
	if q.opts.ReleaseVerifier == nil {
		return ReleaseAuthorization{}, ErrInvalid
	}
	if e := q.opts.ReleaseVerifier.AuthorizeRetirement(ctx, q.opts.Scope); e != nil {
		return ReleaseAuthorization{}, safeReleaseError(e)
	}
	auth, e := q.opts.ReleaseVerifier.VerifyCompletion(ctx, c)
	if e != nil {
		return auth, safeReleaseError(e)
	}
	d, e := telemetry.CanonicalNodeCompletionDigest(c)
	if e != nil || c.Digest != hex.EncodeToString(d[:]) || !q.boundRelease(c.Binding) {
		return auth, ErrInvalid
	}
	return auth, nil
}
func (q *Queue) ConfirmNodeCompletion(ctx context.Context, c telemetry.NodeReleaseCompletion, receipt telemetry.NodeCompletionReceipt) error {
	auth, e := q.authorizeCompletion(ctx, c)
	if e != nil {
		return e
	}
	if telemetry.ValidateNodeCompletionReceipt(receipt) != nil || receipt.Binding != c.Binding || receipt.CompletionDigest != c.Digest || receipt.CloudFinalReceiptID != c.CloudFinalReceiptID || receipt.GatewayRetirementReceiptID != c.GatewayRetirementReceiptID {
		return ErrInvalid
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
	if r.CompletionReceipt != nil {
		if !sameJSON(r.CompletionReceipt, &receipt) || !sameJSON(r.Completion, &c) {
			return ErrConflict
		}
		return q.trimCompletedReleases(ctx, r.Request.SessionEpoch)
	}
	if r.Completion != nil && !sameJSON(r.Completion, &c) {
		return ErrConflict
	}
	if r.Completion == nil && !auth.SignerActive {
		return telemetry.ErrUnauthorized
	}
	if q.opts.Role == Node && r.Phase != "COMPLETION_SEALED" {
		return ErrRole
	}
	if q.opts.Role == Gateway && r.Phase != "FINAL_RECEIVED" && r.Phase != "NODE_COMPLETION_PENDING" {
		return ErrRole
	}
	r.Completion = &c
	r.CompletionReceipt = &receipt
	r.Phase = "COMPLETE"
	if e = q.saveReleaseAndPrefix(ctx, r, true); e != nil {
		return e
	}
	if e = q.fail("node_completion_recorded"); e != nil {
		return e
	}
	return q.trimCompletedReleases(ctx, r.Request.SessionEpoch)
}
func completionMatches(c telemetry.NodeReleaseCompletion, r ReleaseRecord) bool {
	return r.Final != nil && c.Binding == r.Request.Binding() && c.CloudFinalReceiptID == r.Final.CloudFinalReceipt.ID && c.GatewayRetirementReceiptID == r.Final.ID
}
func sameJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}
