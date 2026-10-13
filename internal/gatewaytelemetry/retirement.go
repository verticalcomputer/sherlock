package gatewaytelemetry

import (
	"context"
	"errors"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

type RetirementQueue interface {
	PendingReleases(context.Context, string, int) ([]telemetryjournal.ReleaseRecord, bool, error)
	PrepareCloudRelease(context.Context, telemetry.ReleaseRequest) (telemetry.ReleasePrepareEnvelope, error)
	CommitGatewayRelease(context.Context, telemetry.ReleaseRequest, telemetry.CloudRetirementReceipt) (telemetry.GatewayReleaseCommit, error)
	ConfirmCloudRelease(context.Context, telemetry.ReleaseRequest, telemetry.CloudRetirementReceipt) (telemetry.GatewayRetirementReceipt, error)
	ConfirmNodeCompletion(context.Context, telemetry.NodeReleaseCompletion, telemetry.NodeCompletionReceipt) error
	PruneRetiredReceipts(context.Context, time.Time, int) (int, error)
}

type RetirementCloud interface {
	PrepareRetirement(context.Context, telemetry.ReleaseRequest, telemetry.ReleaseManifest, telemetry.ReleaseAdmissionReceipt) (telemetry.CloudRetirementReceipt, error)
	CommitRetirement(context.Context, telemetry.ReleaseRequest, telemetry.GatewayReleaseCommit) (telemetry.CloudRetirementReceipt, error)
	CompleteRetirement(context.Context, telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error)
}

// drainRetirement performs at most one cloud retirement mutation and persists
// its exact binding before reporting progress. Separate authority/capability
// polls share the pass deadline. FINAL_RECEIVED waits for the node's signed
// local completion without starving another session or ordinary payloads.
func (r *Runtime) drainRetirement(ctx context.Context, id string) (handled, progressed bool, err error) {
	queue, ok := r.queues[id].(RetirementQueue)
	if !ok {
		return false, false, nil
	}
	cloud, ok := r.cloud.(RetirementCloud)
	if !ok {
		return false, false, nil
	}
	records, _, err := queue.PendingReleases(ctx, "", 8)
	if err != nil || len(records) > 8 {
		return true, false, telemetry.ErrUnavailable
	}
	// There are at most eight pending releases. Scan with a per-enrollment cursor
	// so a blocked or waiting predecessor cannot monopolize the control turn.
	start := 0
	for i, record := range records {
		if record.Request.ReleaseID > r.releaseAfter[id] {
			start = i
			break
		}
		start = i + 1
	}
	if start == len(records) {
		start = 0
	}
	for n := 0; n < len(records); n++ {
		record := records[(start+n)%len(records)]
		request := record.Request
		if request.EnrollmentID != id || telemetry.ValidateReleaseRequest(request) != nil {
			return true, false, telemetry.ErrConflict
		}
		if record.Phase == "FINAL_RECEIVED" || record.Phase == "COMPLETE" {
			continue
		}
		r.releaseAfter[id] = request.ReleaseID
		switch record.Phase {
		case "RELEASING":
			envelope, e := queue.PrepareCloudRelease(ctx, request)
			if e != nil {
				// Data not yet cloud-acknowledged must continue draining. Ownership
				// preparation cannot reserve every turn while those originals remain.
				if errors.Is(e, telemetry.ErrBackpressure) || errors.Is(e, telemetryjournal.ErrCapacity) {
					continue
				}
				return true, false, e
			}
			if envelope.Release.Request.Binding() != request.Binding() || envelope.Admission.Binding != request.Binding() {
				return true, false, telemetry.ErrConflict
			}
			receipt, e := cloud.PrepareRetirement(ctx, request, envelope.Release.Manifest, envelope.Admission)
			if e != nil {
				return true, false, e
			}
			if telemetry.ValidateCloudRetirementReceipt(receipt) != nil || receipt.Phase != "PREPARED" || receipt.Binding != request.Binding() || receipt.GatewayAdmissionID != envelope.Admission.ID {
				return true, false, telemetry.ErrConflict
			}
			_, e = queue.CommitGatewayRelease(ctx, request, receipt)
			return true, e == nil, e
		case "RELEASED":
			if record.Commit == nil || telemetry.ValidateGatewayReleaseCommit(*record.Commit) != nil || record.Commit.Binding != request.Binding() {
				return true, false, telemetry.ErrConflict
			}
			receipt, e := cloud.CommitRetirement(ctx, request, *record.Commit)
			if e != nil {
				return true, false, e
			}
			if telemetry.ValidateCloudRetirementReceipt(receipt) != nil || receipt.Phase != "FINAL" || receipt.Binding != request.Binding() || receipt.GatewayCommitID != record.Commit.ID || receipt.GatewayAdmissionID != record.Commit.GatewayAdmissionID || receipt.PreparedReceiptID != record.Commit.PreparedReceiptID {
				return true, false, telemetry.ErrConflict
			}
			_, e = queue.ConfirmCloudRelease(ctx, request, receipt)
			return true, e == nil, e
		case "NODE_COMPLETION_PENDING":
			if record.Completion == nil || record.Final == nil || record.Completion.Binding != request.Binding() {
				return true, false, telemetry.ErrConflict
			}
			receipt, e := cloud.CompleteRetirement(ctx, *record.Completion)
			if e != nil {
				return true, false, e
			}
			c := record.Completion
			if telemetry.ValidateNodeCompletionReceipt(receipt) != nil || receipt.Binding != c.Binding || receipt.CompletionDigest != c.Digest || receipt.CloudFinalReceiptID != c.CloudFinalReceiptID || receipt.GatewayRetirementReceiptID != c.GatewayRetirementReceiptID {
				return true, false, telemetry.ErrConflict
			}
			e = queue.ConfirmNodeCompletion(ctx, *c, receipt)
			if e == nil {
				e = compactGatewaySessions(ctx, queue)
			}
			return true, e == nil, e
		default:
			return true, false, telemetry.ErrConflict
		}
	}
	return false, false, nil
}

func (r *Runtime) pruneRetirement(ctx context.Context, id string) (bool, error) {
	queue, ok := r.queues[id].(RetirementQueue)
	if !ok {
		return false, nil
	}
	if _, ok := r.cloud.(RetirementCloud); !ok {
		return false, nil
	}
	if err := compactGatewaySessions(ctx, queue); err != nil {
		return false, err
	}
	n, err := queue.PruneRetiredReceipts(ctx, r.now(), 128)
	return n > 0, err
}

func compactGatewaySessions(ctx context.Context, queue any) error {
	if compactor, ok := queue.(interface{ CompactGatewaySessions(context.Context) error }); ok {
		return compactor.CompactGatewaySessions(ctx)
	}
	return nil
}
