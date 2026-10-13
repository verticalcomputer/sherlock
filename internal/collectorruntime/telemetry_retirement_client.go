package collectorruntime

import (
	"context"
	"encoding/hex"
	"net/url"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (c *TelemetryClient) RetirementCapabilities(ctx context.Context, id string) (telemetry.RetirementCapabilities, error) {
	var out telemetry.RetirementCapabilities
	if !telemetry.ValidIdentifier(id) {
		return out, telemetry.ErrInvalid
	}
	if err := c.request(ctx, "GET", "/collector/telemetry/v1/enrollments/"+url.PathEscape(id)+"/retirement-capabilities", nil, &out, 4<<10); err != nil {
		return out, err
	}
	if telemetry.ValidateRetirementCapabilities(out) != nil {
		return telemetry.RetirementCapabilities{}, telemetry.ErrInvalid
	}
	return out, nil
}

func (c *TelemetryClient) PrepareRetirement(ctx context.Context, r telemetry.ReleaseRequest, m telemetry.ReleaseManifest, admission telemetry.ReleaseAdmissionReceipt) (telemetry.CloudRetirementReceipt, error) {
	var out telemetry.CloudRetirementReceipt
	if r.ClusterID != c.cluster {
		return out, telemetry.ErrUnauthorized
	}
	e := telemetry.ReleaseEnvelope{Request: r, Manifest: m}
	if telemetry.ValidateReleaseEnvelope(e) != nil || telemetry.ValidateReleaseAdmissionReceipt(admission) != nil || admission.Binding != r.Binding() || !canonicalRelease(r) {
		return out, telemetry.ErrInvalid
	}
	if err := c.request(ctx, "POST", "/collector/telemetry/v1/retirement/prepare", telemetry.ReleasePrepareEnvelope{Release: e, Admission: admission}, &out, 8<<10); err != nil {
		return out, err
	}
	if telemetry.ValidateCloudRetirementReceipt(out) != nil || out.Phase != "PREPARED" || out.Binding != r.Binding() || out.GatewayAdmissionID != admission.ID {
		return telemetry.CloudRetirementReceipt{}, telemetry.ErrConflict
	}
	return out, nil
}

func (c *TelemetryClient) CommitRetirement(ctx context.Context, r telemetry.ReleaseRequest, commit telemetry.GatewayReleaseCommit) (telemetry.CloudRetirementReceipt, error) {
	var out telemetry.CloudRetirementReceipt
	if r.ClusterID != c.cluster {
		return out, telemetry.ErrUnauthorized
	}
	if telemetry.ValidateReleaseRequest(r) != nil || !canonicalRelease(r) || telemetry.ValidateGatewayReleaseCommit(commit) != nil || commit.Binding != r.Binding() {
		return out, telemetry.ErrInvalid
	}
	if err := c.request(ctx, "POST", "/collector/telemetry/v1/retirement/commit", telemetry.ReleaseCommitEnvelope{Request: r, Commit: commit}, &out, 8<<10); err != nil {
		return out, err
	}
	if telemetry.ValidateCloudRetirementReceipt(out) != nil || out.Phase != "FINAL" || out.Binding != r.Binding() || out.GatewayAdmissionID != commit.GatewayAdmissionID || out.PreparedReceiptID != commit.PreparedReceiptID || out.GatewayCommitID != commit.ID {
		return telemetry.CloudRetirementReceipt{}, telemetry.ErrConflict
	}
	return out, nil
}

func (c *TelemetryClient) CompleteRetirement(ctx context.Context, completion telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error) {
	var out telemetry.NodeCompletionReceipt
	if completion.Binding.ClusterID != c.cluster {
		return out, telemetry.ErrUnauthorized
	}
	digest, err := telemetry.CanonicalNodeCompletionDigest(completion)
	if err != nil || completion.Digest != hex.EncodeToString(digest[:]) {
		return out, telemetry.ErrInvalid
	}
	if err := c.request(ctx, "POST", "/collector/telemetry/v1/retirement/complete", completion, &out, 8<<10); err != nil {
		return out, err
	}
	if telemetry.ValidateNodeCompletionReceipt(out) != nil || out.Binding != completion.Binding || out.CompletionDigest != completion.Digest || out.CloudFinalReceiptID != completion.CloudFinalReceiptID || out.GatewayRetirementReceiptID != completion.GatewayRetirementReceiptID {
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrConflict
	}
	return out, nil
}

func canonicalRelease(r telemetry.ReleaseRequest) bool {
	digest, err := telemetry.CanonicalReleaseDigest(r)
	return err == nil && r.Digest == hex.EncodeToString(digest[:])
}
