package nodegateway

import (
	"context"
	"encoding/json"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (c *Client) RetirementCapabilities(ctx context.Context) (telemetry.RetirementCapabilities, error) {
	var out telemetry.RetirementCapabilities
	if err := c.request(ctx, "/node-telemetry/v1/retirement/capabilities", []byte("{}"), &out); err != nil {
		return out, err
	}
	if telemetry.ValidateRetirementCapabilities(out) != nil {
		return telemetry.RetirementCapabilities{}, telemetry.ErrInvalid
	}
	return out, nil
}

func (c *Client) ReleaseOwnership(ctx context.Context, e telemetry.ReleaseEnvelope) (telemetry.GatewayRetirementReceipt, error) {
	var out telemetry.GatewayRetirementReceipt
	r := e.Request
	if telemetry.ValidateReleaseEnvelope(e) != nil {
		return out, telemetry.ErrInvalid
	}
	if r.ClusterID != c.principal.ClusterID || r.NodeID != c.principal.NodeID || r.EnrollmentID != c.principal.EnrollmentID || telemetry.VerifyReleaseSignature(r, c.public[r.SigningKeyID]) != nil {
		return out, telemetry.ErrUnauthorized
	}
	wire, err := json.Marshal(e)
	if err != nil || len(wire) > telemetry.MaxReleaseBytes {
		return out, telemetry.ErrInvalid
	}
	if err := c.request(ctx, "/node-telemetry/v1/retirement/releases", wire, &out); err != nil {
		return out, err
	}
	if telemetry.ValidateGatewayRetirementReceipt(out) != nil || out.Binding != r.Binding() {
		return telemetry.GatewayRetirementReceipt{}, telemetry.ErrConflict
	}
	return out, nil
}

func (c *Client) CompleteNodeRelease(ctx context.Context, completion telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error) {
	var out telemetry.NodeCompletionReceipt
	b := completion.Binding
	if b.ClusterID != c.principal.ClusterID || b.NodeID != c.principal.NodeID || b.EnrollmentID != c.principal.EnrollmentID || telemetry.VerifyNodeCompletionSignature(completion, c.public[completion.SigningKeyID]) != nil {
		return out, telemetry.ErrUnauthorized
	}
	wire, err := json.Marshal(completion)
	if err != nil || len(wire) > telemetry.MaxReleaseBytes {
		return out, telemetry.ErrInvalid
	}
	if err := c.request(ctx, "/node-telemetry/v1/retirement/completions", wire, &out); err != nil {
		return out, err
	}
	if telemetry.ValidateNodeCompletionReceipt(out) != nil || out.Binding != completion.Binding || out.CompletionDigest != completion.Digest || out.CloudFinalReceiptID != completion.CloudFinalReceiptID || out.GatewayRetirementReceiptID != completion.GatewayRetirementReceiptID {
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrConflict
	}
	return out, nil
}
