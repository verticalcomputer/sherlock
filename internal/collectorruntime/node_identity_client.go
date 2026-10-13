package collectorruntime

import (
	"context"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"time"
)

// IssueNodeCertificate relays a protected CSR-bound token through the existing
// authenticated gateway transport. The returned CA is never a trust anchor;
// the node must independently VerifyImport before publishing its public bundle.
func (c *TelemetryClient) IssueNodeCertificate(ctx context.Context, token string, request nodeidentity.Request) (nodeidentity.CertificateBundle, error) {
	var bundle nodeidentity.CertificateBundle
	if request.Scope.ClusterID != c.cluster {
		return bundle, telemetry.ErrUnauthorized
	}
	if _, e := nodeidentity.BootstrapTokenHash(token); e != nil {
		return bundle, telemetry.ErrInvalid
	}
	if _, e := nodeidentity.ValidateRequest(request); e != nil {
		return bundle, telemetry.ErrInvalid
	}
	envelope := struct {
		Token   string               `json:"token"`
		Request nodeidentity.Request `json:"request"`
	}{token, request}
	if e := c.request(ctx, "POST", "/collector/telemetry/v1/node-certificates", envelope, &bundle, nodeidentity.MaxBundleBytes); e != nil {
		return nodeidentity.CertificateBundle{}, e
	}
	now := time.Now()
	if bundle.ProtocolVersion != 1 || bundle.Scope != request.Scope || bundle.CSRSHA256 != request.CSRSHA256 || bundle.SPKISHA256 != request.SPKISHA256 || bundle.IssuedAt.IsZero() || bundle.IssuedAt.After(now.Add(30*time.Second)) || !bundle.NotAfter.After(now) || bundle.NotAfter.Sub(bundle.IssuedAt) > nodeidentity.MaxCertificateLifetime || len(bundle.CertificatePEM) == 0 || len(bundle.CertificatePEM) > nodeidentity.MaxPEMBytes || len(bundle.NodeCAPEM) == 0 || len(bundle.NodeCAPEM) > nodeidentity.MaxPEMBytes {
		return nodeidentity.CertificateBundle{}, telemetry.ErrConflict
	}
	return bundle, nil
}
