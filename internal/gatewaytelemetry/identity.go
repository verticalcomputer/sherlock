package gatewaytelemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"time"
)

// RelayIdentity never starts node ingress or opens telemetry journals. It
// forwards an already-approved protected token and public CSR through this
// gateway's existing authenticated cloud identity. Only the node can import it.
func RelayIdentity(ctx context.Context, c ServiceConfig, token string, request nodeidentity.Request) (nodeidentity.CertificateBundle, error) {
	var zero nodeidentity.CertificateBundle
	approved := false
	for _, id := range c.EnrollmentIDs {
		approved = approved || id == request.Scope.EnrollmentID
	}
	if !approved || !c.FixtureOnly || c.ProtocolVersion != 1 {
		return zero, telemetry.ErrUnauthorized
	}
	ca, _, e := readCertificate(c.NodeCAFile)
	if e != nil {
		return zero, e
	}
	cloud, outbound, _, e := cloudTransport(c, ca)
	if e != nil {
		return zero, e
	}
	defer outbound.CloseIdleConnections()
	grant, e := cloud.Grant(ctx, request.Scope.EnrollmentID)
	if e != nil {
		return zero, e
	}
	if nodeidentity.ValidateRequestForGrant(request, grant, time.Now(), true) != nil {
		return zero, telemetry.ErrUnauthorized
	}
	bundle, e := cloud.IssueNodeCertificate(ctx, token, request)
	if e != nil {
		return zero, e
	}
	block, rest := pem.Decode([]byte(bundle.NodeCAPEM))
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
		return zero, telemetry.ErrConflict
	}
	expected := sha256.Sum256(ca.Raw)
	actual := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(expected[:]) != hex.EncodeToString(actual[:]) {
		return zero, telemetry.ErrConflict
	}
	return bundle, nil
}
