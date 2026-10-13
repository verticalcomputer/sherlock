package diagnosticpolicy

import (
	"context"
	"errors"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
)

type KeyReader interface {
	FindKey(context.Context, string) (auth.StoredKey, error)
}
type Clock interface{ Now() time.Time }

type Authorizer struct {
	keys  KeyReader
	clock Clock
}

func NewAuthorizer(keys KeyReader, clock Clock) (*Authorizer, error) {
	if keys == nil || clock == nil {
		return nil, errors.New("diagnostic key reader and clock are required")
	}
	return &Authorizer{keys: keys, clock: clock}, nil
}

func (authorizer *Authorizer) AuthorizeDiagnostic(ctx context.Context, request application.DiagnosticAuthorizationRequest) (application.DiagnosticAuthorizationDecision, error) {
	key, err := authorizer.keys.FindKey(ctx, request.ActorID)
	if err != nil {
		return application.DiagnosticAuthorizationDecision{ReasonCode: "KEY_UNAVAILABLE"}, nil
	}
	now := authorizer.clock.Now()
	if key.ClusterID != request.ClusterID || key.RevokedAt != nil || !key.ExpiresAt.After(now) {
		return application.DiagnosticAuthorizationDecision{ReasonCode: "CLUSTER_SCOPE_DENIED"}, nil
	}
	principal := auth.Principal{KeyID: key.PublicID, ClusterID: key.ClusterID, Label: key.Label, Capabilities: key.Capabilities}
	approvalRequired := request.Privilege == "PRIVILEGED"
	if request.Action != application.DiagnosticActionApprove && !principal.Has(auth.CapabilityInvestigationsRun) {
		return application.DiagnosticAuthorizationDecision{ReasonCode: "CAPABILITY_DENIED"}, nil
	}
	if (request.Action == application.DiagnosticActionApprove || approvalRequired) && !principal.Has(auth.CapabilityDiagnosticsPrivileged) {
		return application.DiagnosticAuthorizationDecision{ReasonCode: "CAPABILITY_DENIED"}, nil
	}
	return application.DiagnosticAuthorizationDecision{Allowed: true, ApprovalRequired: approvalRequired, ReasonCode: "AUTHORIZED"}, nil
}
