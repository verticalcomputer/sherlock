package diagnosticpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type keyReaderFake struct {
	key auth.StoredKey
	err error
}

func (reader keyReaderFake) FindKey(context.Context, string) (auth.StoredKey, error) {
	return reader.key, reader.err
}

type policyClock struct{ now time.Time }

func (clock policyClock) Now() time.Time { return clock.now }

func TestAuthorizerRequiresRunAndPrivilegedCapabilities(t *testing.T) {
	now := time.Now().UTC()
	base := auth.StoredKey{Key: auth.Key{PublicID: "key-1", ClusterID: "cluster-a", ExpiresAt: now.Add(time.Hour), Capabilities: []auth.Capability{auth.CapabilityInvestigationsRun}}}
	authorizer, _ := NewAuthorizer(keyReaderFake{key: base}, policyClock{now})
	request := application.DiagnosticAuthorizationRequest{Action: application.DiagnosticActionStart, ActorID: "key-1", ClusterID: domain.ClusterID("cluster-a"), Privilege: domain.DiagnosticPrivileged}
	decision, err := authorizer.AuthorizeDiagnostic(context.Background(), request)
	if err != nil || decision.Allowed {
		t.Fatalf("privileged request decision=%+v err=%v", decision, err)
	}
	base.Capabilities = append(base.Capabilities, auth.CapabilityDiagnosticsPrivileged)
	authorizer, _ = NewAuthorizer(keyReaderFake{key: base}, policyClock{now})
	decision, err = authorizer.AuthorizeDiagnostic(context.Background(), request)
	if err != nil || !decision.Allowed || !decision.ApprovalRequired {
		t.Fatalf("authorized decision=%+v err=%v", decision, err)
	}
	request.ClusterID = "cluster-b"
	decision, _ = authorizer.AuthorizeDiagnostic(context.Background(), request)
	if decision.Allowed {
		t.Fatal("cross-cluster diagnostic was allowed")
	}
}
