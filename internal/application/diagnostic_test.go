package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestDiagnosticStartPassesSafeAuditIntoAtomicStoreMutation(t *testing.T) {
	now := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	store := &diagnosticRunStoreFake{}
	service := newDiagnosticServiceForTest(t, store, &diagnosticAuditFake{}, now, DiagnosticAuthorizationDecision{Allowed: true, ApprovalRequired: true})
	outcome, err := service.Start(context.Background(), StartDiagnosticInput{
		ActorID: "actor-1", ClusterID: "cluster-1", Definition: diagnosticDefinitionForTest(),
		Targets: []domain.DiagnosticTarget{"node-1"}, Arguments: []domain.DiagnosticArgument{{Name: "query", Value: "temperature"}},
		IdempotencyKey: "request-1", Deadline: now.Add(time.Minute), MaxAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Run.Status() != domain.DiagnosticAwaitingApproval {
		t.Fatalf("status = %s", outcome.Run.Status())
	}
	if store.createAudit.Kind != DiagnosticAuditStart || store.createAudit.Outcome != "ALLOWED" || store.createAudit.DefinitionDigest == (domain.SHA256{}) {
		t.Fatalf("missing atomic safe audit: %+v", store.createAudit)
	}
}

func TestDiagnosticDeniedStartRequiresDurableAudit(t *testing.T) {
	now := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	audit := &diagnosticAuditFake{err: errors.New("audit unavailable")}
	service := newDiagnosticServiceForTest(t, &diagnosticRunStoreFake{}, audit, now, DiagnosticAuthorizationDecision{Allowed: false, ReasonCode: "CAPABILITY_REQUIRED"})
	_, err := service.Start(context.Background(), StartDiagnosticInput{
		ActorID: "actor-1", ClusterID: "cluster-1", Definition: diagnosticDefinitionForTest(), Targets: []domain.DiagnosticTarget{"node-1"},
		IdempotencyKey: "request-1", Deadline: now.Add(time.Minute), MaxAttempts: 1,
	})
	if err == nil || errors.Is(err, ErrDiagnosticForbidden) {
		t.Fatalf("audit failure must be returned before denial: %v", err)
	}
	if audit.event.Kind != DiagnosticAuditStart || audit.event.Outcome != "DENIED" {
		t.Fatalf("unexpected denial audit: %+v", audit.event)
	}
}

func TestDiagnosticPreviewAuditCannotContainArgumentsOrOutput(t *testing.T) {
	now := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	audit := &diagnosticAuditFake{}
	service := newDiagnosticServiceForTest(t, &diagnosticRunStoreFake{}, audit, now, DiagnosticAuthorizationDecision{Allowed: true})
	decision, err := service.PreviewAuthorization(context.Background(), PreviewDiagnosticInput{ActorID: "actor-1", ClusterID: "cluster-1", Definition: diagnosticDefinitionForTest(), Targets: []domain.DiagnosticTarget{"node-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || audit.event.Kind != DiagnosticAuditPreview || audit.event.TargetDigest == (domain.SHA256{}) {
		t.Fatalf("preview/audit mismatch: %+v %+v", decision, audit.event)
	}
}

func newDiagnosticServiceForTest(t *testing.T, store DiagnosticRunStore, audit DiagnosticAuditSink, now time.Time, decision DiagnosticAuthorizationDecision) *DiagnosticService {
	t.Helper()
	service, err := NewDiagnosticService(store,
		diagnosticVerifierFake{definition: VerifiedDiagnosticDefinition{Reference: diagnosticDefinitionForTest(), Privilege: domain.DiagnosticPrivileged, Issuer: "test", ExpiresAt: now.Add(time.Hour)}},
		diagnosticAuthorizerFake{decision: decision}, audit, diagnosticClock{now: now}, &diagnosticIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func diagnosticDefinitionForTest() domain.DiagnosticDefinitionRef {
	return domain.DiagnosticDefinitionRef{PackID: "base", PackVersion: "1.0.0", DefinitionID: "gpu-query", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("definition"))}
}

type diagnosticVerifierFake struct{ definition VerifiedDiagnosticDefinition }

func (fake diagnosticVerifierFake) VerifyDiagnosticDefinition(context.Context, domain.ClusterID, domain.DiagnosticDefinitionRef, []domain.DiagnosticTarget, []domain.DiagnosticArgument) (VerifiedDiagnosticDefinition, error) {
	return fake.definition, nil
}

type diagnosticAuthorizerFake struct {
	decision DiagnosticAuthorizationDecision
}

func (fake diagnosticAuthorizerFake) AuthorizeDiagnostic(context.Context, DiagnosticAuthorizationRequest) (DiagnosticAuthorizationDecision, error) {
	return fake.decision, nil
}

type diagnosticClock struct{ now time.Time }

func (clock diagnosticClock) Now() time.Time { return clock.now }

type diagnosticIDs struct{ next int }

func (ids *diagnosticIDs) NewID() (string, error) {
	ids.next++
	return "generated-" + string(rune('a'+ids.next)), nil
}

type diagnosticAuditFake struct {
	event DiagnosticAuditEvent
	err   error
}

func (fake *diagnosticAuditFake) AppendDiagnosticAudit(_ context.Context, event DiagnosticAuditEvent) error {
	fake.event = event
	return fake.err
}

type diagnosticRunStoreFake struct {
	run         domain.DiagnosticRun
	createAudit DiagnosticAuditEvent
}

func (fake *diagnosticRunStoreFake) CreateDiagnosticRun(_ context.Context, run domain.DiagnosticRun, _ domain.DiagnosticWorkID, audit DiagnosticAuditEvent) (domain.DiagnosticRun, bool, error) {
	fake.run, fake.createAudit = run, audit
	return run, true, nil
}
func (fake *diagnosticRunStoreFake) LoadDiagnosticRun(context.Context, domain.DiagnosticRunID) (domain.DiagnosticRun, bool, error) {
	return fake.run, fake.run.Version() > 0, nil
}
func (fake *diagnosticRunStoreFake) ApproveDiagnosticRun(_ context.Context, run domain.DiagnosticRun, _ domain.DiagnosticApproval, _ DiagnosticAuditEvent) error {
	fake.run = run
	return nil
}
