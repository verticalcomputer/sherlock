package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

var (
	ErrDiagnosticNotFound          = errors.New("diagnostic run not found")
	ErrDiagnosticConflict          = errors.New("diagnostic state conflicts with the requested operation")
	ErrDiagnosticForbidden         = errors.New("diagnostic action is forbidden")
	ErrDiagnosticDefinitionInvalid = errors.New("diagnostic definition verification failed")
	ErrDiagnosticLeaseInvalid      = errors.New("diagnostic work lease is invalid")
)

// VerifiedDiagnosticDefinition is returned only after the adapter has
// validated a signed pack, its issuer, expiry, compatibility and definition
// digest. It intentionally contains no executable path or argv.
type VerifiedDiagnosticDefinition struct {
	Reference domain.DiagnosticDefinitionRef
	Privilege domain.DiagnosticPrivilege
	Issuer    string
	ExpiresAt time.Time
}

type DiagnosticDefinitionVerifier interface {
	// VerifyDiagnosticDefinition also validates the non-secret arguments
	// against the signed definition schema before any value is persisted.
	VerifyDiagnosticDefinition(context.Context, domain.ClusterID, domain.DiagnosticDefinitionRef, []domain.DiagnosticTarget, []domain.DiagnosticArgument) (VerifiedDiagnosticDefinition, error)
}

type DiagnosticAuthorizationAction string

const (
	DiagnosticActionPreview DiagnosticAuthorizationAction = "PREVIEW"
	DiagnosticActionStart   DiagnosticAuthorizationAction = "START"
	DiagnosticActionApprove DiagnosticAuthorizationAction = "APPROVE"
)

type DiagnosticAuthorizationRequest struct {
	Action     DiagnosticAuthorizationAction
	ActorID    string
	ClusterID  domain.ClusterID
	RunID      domain.DiagnosticRunID
	Definition domain.DiagnosticDefinitionRef
	Privilege  domain.DiagnosticPrivilege
	Targets    []domain.DiagnosticTarget
}

type DiagnosticAuthorizationDecision struct {
	Allowed          bool
	ApprovalRequired bool
	ReasonCode       string
}

type DiagnosticAuthorizer interface {
	AuthorizeDiagnostic(context.Context, DiagnosticAuthorizationRequest) (DiagnosticAuthorizationDecision, error)
}

type DiagnosticAuditKind string

const (
	DiagnosticAuditPreview  DiagnosticAuditKind = "AUTHORIZATION_PREVIEW"
	DiagnosticAuditStart    DiagnosticAuditKind = "START_AUTHORIZATION"
	DiagnosticAuditApproval DiagnosticAuditKind = "APPROVAL"
	DiagnosticAuditClaim    DiagnosticAuditKind = "ATTEMPT_CLAIM"
	DiagnosticAuditResult   DiagnosticAuditKind = "ATTEMPT_RESULT"
)

// DiagnosticAuditEvent contains only bounded attribution and outcome
// metadata. Argument values, output and credentials have no field here.
type DiagnosticAuditEvent struct {
	EventID          string
	Kind             DiagnosticAuditKind
	RunID            domain.DiagnosticRunID
	WorkID           domain.DiagnosticWorkID
	Attempt          int
	ClusterID        domain.ClusterID
	ActorID          string
	Outcome          string
	ReasonCode       string
	OccurredAt       time.Time
	DefinitionDigest domain.SHA256
	TargetDigest     domain.SHA256
}

type DiagnosticAuditSink interface {
	AppendDiagnosticAudit(context.Context, DiagnosticAuditEvent) error
}

type DiagnosticRunStore interface {
	// Mutations must append audit in the same transaction. Exact idempotent
	// replays return the prior run and created=false.
	CreateDiagnosticRun(context.Context, domain.DiagnosticRun, domain.DiagnosticWorkID, DiagnosticAuditEvent) (domain.DiagnosticRun, bool, error)
	LoadDiagnosticRun(context.Context, domain.DiagnosticRunID) (domain.DiagnosticRun, bool, error)
	ApproveDiagnosticRun(context.Context, domain.DiagnosticRun, domain.DiagnosticApproval, DiagnosticAuditEvent) error
}

type DiagnosticWorkStore interface {
	// Claim and RecordDiagnosticAttempt commit their audit record atomically
	// with the lease/result state change.
	ClaimDiagnosticWork(context.Context, domain.ClusterID, domain.CollectorID, string, time.Duration, DiagnosticAuditEvent) (domain.DiagnosticWorkLease, bool, error)
	LoadDiagnosticWorkLease(context.Context, domain.ClusterID, domain.CollectorID, domain.DiagnosticWorkID, int, string) (domain.DiagnosticWorkLease, error)
	RecordDiagnosticAttempt(context.Context, domain.ClusterID, domain.CollectorID, domain.DiagnosticWorkLease, domain.DiagnosticAttemptResult, DiagnosticAuditEvent) (domain.DiagnosticRun, bool, error)
}

// DiagnosticExecutionPlan is opaque policy output. The digest binds the exact
// verified definition, executable identity, argv and resource limits. It must
// not contain a credential value; execution adapters receive credentials only
// via a separate, ephemeral channel.
type DiagnosticExecutionPlan struct {
	RunID    domain.DiagnosticRunID
	WorkID   domain.DiagnosticWorkID
	Attempt  int
	RunnerID string
	Targets  []domain.DiagnosticTarget
	// PlanHandle is an opaque, adapter-owned reference to the already resolved
	// immutable plan. It is never an executable path or user command.
	PlanHandle string
	PlanDigest domain.SHA256
}

type DiagnosticPlanResolver interface {
	ResolveDiagnosticPlan(context.Context, VerifiedDiagnosticDefinition, []domain.DiagnosticTarget, []domain.DiagnosticArgument) (DiagnosticExecutionPlan, error)
}

type DiagnosticExecutor interface {
	ExecuteDiagnostic(context.Context, DiagnosticExecutionPlan) (domain.DiagnosticAttemptResult, error)
}

type DiagnosticService struct {
	store      DiagnosticRunStore
	verifier   DiagnosticDefinitionVerifier
	authorizer DiagnosticAuthorizer
	audit      DiagnosticAuditSink
	clock      Clock
	ids        IDGenerator
}

func NewDiagnosticService(store DiagnosticRunStore, verifier DiagnosticDefinitionVerifier, authorizer DiagnosticAuthorizer, audit DiagnosticAuditSink, clock Clock, ids IDGenerator) (*DiagnosticService, error) {
	if store == nil || verifier == nil || authorizer == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("diagnostic service dependencies are required")
	}
	return &DiagnosticService{store: store, verifier: verifier, authorizer: authorizer, audit: audit, clock: clock, ids: ids}, nil
}

type PreviewDiagnosticInput struct {
	ActorID    string
	ClusterID  domain.ClusterID
	Definition domain.DiagnosticDefinitionRef
	Targets    []domain.DiagnosticTarget
	Arguments  []domain.DiagnosticArgument
}

func (service *DiagnosticService) PreviewAuthorization(ctx context.Context, input PreviewDiagnosticInput) (DiagnosticAuthorizationDecision, error) {
	verified, err := service.verify(ctx, input.ClusterID, input.Definition, input.Targets, input.Arguments)
	if err != nil {
		if auditErr := service.appendAudit(ctx, DiagnosticAuditEvent{Kind: DiagnosticAuditPreview, ClusterID: input.ClusterID, ActorID: input.ActorID, Outcome: "DENIED", ReasonCode: "DEFINITION_INVALID", DefinitionDigest: diagnosticAuditDigest(input.Definition), TargetDigest: domain.DiagnosticTargetsDigest(input.Targets)}); auditErr != nil {
			return DiagnosticAuthorizationDecision{}, auditErr
		}
		return DiagnosticAuthorizationDecision{}, err
	}
	request := DiagnosticAuthorizationRequest{
		Action: DiagnosticActionPreview, ActorID: input.ActorID, ClusterID: input.ClusterID,
		Definition: input.Definition, Privilege: verified.Privilege,
		Targets: append([]domain.DiagnosticTarget(nil), input.Targets...),
	}
	decision, authErr := service.authorizer.AuthorizeDiagnostic(ctx, request)
	outcome := "DENIED"
	if authErr == nil && decision.Allowed {
		outcome = "ALLOWED"
	}
	if err := service.appendAudit(ctx, DiagnosticAuditEvent{
		Kind: DiagnosticAuditPreview, ClusterID: input.ClusterID, ActorID: input.ActorID,
		Outcome: outcome, ReasonCode: decision.ReasonCode, DefinitionDigest: input.Definition.DefinitionDigest,
		TargetDigest: domain.DiagnosticTargetsDigest(input.Targets),
	}); err != nil {
		return DiagnosticAuthorizationDecision{}, err
	}
	if authErr != nil {
		return DiagnosticAuthorizationDecision{}, fmt.Errorf("authorize diagnostic preview: %w", authErr)
	}
	return decision, nil
}

type StartDiagnosticInput struct {
	ActorID        string
	ClusterID      domain.ClusterID
	Definition     domain.DiagnosticDefinitionRef
	Targets        []domain.DiagnosticTarget
	Arguments      []domain.DiagnosticArgument
	IdempotencyKey string
	Deadline       time.Time
	MaxAttempts    int
}

type StartDiagnosticOutcome struct {
	Run                domain.DiagnosticRun
	PreviouslyRecorded bool
}

func (service *DiagnosticService) Start(ctx context.Context, input StartDiagnosticInput) (StartDiagnosticOutcome, error) {
	verified, err := service.verify(ctx, input.ClusterID, input.Definition, input.Targets, input.Arguments)
	if err != nil {
		if auditErr := service.appendAudit(ctx, DiagnosticAuditEvent{Kind: DiagnosticAuditStart, ClusterID: input.ClusterID, ActorID: input.ActorID, Outcome: "DENIED", ReasonCode: "DEFINITION_INVALID", DefinitionDigest: diagnosticAuditDigest(input.Definition), TargetDigest: domain.DiagnosticTargetsDigest(input.Targets)}); auditErr != nil {
			return StartDiagnosticOutcome{}, auditErr
		}
		return StartDiagnosticOutcome{}, err
	}
	decision, err := service.authorizer.AuthorizeDiagnostic(ctx, DiagnosticAuthorizationRequest{
		Action: DiagnosticActionStart, ActorID: input.ActorID, ClusterID: input.ClusterID,
		Definition: input.Definition, Privilege: verified.Privilege, Targets: append([]domain.DiagnosticTarget(nil), input.Targets...),
	})
	if err != nil {
		_ = service.appendAudit(ctx, DiagnosticAuditEvent{Kind: DiagnosticAuditStart, ClusterID: input.ClusterID, ActorID: input.ActorID, Outcome: "ERROR", ReasonCode: "AUTHORIZER_ERROR", DefinitionDigest: input.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(input.Targets)})
		return StartDiagnosticOutcome{}, fmt.Errorf("authorize diagnostic start: %w", err)
	}
	if !decision.Allowed {
		if auditErr := service.appendAudit(ctx, DiagnosticAuditEvent{Kind: DiagnosticAuditStart, ClusterID: input.ClusterID, ActorID: input.ActorID, Outcome: "DENIED", ReasonCode: decision.ReasonCode, DefinitionDigest: input.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(input.Targets)}); auditErr != nil {
			return StartDiagnosticOutcome{}, auditErr
		}
		return StartDiagnosticOutcome{}, ErrDiagnosticForbidden
	}
	runValue, err := service.ids.NewID()
	if err != nil {
		return StartDiagnosticOutcome{}, fmt.Errorf("create diagnostic run identifier: %w", err)
	}
	workValue, err := service.ids.NewID()
	if err != nil {
		return StartDiagnosticOutcome{}, fmt.Errorf("create diagnostic work identifier: %w", err)
	}
	now := service.clock.Now().UTC()
	run, err := domain.NewDiagnosticRun(domain.DiagnosticRequest{
		RunID: domain.DiagnosticRunID(runValue), ClusterID: input.ClusterID, Definition: input.Definition,
		Privilege: verified.Privilege, Targets: input.Targets, Arguments: input.Arguments,
		RequestedBy: input.ActorID, IdempotencyKey: input.IdempotencyKey, RequestedAt: now,
		Deadline: input.Deadline.UTC(), MaxAttempts: input.MaxAttempts,
	}, decision.ApprovalRequired)
	if err != nil {
		return StartDiagnosticOutcome{}, fmt.Errorf("validate diagnostic request: %w", err)
	}
	audit, err := service.newAudit(DiagnosticAuditEvent{
		Kind: DiagnosticAuditStart, RunID: run.Request().RunID, ClusterID: input.ClusterID, ActorID: input.ActorID,
		Outcome: "ALLOWED", ReasonCode: decision.ReasonCode, DefinitionDigest: input.Definition.DefinitionDigest,
		TargetDigest: domain.DiagnosticTargetsDigest(input.Targets),
	})
	if err != nil {
		return StartDiagnosticOutcome{}, err
	}
	stored, created, err := service.store.CreateDiagnosticRun(ctx, run, domain.DiagnosticWorkID(workValue), audit)
	if err != nil {
		return StartDiagnosticOutcome{}, fmt.Errorf("create diagnostic run: %w", err)
	}
	return StartDiagnosticOutcome{Run: stored, PreviouslyRecorded: !created}, nil
}

func diagnosticAuditDigest(reference domain.DiagnosticDefinitionRef) domain.SHA256 {
	if reference.DefinitionDigest != (domain.SHA256{}) {
		return reference.DefinitionDigest
	}
	return domain.ChecksumSHA256([]byte("invalid-reference\x00" + reference.PackID + "\x00" + reference.PackVersion + "\x00" + string(reference.DefinitionID) + "\x00" + reference.DefinitionVersion))
}

type ApproveDiagnosticInput struct {
	ClusterID  domain.ClusterID
	RunID      domain.DiagnosticRunID
	ApprovedBy string
	ExpiresAt  time.Time
}

func (service *DiagnosticService) Approve(ctx context.Context, input ApproveDiagnosticInput) (domain.DiagnosticRun, error) {
	run, found, err := service.store.LoadDiagnosticRun(ctx, input.RunID)
	if err != nil {
		return domain.DiagnosticRun{}, fmt.Errorf("load diagnostic run: %w", err)
	}
	if !found {
		return domain.DiagnosticRun{}, ErrDiagnosticNotFound
	}
	request := run.Request()
	if input.ClusterID == "" || request.ClusterID != input.ClusterID {
		return domain.DiagnosticRun{}, ErrDiagnosticNotFound
	}
	decision, err := service.authorizer.AuthorizeDiagnostic(ctx, DiagnosticAuthorizationRequest{
		Action: DiagnosticActionApprove, ActorID: input.ApprovedBy, ClusterID: request.ClusterID,
		RunID: input.RunID, Definition: request.Definition, Privilege: request.Privilege, Targets: request.Targets,
	})
	if err != nil {
		_ = service.appendAudit(ctx, DiagnosticAuditEvent{Kind: DiagnosticAuditApproval, RunID: input.RunID, ClusterID: request.ClusterID, ActorID: input.ApprovedBy, Outcome: "ERROR", ReasonCode: "AUTHORIZER_ERROR", DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets)})
		return domain.DiagnosticRun{}, fmt.Errorf("authorize diagnostic approval: %w", err)
	}
	if !decision.Allowed {
		if auditErr := service.appendAudit(ctx, DiagnosticAuditEvent{Kind: DiagnosticAuditApproval, RunID: input.RunID, ClusterID: request.ClusterID, ActorID: input.ApprovedBy, Outcome: "DENIED", ReasonCode: decision.ReasonCode, DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets)}); auditErr != nil {
			return domain.DiagnosticRun{}, auditErr
		}
		return domain.DiagnosticRun{}, ErrDiagnosticForbidden
	}
	approvalValue, err := service.ids.NewID()
	if err != nil {
		return domain.DiagnosticRun{}, fmt.Errorf("create diagnostic approval identifier: %w", err)
	}
	now := service.clock.Now().UTC()
	approval := domain.DiagnosticApproval{
		ApprovalID: domain.DiagnosticApprovalID(approvalValue), RunID: input.RunID,
		DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets),
		ApprovedBy: input.ApprovedBy, ApprovedAt: now, ExpiresAt: input.ExpiresAt.UTC(), RunVersion: run.Version(),
	}
	approved, err := run.Approve(approval, now)
	if err != nil {
		return domain.DiagnosticRun{}, fmt.Errorf("approve diagnostic run: %w", err)
	}
	audit, err := service.newAudit(DiagnosticAuditEvent{
		Kind: DiagnosticAuditApproval, RunID: input.RunID, ClusterID: request.ClusterID, ActorID: input.ApprovedBy,
		Outcome: "APPROVED", DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: approval.TargetDigest,
	})
	if err != nil {
		return domain.DiagnosticRun{}, err
	}
	if err := service.store.ApproveDiagnosticRun(ctx, approved, approval, audit); err != nil {
		return domain.DiagnosticRun{}, fmt.Errorf("persist diagnostic approval: %w", err)
	}
	return approved, nil
}

func (service *DiagnosticService) verify(ctx context.Context, clusterID domain.ClusterID, reference domain.DiagnosticDefinitionRef, targets []domain.DiagnosticTarget, arguments []domain.DiagnosticArgument) (VerifiedDiagnosticDefinition, error) {
	if err := reference.Validate(); err != nil {
		return VerifiedDiagnosticDefinition{}, err
	}
	verified, err := service.verifier.VerifyDiagnosticDefinition(ctx, clusterID, reference, append([]domain.DiagnosticTarget(nil), targets...), append([]domain.DiagnosticArgument(nil), arguments...))
	if err != nil {
		return VerifiedDiagnosticDefinition{}, fmt.Errorf("%w: %v", ErrDiagnosticDefinitionInvalid, err)
	}
	if verified.Reference != reference || verified.ExpiresAt.IsZero() || !verified.ExpiresAt.After(service.clock.Now().UTC()) {
		return VerifiedDiagnosticDefinition{}, ErrDiagnosticDefinitionInvalid
	}
	if err := verified.Privilege.Validate(); err != nil {
		return VerifiedDiagnosticDefinition{}, ErrDiagnosticDefinitionInvalid
	}
	return verified, nil
}

func (service *DiagnosticService) appendAudit(ctx context.Context, event DiagnosticAuditEvent) error {
	event, err := service.newAudit(event)
	if err != nil {
		return err
	}
	if err := service.audit.AppendDiagnosticAudit(ctx, event); err != nil {
		return fmt.Errorf("append required diagnostic audit event: %w", err)
	}
	return nil
}

func (service *DiagnosticService) newAudit(event DiagnosticAuditEvent) (DiagnosticAuditEvent, error) {
	eventValue, err := service.ids.NewID()
	if err != nil {
		return DiagnosticAuditEvent{}, fmt.Errorf("create diagnostic audit identifier: %w", err)
	}
	event.EventID = eventValue
	event.OccurredAt = service.clock.Now().UTC()
	return event, nil
}

type DiagnosticWorker struct {
	store DiagnosticWorkStore
	clock Clock
	ids   IDGenerator
}

func NewDiagnosticWorker(store DiagnosticWorkStore, clock Clock, ids IDGenerator) (*DiagnosticWorker, error) {
	if store == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("diagnostic worker dependencies are required")
	}
	return &DiagnosticWorker{store: store, clock: clock, ids: ids}, nil
}

func (worker *DiagnosticWorker) Claim(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, leaseToken string, leaseFor time.Duration) (domain.DiagnosticWorkLease, bool, error) {
	if clusterID == "" || collectorID == "" {
		return domain.DiagnosticWorkLease{}, false, ErrDiagnosticLeaseInvalid
	}
	audit, err := worker.newAudit(DiagnosticAuditEvent{Kind: DiagnosticAuditClaim, ClusterID: clusterID, ActorID: string(collectorID), Outcome: "CLAIMED"})
	if err != nil {
		return domain.DiagnosticWorkLease{}, false, err
	}
	return worker.store.ClaimDiagnosticWork(ctx, clusterID, collectorID, leaseToken, leaseFor, audit)
}

func (worker *DiagnosticWorker) Record(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, workID domain.DiagnosticWorkID, attempt int, leaseToken string, result domain.DiagnosticAttemptResult) (domain.DiagnosticRun, bool, error) {
	lease, err := worker.store.LoadDiagnosticWorkLease(ctx, clusterID, collectorID, workID, attempt, leaseToken)
	if err != nil {
		return domain.DiagnosticRun{}, false, err
	}
	request := lease.Work.Run.Request()
	if clusterID == "" || collectorID == "" || request.ClusterID != clusterID || lease.RunnerID != string(collectorID) || result.WorkID != workID || result.Attempt != attempt || result.RunnerID != string(collectorID) {
		return domain.DiagnosticRun{}, false, ErrDiagnosticLeaseInvalid
	}
	audit, err := worker.newAudit(DiagnosticAuditEvent{
		Kind: DiagnosticAuditResult, RunID: request.RunID, WorkID: lease.Work.WorkID, Attempt: lease.Attempt,
		ClusterID: clusterID, ActorID: string(collectorID), Outcome: "RECORDED",
		DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets),
	})
	if err != nil {
		return domain.DiagnosticRun{}, false, err
	}
	return worker.store.RecordDiagnosticAttempt(ctx, clusterID, collectorID, lease, result, audit)
}

func (worker *DiagnosticWorker) newAudit(event DiagnosticAuditEvent) (DiagnosticAuditEvent, error) {
	eventID, err := worker.ids.NewID()
	if err != nil {
		return DiagnosticAuditEvent{}, fmt.Errorf("create diagnostic audit identifier: %w", err)
	}
	event.EventID = eventID
	event.OccurredAt = worker.clock.Now().UTC()
	return event, nil
}
