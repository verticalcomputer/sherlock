package domain

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const InvestigationSchemaVersion = 1

var ErrInvestigationBudgetExceeded = errors.New("investigation budget exceeded")

type IncidentID string
type InvestigationID string
type InvestigationEventID string
type InvestigationApprovalID string
type InvestigationActionID string
type HypothesisID string
type FindingID string

type IncidentStatus string

const (
	IncidentOpen     IncidentStatus = "OPEN"
	IncidentResolved IncidentStatus = "RESOLVED"
	IncidentClosed   IncidentStatus = "CLOSED"
)

func (status IncidentStatus) Validate() error {
	switch status {
	case IncidentOpen, IncidentResolved, IncidentClosed:
		return nil
	default:
		return fmt.Errorf("unknown incident status %q", status)
	}
}

func (status IncidentStatus) Terminal() bool { return status == IncidentClosed }

// Incident groups one or more investigations without allowing callers to
// mutate its lifecycle fields directly.
type Incident struct {
	id        IncidentID
	clusterID ClusterID
	title     string
	createdBy string
	createdAt time.Time
	status    IncidentStatus
	version   int
}

func NewIncident(id IncidentID, clusterID ClusterID, title, createdBy string, createdAt time.Time) (Incident, error) {
	return ReconstituteIncident(id, clusterID, title, createdBy, createdAt, IncidentOpen, 1)
}

func ReconstituteIncident(id IncidentID, clusterID ClusterID, title, createdBy string, createdAt time.Time, status IncidentStatus, version int) (Incident, error) {
	if !validInvestigationToken(string(id)) || clusterID == "" || !validInvestigationText(title, 256) || !validInvestigationToken(createdBy) || createdAt.IsZero() {
		return Incident{}, fmt.Errorf("incident identity and metadata are invalid")
	}
	if err := status.Validate(); err != nil {
		return Incident{}, err
	}
	if version < 1 {
		return Incident{}, fmt.Errorf("incident version must be positive")
	}
	return Incident{id: id, clusterID: clusterID, title: title, createdBy: createdBy, createdAt: createdAt.UTC(), status: status, version: version}, nil
}

func (incident Incident) ID() IncidentID         { return incident.id }
func (incident Incident) ClusterID() ClusterID   { return incident.clusterID }
func (incident Incident) Title() string          { return incident.title }
func (incident Incident) CreatedBy() string      { return incident.createdBy }
func (incident Incident) CreatedAt() time.Time   { return incident.createdAt }
func (incident Incident) Status() IncidentStatus { return incident.status }
func (incident Incident) Version() int           { return incident.version }

func (incident Incident) Resolve() (Incident, error) {
	if incident.status != IncidentOpen {
		return Incident{}, transitionConflict("resolve incident", string(incident.status))
	}
	incident.status = IncidentResolved
	incident.version++
	return incident, nil
}

func (incident Incident) Close() (Incident, error) {
	if incident.status != IncidentOpen && incident.status != IncidentResolved {
		return Incident{}, transitionConflict("close incident", string(incident.status))
	}
	incident.status = IncidentClosed
	incident.version++
	return incident, nil
}

type InvestigationStatus string

const (
	InvestigationInitializing     InvestigationStatus = "INITIALIZING"
	InvestigationPlanning         InvestigationStatus = "PLANNING"
	InvestigationPolicyCheck      InvestigationStatus = "POLICY_CHECK"
	InvestigationAwaitingApproval InvestigationStatus = "AWAITING_APPROVAL"
	InvestigationExecuting        InvestigationStatus = "EXECUTING"
	// InvestigationAwaitingEvidence means execution has been dispatched and has
	// not completed. It is distinct from EXECUTING so the admin UI and the
	// stop-reason taxonomy can say honestly why an investigation is not
	// advancing, instead of showing a run that looks stuck mid-step.
	InvestigationAwaitingEvidence  InvestigationStatus = "AWAITING_EVIDENCE"
	InvestigationRecordingEvidence InvestigationStatus = "RECORDING_EVIDENCE"
	InvestigationUpdatingLedger    InvestigationStatus = "UPDATING_LEDGER"
	InvestigationSynthesizing      InvestigationStatus = "SYNTHESIZING"
	InvestigationCompleted         InvestigationStatus = "COMPLETED"
	InvestigationPartial           InvestigationStatus = "PARTIAL"
	InvestigationBlocked           InvestigationStatus = "BLOCKED"
	InvestigationCancelled         InvestigationStatus = "CANCELLED"
)

func (status InvestigationStatus) Validate() error {
	switch status {
	case InvestigationInitializing, InvestigationPlanning, InvestigationPolicyCheck,
		InvestigationAwaitingApproval, InvestigationExecuting, InvestigationAwaitingEvidence, InvestigationRecordingEvidence,
		InvestigationUpdatingLedger, InvestigationSynthesizing, InvestigationCompleted,
		InvestigationPartial, InvestigationBlocked, InvestigationCancelled:
		return nil
	default:
		return fmt.Errorf("unknown investigation status %q", status)
	}
}

func (status InvestigationStatus) Terminal() bool {
	return status == InvestigationCompleted || status == InvestigationPartial || status == InvestigationBlocked || status == InvestigationCancelled
}

type InvestigationStopReason string

const (
	StopSuccessCriteriaMet InvestigationStopReason = "SUCCESS_CRITERIA_MET"
	StopNoUsefulAction     InvestigationStopReason = "NO_USEFUL_ACTION"
	StopBudgetExceeded     InvestigationStopReason = "BUDGET_EXCEEDED"
	StopApprovalDenied     InvestigationStopReason = "APPROVAL_DENIED"
	StopApprovalExpired    InvestigationStopReason = "APPROVAL_EXPIRED"
	StopAccessUnavailable  InvestigationStopReason = "ACCESS_UNAVAILABLE"
	StopSourceUnavailable  InvestigationStopReason = "SOURCE_UNAVAILABLE"
	StopOperatorCancelled  InvestigationStopReason = "OPERATOR_CANCELLED"
	// StopContextExhausted means Sherlock retained the investigation evidence,
	// but could not fit the next planning or synthesis request into its bounded
	// context pipeline. It is deliberately distinct from ACCESS_UNAVAILABLE:
	// the cluster and collector may be healthy, and the corrective owner is
	// Sherlock rather than data-center operations.
	StopContextExhausted InvestigationStopReason = "CONTEXT_EXHAUSTED"
	// StopPolicyExhausted separates "the planner kept proposing work the
	// reviewed tool policy refuses" from "the planner had nothing useful left".
	// Only the controller may set it; a model can never request it.
	StopPolicyExhausted InvestigationStopReason = "POLICY_EXHAUSTED"
)

func (reason InvestigationStopReason) Validate() error {
	switch reason {
	case StopSuccessCriteriaMet, StopNoUsefulAction, StopBudgetExceeded, StopApprovalDenied,
		StopApprovalExpired, StopAccessUnavailable, StopSourceUnavailable, StopOperatorCancelled,
		StopPolicyExhausted, StopContextExhausted:
		return nil
	default:
		return fmt.Errorf("unknown investigation stop reason %q", reason)
	}
}

type InvestigationScope struct {
	EntityKind string
	EntityIDs  []string
	Start      time.Time
	End        time.Time
}

func (scope InvestigationScope) Validate() error {
	if !validInvestigationToken(scope.EntityKind) || len(scope.EntityIDs) < 1 || len(scope.EntityIDs) > 256 || scope.Start.IsZero() || scope.End.IsZero() || scope.End.Before(scope.Start) {
		return fmt.Errorf("investigation scope is invalid")
	}
	seen := make(map[string]struct{}, len(scope.EntityIDs))
	for _, id := range scope.EntityIDs {
		if !validInvestigationToken(id) && !(scope.EntityKind == "collection_job" && ValidCollectionJobID(id)) {
			return fmt.Errorf("investigation scope entity is invalid")
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("investigation scope entities must be unique")
		}
		seen[id] = struct{}{}
	}
	return nil
}

type InvestigationBudget struct {
	MaxDecisions int
	MaxToolCalls int
	// MaxDiagnosticCalls bounds remote diagnostic execution separately from
	// MaxToolCalls, which bounds reads over already committed evidence. A
	// diagnostic fans out across nodes and consumes cluster resources, so an
	// operator must be able to grant evidence access without granting execution
	// volume. It defaults to zero, so no existing request gains execution.
	MaxDiagnosticCalls int
	MaxPrivilegedCalls int
	// MaxFanOut is the maximum target count of one durable action. Larger
	// proposals are split before admission; it is not a cumulative target cap.
	MaxFanOut      int
	MaxModelTokens int64
	MaxCostMicros  int64
}

func (budget InvestigationBudget) Validate() error {
	if budget.MaxDecisions < 1 || budget.MaxToolCalls < 1 || budget.MaxDiagnosticCalls < 0 || budget.MaxPrivilegedCalls < 0 || budget.MaxFanOut < 1 || budget.MaxModelTokens < 0 || budget.MaxCostMicros < 0 {
		return fmt.Errorf("investigation budget limits are invalid")
	}
	return nil
}

type InvestigationBudgetUsage struct {
	Decisions       int
	ToolCalls       int
	DiagnosticCalls int
	PrivilegedCalls int
	// FanOut records the largest admitted action for audit and reconstruction.
	FanOut      int
	ModelTokens int64
	CostMicros  int64
}

func (usage InvestigationBudgetUsage) Validate() error {
	if usage.Decisions < 0 || usage.ToolCalls < 0 || usage.DiagnosticCalls < 0 || usage.PrivilegedCalls < 0 || usage.FanOut < 0 || usage.ModelTokens < 0 || usage.CostMicros < 0 {
		return fmt.Errorf("investigation budget usage cannot be negative")
	}
	return nil
}

func (budget InvestigationBudget) Allows(usage InvestigationBudgetUsage) bool {
	return usage.Validate() == nil && usage.Decisions <= budget.MaxDecisions && usage.ToolCalls <= budget.MaxToolCalls &&
		usage.DiagnosticCalls <= budget.MaxDiagnosticCalls &&
		usage.PrivilegedCalls <= budget.MaxPrivilegedCalls && usage.FanOut <= budget.MaxFanOut &&
		usage.ModelTokens <= budget.MaxModelTokens && usage.CostMicros <= budget.MaxCostMicros
}

const InvestigationPurposeRepairPlan = "EVIDENCE_REPAIR_PLAN"

type InvestigationRequest struct {
	Purpose         string
	ID              InvestigationID
	IncidentID      IncidentID
	ClusterID       ClusterID
	Question        string
	RequestedBy     string
	IdempotencyKey  string
	Scope           InvestigationScope
	SuccessCriteria []string
	Budget          InvestigationBudget
	RequestedAt     time.Time
	Deadline        time.Time
}

func (request InvestigationRequest) Validate() error {
	if request.Purpose != "" && request.Purpose != InvestigationPurposeRepairPlan {
		return fmt.Errorf("invalid investigation purpose")
	}
	if request.Purpose == InvestigationPurposeRepairPlan && (request.Budget.MaxDiagnosticCalls != 0 || request.Budget.MaxPrivilegedCalls != 0 || request.Scope.EntityKind != "cluster" || !slices.Equal(request.Scope.EntityIDs, []string{string(request.ClusterID)})) {
		return fmt.Errorf("repair proposals require cluster scope and no execution budget")
	}
	if !validInvestigationToken(string(request.ID)) || !validInvestigationToken(string(request.IncidentID)) || request.ClusterID == "" || !validInvestigationText(request.Question, 4096) || !validInvestigationToken(request.RequestedBy) || !validInvestigationToken(request.IdempotencyKey) {
		return fmt.Errorf("investigation request identity and metadata are invalid")
	}
	if err := request.Scope.Validate(); err != nil {
		return err
	}
	if len(request.SuccessCriteria) < 1 || len(request.SuccessCriteria) > 32 {
		return fmt.Errorf("investigation must have between 1 and 32 success criteria")
	}
	for _, criterion := range request.SuccessCriteria {
		if !validInvestigationText(criterion, 512) {
			return fmt.Errorf("investigation success criterion is invalid")
		}
	}
	if err := request.Budget.Validate(); err != nil {
		return err
	}
	if request.RequestedAt.IsZero() || request.Deadline.IsZero() || !request.Deadline.After(request.RequestedAt) || request.Deadline.Sub(request.RequestedAt) > 24*time.Hour {
		return fmt.Errorf("investigation deadline must be after request time and within twenty-four hours")
	}
	return nil
}

type InvestigationAction struct {
	ID     InvestigationActionID
	ToolID string
	Digest SHA256
	// Diagnostic marks remote execution rather than a read over already
	// committed evidence. It selects which budget dimension the action spends;
	// it is set from the reviewed tool definition, never from model output.
	Diagnostic bool
	Privileged bool
	FanOut     int
	Targets    []string
	Start      time.Time
	End        time.Time
	Arguments  []InvestigationArgument
}

type InvestigationArgument struct {
	Name       string
	Kind       string
	String     string
	Integer    int64
	Boolean    bool
	Timestamp  time.Time
	StringList []string
}

func (action InvestigationAction) Validate() error {
	if !validInvestigationToken(string(action.ID)) || !validInvestigationToken(action.ToolID) || action.Digest == (SHA256{}) || action.FanOut < 1 {
		return fmt.Errorf("investigation action is invalid")
	}
	if len(action.Targets) == 0 {
		if !action.Start.IsZero() || !action.End.IsZero() || len(action.Arguments) != 0 {
			return fmt.Errorf("investigation action invocation is incomplete")
		}
		return nil
	}
	if len(action.Targets) != action.FanOut || action.Start.IsZero() || action.End.IsZero() || action.End.Before(action.Start) {
		return fmt.Errorf("investigation action invocation scope is invalid")
	}
	seenTargets := map[string]struct{}{}
	for _, target := range action.Targets {
		if !validInvestigationToken(target) && !(action.ToolID == "cluster.source_freshness.v1" && ValidCollectionJobID(target)) {
			return fmt.Errorf("investigation action target is invalid")
		}
		if _, exists := seenTargets[target]; exists {
			return fmt.Errorf("investigation action targets must be unique")
		}
		seenTargets[target] = struct{}{}
	}
	seenArguments := map[string]struct{}{}
	for _, argument := range action.Arguments {
		if !validInvestigationToken(argument.Name) || !slices.Contains([]string{"STRING", "INTEGER", "BOOLEAN", "TIMESTAMP", "STRING_LIST"}, argument.Kind) {
			return fmt.Errorf("investigation action argument is invalid")
		}
		if _, exists := seenArguments[argument.Name]; exists {
			return fmt.Errorf("investigation action arguments must be unique")
		}
		seenArguments[argument.Name] = struct{}{}
		if argument.Kind == "TIMESTAMP" && argument.Timestamp.IsZero() {
			return fmt.Errorf("investigation action timestamp is required")
		}
		if argument.Kind == "STRING_LIST" && len(argument.StringList) == 0 {
			return fmt.Errorf("investigation action string list is empty")
		}
	}
	return nil
}

type InvestigationApproval struct {
	ID                   InvestigationApprovalID
	InvestigationID      InvestigationID
	ActionID             InvestigationActionID
	ActionDigest         SHA256
	InvestigationVersion int
	ApprovedBy           string
	ApprovedAt           time.Time
	ExpiresAt            time.Time
}

func (approval InvestigationApproval) ValidateFor(investigation Investigation, now time.Time) error {
	action, exists := investigation.PendingAction()
	if !exists || investigation.status != InvestigationAwaitingApproval {
		return transitionConflict("approve action", string(investigation.status))
	}
	if !validInvestigationToken(string(approval.ID)) || !validInvestigationToken(approval.ApprovedBy) {
		return fmt.Errorf("investigation approval identity is invalid")
	}
	if approval.InvestigationID != investigation.request.ID || approval.ActionID != action.ID || approval.ActionDigest != action.Digest {
		return fmt.Errorf("investigation approval does not match the pending action")
	}
	if approval.InvestigationVersion != investigation.version {
		return fmt.Errorf("investigation approval version is stale")
	}
	if approval.ApprovedAt.IsZero() || approval.ExpiresAt.IsZero() || approval.ExpiresAt.Before(approval.ApprovedAt) || !approval.ExpiresAt.After(now.UTC()) || approval.ExpiresAt.Sub(approval.ApprovedAt) > 15*time.Minute {
		return fmt.Errorf("investigation approval is expired or exceeds fifteen minutes")
	}
	return nil
}

type Investigation struct {
	request       InvestigationRequest
	status        InvestigationStatus
	stopReason    InvestigationStopReason
	usage         InvestigationBudgetUsage
	pendingAction *InvestigationAction
	version       int
}

func NewInvestigation(request InvestigationRequest) (Investigation, error) {
	if err := request.Validate(); err != nil {
		return Investigation{}, err
	}
	return Investigation{request: cloneInvestigationRequest(request), status: InvestigationInitializing, version: 1}, nil
}

func ReconstituteInvestigation(request InvestigationRequest, status InvestigationStatus, stopReason InvestigationStopReason, usage InvestigationBudgetUsage, pendingAction *InvestigationAction, version int) (Investigation, error) {
	if err := request.Validate(); err != nil {
		return Investigation{}, err
	}
	if err := status.Validate(); err != nil {
		return Investigation{}, err
	}
	if err := usage.Validate(); err != nil || !request.Budget.Allows(usage) {
		return Investigation{}, fmt.Errorf("investigation budget usage exceeds its limits")
	}
	if version < 1 {
		return Investigation{}, fmt.Errorf("investigation version must be positive")
	}
	if status.Terminal() {
		if err := stopReason.Validate(); err != nil {
			return Investigation{}, fmt.Errorf("terminal investigation requires a valid stop reason: %w", err)
		}
		switch status {
		case InvestigationCompleted:
			if stopReason != StopSuccessCriteriaMet {
				return Investigation{}, fmt.Errorf("completed investigation requires the success-criteria stop reason")
			}
		case InvestigationCancelled:
			if stopReason != StopOperatorCancelled {
				return Investigation{}, fmt.Errorf("cancelled investigation requires the operator-cancelled stop reason")
			}
		case InvestigationPartial, InvestigationBlocked:
			if stopReason == StopSuccessCriteriaMet || stopReason == StopOperatorCancelled {
				return Investigation{}, fmt.Errorf("partial or blocked investigation requires a limiting stop reason")
			}
		}
	} else if stopReason != "" {
		return Investigation{}, fmt.Errorf("non-terminal investigation cannot have a stop reason")
	}
	if status == InvestigationAwaitingApproval {
		if pendingAction == nil || !pendingAction.Privileged {
			return Investigation{}, fmt.Errorf("approval wait requires a privileged pending action")
		}
		if err := pendingAction.Validate(); err != nil {
			return Investigation{}, err
		}
	} else if pendingAction != nil {
		return Investigation{}, fmt.Errorf("pending action is only valid while awaiting approval")
	}
	return Investigation{request: cloneInvestigationRequest(request), status: status, stopReason: stopReason, usage: usage, pendingAction: cloneInvestigationAction(pendingAction), version: version}, nil
}

func (investigation Investigation) Request() InvestigationRequest {
	return cloneInvestigationRequest(investigation.request)
}
func (investigation Investigation) Status() InvestigationStatus { return investigation.status }
func (investigation Investigation) StopReason() InvestigationStopReason {
	return investigation.stopReason
}
func (investigation Investigation) Usage() InvestigationBudgetUsage { return investigation.usage }
func (investigation Investigation) Version() int                    { return investigation.version }
func (investigation Investigation) PendingAction() (InvestigationAction, bool) {
	if investigation.pendingAction == nil {
		return InvestigationAction{}, false
	}
	return *investigation.pendingAction, true
}

func (investigation Investigation) BeginPlanning(now time.Time) (Investigation, error) {
	return investigation.transition(now, "begin planning", InvestigationPlanning, InvestigationInitializing, InvestigationUpdatingLedger)
}

func (investigation Investigation) BeginPolicyCheck(now time.Time) (Investigation, error) {
	return investigation.transition(now, "begin policy check", InvestigationPolicyCheck, InvestigationPlanning)
}

func (investigation Investigation) AwaitApproval(action InvestigationAction, now time.Time) (Investigation, error) {
	if err := investigation.canTransition(now, "await approval", InvestigationPolicyCheck); err != nil {
		return Investigation{}, err
	}
	if err := action.Validate(); err != nil {
		return Investigation{}, err
	}
	if !action.Privileged {
		return Investigation{}, fmt.Errorf("only a privileged action can require approval")
	}
	if !investigation.request.Budget.Allows(addBudgetUsage(investigation.usage, actionBudgetUsage(action))) {
		return Investigation{}, fmt.Errorf("pending action exceeds investigation budget")
	}
	investigation.status = InvestigationAwaitingApproval
	investigation.pendingAction = cloneInvestigationAction(&action)
	investigation.version++
	return investigation, nil
}

func (investigation Investigation) Approve(approval InvestigationApproval, now time.Time) (Investigation, error) {
	if err := investigation.ensureActive(now); err != nil {
		return Investigation{}, err
	}
	if err := approval.ValidateFor(investigation, now); err != nil {
		return Investigation{}, err
	}
	action := *investigation.pendingAction
	usage := actionBudgetUsage(action)
	if err := investigation.consume(usage); err != nil {
		return Investigation{}, err
	}
	investigation.usage = addBudgetUsage(investigation.usage, usage)
	investigation.pendingAction = nil
	investigation.status = InvestigationExecuting
	investigation.version++
	return investigation, nil
}

func (investigation Investigation) Execute(action InvestigationAction, now time.Time) (Investigation, error) {
	if err := investigation.canTransition(now, "execute action", InvestigationPolicyCheck); err != nil {
		return Investigation{}, err
	}
	if err := action.Validate(); err != nil {
		return Investigation{}, err
	}
	if action.Privileged {
		return Investigation{}, fmt.Errorf("privileged action requires an action-bound approval")
	}
	usage := actionBudgetUsage(action)
	if err := investigation.consume(usage); err != nil {
		return Investigation{}, err
	}
	investigation.usage = addBudgetUsage(investigation.usage, usage)
	investigation.status = InvestigationExecuting
	investigation.version++
	return investigation, nil
}

func (investigation Investigation) BeginEvidenceRecording(now time.Time) (Investigation, error) {
	return investigation.transition(now, "begin evidence recording", InvestigationRecordingEvidence, InvestigationExecuting, InvestigationAwaitingEvidence)
}

// AwaitEvidence parks an investigation whose execution has been dispatched but
// has not completed. The budget was already consumed when the action was
// admitted, so parking spends nothing further and re-entering costs nothing:
// the action's idempotency key means a re-dispatch returns the in-flight run
// rather than starting a second one.
func (investigation Investigation) AwaitEvidence(now time.Time) (Investigation, error) {
	return investigation.transition(now, "await outstanding evidence", InvestigationAwaitingEvidence, InvestigationExecuting, InvestigationAwaitingEvidence)
}

// ResumeExecution returns a parked investigation to EXECUTING so the next lease
// claim retries the dispatch. It is the only way out of AWAITING_EVIDENCE other
// than the result arriving or the deadline passing.
func (investigation Investigation) ResumeExecution(now time.Time) (Investigation, error) {
	return investigation.transition(now, "resume outstanding execution", InvestigationExecuting, InvestigationAwaitingEvidence)
}

func (investigation Investigation) BeginLedgerUpdate(now time.Time) (Investigation, error) {
	return investigation.transition(now, "begin ledger update", InvestigationUpdatingLedger, InvestigationRecordingEvidence)
}

func (investigation Investigation) BeginSynthesis(now time.Time) (Investigation, error) {
	return investigation.transition(now, "begin synthesis", InvestigationSynthesizing, InvestigationPlanning, InvestigationUpdatingLedger)
}

func (investigation Investigation) RecordDecision(usage InvestigationBudgetUsage, now time.Time) (Investigation, error) {
	if err := investigation.canTransition(now, "record decision", InvestigationPlanning); err != nil {
		return Investigation{}, err
	}
	if usage.Decisions != 1 || usage.ToolCalls != 0 || usage.DiagnosticCalls != 0 || usage.PrivilegedCalls != 0 || usage.FanOut != 0 {
		return Investigation{}, fmt.Errorf("decision usage may contain one decision plus token and cost usage only")
	}
	if err := investigation.consume(usage); err != nil {
		return Investigation{}, err
	}
	investigation.usage = addBudgetUsage(investigation.usage, usage)
	investigation.version++
	return investigation, nil
}

// RecordModelUsage accounts for the separately structured synthesis call. It
// cannot consume decisions or tool authority and is only valid in synthesis.
func (investigation Investigation) RecordModelUsage(usage InvestigationBudgetUsage, now time.Time) (Investigation, error) {
	if err := investigation.canTransition(now, "record synthesis model usage", InvestigationSynthesizing); err != nil {
		return Investigation{}, err
	}
	if usage.Decisions != 0 || usage.ToolCalls != 0 || usage.DiagnosticCalls != 0 || usage.PrivilegedCalls != 0 || usage.FanOut != 0 {
		return Investigation{}, fmt.Errorf("synthesis usage may contain only token or cost usage")
	}
	if err := investigation.consume(usage); err != nil {
		return Investigation{}, err
	}
	investigation.usage = addBudgetUsage(investigation.usage, usage)
	return investigation, nil
}

func (investigation Investigation) Complete(now time.Time) (Investigation, error) {
	if err := investigation.canTransition(now, "complete investigation", InvestigationSynthesizing); err != nil {
		return Investigation{}, err
	}
	return investigation.finish(InvestigationCompleted, StopSuccessCriteriaMet), nil
}

func (investigation Investigation) Stop(status InvestigationStatus, reason InvestigationStopReason, now time.Time) (Investigation, error) {
	if status != InvestigationPartial && status != InvestigationBlocked {
		return Investigation{}, fmt.Errorf("stop outcome must be PARTIAL or BLOCKED")
	}
	if investigation.status.Terminal() {
		return Investigation{}, transitionConflict("stop investigation", string(investigation.status))
	}
	if now.IsZero() {
		return Investigation{}, fmt.Errorf("transition time is required")
	}
	if err := reason.Validate(); err != nil || reason == StopSuccessCriteriaMet || reason == StopOperatorCancelled {
		return Investigation{}, fmt.Errorf("partial or blocked investigation requires a valid limiting reason")
	}
	return investigation.finish(status, reason), nil
}

func (investigation Investigation) Cancel(now time.Time) (Investigation, error) {
	if investigation.status.Terminal() {
		return Investigation{}, transitionConflict("cancel investigation", string(investigation.status))
	}
	if now.IsZero() {
		return Investigation{}, fmt.Errorf("transition time is required")
	}
	return investigation.finish(InvestigationCancelled, StopOperatorCancelled), nil
}

func (investigation Investigation) DeadlineExceeded(now time.Time) bool {
	return !now.IsZero() && !now.UTC().Before(investigation.request.Deadline)
}

func (investigation Investigation) finish(status InvestigationStatus, reason InvestigationStopReason) Investigation {
	investigation.status = status
	investigation.stopReason = reason
	investigation.pendingAction = nil
	investigation.version++
	return investigation
}

func (investigation Investigation) transition(now time.Time, operation string, next InvestigationStatus, allowed ...InvestigationStatus) (Investigation, error) {
	if err := investigation.canTransition(now, operation, allowed...); err != nil {
		return Investigation{}, err
	}
	investigation.status = next
	investigation.version++
	return investigation, nil
}

func (investigation Investigation) canTransition(now time.Time, operation string, allowed ...InvestigationStatus) error {
	if err := investigation.ensureActive(now); err != nil {
		return err
	}
	if !slices.Contains(allowed, investigation.status) {
		return transitionConflict(operation, string(investigation.status))
	}
	return nil
}

func (investigation Investigation) ensureActive(now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("transition time is required")
	}
	if investigation.status.Terminal() {
		return transitionConflict("transition investigation", string(investigation.status))
	}
	if investigation.DeadlineExceeded(now) {
		return fmt.Errorf("investigation deadline is exceeded")
	}
	return nil
}

func (investigation Investigation) consume(usage InvestigationBudgetUsage) error {
	if err := usage.Validate(); err != nil {
		return err
	}
	if !investigation.request.Budget.Allows(addBudgetUsage(investigation.usage, usage)) {
		return fmt.Errorf("%w: requested usage is outside the admitted limits", ErrInvestigationBudgetExceeded)
	}
	return nil
}

type InvestigationEventKind string

const (
	InvestigationEventCreated           InvestigationEventKind = "CREATED"
	InvestigationEventStateChanged      InvestigationEventKind = "STATE_CHANGED"
	InvestigationEventBudgetConsumed    InvestigationEventKind = "BUDGET_CONSUMED"
	InvestigationEventApprovalGranted   InvestigationEventKind = "APPROVAL_GRANTED"
	InvestigationEventEvidenceAdded     InvestigationEventKind = "EVIDENCE_ADDED"
	InvestigationEventHypothesisUpdated InvestigationEventKind = "HYPOTHESIS_UPDATED"
	InvestigationEventFindingAdded      InvestigationEventKind = "FINDING_ADDED"
)

func (kind InvestigationEventKind) Validate() error {
	switch kind {
	case InvestigationEventCreated, InvestigationEventStateChanged, InvestigationEventBudgetConsumed,
		InvestigationEventApprovalGranted, InvestigationEventEvidenceAdded,
		InvestigationEventHypothesisUpdated, InvestigationEventFindingAdded:
		return nil
	default:
		return fmt.Errorf("unknown investigation event kind %q", kind)
	}
}

type InvestigationEvent struct {
	ID              InvestigationEventID
	InvestigationID InvestigationID
	Sequence        int64
	Kind            InvestigationEventKind
	From            InvestigationStatus
	To              InvestigationStatus
	OccurredAt      time.Time
	Details         InvestigationEventDetails
}

// InvestigationEventDetails is a bounded machine classification, never error
// text. Zero values retain compatibility with historical empty event payloads.
type InvestigationEventDetails struct {
	StopReason   InvestigationStopReason `json:"stop_reason,omitempty"`
	FailureCode  string                  `json:"failure_code,omitempty"`
	FailureStage string                  `json:"failure_stage,omitempty"`
}

func (details InvestigationEventDetails) Validate() error {
	if details.StopReason != "" {
		if err := details.StopReason.Validate(); err != nil {
			return err
		}
	}
	if details.FailureCode == "" && details.FailureStage == "" {
		return nil
	}
	if details.StopReason == "" {
		return fmt.Errorf("failure classification requires a stop reason")
	}
	switch details.FailureCode {
	case "UNCLASSIFIED", "REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE", "REQUIRED_EVIDENCE_EXCEEDS_ALLOWANCE", "CONTEXT_EXCEEDS_ENCODED_LIMIT", "PROVIDER_INPUT_EXCEEDS_ALLOWANCE", "EVIDENCE_CONTEXT_UNUSABLE", "CONTEXT_CHECKPOINT_MISMATCH", "TOKEN_ESTIMATOR_UNDERRUN", "BUDGET_EXCEEDED", "REPAIR_WARNING_SNAPSHOT_INVALID":
	default:
		return fmt.Errorf("invalid investigation event failure code")
	}
	switch details.FailureStage {
	case "LOAD", "PLANNING", "POLICY_CHECK", "EXECUTION", "EVIDENCE_RECORDING", "LEDGER_UPDATE", "SYNTHESIS", "TRANSITION_PERSISTENCE":
	default:
		return fmt.Errorf("invalid investigation event failure stage")
	}
	return nil
}

func (event InvestigationEvent) Validate() error {
	if err := event.Details.Validate(); err != nil {
		return err
	}
	if event.Details.StopReason != "" && (event.Kind != InvestigationEventStateChanged || !event.To.Terminal()) {
		return fmt.Errorf("only terminal transitions may carry stop details")
	}
	if !validInvestigationToken(string(event.ID)) || !validInvestigationToken(string(event.InvestigationID)) || event.Sequence < 1 || event.OccurredAt.IsZero() {
		return fmt.Errorf("investigation event identity and ordering are invalid")
	}
	if err := event.Kind.Validate(); err != nil {
		return err
	}
	if event.Kind == InvestigationEventStateChanged {
		if err := event.From.Validate(); err != nil {
			return err
		}
		if err := event.To.Validate(); err != nil {
			return err
		}
		if event.From == event.To || event.From.Terminal() {
			return fmt.Errorf("investigation state-change event is invalid")
		}
	} else if event.From != "" || event.To != "" {
		return fmt.Errorf("only state-change events may carry states")
	}
	return nil
}

type InvestigationEventHistory struct {
	events []InvestigationEvent
}

func NewInvestigationEventHistory(events []InvestigationEvent, investigationID InvestigationID) (InvestigationEventHistory, error) {
	history := InvestigationEventHistory{}
	for _, event := range events {
		var err error
		history, err = history.Append(event, investigationID)
		if err != nil {
			return InvestigationEventHistory{}, err
		}
	}
	return history, nil
}

func (history InvestigationEventHistory) Events() []InvestigationEvent {
	return slices.Clone(history.events)
}

func (history InvestigationEventHistory) Append(event InvestigationEvent, investigationID InvestigationID) (InvestigationEventHistory, error) {
	if err := event.Validate(); err != nil {
		return InvestigationEventHistory{}, err
	}
	if event.InvestigationID != investigationID {
		return InvestigationEventHistory{}, fmt.Errorf("investigation event belongs to a different investigation")
	}
	wantSequence := int64(len(history.events) + 1)
	if event.Sequence != wantSequence {
		return InvestigationEventHistory{}, fmt.Errorf("investigation event sequence must be %d", wantSequence)
	}
	if len(history.events) > 0 && event.OccurredAt.Before(history.events[len(history.events)-1].OccurredAt) {
		return InvestigationEventHistory{}, fmt.Errorf("investigation event time cannot move backwards")
	}
	history.events = append(slices.Clone(history.events), event)
	return history, nil
}

type InvestigationEvidence struct {
	EvidenceID      EvidenceID
	InvestigationID InvestigationID
	ClusterID       ClusterID
	EntityIDs       []string
	Status          EvidenceStatus
	ObservedStart   time.Time
	ObservedEnd     time.Time
	RecordedAt      time.Time
}

func (entry InvestigationEvidence) ValidateFor(investigation Investigation) error {
	if entry.EvidenceID == "" || entry.InvestigationID != investigation.request.ID || entry.ClusterID != investigation.request.ClusterID || entry.RecordedAt.IsZero() || len(entry.EntityIDs) == 0 {
		return fmt.Errorf("investigation evidence identity and provenance are invalid")
	}
	if validateEvidenceStatus(entry.Status) != nil || entry.ObservedStart.IsZero() || entry.ObservedEnd.Before(entry.ObservedStart) || entry.RecordedAt.Before(entry.ObservedEnd) {
		return fmt.Errorf("investigation evidence status and time provenance are invalid")
	}
	allowed := make(map[string]struct{}, len(investigation.request.Scope.EntityIDs))
	for _, id := range investigation.request.Scope.EntityIDs {
		allowed[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(entry.EntityIDs))
	for _, id := range entry.EntityIDs {
		if _, exists := allowed[id]; !exists {
			return fmt.Errorf("investigation evidence is outside the investigation scope")
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("investigation evidence entities must be unique")
		}
		seen[id] = struct{}{}
	}
	return nil
}

type EvidenceLedger struct {
	entries []InvestigationEvidence
}

func NewEvidenceLedger(entries []InvestigationEvidence, investigation Investigation) (EvidenceLedger, error) {
	ledger := EvidenceLedger{}
	for _, entry := range entries {
		if err := entry.ValidateFor(investigation); err != nil {
			return EvidenceLedger{}, err
		}
		if ledger.Contains(entry.EvidenceID) {
			return EvidenceLedger{}, fmt.Errorf("investigation evidence already exists")
		}
		entry.EntityIDs = slices.Clone(entry.EntityIDs)
		ledger.entries = append(ledger.entries, entry)
	}
	return ledger, nil
}

func (ledger EvidenceLedger) Entries() []InvestigationEvidence {
	entries := slices.Clone(ledger.entries)
	for index := range entries {
		entries[index].EntityIDs = slices.Clone(entries[index].EntityIDs)
	}
	return entries
}

func (ledger EvidenceLedger) Contains(id EvidenceID) bool {
	return slices.ContainsFunc(ledger.entries, func(entry InvestigationEvidence) bool { return entry.EvidenceID == id })
}

func (ledger EvidenceLedger) Covers(id EvidenceID, entityID string) bool {
	return slices.ContainsFunc(ledger.entries, func(entry InvestigationEvidence) bool {
		return entry.EvidenceID == id && slices.Contains(entry.EntityIDs, entityID)
	})
}

func (ledger EvidenceLedger) Append(entry InvestigationEvidence, investigation Investigation) (EvidenceLedger, error) {
	if investigation.status != InvestigationRecordingEvidence && investigation.status != InvestigationUpdatingLedger {
		return EvidenceLedger{}, transitionConflict("record evidence", string(investigation.status))
	}
	if err := entry.ValidateFor(investigation); err != nil {
		return EvidenceLedger{}, err
	}
	if ledger.Contains(entry.EvidenceID) {
		return EvidenceLedger{}, fmt.Errorf("investigation evidence already exists")
	}
	entry.EntityIDs = slices.Clone(entry.EntityIDs)
	ledger.entries = append(slices.Clone(ledger.entries), entry)
	return ledger, nil
}

type HypothesisStatus string

const (
	HypothesisProposed   HypothesisStatus = "PROPOSED"
	HypothesisSupported  HypothesisStatus = "SUPPORTED"
	HypothesisWeakened   HypothesisStatus = "WEAKENED"
	HypothesisRefuted    HypothesisStatus = "REFUTED"
	HypothesisUnresolved HypothesisStatus = "UNRESOLVED"
)

func (status HypothesisStatus) Validate() error {
	switch status {
	case HypothesisProposed, HypothesisSupported, HypothesisWeakened, HypothesisRefuted, HypothesisUnresolved:
		return nil
	default:
		return fmt.Errorf("unknown hypothesis status %q", status)
	}
}

type Hypothesis struct {
	ID                    HypothesisID
	InvestigationID       InvestigationID
	Statement             string
	Status                HypothesisStatus
	Confidence            float64
	SupportingEvidence    []EvidenceID
	ContradictingEvidence []EvidenceID
	UnresolvedTests       []string
	Version               int
}

func (hypothesis Hypothesis) Validate(ledger EvidenceLedger, investigation Investigation) error {
	if !validInvestigationToken(string(hypothesis.ID)) || hypothesis.InvestigationID != investigation.request.ID || !validInvestigationText(hypothesis.Statement, 2048) || hypothesis.Confidence < 0 || hypothesis.Confidence > 1 || hypothesis.Version < 1 {
		return fmt.Errorf("hypothesis identity or content is invalid")
	}
	if err := hypothesis.Status.Validate(); err != nil {
		return err
	}
	supportRequired := hypothesis.Status == HypothesisSupported
	if err := validateEvidenceCitations(ledger, hypothesis.SupportingEvidence, supportRequired); err != nil {
		return fmt.Errorf("hypothesis supporting evidence: %w", err)
	}
	contradictionRequired := hypothesis.Status == HypothesisWeakened || hypothesis.Status == HypothesisRefuted
	if err := validateEvidenceCitations(ledger, hypothesis.ContradictingEvidence, contradictionRequired); err != nil {
		return fmt.Errorf("hypothesis contradicting evidence: %w", err)
	}
	if overlapsEvidence(hypothesis.SupportingEvidence, hypothesis.ContradictingEvidence) {
		return fmt.Errorf("evidence cannot both support and contradict a hypothesis")
	}
	if len(hypothesis.UnresolvedTests) > 32 {
		return fmt.Errorf("hypothesis has too many unresolved tests")
	}
	for _, test := range hypothesis.UnresolvedTests {
		if !validInvestigationText(test, 512) {
			return fmt.Errorf("hypothesis unresolved test is invalid")
		}
	}
	return nil
}

type HypothesisLedger struct {
	entries []Hypothesis
}

func NewHypothesisLedger(entries []Hypothesis, evidence EvidenceLedger, investigation Investigation) (HypothesisLedger, error) {
	ledger := HypothesisLedger{}
	for _, hypothesis := range entries {
		if err := hypothesis.Validate(evidence, investigation); err != nil {
			return HypothesisLedger{}, err
		}
		if slices.ContainsFunc(ledger.entries, func(current Hypothesis) bool { return current.ID == hypothesis.ID }) {
			return HypothesisLedger{}, fmt.Errorf("hypothesis already exists")
		}
		ledger.entries = append(ledger.entries, cloneHypothesis(hypothesis))
	}
	return ledger, nil
}

func (ledger HypothesisLedger) Entries() []Hypothesis { return cloneHypotheses(ledger.entries) }

func (ledger HypothesisLedger) Upsert(hypothesis Hypothesis, evidence EvidenceLedger, investigation Investigation) (HypothesisLedger, error) {
	if investigation.status != InvestigationPlanning && investigation.status != InvestigationUpdatingLedger {
		return HypothesisLedger{}, transitionConflict("update hypothesis", string(investigation.status))
	}
	if err := hypothesis.Validate(evidence, investigation); err != nil {
		return HypothesisLedger{}, err
	}
	entries := cloneHypotheses(ledger.entries)
	for index, current := range entries {
		if current.ID != hypothesis.ID {
			continue
		}
		if hypothesis.Version != current.Version+1 {
			return HypothesisLedger{}, fmt.Errorf("hypothesis version is stale")
		}
		entries[index] = cloneHypothesis(hypothesis)
		ledger.entries = entries
		return ledger, nil
	}
	if hypothesis.Version != 1 {
		return HypothesisLedger{}, fmt.Errorf("new hypothesis version must be one")
	}
	ledger.entries = append(entries, cloneHypothesis(hypothesis))
	return ledger, nil
}

type FindingKind string

const (
	FindingObservation    FindingKind = "OBSERVATION"
	FindingDerivedSignal  FindingKind = "DERIVED_SIGNAL"
	FindingHypothesis     FindingKind = "HYPOTHESIS"
	FindingRecommendation FindingKind = "RECOMMENDATION"
)

func (kind FindingKind) Validate() error {
	switch kind {
	case FindingObservation, FindingDerivedSignal, FindingHypothesis, FindingRecommendation:
		return nil
	default:
		return fmt.Errorf("unknown finding kind %q", kind)
	}
}

type FindingStatus string

const (
	FindingCurrent    FindingStatus = "CURRENT"
	FindingSuperseded FindingStatus = "SUPERSEDED"
)

// Finding severity reuses HealthSeverity rather than carrying a second scale.
// Severity decides operational action -- RMA, drain, monitor, ignore -- and a
// finding that means what a health signal means must say the same word, or the
// two cannot be compared by whoever is on call.
func ValidateFindingSeverity(value string) error {
	switch HealthSeverity(value) {
	case HealthSeverityUnknown, HealthSeverityInfo, HealthSeverityWarning, HealthSeverityCritical:
		return nil
	default:
		return fmt.Errorf("unknown finding severity %q", value)
	}
}

// FindingSeverityAtLeast reports whether left is at least as severe as right.
// Ordering is explicit because UNKNOWN is not less severe than INFO in any
// useful sense; it means the question was not answered, so it sorts below
// everything actionable but must never be treated as a clean result.
func FindingSeverityAtLeast(left, right HealthSeverity) bool {
	return findingSeverityRank(left) >= findingSeverityRank(right)
}

func findingSeverityRank(value HealthSeverity) int {
	switch value {
	case HealthSeverityCritical:
		return 3
	case HealthSeverityWarning:
		return 2
	case HealthSeverityInfo:
		return 1
	default:
		return 0
	}
}

type Finding struct {
	ID                 FindingID
	InvestigationID    InvestigationID
	Kind               FindingKind
	Statement          string
	EntityIDs          []string
	Severity           string
	Confidence         *float64
	EvidenceIDs        []EvidenceID
	CounterEvidenceIDs []EvidenceID
	Status             FindingStatus
}

func (finding Finding) Validate(ledger EvidenceLedger, investigation Investigation) error {
	if !validInvestigationToken(string(finding.ID)) || finding.InvestigationID != investigation.request.ID || !validInvestigationText(finding.Statement, 4096) || len(finding.EntityIDs) == 0 {
		return fmt.Errorf("finding identity or content is invalid")
	}
	if err := ValidateFindingSeverity(finding.Severity); err != nil {
		return err
	}
	if err := finding.Kind.Validate(); err != nil {
		return err
	}
	if finding.Status != FindingCurrent && finding.Status != FindingSuperseded {
		return fmt.Errorf("unknown finding status %q", finding.Status)
	}
	if finding.Kind == FindingHypothesis {
		if finding.Confidence == nil || *finding.Confidence < 0 || *finding.Confidence > 1 {
			return fmt.Errorf("hypothesis finding requires confidence between zero and one")
		}
	} else if finding.Confidence != nil {
		return fmt.Errorf("confidence is only valid for hypothesis findings")
	}
	if err := validateEvidenceCitations(ledger, finding.EvidenceIDs, finding.Kind != FindingRecommendation); err != nil {
		return fmt.Errorf("finding evidence: %w", err)
	}
	if err := validateEvidenceCitations(ledger, finding.CounterEvidenceIDs, false); err != nil {
		return fmt.Errorf("finding counter-evidence: %w", err)
	}
	if overlapsEvidence(finding.EvidenceIDs, finding.CounterEvidenceIDs) {
		return fmt.Errorf("evidence cannot support and contradict the same finding")
	}
	allowed := make(map[string]struct{}, len(investigation.request.Scope.EntityIDs))
	for _, id := range investigation.request.Scope.EntityIDs {
		allowed[id] = struct{}{}
	}
	seenEntities := make(map[string]struct{}, len(finding.EntityIDs))
	for _, id := range finding.EntityIDs {
		if _, exists := allowed[id]; !exists {
			return fmt.Errorf("finding is outside the investigation scope")
		}
		if _, exists := seenEntities[id]; exists {
			return fmt.Errorf("finding entities must be unique")
		}
		seenEntities[id] = struct{}{}
		if finding.Kind != FindingRecommendation && !slices.ContainsFunc(finding.EvidenceIDs, func(evidenceID EvidenceID) bool { return ledger.Covers(evidenceID, id) }) {
			return fmt.Errorf("finding evidence does not cover entity %q", id)
		}
	}
	return nil
}

type FindingLedger struct {
	entries []Finding
}

func NewFindingLedger(entries []Finding, evidence EvidenceLedger, investigation Investigation) (FindingLedger, error) {
	ledger := FindingLedger{}
	for _, finding := range entries {
		if err := finding.Validate(evidence, investigation); err != nil {
			return FindingLedger{}, err
		}
		if slices.ContainsFunc(ledger.entries, func(current Finding) bool { return current.ID == finding.ID }) {
			return FindingLedger{}, fmt.Errorf("finding already exists")
		}
		ledger.entries = append(ledger.entries, cloneFinding(finding))
	}
	return ledger, nil
}

func (ledger FindingLedger) Entries() []Finding {
	result := make([]Finding, len(ledger.entries))
	for index := range ledger.entries {
		result[index] = cloneFinding(ledger.entries[index])
	}
	return result
}

func (ledger FindingLedger) Append(finding Finding, evidence EvidenceLedger, investigation Investigation) (FindingLedger, error) {
	if investigation.status != InvestigationSynthesizing {
		return FindingLedger{}, transitionConflict("record finding", string(investigation.status))
	}
	if err := finding.Validate(evidence, investigation); err != nil {
		return FindingLedger{}, err
	}
	if slices.ContainsFunc(ledger.entries, func(current Finding) bool { return current.ID == finding.ID }) {
		return FindingLedger{}, fmt.Errorf("finding already exists")
	}
	ledger.entries = append(ledger.Entries(), cloneFinding(finding))
	return ledger, nil
}

// A report section is narrative the synthesis model produced that is not a
// claim about a specific entity, and therefore cannot be a Finding: a timeline
// entry is anchored to an instant rather than to a subject, and a statement of
// what remains unknown is by construction a claim about what the evidence does
// not cover. Forcing either through Finding.Validate would discard exactly the
// content worth keeping, because that validator requires every named entity to
// be covered by a citation.
//
// Sections are still untrusted model prose, so every citation they carry is
// resolved against the durable ledger on the same terms findings use. What
// differs is only the entity-coverage rule, which does not apply here.
type ReportSectionID string

type ReportSectionKind string

const (
	ReportSectionTimeline ReportSectionKind = "TIMELINE"
	ReportSectionUnknown  ReportSectionKind = "UNKNOWN"
	ReportSectionCoverage ReportSectionKind = "COVERAGE"
)

func (kind ReportSectionKind) Validate() error {
	switch kind {
	case ReportSectionTimeline, ReportSectionUnknown, ReportSectionCoverage:
		return nil
	default:
		return fmt.Errorf("unknown report section kind %q", kind)
	}
}

type ReportSection struct {
	ID              ReportSectionID
	InvestigationID InvestigationID
	Kind            ReportSectionKind
	Ordinal         int
	Statement       string
	ObservedAt      *time.Time
	EvidenceIDs     []EvidenceID
}

// Validate refuses any section whose citation is absent from the ledger.
//
// A timeline entry must cite evidence: it asserts that something happened at an
// instant, and an uncited instant is invented. Unknown and coverage statements
// may cite nothing, because a truthful statement about absent data has no
// evidence to point at; requiring a citation there would suppress the honest
// answer and leave the report looking more complete than the run was.
func (section ReportSection) Validate(ledger EvidenceLedger, investigation Investigation) error {
	if !validInvestigationToken(string(section.ID)) || section.InvestigationID != investigation.request.ID || !validInvestigationText(section.Statement, 4096) || section.Ordinal < 0 {
		return fmt.Errorf("report section identity or content is invalid")
	}
	if err := section.Kind.Validate(); err != nil {
		return err
	}
	if section.Kind == ReportSectionTimeline {
		if section.ObservedAt == nil || section.ObservedAt.IsZero() {
			return fmt.Errorf("timeline section requires an observation time")
		}
	} else if section.ObservedAt != nil {
		return fmt.Errorf("only timeline sections carry an observation time")
	}
	if err := validateEvidenceCitations(ledger, section.EvidenceIDs, section.Kind == ReportSectionTimeline); err != nil {
		return fmt.Errorf("report section evidence: %w", err)
	}
	return nil
}

func cloneReportSection(section ReportSection) ReportSection {
	section.EvidenceIDs = slices.Clone(section.EvidenceIDs)
	if section.ObservedAt != nil {
		observed := section.ObservedAt.UTC()
		section.ObservedAt = &observed
	}
	return section
}

// CloneReportSections copies a section list across a trust boundary.
func CloneReportSections(sections []ReportSection) []ReportSection {
	result := make([]ReportSection, len(sections))
	for index := range sections {
		result[index] = cloneReportSection(sections[index])
	}
	return result
}

// ActionCard is the single primary operational handoff produced by an
// investigation. It is deliberately separate from a proposed tool action: a
// card tells a named owner what to do next even when the investigation could
// not safely execute another diagnostic itself.
type ActionCardID string

type ActionOwner string

const (
	ActionOwnerSherlock             ActionOwner = "SHERLOCK"
	ActionOwnerClusterOperations    ActionOwner = "CLUSTER_OPERATIONS"
	ActionOwnerDatacenterOperations ActionOwner = "DATACENTER_OPERATIONS"
	ActionOwnerWorkloadOwner        ActionOwner = "WORKLOAD_OWNER"
	ActionOwnerMonitoring           ActionOwner = "MONITORING"
)

func (owner ActionOwner) Validate() error {
	switch owner {
	case ActionOwnerSherlock, ActionOwnerClusterOperations, ActionOwnerDatacenterOperations, ActionOwnerWorkloadOwner, ActionOwnerMonitoring:
		return nil
	default:
		return fmt.Errorf("unknown action-card owner %q", owner)
	}
}

type ActionUrgency string

const (
	ActionUrgencyImmediate ActionUrgency = "IMMEDIATE"
	ActionUrgencyNextShift ActionUrgency = "NEXT_SHIFT"
	ActionUrgencyPlanned   ActionUrgency = "PLANNED"
	ActionUrgencyMonitor   ActionUrgency = "MONITOR"
)

func (urgency ActionUrgency) Validate() error {
	switch urgency {
	case ActionUrgencyImmediate, ActionUrgencyNextShift, ActionUrgencyPlanned, ActionUrgencyMonitor:
		return nil
	default:
		return fmt.Errorf("unknown action-card urgency %q", urgency)
	}
}

type ActionCard struct {
	ID                  ActionCardID
	InvestigationID     InvestigationID
	Owner               ActionOwner
	Action              string
	Urgency             ActionUrgency
	Targets             []string
	Rationale           string
	EvidenceIDs         []EvidenceID
	BlockingGaps        []string
	EscalationCondition string
}

type ActionCardInput struct {
	Owner               ActionOwner
	Action              string
	Urgency             ActionUrgency
	Targets             []string
	Rationale           string
	EvidenceIDs         []EvidenceID
	BlockingGaps        []string
	EscalationCondition string
}

// NewActionCard validates the complete card at its durable trust boundary.
// Evidence is optional for a deterministic failure card, but every supplied
// citation must exist in the investigation ledger.
func NewActionCard(id ActionCardID, investigation Investigation, ledger EvidenceLedger, input ActionCardInput) (ActionCard, error) {
	card := ActionCard{
		ID: id, InvestigationID: investigation.request.ID, Owner: input.Owner,
		Action: input.Action, Urgency: input.Urgency, Targets: slices.Clone(input.Targets),
		Rationale: input.Rationale, EvidenceIDs: slices.Clone(input.EvidenceIDs),
		BlockingGaps: slices.Clone(input.BlockingGaps), EscalationCondition: input.EscalationCondition,
	}
	if err := card.Validate(ledger, investigation); err != nil {
		return ActionCard{}, err
	}
	return card, nil
}

func (card ActionCard) Validate(ledger EvidenceLedger, investigation Investigation) error {
	if !validInvestigationToken(string(card.ID)) || card.InvestigationID != investigation.request.ID {
		return fmt.Errorf("action-card identity is invalid")
	}
	if err := card.Owner.Validate(); err != nil {
		return err
	}
	if err := card.Urgency.Validate(); err != nil {
		return err
	}
	if !validInvestigationText(card.Action, 4096) || !validInvestigationText(card.Rationale, 4096) || !validInvestigationText(card.EscalationCondition, 4096) {
		return fmt.Errorf("action-card content is invalid")
	}
	if len(card.Targets) == 0 {
		return fmt.Errorf("action card requires at least one target")
	}
	seenTargets := make(map[string]struct{}, len(card.Targets))
	for _, target := range card.Targets {
		if !validInvestigationText(target, 512) {
			return fmt.Errorf("action-card target is invalid")
		}
		if _, exists := seenTargets[target]; exists {
			return fmt.Errorf("action-card targets must be unique")
		}
		seenTargets[target] = struct{}{}
	}
	for _, gap := range card.BlockingGaps {
		if !validInvestigationText(gap, 4096) {
			return fmt.Errorf("action-card blocking gap is invalid")
		}
	}
	if err := validateEvidenceCitations(ledger, card.EvidenceIDs, false); err != nil {
		return fmt.Errorf("action-card evidence: %w", err)
	}
	return nil
}

func CloneActionCard(card *ActionCard) *ActionCard {
	if card == nil {
		return nil
	}
	copy := *card
	copy.Targets = slices.Clone(card.Targets)
	copy.EvidenceIDs = slices.Clone(card.EvidenceIDs)
	copy.BlockingGaps = slices.Clone(card.BlockingGaps)
	return &copy
}

// A report that quietly drops what it could not support is lossy in a way no
// reader can detect. Statements are refused for good reasons -- citations that
// cover no entity in the ledger, citations the ledger never held -- and
// refusing them is right; leaving no trace of the refusal is not, because the
// report then looks like the model's whole answer when it is a subset.
//
// Only the kind and the reason are recorded, never the refused text. The text
// is untrusted prose that failed validation, and persisting it would recreate
// the exact exposure the validation exists to prevent.
type ReportOmission struct {
	InvestigationID InvestigationID
	Kind            string
	Reason          string
	Count           int
}

const (
	// OmissionNoSupportedEntity marks a statement whose citations covered no
	// entity in the durable ledger, so it supported no claim about anything.
	OmissionNoSupportedEntity = "NO_SUPPORTED_ENTITY"
	// OmissionCitationNotInLedger marks a section citing evidence the ledger
	// never held.
	OmissionCitationNotInLedger = "CITATION_NOT_IN_LEDGER"
	// OmissionValidationRefused marks a finding the domain refused when it was
	// offered for durable record.
	OmissionValidationRefused = "VALIDATION_REFUSED"
	// The reasons above record what the model answered and the domain then
	// refused. The three below record what the model was never shown, because
	// the context builder dropped it before the call. That loss is the more
	// consequential of the two -- a refused statement at least had its evidence
	// considered -- and it used to leave no trace at all, so a report thinned by
	// a full context read as a complete answer over a thin cluster.
	//
	// OmissionContextItemLimit marks evidence or a hypothesis dropped because the
	// context already held as many items as the reviewed limits allow.
	OmissionContextItemLimit = "CONTEXT_ITEM_LIMIT"
	// OmissionContextSizeLimit marks evidence or a hypothesis dropped because the
	// encoded context reached its byte ceiling.
	OmissionContextSizeLimit = "CONTEXT_SIZE_LIMIT"
	// OmissionProviderInputAllowance marks evidence dropped because the assembled
	// context exceeded what the provider accepts as input.
	OmissionProviderInputAllowance = "PROVIDER_INPUT_ALLOWANCE"
)

func (omission ReportOmission) Validate(investigation Investigation) error {
	if omission.InvestigationID != investigation.request.ID || omission.Count < 1 {
		return fmt.Errorf("report omission identity or count is invalid")
	}
	if !validInvestigationToken(omission.Kind) {
		return fmt.Errorf("report omission kind is invalid")
	}
	switch omission.Reason {
	case OmissionNoSupportedEntity, OmissionCitationNotInLedger, OmissionValidationRefused,
		OmissionContextItemLimit, OmissionContextSizeLimit, OmissionProviderInputAllowance:
		return nil
	default:
		return fmt.Errorf("unknown report omission reason %q", omission.Reason)
	}
}

// MergeReportOmissions accumulates counts by kind and reason. Drops happen in
// more than one place -- the mapper refuses unsupported statements, the
// controller refuses what the domain will not accept -- and the report should
// state one total per cause, not one row per site.
func MergeReportOmissions(into []ReportOmission, add ...ReportOmission) []ReportOmission {
	for _, omission := range add {
		if omission.Count < 1 {
			continue
		}
		index := slices.IndexFunc(into, func(current ReportOmission) bool {
			return current.Kind == omission.Kind && current.Reason == omission.Reason && current.InvestigationID == omission.InvestigationID
		})
		if index < 0 {
			into = append(into, omission)
			continue
		}
		into[index].Count += omission.Count
	}
	return into
}

type TransitionConflictError struct {
	Operation string
	From      string
}

func (conflict TransitionConflictError) Error() string {
	return fmt.Sprintf("cannot %s from %s", conflict.Operation, conflict.From)
}

func transitionConflict(operation, from string) error {
	return TransitionConflictError{Operation: operation, From: from}
}

func validInvestigationToken(value string) bool {
	return validDiagnosticToken(value)
}

func validInvestigationText(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum && strings.IndexByte(value, 0) < 0
}

func cloneInvestigationRequest(request InvestigationRequest) InvestigationRequest {
	request.Scope.EntityIDs = slices.Clone(request.Scope.EntityIDs)
	request.SuccessCriteria = slices.Clone(request.SuccessCriteria)
	request.RequestedAt = request.RequestedAt.UTC()
	request.Deadline = request.Deadline.UTC()
	request.Scope.Start = request.Scope.Start.UTC()
	request.Scope.End = request.Scope.End.UTC()
	return request
}

func cloneInvestigationAction(action *InvestigationAction) *InvestigationAction {
	if action == nil {
		return nil
	}
	copy := *action
	copy.Targets = slices.Clone(action.Targets)
	copy.Arguments = slices.Clone(action.Arguments)
	for index := range copy.Arguments {
		copy.Arguments[index].StringList = slices.Clone(copy.Arguments[index].StringList)
	}
	return &copy
}

// actionBudgetUsage charges one action to the dimension that matches what it
// actually does. A diagnostic is remote execution and spends the diagnostic
// grant; an evidence lookup spends the tool-call grant. A privileged action
// additionally spends privilege, so a privileged diagnostic needs both grants
// and cannot be paid for out of either one alone.
func actionBudgetUsage(action InvestigationAction) InvestigationBudgetUsage {
	usage := InvestigationBudgetUsage{FanOut: action.FanOut}
	if action.Diagnostic {
		usage.DiagnosticCalls = 1
	} else {
		usage.ToolCalls = 1
	}
	if action.Privileged {
		usage.PrivilegedCalls = 1
	}
	return usage
}

func addBudgetUsage(left, right InvestigationBudgetUsage) InvestigationBudgetUsage {
	return InvestigationBudgetUsage{Decisions: left.Decisions + right.Decisions, ToolCalls: left.ToolCalls + right.ToolCalls,
		DiagnosticCalls: left.DiagnosticCalls + right.DiagnosticCalls,
		PrivilegedCalls: left.PrivilegedCalls + right.PrivilegedCalls, FanOut: max(left.FanOut, right.FanOut),
		ModelTokens: left.ModelTokens + right.ModelTokens, CostMicros: left.CostMicros + right.CostMicros}
}

func validateEvidenceCitations(ledger EvidenceLedger, citations []EvidenceID, required bool) error {
	if required && len(citations) == 0 {
		return fmt.Errorf("at least one evidence citation is required")
	}
	seen := make(map[EvidenceID]struct{}, len(citations))
	for _, id := range citations {
		if id == "" || !ledger.Contains(id) {
			return fmt.Errorf("citation %q does not exist in the investigation ledger", id)
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("evidence citations must be unique")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func overlapsEvidence(left, right []EvidenceID) bool {
	values := make(map[EvidenceID]struct{}, len(left))
	for _, id := range left {
		values[id] = struct{}{}
	}
	for _, id := range right {
		if _, exists := values[id]; exists {
			return true
		}
	}
	return false
}

func cloneHypothesis(hypothesis Hypothesis) Hypothesis {
	hypothesis.SupportingEvidence = slices.Clone(hypothesis.SupportingEvidence)
	hypothesis.ContradictingEvidence = slices.Clone(hypothesis.ContradictingEvidence)
	hypothesis.UnresolvedTests = slices.Clone(hypothesis.UnresolvedTests)
	return hypothesis
}

func cloneHypotheses(values []Hypothesis) []Hypothesis {
	result := make([]Hypothesis, len(values))
	for index := range values {
		result[index] = cloneHypothesis(values[index])
	}
	return result
}

func cloneFinding(finding Finding) Finding {
	finding.EntityIDs = slices.Clone(finding.EntityIDs)
	finding.EvidenceIDs = slices.Clone(finding.EvidenceIDs)
	finding.CounterEvidenceIDs = slices.Clone(finding.CounterEvidenceIDs)
	if finding.Confidence != nil {
		confidence := *finding.Confidence
		finding.Confidence = &confidence
	}
	return finding
}
