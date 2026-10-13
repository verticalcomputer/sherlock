package application

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

var (
	ErrInvestigationNotFound = errors.New("investigation not found")
	ErrInvestigationConflict = errors.New("investigation state conflict")
)

// Fixed failure codes passed by the supervisor after it classifies dependency
// sentinels that application cannot import without creating a package cycle.
// They are not provider text and are safe inputs to deterministic terminal
// recovery. Unknown strings are intentionally discarded.
const (
	FailureRequiredContext         = "REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE"
	FailureRequiredEvidenceContext = "REQUIRED_EVIDENCE_EXCEEDS_ALLOWANCE"
	FailureEncodedContext          = "CONTEXT_EXCEEDS_ENCODED_LIMIT"
	FailureProviderInputContext    = "PROVIDER_INPUT_EXCEEDS_ALLOWANCE"
	FailureEvidenceContextUnusable = "EVIDENCE_CONTEXT_UNUSABLE"
	FailureCheckpointMismatch      = "CONTEXT_CHECKPOINT_MISMATCH"
	FailureEstimatorUnderrun       = "TOKEN_ESTIMATOR_UNDERRUN"
	FailureBudgetExceeded          = "BUDGET_EXCEEDED"
	FailureRepairSnapshot          = "REPAIR_WARNING_SNAPSHOT_INVALID"
)

type classifiedInvestigationFailure struct {
	cause error
	code  string
}

func (failure *classifiedInvestigationFailure) Error() string          { return failure.cause.Error() }
func (failure *classifiedInvestigationFailure) Unwrap() error          { return failure.cause }
func (failure *classifiedInvestigationFailure) SafeReasonCode() string { return failure.code }

// ClassifyInvestigationFailure attaches a reviewed fixed reason to a failure
// while retaining its sentinel chain. It is used at the supervisor boundary;
// arbitrary strings never become durable report content.
func ClassifyInvestigationFailure(cause error, code string) error {
	if cause == nil || !terminalFailureCode(code) {
		return cause
	}
	return &classifiedInvestigationFailure{cause: cause, code: code}
}

func terminalFailureCode(code string) bool {
	switch code {
	case FailureRequiredContext, FailureRequiredEvidenceContext, FailureEncodedContext,
		FailureProviderInputContext, FailureEvidenceContextUnusable, FailureCheckpointMismatch,
		FailureEstimatorUnderrun, FailureBudgetExceeded, FailureRepairSnapshot:
		return true
	default:
		return false
	}
}

type InvestigationAdvanceStage string

const (
	InvestigationAdvanceLoad        InvestigationAdvanceStage = "LOAD"
	InvestigationAdvancePlanning    InvestigationAdvanceStage = "PLANNING"
	InvestigationAdvancePolicy      InvestigationAdvanceStage = "POLICY_CHECK"
	InvestigationAdvanceExecution   InvestigationAdvanceStage = "EXECUTION"
	InvestigationAdvanceEvidence    InvestigationAdvanceStage = "EVIDENCE_RECORDING"
	InvestigationAdvanceLedger      InvestigationAdvanceStage = "LEDGER_UPDATE"
	InvestigationAdvanceSynthesis   InvestigationAdvanceStage = "SYNTHESIS"
	InvestigationAdvancePersistence InvestigationAdvanceStage = "TRANSITION_PERSISTENCE"
)

// InvestigationAdvanceError identifies the safe workflow stage and durable
// state of a failed transition while retaining the original error for local
// classification. Callers must not expose Error() directly through the API.
type InvestigationAdvanceError struct {
	Stage InvestigationAdvanceStage
	State domain.InvestigationStatus
	Err   error
}

func (failure *InvestigationAdvanceError) Error() string {
	return fmt.Sprintf("investigation advance failed at %s from %s: %v", failure.Stage, failure.State, failure.Err)
}

func (failure *InvestigationAdvanceError) Unwrap() error { return failure.Err }

func advanceFailure(stage InvestigationAdvanceStage, state domain.InvestigationStatus, err error) error {
	if err == nil {
		return nil
	}
	return &InvestigationAdvanceError{Stage: stage, State: state, Err: err}
}

func advanceStage(state domain.InvestigationStatus) InvestigationAdvanceStage {
	switch state {
	case domain.InvestigationInitializing, domain.InvestigationPlanning:
		return InvestigationAdvancePlanning
	case domain.InvestigationPolicyCheck, domain.InvestigationAwaitingApproval:
		return InvestigationAdvancePolicy
	case domain.InvestigationExecuting, domain.InvestigationAwaitingEvidence:
		return InvestigationAdvanceExecution
	case domain.InvestigationRecordingEvidence:
		return InvestigationAdvanceEvidence
	case domain.InvestigationUpdatingLedger:
		return InvestigationAdvanceLedger
	case domain.InvestigationSynthesizing:
		return InvestigationAdvanceSynthesis
	default:
		return InvestigationAdvanceLoad
	}
}

// InvestigationSnapshot is the complete durable controller state. A store
// commits it together with the transition event using optimistic versioning.
// Proposed actions and pending evidence are persisted so a process restart
// never depends on an in-memory planner result or execution response.
type InvestigationSnapshot struct {
	Investigation      domain.Investigation
	ProposedAction     *domain.InvestigationAction
	PriorActions       []InvestigationActionHistory
	PendingEvidence    []domain.InvestigationEvidence
	Evidence           domain.EvidenceLedger
	Hypotheses         domain.HypothesisLedger
	Findings           []domain.Finding
	ReportSections     []domain.ReportSection
	ReportOmissions    []domain.ReportOmission
	PrimaryActionCard  *domain.ActionCard
	ProposedHypotheses []domain.Hypothesis
	ProposedFindings   []domain.Finding
	RequestedOutcome   domain.InvestigationStatus
	RequestedStop      domain.InvestigationStopReason
	ExecutionReceipt   string
	DiagnosticRunID    domain.DiagnosticRunID
}

// InvestigationActionHistory is the durable, credential-free result of an
// action already attempted by this investigation. It gives the planner enough
// information to avoid paying for an exact repeat and to distinguish a useful
// action from one that added no evidence.
type InvestigationActionHistory struct {
	Digest      domain.SHA256
	ToolID      string
	Outcome     string
	Targets     []string
	Start       time.Time
	End         time.Time
	EvidenceIDs []domain.EvidenceID
}

type InvestigationStore interface {
	CreateInvestigation(context.Context, InvestigationSnapshot, domain.InvestigationEvent) (bool, error)
	LoadInvestigation(context.Context, domain.InvestigationID) (InvestigationSnapshot, bool, error)
	SaveInvestigation(context.Context, int, InvestigationSnapshot, domain.InvestigationEvent) error
	RecordInvestigationApproval(context.Context, domain.InvestigationApproval, int, InvestigationSnapshot, domain.InvestigationEvent) error
}

type InvestigationDecision struct {
	Action      *domain.InvestigationAction
	Stop        bool
	Outcome     domain.InvestigationStatus
	Reason      domain.InvestigationStopReason
	ModelTokens int64
	CostMicros  int64
	Hypotheses  []domain.Hypothesis
	Findings    []domain.Finding
}

type InvestigationPlanner interface {
	Decide(context.Context, InvestigationSnapshot) (InvestigationDecision, error)
}

// InvestigationSynthesizer is an optional M7 role implemented by AI-backed
// planners. The M6 scripted planner intentionally does not implement it, so
// deterministic workflow tests keep their original behavior.
type InvestigationSynthesizer interface {
	Synthesize(context.Context, InvestigationSnapshot) (InvestigationSynthesis, error)
}

type InvestigationSynthesis struct {
	Findings    []domain.Finding
	Sections    []domain.ReportSection
	Omissions   []domain.ReportOmission
	ActionCard  *domain.ActionCard
	ModelTokens int64
	CostMicros  int64
	Disposition InvestigationSynthesisDisposition
}

// InvestigationSynthesisDisposition distinguishes a complete validated report
// from a useful but incomplete report and from a deterministic safe fallback.
// The controller uses this reviewed classification, not the planner's requested
// terminal status, to decide whether COMPLETED is permitted.
type InvestigationSynthesisDisposition string

const (
	SynthesisValidatedComplete InvestigationSynthesisDisposition = "VALIDATED_COMPLETE"
	SynthesisValidatedPartial  InvestigationSynthesisDisposition = "VALIDATED_PARTIAL"
	SynthesisSafeFallback      InvestigationSynthesisDisposition = "SAFE_FALLBACK"
)

func (disposition InvestigationSynthesisDisposition) Validate() error {
	switch disposition {
	case SynthesisValidatedComplete, SynthesisValidatedPartial, SynthesisSafeFallback:
		return nil
	default:
		return fmt.Errorf("unknown synthesis disposition %q", disposition)
	}
}

type InvestigationExecutionResult struct {
	Receipt         string
	Evidence        []domain.InvestigationEvidence
	DiagnosticRunID domain.DiagnosticRunID
}

// ErrInvestigationExecutionPending means execution has been dispatched and has
// not completed. It is a sentinel, matched by value and never by message text,
// because an unclassified error here costs a debugging cycle and because a
// pending execution is not a failure: no transition is performed, the lease is
// released, and the next claim retries the dispatch.
//
// It is safe to retry precisely because the executor applies the action's
// idempotency key at the external boundary, so a re-dispatch returns the
// in-flight run rather than starting a second remote execution.
var ErrInvestigationExecutionPending = errors.New("investigation execution is still outstanding")

// InvestigationExecutor must apply idempotencyKey at the external boundary.
// M5 diagnostic execution satisfies this by returning the prior run for an
// exact replay. This closes the crash-after-dispatch window.
//
// An executor whose work has not finished returns ErrInvestigationExecutionPending.
type InvestigationExecutor interface {
	ExecuteInvestigationAction(context.Context, string, domain.InvestigationAction) (InvestigationExecutionResult, error)
}

type InvestigationController struct {
	store    InvestigationStore
	planner  InvestigationPlanner
	executor InvestigationExecutor
	clock    Clock
	ids      IDGenerator
}

func NewInvestigationController(store InvestigationStore, planner InvestigationPlanner, executor InvestigationExecutor, clock Clock, ids IDGenerator) (*InvestigationController, error) {
	if store == nil || planner == nil || executor == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("investigation controller dependencies are required")
	}
	return &InvestigationController{store: store, planner: planner, executor: executor, clock: clock, ids: ids}, nil
}

type StartInvestigationInput struct {
	Request domain.InvestigationRequest
}

func (controller *InvestigationController) Start(ctx context.Context, input StartInvestigationInput) (InvestigationSnapshot, bool, error) {
	investigation, err := domain.NewInvestigation(input.Request)
	if err != nil {
		return InvestigationSnapshot{}, false, err
	}
	event, err := controller.event(investigation, domain.InvestigationEventCreated, "", "")
	if err != nil {
		return InvestigationSnapshot{}, false, err
	}
	snapshot := InvestigationSnapshot{Investigation: investigation}
	created, err := controller.store.CreateInvestigation(ctx, snapshot, event)
	if err != nil {
		return InvestigationSnapshot{}, false, fmt.Errorf("create investigation %s: %w", input.Request.ID, err)
	}
	if !created || input.Request.Purpose == domain.InvestigationPurposeRepairPlan {
		prior, found, loadErr := controller.store.LoadInvestigation(ctx, input.Request.ID)
		if loadErr != nil || !found {
			return InvestigationSnapshot{}, false, fmt.Errorf("load idempotent investigation %s: %w", input.Request.ID, loadErr)
		}
		return prior, created, nil
	}
	return snapshot, true, nil
}

// Advance performs at most one durable state transition. Callers may stop and
// construct a new controller after every successful call without losing work.
func (controller *InvestigationController) Advance(ctx context.Context, id domain.InvestigationID) (InvestigationSnapshot, error) {
	snapshot, found, err := controller.store.LoadInvestigation(ctx, id)
	if err != nil {
		return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceLoad, "", fmt.Errorf("load investigation %s: %w", id, err))
	}
	if !found {
		return InvestigationSnapshot{}, ErrInvestigationNotFound
	}
	current := snapshot.Investigation
	if current.Status().Terminal() || current.Status() == domain.InvestigationAwaitingApproval {
		return snapshot, nil
	}
	now := controller.clock.Now()
	if current.DeadlineExceeded(now) {
		next, stopErr := current.Stop(domain.InvestigationPartial, domain.StopBudgetExceeded, now)
		if stopErr != nil {
			return InvestigationSnapshot{}, advanceFailure(advanceStage(current.Status()), current.Status(), stopErr)
		}
		result, persistErr := controller.persist(ctx, snapshot, next, domain.InvestigationEventStateChanged)
		if persistErr != nil {
			return InvestigationSnapshot{}, advanceFailure(InvestigationAdvancePersistence, current.Status(), persistErr)
		}
		return result, nil
	}

	var next domain.Investigation
	var kind = domain.InvestigationEventStateChanged
	switch current.Status() {
	case domain.InvestigationInitializing:
		next, err = current.BeginPlanning(now)
	case domain.InvestigationPlanning:
		next, err = controller.advancePlanning(ctx, &snapshot, now)
		if next.Status() == domain.InvestigationPlanning {
			kind = domain.InvestigationEventBudgetConsumed
		}
	case domain.InvestigationPolicyCheck:
		if snapshot.ProposedAction == nil {
			return InvestigationSnapshot{}, advanceFailure(InvestigationAdvancePolicy, current.Status(), fmt.Errorf("policy check has no durable proposed action"))
		}
		if !investigationActionWithinBudget(current, *snapshot.ProposedAction) {
			next, err = current.Stop(domain.InvestigationPartial, domain.StopBudgetExceeded, now)
			snapshot.ProposedAction = nil
		} else if snapshot.ProposedAction.Privileged {
			next, err = current.AwaitApproval(*snapshot.ProposedAction, now)
		} else {
			next, err = current.Execute(*snapshot.ProposedAction, now)
		}
	case domain.InvestigationExecuting, domain.InvestigationAwaitingEvidence:
		if snapshot.ProposedAction == nil {
			return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceExecution, current.Status(), fmt.Errorf("execution has no durable proposed action"))
		}
		key := "investigation/" + string(current.Request().ID) + "/action/" + string(snapshot.ProposedAction.ID)
		result, executeErr := controller.executor.ExecuteInvestigationAction(ctx, key, *snapshot.ProposedAction)
		if errors.Is(executeErr, ErrInvestigationExecutionPending) {
			// Perform no transition on the work itself. Parking is idempotent, so
			// repeated claims while a remote execution runs neither advance the
			// investigation nor dispatch it twice.
			if current.Status() == domain.InvestigationAwaitingEvidence {
				return snapshot, nil
			}
			parked, parkErr := current.AwaitEvidence(now)
			if parkErr != nil {
				return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceExecution, current.Status(), parkErr)
			}
			result, persistErr := controller.persist(ctx, snapshot, parked, domain.InvestigationEventStateChanged)
			if persistErr != nil {
				return InvestigationSnapshot{}, advanceFailure(InvestigationAdvancePersistence, current.Status(), persistErr)
			}
			return result, nil
		}
		if executeErr != nil {
			return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceExecution, current.Status(), fmt.Errorf("execute investigation action %s: %w", snapshot.ProposedAction.ID, executeErr))
		}
		if result.Receipt == "" {
			return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceExecution, current.Status(), fmt.Errorf("investigation execution receipt is required"))
		}
		if snapshot.ProposedAction.Diagnostic != (result.DiagnosticRunID != "") {
			return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceExecution, current.Status(), fmt.Errorf("investigation diagnostic run attribution is invalid"))
		}
		snapshot.ExecutionReceipt = result.Receipt
		snapshot.DiagnosticRunID = result.DiagnosticRunID
		snapshot.PendingEvidence = cloneInvestigationEvidence(result.Evidence)
		next, err = current.BeginEvidenceRecording(now)
	case domain.InvestigationRecordingEvidence:
		ledger := snapshot.Evidence
		for _, evidence := range snapshot.PendingEvidence {
			ledger, err = ledger.Append(evidence, current)
			if err != nil {
				return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceEvidence, current.Status(), err)
			}
		}
		snapshot.Evidence = ledger
		if snapshot.ProposedAction != nil {
			outcome := investigationActionEvidenceOutcome(snapshot.PendingEvidence)
			history := InvestigationActionHistory{
				Digest:  snapshot.ProposedAction.Digest,
				ToolID:  snapshot.ProposedAction.ToolID,
				Outcome: outcome,
				Targets: slices.Clone(snapshot.ProposedAction.Targets),
				Start:   snapshot.ProposedAction.Start,
				End:     snapshot.ProposedAction.End,
			}
			for _, evidence := range snapshot.PendingEvidence {
				history.EvidenceIDs = append(history.EvidenceIDs, evidence.EvidenceID)
			}
			snapshot.PriorActions = upsertActionHistory(snapshot.PriorActions, history)
		}
		snapshot.PendingEvidence = nil
		next, err = current.BeginLedgerUpdate(now)
	case domain.InvestigationUpdatingLedger:
		for _, hypothesis := range snapshot.ProposedHypotheses {
			ledger, upsertErr := snapshot.Hypotheses.Upsert(hypothesis, snapshot.Evidence, current)
			if upsertErr != nil {
				return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceLedger, current.Status(), upsertErr)
			}
			snapshot.Hypotheses = ledger
		}
		for _, finding := range snapshot.ProposedFindings {
			if validateErr := finding.Validate(snapshot.Evidence, current); validateErr != nil {
				return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceLedger, current.Status(), validateErr)
			}
			snapshot.Findings = append(snapshot.Findings, finding)
		}
		snapshot.ProposedHypotheses = nil
		snapshot.ProposedFindings = nil
		snapshot.ProposedAction = nil
		snapshot.ExecutionReceipt = ""
		snapshot.DiagnosticRunID = ""
		next, err = current.BeginPlanning(now)
	case domain.InvestigationSynthesizing:
		// Absence of a synthesizer is a safe fallback, never implicit evidence
		// that the planner's requested success criteria were met.
		disposition, rejectedFindings := SynthesisSafeFallback, 0
		if synthesizer, ok := controller.planner.(InvestigationSynthesizer); ok {
			result, synthesisErr := synthesizer.Synthesize(ctx, snapshot)
			if synthesisErr != nil {
				return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), fmt.Errorf("synthesize investigation: %w", synthesisErr))
			}
			current, err = current.RecordModelUsage(domain.InvestigationBudgetUsage{ModelTokens: result.ModelTokens, CostMicros: result.CostMicros}, now)
			if err != nil {
				return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), err)
			}
			// Validation keeps unsupported claims out of the durable record; it is
			// not a reason to destroy the record. A run that spent its whole budget
			// gathering evidence used to end as a system failure with no findings
			// at all because one statement among several cited evidence that did
			// not cover an entity it named. Reject that finding and keep the rest.
			snapshot.ReportOmissions = domain.MergeReportOmissions(snapshot.ReportOmissions, result.Omissions...)
			for _, finding := range result.Findings {
				if validateErr := finding.Validate(snapshot.Evidence, current); validateErr != nil {
					rejectedFindings++
					// A refused finding is not a defect to hide. Counting it by kind
					// and reason is what lets the report say it is a subset of the
					// model's answer rather than pass itself off as the whole of it.
					snapshot.ReportOmissions = domain.MergeReportOmissions(snapshot.ReportOmissions, domain.ReportOmission{InvestigationID: current.Request().ID, Kind: string(finding.Kind), Reason: domain.OmissionValidationRefused, Count: 1})
					continue
				}
				snapshot.Findings = append(snapshot.Findings, finding)
			}
			// Sections are held to the same rule as findings: an entry citing
			// evidence the ledger does not hold is refused on its own, and the
			// rest of the report survives. Unlike a rejected finding this does
			// not by itself demote a complete report, because a section carries
			// narrative rather than a claim the success criteria rest on.
			for _, section := range result.Sections {
				if validateErr := section.Validate(snapshot.Evidence, current); validateErr != nil {
					snapshot.ReportOmissions = domain.MergeReportOmissions(snapshot.ReportOmissions, domain.ReportOmission{InvestigationID: current.Request().ID, Kind: string(section.Kind), Reason: domain.OmissionCitationNotInLedger, Count: 1})
					continue
				}
				snapshot.ReportSections = append(snapshot.ReportSections, section)
			}
			if result.ActionCard != nil {
				if validateErr := result.ActionCard.Validate(snapshot.Evidence, current); validateErr != nil {
					return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), validateErr)
				}
				snapshot.PrimaryActionCard = domain.CloneActionCard(result.ActionCard)
			}
			if err := result.Disposition.Validate(); err != nil {
				return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), err)
			}
			disposition = result.Disposition
			// A report that lost findings to validation is not a complete one, so
			// it must not be promoted to COMPLETED on the strength of what the
			// provider claimed.
			if rejectedFindings > 0 && disposition == SynthesisValidatedComplete {
				disposition = SynthesisValidatedPartial
			}
		}
		snapshot.RequestedOutcome, snapshot.RequestedStop, err = resolveSynthesisTerminal(snapshot.RequestedOutcome, snapshot.RequestedStop, disposition)
		if err != nil {
			return InvestigationSnapshot{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), err)
		}
		if snapshot.RequestedOutcome == domain.InvestigationCompleted {
			next, err = current.Complete(now)
		} else {
			next, err = current.Stop(snapshot.RequestedOutcome, snapshot.RequestedStop, now)
		}
	default:
		return InvestigationSnapshot{}, advanceFailure(advanceStage(current.Status()), current.Status(), fmt.Errorf("unsupported investigation state %s", current.Status()))
	}
	if err != nil {
		return InvestigationSnapshot{}, advanceFailure(advanceStage(current.Status()), current.Status(), err)
	}
	result, err := controller.persist(ctx, snapshot, next, kind)
	if err != nil {
		return InvestigationSnapshot{}, advanceFailure(InvestigationAdvancePersistence, current.Status(), err)
	}
	return result, nil
}

func investigationActionEvidenceOutcome(evidence []domain.InvestigationEvidence) string {
	if len(evidence) == 0 {
		return "NO_EVIDENCE"
	}
	allNoData, allUnavailable := true, true
	for _, entry := range evidence {
		allNoData = allNoData && entry.Status == domain.EvidenceNoData
		allUnavailable = allUnavailable && entry.Status == domain.EvidenceUnavailable
	}
	if allNoData {
		return "NO_EVIDENCE"
	}
	if allUnavailable {
		return "UNAVAILABLE"
	}
	return "SUCCEEDED"
}

func investigationActionWithinBudget(current domain.Investigation, action domain.InvestigationAction) bool {
	usage := current.Usage()
	usage.ToolCalls++
	usage.FanOut = max(usage.FanOut, action.FanOut)
	if action.Privileged {
		usage.PrivilegedCalls++
	}
	return current.Request().Budget.Allows(usage)
}

// synthesisAffordable reports whether the remaining model token and cost
// allowance can still support one synthesis call. It mirrors the planner's own
// reserve so the two agree on what "affordable" means. Exhausted tool calls or
// decisions say nothing about whether a report can be produced.
func synthesisAffordable(current domain.Investigation) bool {
	budget, usage := current.Request().Budget, current.Usage()
	reserve := min(max(budget.MaxModelTokens/8, 128), 8192)
	return budget.MaxModelTokens-usage.ModelTokens >= reserve && budget.MaxCostMicros-usage.CostMicros > 0
}

func (controller *InvestigationController) advancePlanning(ctx context.Context, snapshot *InvestigationSnapshot, now time.Time) (domain.Investigation, error) {
	current := snapshot.Investigation
	if snapshot.RequestedOutcome != "" {
		return current.BeginSynthesis(now)
	}
	if snapshot.ProposedAction != nil {
		return current.BeginPolicyCheck(now)
	}
	decision, err := controller.planner.Decide(ctx, *snapshot)
	if err != nil {
		return domain.Investigation{}, fmt.Errorf("plan investigation: %w", err)
	}
	usage := domain.InvestigationBudgetUsage{Decisions: 1, ModelTokens: decision.ModelTokens, CostMicros: decision.CostMicros}
	// A preflight budget stop performs no provider work and must not enter
	// synthesis when the remainder cannot pay for it. The planner reports a
	// single BUDGET_EXCEEDED for every exhausted dimension, so the remainder has
	// to be tested rather than assumed: an investigation that spends its tool
	// calls or decisions while holding most of its token allowance has gathered
	// evidence and can still afford the report it exists to produce. Discarding
	// that report was leaving fully worked investigations with no findings.
	if decision.Stop && decision.Reason == domain.StopBudgetExceeded && decision.ModelTokens == 0 && decision.CostMicros == 0 {
		if !synthesisAffordable(current) {
			return current.Stop(domain.InvestigationPartial, domain.StopBudgetExceeded, now)
		}
		// No provider call was made, so no decision is consumed either: charging
		// one here would exceed an already exhausted decision allowance and drop
		// straight back out to a terminal stop, which is how fully worked
		// investigations were ending with no report at all.
		snapshot.RequestedOutcome, snapshot.RequestedStop = decision.Outcome, decision.Reason
		snapshot.ProposedHypotheses, snapshot.ProposedFindings = nil, nil
		return current.BeginSynthesis(now)
	}
	next, err := current.RecordDecision(usage, now)
	if err != nil {
		// Provider usage is already durably audited. If actual usage crossed the
		// admitted ceiling, preserve the admitted ledger and terminate with the
		// correct cause instead of sending the error to the generic supervisor.
		if errors.Is(err, domain.ErrInvestigationBudgetExceeded) {
			return current.Stop(domain.InvestigationPartial, domain.StopBudgetExceeded, now)
		}
		return domain.Investigation{}, err
	}
	for _, hypothesis := range decision.Hypotheses {
		ledger, upsertErr := snapshot.Hypotheses.Upsert(hypothesis, snapshot.Evidence, next)
		if upsertErr != nil {
			return domain.Investigation{}, fmt.Errorf("persist planner hypothesis: %w", upsertErr)
		}
		snapshot.Hypotheses = ledger
	}
	if decision.Stop {
		if decision.Outcome != domain.InvestigationCompleted && decision.Outcome != domain.InvestigationPartial && decision.Outcome != domain.InvestigationBlocked {
			return domain.Investigation{}, fmt.Errorf("planner stop outcome must be COMPLETED, PARTIAL, or BLOCKED")
		}
		if err := validateRequestedTerminal(decision.Outcome, decision.Reason); err != nil {
			return domain.Investigation{}, err
		}
		snapshot.RequestedOutcome, snapshot.RequestedStop = decision.Outcome, decision.Reason
	} else if decision.Action == nil {
		return domain.Investigation{}, fmt.Errorf("planner decision requires an action or stop")
	} else {
		action := *decision.Action
		snapshot.ProposedAction = &action
	}
	// Planner hypotheses are committed with the planning decision itself. They
	// must not live only in ProposedHypotheses because each supervisor scan
	// reloads the snapshot from PostgreSQL before the later ledger transition.
	snapshot.ProposedHypotheses = nil
	snapshot.ProposedFindings = slices.Clone(decision.Findings)
	return next, nil
}

func validateRequestedTerminal(outcome domain.InvestigationStatus, reason domain.InvestigationStopReason) error {
	if err := reason.Validate(); err != nil {
		return err
	}
	if outcome == domain.InvestigationCompleted {
		if reason != domain.StopSuccessCriteriaMet {
			return fmt.Errorf("completed investigation request requires success criteria")
		}
		return nil
	}
	if outcome != domain.InvestigationPartial && outcome != domain.InvestigationBlocked {
		return fmt.Errorf("terminal investigation request is invalid")
	}
	if reason == domain.StopSuccessCriteriaMet || reason == domain.StopOperatorCancelled {
		return fmt.Errorf("limited investigation request requires a limiting reason")
	}
	return nil
}

func resolveSynthesisTerminal(outcome domain.InvestigationStatus, reason domain.InvestigationStopReason, disposition InvestigationSynthesisDisposition) (domain.InvestigationStatus, domain.InvestigationStopReason, error) {
	if err := validateRequestedTerminal(outcome, reason); err != nil {
		return "", "", err
	}
	if err := disposition.Validate(); err != nil {
		return "", "", err
	}
	if disposition == SynthesisValidatedComplete && ((outcome == domain.InvestigationCompleted && reason == domain.StopSuccessCriteriaMet) || (outcome == domain.InvestigationPartial && reason == domain.StopNoUsefulAction)) {
		return domain.InvestigationCompleted, domain.StopSuccessCriteriaMet, nil
	}
	if outcome == domain.InvestigationCompleted {
		return domain.InvestigationPartial, domain.StopNoUsefulAction, nil
	}
	return outcome, reason, nil
}

func upsertActionHistory(values []InvestigationActionHistory, value InvestigationActionHistory) []InvestigationActionHistory {
	result := slices.Clone(values)
	for index := range result {
		if result[index].Digest == value.Digest {
			result[index] = value
			return result
		}
	}
	return append(result, value)
}

func (controller *InvestigationController) Approve(ctx context.Context, id domain.InvestigationID, approval domain.InvestigationApproval) (InvestigationSnapshot, error) {
	snapshot, found, err := controller.store.LoadInvestigation(ctx, id)
	if err != nil || !found {
		if err == nil {
			err = ErrInvestigationNotFound
		}
		return InvestigationSnapshot{}, err
	}
	before := snapshot.Investigation
	next, err := before.Approve(approval, controller.clock.Now())
	if err != nil {
		return InvestigationSnapshot{}, err
	}
	snapshot.Investigation = next
	event, err := controller.event(next, domain.InvestigationEventApprovalGranted, before.Status(), next.Status())
	if err != nil {
		return InvestigationSnapshot{}, err
	}
	if err := controller.store.RecordInvestigationApproval(ctx, approval, before.Version(), snapshot, event); err != nil {
		return InvestigationSnapshot{}, fmt.Errorf("record investigation approval: %w", err)
	}
	return snapshot, nil
}

func (controller *InvestigationController) Cancel(ctx context.Context, id domain.InvestigationID) (InvestigationSnapshot, error) {
	return controller.CancelExpected(ctx, id, 0)
}

// StopAfterFailure durably contains an unexpected planner or executor failure
// to one investigation. Typed budget failures retain BUDGET_EXCEEDED and typed
// context-pipeline failures retain CONTEXT_EXHAUSTED; neither is mislabeled as
// cluster access loss. A bounded, model-free report preserves what was learned
// and gives the operator a next action even when no further model call fits.
// Failure text is intentionally not persisted because it is not evidence.
func (controller *InvestigationController) StopAfterFailure(ctx context.Context, id domain.InvestigationID, cause error) (InvestigationSnapshot, error) {
	snapshot, found, err := controller.store.LoadInvestigation(ctx, id)
	if err != nil {
		return InvestigationSnapshot{}, fmt.Errorf("load unavailable investigation %s: %w", id, err)
	}
	if !found {
		return InvestigationSnapshot{}, ErrInvestigationNotFound
	}
	current := snapshot.Investigation
	if current.Status().Terminal() || current.Status() == domain.InvestigationAwaitingApproval {
		return snapshot, nil
	}
	outcome := domain.InvestigationBlocked
	if len(snapshot.Evidence.Entries()) > 0 {
		outcome = domain.InvestigationPartial
	}
	reason := domain.StopAccessUnavailable
	if errors.Is(cause, domain.ErrInvestigationBudgetExceeded) {
		reason = domain.StopBudgetExceeded
		outcome = domain.InvestigationPartial
	} else if isContextPipelineFailure(cause) {
		reason = domain.StopContextExhausted
		if len(snapshot.Evidence.Entries()) > 0 {
			outcome = domain.InvestigationPartial
		}
	}
	addTerminalFailureReport(&snapshot, reason)
	next, err := current.Stop(outcome, reason, controller.clock.Now())
	if err != nil {
		return InvestigationSnapshot{}, err
	}
	snapshot.ProposedAction = nil
	snapshot.PendingEvidence = nil
	snapshot.ProposedHypotheses = nil
	snapshot.ProposedFindings = nil
	snapshot.RequestedOutcome = ""
	snapshot.RequestedStop = ""
	snapshot.ExecutionReceipt = ""
	return controller.persistWithFailure(ctx, snapshot, next, domain.InvestigationEventStateChanged, cause)
}

func isContextPipelineFailure(cause error) bool {
	type safeReason interface{ SafeReasonCode() string }
	var classified safeReason
	if !errors.As(cause, &classified) {
		return false
	}
	switch classified.SafeReasonCode() {
	case FailureRequiredContext, FailureRequiredEvidenceContext, FailureEncodedContext,
		FailureProviderInputContext, FailureEvidenceContextUnusable, FailureCheckpointMismatch,
		FailureEstimatorUnderrun:
		return true
	default:
		return false
	}
}

const terminalReportCitationLimit = 8

// addTerminalFailureReport never invokes a provider. It records only counts
// derived from the durable snapshot, a bounded sample of already-admitted
// evidence IDs, and a reviewed recommendation. It therefore remains available
// for the exact condition where a normal synthesis request cannot be encoded.
func addTerminalFailureReport(snapshot *InvestigationSnapshot, reason domain.InvestigationStopReason) {
	current := snapshot.Investigation
	evidence := snapshot.Evidence.Entries()
	counts := map[domain.EvidenceStatus]int{}
	for _, entry := range evidence {
		counts[entry.Status]++
	}
	hypotheses := snapshot.Hypotheses.Entries()
	resolvedHypotheses := 0
	for _, hypothesis := range hypotheses {
		if hypothesis.Status != domain.HypothesisProposed && hypothesis.Status != domain.HypothesisUnresolved {
			resolvedHypotheses++
		}
	}
	citations := make([]domain.EvidenceID, 0, min(len(evidence), terminalReportCitationLimit))
	for _, entry := range evidence[:min(len(evidence), terminalReportCitationLimit)] {
		citations = append(citations, entry.EvidenceID)
	}
	section := domain.ReportSection{
		ID:              domain.ReportSectionID("report-terminal-recovery-" + string(current.Request().ID)),
		InvestigationID: current.Request().ID,
		Kind:            domain.ReportSectionCoverage,
		Ordinal:         len(snapshot.ReportSections),
		Statement: fmt.Sprintf(
			"Terminal fallback retained %d evidence records (complete=%d, partial=%d, no_data=%d, unavailable=%d) and %d hypotheses (%d resolved). Citations are a bounded sample of at most %d retained evidence IDs.",
			len(evidence), counts[domain.EvidenceComplete], counts[domain.EvidencePartial], counts[domain.EvidenceNoData], counts[domain.EvidenceUnavailable], len(hypotheses), resolvedHypotheses, terminalReportCitationLimit,
		),
		EvidenceIDs: citations,
	}
	if section.Validate(snapshot.Evidence, current) == nil {
		snapshot.ReportSections = append(snapshot.ReportSections, section)
	}

	statement := "Sherlock operations: restore the failed investigation dependency and rerun. Escalate to data-center operations only after collected evidence identifies a node or GPU action."
	switch reason {
	case domain.StopContextExhausted:
		statement = "Sherlock engineering: compact the retained evidence and planning context, then rerun this investigation. Escalate to data-center operations only if the rerun confirms a node or GPU fault."
	case domain.StopBudgetExceeded:
		statement = "Sherlock operations: review the retained evidence and rerun with an explicitly approved budget or a narrower scope. Escalate to data-center operations only if the evidence confirms a node or GPU fault."
	}
	recommendation := domain.Finding{
		ID:              domain.FindingID("finding-terminal-recovery-" + string(current.Request().ID)),
		InvestigationID: current.Request().ID,
		Kind:            domain.FindingRecommendation,
		Statement:       statement,
		EntityIDs:       slices.Clone(current.Request().Scope.EntityIDs),
		Severity:        string(domain.HealthSeverityInfo),
		Status:          domain.FindingCurrent,
	}
	if recommendation.Validate(snapshot.Evidence, current) == nil {
		snapshot.Findings = append(snapshot.Findings, recommendation)
	}

	gap := "The investigation dependency failed before a validated synthesis completed."
	if reason == domain.StopContextExhausted {
		gap = "The bounded planning or synthesis context could not admit the retained evidence."
	} else if reason == domain.StopBudgetExceeded {
		gap = "The approved investigation budget was exhausted before a validated synthesis completed."
	}
	card, err := domain.NewActionCard(domain.ActionCardID("action-card-"+string(current.Request().ID)), current, snapshot.Evidence, domain.ActionCardInput{
		Owner:               domain.ActionOwnerSherlock,
		Action:              statement,
		Urgency:             domain.ActionUrgencyNextShift,
		Targets:             slices.Clone(current.Request().Scope.EntityIDs),
		Rationale:           fmt.Sprintf("The terminal fallback retained %d evidence records and %d hypotheses; a data-center fault is not yet established.", len(evidence), len(hypotheses)),
		EvidenceIDs:         citations,
		BlockingGaps:        []string{gap},
		EscalationCondition: "Escalate to data-center operations only when retained or newly collected evidence identifies a concrete node or GPU fault and the required physical action.",
	})
	if err == nil {
		snapshot.PrimaryActionCard = &card
	}
}

// CancelExpected applies optimistic concurrency when expectedVersion is
// positive. A zero value retains the internal, unconditional cancellation API.
func (controller *InvestigationController) CancelExpected(ctx context.Context, id domain.InvestigationID, expectedVersion int) (InvestigationSnapshot, error) {
	snapshot, found, err := controller.store.LoadInvestigation(ctx, id)
	if err != nil || !found {
		if err == nil {
			err = ErrInvestigationNotFound
		}
		return InvestigationSnapshot{}, err
	}
	if expectedVersion > 0 && snapshot.Investigation.Version() != expectedVersion {
		return InvestigationSnapshot{}, ErrInvestigationConflict
	}
	next, err := snapshot.Investigation.Cancel(controller.clock.Now())
	if err != nil {
		return InvestigationSnapshot{}, err
	}
	return controller.persist(ctx, snapshot, next, domain.InvestigationEventStateChanged)
}

func (controller *InvestigationController) persist(ctx context.Context, snapshot InvestigationSnapshot, next domain.Investigation, kind domain.InvestigationEventKind) (InvestigationSnapshot, error) {
	return controller.persistWithFailure(ctx, snapshot, next, kind, nil)
}

func (controller *InvestigationController) persistWithFailure(ctx context.Context, snapshot InvestigationSnapshot, next domain.Investigation, kind domain.InvestigationEventKind, cause error) (InvestigationSnapshot, error) {
	before := snapshot.Investigation
	snapshot.Investigation = next
	if err := ensureTerminalActionCard(&snapshot); err != nil {
		return InvestigationSnapshot{}, fmt.Errorf("ensure terminal investigation action card: %w", err)
	}
	event, err := controller.event(next, kind, before.Status(), next.Status())
	if err != nil {
		return InvestigationSnapshot{}, err
	}
	if cause != nil {
		event.Details.FailureStage = string(advanceStage(before.Status()))
		event.Details.FailureCode = "UNCLASSIFIED"
		if errors.Is(cause, domain.ErrInvestigationBudgetExceeded) {
			event.Details.FailureCode = FailureBudgetExceeded
		}
		var classified interface{ SafeReasonCode() string }
		if errors.As(cause, &classified) && terminalFailureCode(classified.SafeReasonCode()) {
			event.Details.FailureCode = classified.SafeReasonCode()
		}
		var advanceErr *InvestigationAdvanceError
		if errors.As(cause, &advanceErr) {
			candidate := event.Details
			candidate.FailureStage = string(advanceErr.Stage)
			if candidate.Validate() == nil {
				event.Details = candidate
			}
		}
		if err := event.Validate(); err != nil {
			return InvestigationSnapshot{}, err
		}
	}
	if err := controller.store.SaveInvestigation(ctx, before.Version(), snapshot, event); err != nil {
		return InvestigationSnapshot{}, fmt.Errorf("persist investigation transition: %w", err)
	}
	return snapshot, nil
}

// ensureTerminalActionCard makes the operational handoff invariant independent
// of how an investigation reached a terminal state. Normal synthesis and the
// model-free failure path provide richer cards; this deterministic fallback
// covers cancellation, deadline, preflight-budget, and empty-synthesis paths.
func ensureTerminalActionCard(snapshot *InvestigationSnapshot) error {
	if !snapshot.Investigation.Status().Terminal() || snapshot.PrimaryActionCard != nil {
		return nil
	}
	current := snapshot.Investigation
	evidence := snapshot.Evidence.Entries()
	citations := make([]domain.EvidenceID, 0, min(len(evidence), terminalReportCitationLimit))
	for _, entry := range evidence[:min(len(evidence), terminalReportCitationLimit)] {
		citations = append(citations, entry.EvidenceID)
	}

	action := "Sherlock operations: review the retained investigation report and assign the next safe diagnostic or operational step."
	gap := "The terminal investigation did not produce a primary synthesized recommendation."
	urgency := domain.ActionUrgencyNextShift
	if current.Status() == domain.InvestigationCancelled {
		action = "Sherlock operations: confirm that no further investigation is required; otherwise reopen the investigation with a current scope."
		gap = "The investigation was cancelled before a primary recommendation was produced."
		urgency = domain.ActionUrgencyMonitor
	}
	card, err := domain.NewActionCard(domain.ActionCardID("action-card-"+string(current.Request().ID)), current, snapshot.Evidence, domain.ActionCardInput{
		Owner:               domain.ActionOwnerSherlock,
		Action:              action,
		Urgency:             urgency,
		Targets:             slices.Clone(current.Request().Scope.EntityIDs),
		Rationale:           fmt.Sprintf("The investigation ended %s with reason %s after retaining %d evidence records.", current.Status(), current.StopReason(), len(evidence)),
		EvidenceIDs:         citations,
		BlockingGaps:        []string{gap},
		EscalationCondition: "Escalate to the named infrastructure owner only when retained or newly collected evidence identifies a concrete fault and required action.",
	})
	if err != nil {
		return err
	}
	snapshot.PrimaryActionCard = &card
	return nil
}

func (controller *InvestigationController) event(investigation domain.Investigation, kind domain.InvestigationEventKind, from, to domain.InvestigationStatus) (domain.InvestigationEvent, error) {
	id, err := controller.ids.NewID()
	if err != nil {
		return domain.InvestigationEvent{}, err
	}
	event := domain.InvestigationEvent{ID: domain.InvestigationEventID(id), InvestigationID: investigation.Request().ID, Sequence: int64(investigation.Version()), Kind: kind, From: from, To: to, OccurredAt: controller.clock.Now()}
	if kind == domain.InvestigationEventStateChanged && to.Terminal() {
		event.Details.StopReason = investigation.StopReason()
	}
	if kind != domain.InvestigationEventStateChanged {
		event.From, event.To = "", ""
	}
	if err := event.Validate(); err != nil {
		return domain.InvestigationEvent{}, err
	}
	return event, nil
}

// ScriptedInvestigationPlanner is the M6 deterministic planner stub. It has no
// model dependency and selects solely by persisted decision count.
type ScriptedInvestigationPlanner struct{ Decisions []InvestigationDecision }

func (planner ScriptedInvestigationPlanner) Decide(_ context.Context, snapshot InvestigationSnapshot) (InvestigationDecision, error) {
	index := snapshot.Investigation.Usage().Decisions
	if index < 0 || index >= len(planner.Decisions) {
		return InvestigationDecision{}, fmt.Errorf("deterministic investigation script exhausted at decision %d", index)
	}
	decision := planner.Decisions[index]
	if decision.Action != nil {
		action := *decision.Action
		decision.Action = &action
	}
	decision.Hypotheses = slices.Clone(decision.Hypotheses)
	decision.Findings = slices.Clone(decision.Findings)
	return decision, nil
}

func cloneInvestigationEvidence(values []domain.InvestigationEvidence) []domain.InvestigationEvidence {
	result := slices.Clone(values)
	for index := range result {
		result[index].EntityIDs = slices.Clone(result[index].EntityIDs)
	}
	return result
}
