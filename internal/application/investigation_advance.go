package application

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

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
	var next domain.Investigation
	kind := domain.InvestigationEventStateChanged
	if current.DeadlineExceeded(now) {
		next, err = current.Stop(domain.InvestigationPartial, domain.StopBudgetExceeded, now)
	} else {
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
			next, err = controller.advanceExecution(ctx, &snapshot, now)
			if err == ErrInvestigationExecutionPending {
				return snapshot, nil
			}
		case domain.InvestigationRecordingEvidence:
			next, err = recordPendingInvestigationEvidence(&snapshot, now)
		case domain.InvestigationUpdatingLedger:
			next, err = updateInvestigationLedger(&snapshot, now)
		case domain.InvestigationSynthesizing:
			next, err = controller.advanceSynthesis(ctx, &snapshot, now)
			if err != nil {
				return InvestigationSnapshot{}, err
			}
		default:
			return InvestigationSnapshot{}, advanceFailure(advanceStage(current.Status()), current.Status(), fmt.Errorf("unsupported investigation state %s", current.Status()))
		}
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

func (controller *InvestigationController) advanceExecution(ctx context.Context, snapshot *InvestigationSnapshot, now time.Time) (domain.Investigation, error) {
	current := snapshot.Investigation
	if snapshot.ProposedAction == nil {
		return domain.Investigation{}, fmt.Errorf("execution has no durable proposed action")
	}
	key := "investigation/" + string(current.Request().ID) + "/action/" + string(snapshot.ProposedAction.ID)
	result, executeErr := controller.executor.ExecuteInvestigationAction(ctx, key, *snapshot.ProposedAction)
	if errors.Is(executeErr, ErrInvestigationExecutionPending) {
		if current.Status() == domain.InvestigationAwaitingEvidence {
			return domain.Investigation{}, ErrInvestigationExecutionPending
		}
		return current.AwaitEvidence(now)
	}
	if executeErr != nil {
		return domain.Investigation{}, fmt.Errorf("execute investigation action %s: %w", snapshot.ProposedAction.ID, executeErr)
	}
	if result.Receipt == "" {
		return domain.Investigation{}, fmt.Errorf("investigation execution receipt is required")
	}
	if snapshot.ProposedAction.Diagnostic != (result.DiagnosticRunID != "") {
		return domain.Investigation{}, fmt.Errorf("investigation diagnostic run attribution is invalid")
	}
	snapshot.ExecutionReceipt = result.Receipt
	snapshot.DiagnosticRunID = result.DiagnosticRunID
	snapshot.PendingEvidence = cloneInvestigationEvidence(result.Evidence)
	return current.BeginEvidenceRecording(now)
}

func recordPendingInvestigationEvidence(snapshot *InvestigationSnapshot, now time.Time) (domain.Investigation, error) {
	current := snapshot.Investigation
	ledger := snapshot.Evidence
	var err error
	for _, evidence := range snapshot.PendingEvidence {
		ledger, err = ledger.Append(evidence, current)
		if err != nil {
			return domain.Investigation{}, err
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
	return current.BeginLedgerUpdate(now)
}

func updateInvestigationLedger(snapshot *InvestigationSnapshot, now time.Time) (domain.Investigation, error) {
	current := snapshot.Investigation
	for _, hypothesis := range snapshot.ProposedHypotheses {
		ledger, upsertErr := snapshot.Hypotheses.Upsert(hypothesis, snapshot.Evidence, current)
		if upsertErr != nil {
			return domain.Investigation{}, upsertErr
		}
		snapshot.Hypotheses = ledger
	}
	for _, finding := range snapshot.ProposedFindings {
		if validateErr := finding.Validate(snapshot.Evidence, current); validateErr != nil {
			return domain.Investigation{}, validateErr
		}
		snapshot.Findings = append(snapshot.Findings, finding)
	}
	snapshot.ProposedHypotheses = nil
	snapshot.ProposedFindings = nil
	snapshot.ProposedAction = nil
	snapshot.ExecutionReceipt = ""
	snapshot.DiagnosticRunID = ""
	return current.BeginPlanning(now)
}

func (controller *InvestigationController) advanceSynthesis(ctx context.Context, snapshot *InvestigationSnapshot, now time.Time) (domain.Investigation, error) {
	current := snapshot.Investigation
	var err error
	var next domain.Investigation
	// Absence of a synthesizer is a safe fallback, never implicit evidence
	// that the planner's requested success criteria were met.
	disposition, rejectedFindings := SynthesisSafeFallback, 0
	if synthesizer, ok := controller.planner.(InvestigationSynthesizer); ok {
		result, synthesisErr := synthesizer.Synthesize(ctx, *snapshot)
		if synthesisErr != nil {
			return domain.Investigation{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), fmt.Errorf("synthesize investigation: %w", synthesisErr))
		}
		current, err = current.RecordModelUsage(domain.InvestigationBudgetUsage{ModelTokens: result.ModelTokens, CostMicros: result.CostMicros}, now)
		if err != nil {
			return domain.Investigation{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), err)
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
				return domain.Investigation{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), validateErr)
			}
			snapshot.PrimaryActionCard = domain.CloneActionCard(result.ActionCard)
		}
		if err := result.Disposition.Validate(); err != nil {
			return domain.Investigation{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), err)
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
		return domain.Investigation{}, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), err)
	}
	if snapshot.RequestedOutcome == domain.InvestigationCompleted {
		next, err = current.Complete(now)
	} else {
		next, err = current.Stop(snapshot.RequestedOutcome, snapshot.RequestedStop, now)
	}
	return next, advanceFailure(InvestigationAdvanceSynthesis, current.Status(), err)
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
