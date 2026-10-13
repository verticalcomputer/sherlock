// Package investigation joins the untrusted model boundary to the durable M6
// controller through the reviewed, read-only tool catalog.
package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/clustermemory"
	"github.com/verticalcomputer/sherlock/internal/contextbudget"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

type AuthorityResolver interface {
	ResolveInvestigationAuthority(context.Context, application.InvestigationSnapshot) (investigationtools.Filter, error)
}

type DuplicateCallStore interface {
	HasInvestigationActionDigest(context.Context, domain.InvestigationID, domain.SHA256) (bool, error)
}

type ClusterDuplicateCallStore interface {
	HasClusterInvestigationActionDigest(context.Context, domain.ClusterID, domain.SHA256) (bool, error)
}

// DiagnosticFreshnessStore reports, for each requested target, when a
// successful execution of one diagnostic definition last observed it. A target
// with no entry has no current result.
//
// Novelty for a diagnostic is a recency question rather than an identity one.
// A diagnostic reads live state, so the same call twice can legitimately
// return different answers: a counter increments, a new XID appears, remap
// state changes after a workload drains. The digest still closes the
// crash-after-dispatch window; it no longer decides whether the work is novel.
type DiagnosticFreshnessStore interface {
	LatestInvestigationDiagnostics(context.Context, domain.InvestigationID, string, []string, time.Time) (map[string]time.Time, error)
}

type ClusterDiagnosticFreshnessStore interface {
	LatestClusterDiagnostics(context.Context, domain.ClusterID, string, []string, time.Time) (map[string]time.Time, error)
}

type ContextSource interface {
	InvestigationContext(context.Context, application.InvestigationSnapshot) (investigationcontext.Input, error)
}

type Config struct {
	Provider                string
	Model                   string
	ModelConfigVersion      string
	PlanningPrompt          string
	SynthesisPrompt         string
	ToolSchemaVersion       string
	ModelCallReservationTTL time.Duration
}

type Orchestrator struct {
	provider      modelprovider.Provider
	catalog       *investigationtools.Catalog
	authority     AuthorityResolver
	duplicates    DuplicateCallStore
	contexts      ContextSource
	builder       *investigationcontext.Builder
	audits        application.ModelCallAuditSink
	reservations  application.ModelCallReservationStore
	payloads      application.ModelPayloadEvidenceSink
	clock         application.Clock
	ids           application.IDGenerator
	config        Config
	memory        clustermemory.Reader
	memoryMode    clustermemory.Mode
	budgets       *contextbudget.Manager
	contextEngine *investigationcontext.Engine
}

func NewOrchestrator(provider modelprovider.Provider, catalog *investigationtools.Catalog, authority AuthorityResolver, duplicates DuplicateCallStore, contexts ContextSource, builder *investigationcontext.Builder, audits application.ModelCallAuditSink, clock application.Clock, ids application.IDGenerator, config Config, payloads ...application.ModelPayloadEvidenceSink) (*Orchestrator, error) {
	reservations, reservationOK := audits.(application.ModelCallReservationStore)
	if provider == nil || catalog == nil || authority == nil || duplicates == nil || contexts == nil || builder == nil || audits == nil || !reservationOK || clock == nil || ids == nil {
		return nil, fmt.Errorf("AI investigation dependencies are required")
	}
	testAudit := application.ModelCallAudit{CallID: "validate", CallKey: "validate", InvestigationID: "validate", ClusterID: "validate", Kind: application.ModelCallPlanning, Provider: config.Provider, Model: config.Model, ModelConfigVersion: config.ModelConfigVersion, PromptSchemaVersion: config.PlanningPrompt, ToolSchemaVersion: config.ToolSchemaVersion, Outcome: application.ModelCallSucceeded, OccurredAt: time.Unix(1, 0)}
	if err := testAudit.Validate(); err != nil || config.SynthesisPrompt == "" || config.ModelCallReservationTTL <= 0 {
		return nil, fmt.Errorf("AI investigation configuration is invalid")
	}
	var payloadSink application.ModelPayloadEvidenceSink
	if len(payloads) > 0 {
		payloadSink = payloads[0]
	}
	return &Orchestrator{provider: provider, catalog: catalog, authority: authority, duplicates: duplicates, contexts: contexts, builder: builder, audits: audits, reservations: reservations, payloads: payloadSink, clock: clock, ids: ids, config: config}, nil
}

func (orchestrator *Orchestrator) ConfigureMemory(reader clustermemory.Reader, mode clustermemory.Mode) error {
	if orchestrator == nil || reader == nil || mode.Validate() != nil || mode == clustermemory.ModeDisabled {
		return fmt.Errorf("cluster memory runtime configuration is invalid")
	}
	orchestrator.memory, orchestrator.memoryMode = reader, mode
	return nil
}

func (orchestrator *Orchestrator) ConfigureContextBudget(manager *contextbudget.Manager) error {
	if orchestrator == nil || manager == nil {
		return fmt.Errorf("context budget manager is required")
	}
	orchestrator.budgets = manager
	return nil
}

func (orchestrator *Orchestrator) ConfigureContextEngine(engine *investigationcontext.Engine) error {
	if orchestrator == nil || engine == nil {
		return fmt.Errorf("context engine is required")
	}
	orchestrator.contextEngine = engine
	return nil
}

// planRejection reports that one planning turn proposed work the controller
// refused to execute. An empty guidance means the turn was not rejected.
type planRejection struct {
	guidance string
	reason   domain.InvestigationStopReason
}

type modelPayloadReferences struct {
	input  domain.EvidenceID
	output domain.EvidenceID
}

const (
	absoluteMinimumPlanningTokenReserve int64 = 128
	maximumMinimumPlanningTokenReserve  int64 = 8_192
	// One replan is enough to recover a model that forgot a prior action or a
	// per-tool bound without letting a stuck planner burn the token budget on
	// repeated proposals.
	maximumRejectedPlanReplans = 1
)

func (orchestrator *Orchestrator) Decide(ctx context.Context, snapshot application.InvestigationSnapshot) (application.InvestigationDecision, error) {
	if snapshot.Investigation.Request().Purpose == domain.InvestigationPurposeRepairPlan {
		return orchestrator.decideRepairProposal(ctx, snapshot)
	}
	budget, usage := snapshot.Investigation.Request().Budget, snapshot.Investigation.Usage()
	minimumTokenReserve := min(max(budget.MaxModelTokens/8, absoluteMinimumPlanningTokenReserve), maximumMinimumPlanningTokenReserve)
	if budget.MaxDecisions-usage.Decisions < 1 {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopBudgetExceeded}, nil
	}
	// The reviewed XID playbook needs authority and catalog bounds, but no model
	// context or model budget. Resolve it before loading or encoding retained
	// evidence so context growth cannot prevent the deterministic diagnostic pass.
	if strings.Contains(strings.ToLower(snapshot.Investigation.Request().Question), "xid") {
		filter, err := orchestrator.resolveAuthorityFilter(ctx, snapshot)
		if err != nil {
			return application.InvestigationDecision{}, err
		}
		if decision, handled, planErr := orchestrator.deterministicXIDPlan(ctx, snapshot, filter); planErr != nil {
			return application.InvestigationDecision{}, planErr
		} else if handled {
			return decision, nil
		}
	}
	// Either grant can carry the next turn, so exhausting one is not the end of
	// the run: a run out of evidence lookups may still hold execution authority,
	// and the reverse. Stopping requires both to be empty.
	actionAuthority := budget.MaxToolCalls - usage.ToolCalls + budget.MaxDiagnosticCalls - usage.DiagnosticCalls
	if actionAuthority < 1 || budget.MaxModelTokens-usage.ModelTokens < minimumTokenReserve || budget.MaxCostMicros-usage.CostMicros <= 0 {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopBudgetExceeded}, nil
	}
	filter, modelContext, tools, err := orchestrator.inputs(ctx, snapshot)
	if err != nil {
		return application.InvestigationDecision{}, err
	}
	// A duplicate or out-of-policy proposal is a recoverable planning mistake,
	// not a terminal state: durable evidence already answers the first, and the
	// second only means the planner could not see a per-tool bound. Replan a
	// bounded number of times with the rejection stated explicitly, and only stop
	// when the model still cannot find an admissible novel observation or the
	// planning budget for a further call is gone. Spend stays attributed.
	baseCallKey := fmt.Sprintf("investigation/%s/planning/%d", snapshot.Investigation.Request().ID, snapshot.Investigation.Version())
	var spentTokens, spentCost int64
	guidance := ""
	for attempt := 0; ; attempt++ {
		callKey := baseCallKey
		if attempt > 0 {
			callKey = fmt.Sprintf("%s/replan/%d", baseCallKey, attempt)
		}
		decision, rejection, err := orchestrator.planAttempt(ctx, snapshot, filter, modelContext, tools, callKey, guidance)
		if err != nil {
			return application.InvestigationDecision{}, err
		}
		decision.ModelTokens += spentTokens
		decision.CostMicros += spentCost
		if rejection.guidance == "" {
			return decision, nil
		}
		// The attempt just made is the best available predictor of what another
		// one costs, and on real investigations a planning call runs tens of
		// thousands of tokens against a reserve of a few thousand. Requiring only
		// the abstract reserve would authorize a replan the run cannot pay for.
		attemptTokens := decision.ModelTokens - spentTokens
		attemptCost := decision.CostMicros - spentCost
		spentTokens, spentCost = decision.ModelTokens, decision.CostMicros
		requiredTokens := max(minimumTokenReserve, attemptTokens)
		if attempt >= maximumRejectedPlanReplans || budget.MaxModelTokens-usage.ModelTokens-spentTokens < requiredTokens || budget.MaxCostMicros-usage.CostMicros-spentCost <= attemptCost {
			decision.Action = nil
			// The reason distinguishes a planner with nothing new to observe from
			// one that kept proposing work the reviewed policy refuses, which is an
			// operator-visible catalog or scope problem rather than a quiet stop.
			decision.Stop, decision.Outcome, decision.Reason = true, domain.InvestigationPartial, rejection.reason
			return decision, nil
		}
		guidance = rejection.guidance
	}
}

// deterministicXIDPlan keeps the reviewed XID playbook out of the model's
// discretion. An automatic XID investigation performs one bounded pass over
// the three signed GPU diagnostics and kernel correlation before synthesis;
// it never burns planning calls on successively sliced views of the same
// sticky Prometheus gauge.
func (orchestrator *Orchestrator) deterministicXIDPlan(ctx context.Context, snapshot application.InvestigationSnapshot, filter investigationtools.Filter) (application.InvestigationDecision, bool, error) {
	request := snapshot.Investigation.Request()
	if !strings.Contains(strings.ToLower(request.Question), "xid") {
		return application.InvestigationDecision{}, false, nil
	}
	facts := investigationtools.XIDDecisionFacts{AttemptedTools: make(map[investigationtools.ToolID]string)}
	failures := make(map[investigationtools.ToolID]string)
	covered := make(map[investigationtools.ToolID]map[string]struct{})
	for _, toolID := range investigationtools.XIDRequiredEvidenceTools() {
		covered[toolID] = make(map[string]struct{})
	}
	for _, action := range snapshot.PriorActions {
		toolID := investigationtools.ToolID(action.ToolID)
		if _, required := covered[toolID]; !required {
			continue
		}
		if action.Outcome == "FAILED" || action.Outcome == "REJECTED" || action.Outcome == "OUTCOME_UNKNOWN" || action.Outcome == "UNAVAILABLE" {
			failures[toolID] = action.Outcome
		}
		for _, target := range action.Targets {
			covered[toolID][target] = struct{}{}
		}
	}
	for toolID, targets := range covered {
		allTargets := len(request.Scope.EntityIDs) > 0
		for _, target := range request.Scope.EntityIDs {
			if _, ok := targets[target]; !ok {
				allTargets = false
				break
			}
		}
		if allTargets {
			facts.AttemptedTools[toolID] = "SUCCEEDED"
			if failure := failures[toolID]; failure != "" {
				facts.AttemptedTools[toolID] = failure
			}
		}
	}
	policy := investigationtools.DecideXIDAction(facts)
	if policy.Disposition != investigationtools.XIDGatherEvidence {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopNoUsefulAction}, true, nil
	}
	bounds, available := orchestrator.catalog.ToolBounds(filter, policy.NextToolID)
	if !available {
		// The policy is real authority, not prompt advice. If its required tool is
		// unavailable, stop for the durable terminal/action-card path rather than
		// letting a model substitute repeated metric lookups.
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopPolicyExhausted}, true, nil
	}
	budget, usage := request.Budget, snapshot.Investigation.Usage()
	if (bounds.Diagnostic && usage.DiagnosticCalls >= budget.MaxDiagnosticCalls) || (!bounds.Diagnostic && usage.ToolCalls >= budget.MaxToolCalls) {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopBudgetExceeded}, true, nil
	}
	targetLimit := min(bounds.MaxTargets, budget.MaxFanOut)
	if targetLimit < 1 {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopBudgetExceeded}, true, nil
	}
	targets := make([]string, 0, len(request.Scope.EntityIDs))
	for _, target := range request.Scope.EntityIDs {
		if _, alreadyCovered := covered[policy.NextToolID][target]; !alreadyCovered {
			targets = append(targets, target)
		}
	}
	slices.Sort(targets)
	if len(targets) > targetLimit {
		targets = targets[:targetLimit]
	}
	end := request.Scope.End.UTC()
	start := request.Scope.Start.UTC()
	if end.Sub(start) > bounds.MaxWindow {
		start = end.Add(-bounds.MaxWindow)
	}
	call := investigationtools.Call{ToolID: policy.NextToolID, EntityKind: request.Scope.EntityKind, Targets: targets, Start: start, End: end}
	canonical, err := orchestrator.catalog.CanonicalCallKey(filter, call)
	if err != nil {
		return application.InvestigationDecision{}, true, fmt.Errorf("build deterministic XID action: %w", err)
	}
	id, err := orchestrator.ids.NewID()
	if err != nil {
		return application.InvestigationDecision{}, true, err
	}
	return application.InvestigationDecision{Action: &domain.InvestigationAction{
		ID: domain.InvestigationActionID(id), ToolID: string(policy.NextToolID),
		Digest: domain.ChecksumSHA256([]byte(canonical)), Diagnostic: bounds.Diagnostic,
		FanOut: len(targets), Targets: targets, Start: start, End: end,
	}}, true, nil
}

// planAttempt performs exactly one durable planning call. A non-empty rejection
// means the proposal was refused before execution and carries both the
// server-authored guidance a replan must receive and the terminal reason that
// applies if no attempt remains; the returned decision then holds only the
// spend of this attempt.
func (orchestrator *Orchestrator) planAttempt(ctx context.Context, snapshot application.InvestigationSnapshot, filter investigationtools.Filter, modelContext investigationcontext.Context, tools []modelprovider.AvailableTool, callKey string, guidance string) (application.InvestigationDecision, planRejection, error) {
	budget, usage := snapshot.Investigation.Request().Budget, snapshot.Investigation.Usage()
	request := planningRequest(snapshot, modelContext, tools, orchestrator.config)
	if guidance != "" {
		request.StateSummary = strings.TrimSpace(request.StateSummary + " " + guidance)
	}
	selection := contextbudget.Selection{FallbackState: "DISABLED", ShadowOnly: true}
	request, selection = orchestrator.retrieveMemory(ctx, snapshot, request, selection)
	var contextManifest contextbudget.Manifest
	if orchestrator.budgets != nil {
		var err error
		request, contextManifest, err = orchestrator.budgets.PreparePlanning(ctx, snapshot, callKey, request, selection)
		if err != nil {
			return application.InvestigationDecision{}, planRejection{}, err
		}
	}
	if err := orchestrator.reserveModelCall(ctx, snapshot, application.ModelCallPlanning, callKey); err != nil {
		return application.InvestigationDecision{}, planRejection{}, err
	}
	result, callErr := orchestrator.provider.Plan(ctx, request)
	if callErr != nil {
		if ctx.Err() != nil {
			// The provider may have received an interrupted request. Leave the
			// reservation open so expiry classifies it OUTCOME_UNKNOWN.
			return application.InvestigationDecision{}, planRejection{}, ctx.Err()
		}
		metadata, trace := modelFailureDetails(callErr)
		payloadReferences, recordErr := orchestrator.recordModelPayloads(ctx, snapshot, application.ModelCallPlanning, callKey, trace)
		if recordErr != nil {
			return application.InvestigationDecision{}, planRejection{}, recordErr
		}
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, metadata, application.ModelCallFailed, safeModelFailureReason(callErr), orchestrator.config.PlanningPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationDecision{}, planRejection{}, auditErr
		}
		return application.InvestigationDecision{}, planRejection{}, fmt.Errorf("model planning call failed: %w", callErr)
	}
	if orchestrator.budgets != nil && result.Metadata.InputTokens > 0 {
		if observeErr := orchestrator.budgets.Observe(ctx, contextManifest, result.Metadata.InputTokens); observeErr != nil && !errors.Is(observeErr, contextbudget.ErrEstimatorUnderrun) {
			return application.InvestigationDecision{}, planRejection{}, fmt.Errorf("record token calibration: %w", observeErr)
		}
	}
	payloadReferences, err := orchestrator.recordModelPayloads(ctx, snapshot, application.ModelCallPlanning, callKey, result.Trace)
	if err != nil {
		return application.InvestigationDecision{}, planRejection{}, err
	}
	if err := result.ValidateFor(request); err != nil {
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallRejected, "INVALID_MODEL_OUTPUT", orchestrator.config.PlanningPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationDecision{}, planRejection{}, auditErr
		}
		return application.InvestigationDecision{}, planRejection{}, fmt.Errorf("validate model planning result: %w", err)
	}
	if err := orchestrator.validateMetadata(result.Metadata); err != nil {
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallRejected, "UNEXPECTED_MODEL_CONFIGURATION", orchestrator.config.PlanningPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationDecision{}, planRejection{}, auditErr
		}
		return application.InvestigationDecision{}, planRejection{}, err
	}
	decision := application.InvestigationDecision{ModelTokens: result.Metadata.InputTokens + result.Metadata.OutputTokens, CostMicros: result.Metadata.CostMicros}
	if result.Metadata.Outcome == modelprovider.OutcomeRefused {
		if err := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallRejected, "MODEL_REFUSED", orchestrator.config.PlanningPrompt, payloadReferences); err != nil {
			return application.InvestigationDecision{}, planRejection{}, err
		}
		decision.Stop, decision.Outcome, decision.Reason = true, domain.InvestigationPartial, domain.StopNoUsefulAction
		return decision, planRejection{}, nil
	}
	decision.Hypotheses, err = orchestrator.mapHypotheses(result.Response.HypothesisUpdates, snapshot)
	if err != nil {
		return application.InvestigationDecision{}, planRejection{}, err
	}
	if result.Response.Stop {
		if err := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallSucceeded, "", orchestrator.config.PlanningPrompt, payloadReferences); err != nil {
			return application.InvestigationDecision{}, planRejection{}, err
		}
		decision.Stop = true
		decision.Outcome, decision.Reason = mapStop(*result.Response.StopReason)
		return decision, planRejection{}, nil
	}
	// Provider schemas allow an ordered plan, while the durable controller
	// intentionally executes one action per transition. Sequentialize a valid
	// plan by taking priority 1 only; later actions are speculative and must be
	// regenerated after the durable result changes evidence and coverage.
	action, ok := nextPlannedAction(result.Response.Actions)
	if !ok {
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallRejected, "ACTION_COUNT_INVALID", orchestrator.config.PlanningPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationDecision{}, planRejection{}, auditErr
		}
		return application.InvestigationDecision{}, planRejection{}, fmt.Errorf("continuing plan has no priority-one action")
	}
	calls, err := orchestrator.catalog.DecodeCallBatches(filter, investigationtools.ToolID(action.ToolID), action.Arguments, budget.MaxFanOut)
	if err != nil {
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallRejected, "TOOL_CALL_REJECTED", orchestrator.config.PlanningPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationDecision{}, planRejection{}, auditErr
		}
		// A proposal outside the reviewed tool policy never executes, but it is a
		// recoverable planning mistake: the planner sees the investigation scope,
		// not every per-tool bound. Report the enforced limits so the bounded
		// replan can correct the call instead of failing the whole transition.
		return decision, planRejection{guidance: orchestrator.policyReplanGuidance(filter, snapshot, action.ToolID), reason: domain.StopPolicyExhausted}, nil
	}
	// The operation class comes from the reviewed definition, never from the
	// model's proposal. It decides both which grant this action spends and how
	// its novelty is judged, so it is resolved before admission.
	bounds, available := orchestrator.catalog.ToolBounds(filter, investigationtools.ToolID(action.ToolID))
	if !available {
		return application.InvestigationDecision{}, planRejection{}, fmt.Errorf("admitted tool %q is no longer available to this investigation", action.ToolID)
	}
	call, digest, staleAt, ok, err := orchestrator.nextNovelBatch(ctx, snapshot.Investigation.Request().ID, snapshot.Investigation.Request().ClusterID, filter, bounds, calls)
	if err != nil {
		return application.InvestigationDecision{}, planRejection{}, err
	}
	if !ok {
		reasonCode, guidance := "DUPLICATE_TOOL_CALL", duplicateReplanGuidance(action.ToolID, calls)
		if bounds.Diagnostic {
			reasonCode, guidance = "DIAGNOSTIC_RESULT_STILL_CURRENT", freshDiagnosticReplanGuidance(action.ToolID, calls, staleAt)
		}
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallRejected, reasonCode, orchestrator.config.PlanningPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationDecision{}, planRejection{}, auditErr
		}
		// Neither refusal is terminal. A repeated read cannot add information, and
		// a still-current diagnostic would re-observe state that has not moved;
		// both are recoverable planning mistakes, so state the reason and replan
		// rather than ending a run that has already done real work.
		return decision, planRejection{guidance: guidance, reason: domain.StopNoUsefulAction}, nil
	}
	prospective := usage
	if bounds.Diagnostic {
		prospective.DiagnosticCalls++
	} else {
		prospective.ToolCalls++
	}
	prospective.FanOut = max(prospective.FanOut, len(call.Targets))
	if !budget.Allows(prospective) {
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallSucceeded, "", orchestrator.config.PlanningPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationDecision{}, planRejection{}, auditErr
		}
		decision.Stop = true
		decision.Outcome = domain.InvestigationPartial
		decision.Reason = domain.StopBudgetExceeded
		return decision, planRejection{}, nil
	}
	id, err := orchestrator.ids.NewID()
	if err != nil {
		return application.InvestigationDecision{}, planRejection{}, err
	}
	decision.Action = &domain.InvestigationAction{ID: domain.InvestigationActionID(id), ToolID: action.ToolID, Digest: digest, Diagnostic: bounds.Diagnostic, FanOut: len(call.Targets), Targets: slices.Clone(call.Targets), Start: call.Start, End: call.End, Arguments: domainArguments(call.Arguments)}
	if err := orchestrator.audit(ctx, snapshot, application.ModelCallPlanning, callKey, result.Metadata, application.ModelCallSucceeded, "", orchestrator.config.PlanningPrompt, payloadReferences); err != nil {
		return application.InvestigationDecision{}, planRejection{}, err
	}
	return decision, planRejection{}, nil
}

// policyReplanGuidance states the reviewed bounds the rejected tool enforces.
// It reports only server-owned policy: no model text and no argument value the
// model supplied crosses back into the next prompt.
// rejectedTargets names at most eight of the deterministically resolved
// targets a rejected proposal covered, so guidance stays bounded.
func rejectedTargets(calls []investigationtools.Call) []string {
	targets := make([]string, 0, 8)
	for _, call := range calls {
		for _, target := range call.Targets {
			if !slices.Contains(targets, target) {
				targets = append(targets, target)
			}
			if len(targets) >= 8 {
				return targets
			}
		}
	}
	return targets
}

// freshDiagnosticReplanGuidance states the server-owned recency policy the
// proposal ran into and the moment it lifts, so the planner can choose other
// work now instead of retrying a probe that would observe unchanged state. It
// echoes no model prose: only the catalog tool identifier, the targets the
// controller itself resolved, and a time the controller computed.
func freshDiagnosticReplanGuidance(toolID string, calls []investigationtools.Call, staleAt time.Time) string {
	scope := "the requested targets"
	if targets := rejectedTargets(calls); len(targets) > 0 {
		scope = strings.Join(targets, ", ")
	}
	when := "shortly"
	if !staleAt.IsZero() {
		when = "at " + staleAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("The previous proposal %s over %s was rejected without executing: every one of those targets already holds a current result from that diagnostic, so re-running it now would observe state that has not changed. Those results become stale %s. Until then, select a different diagnostic, a different target, or an evidence lookup that closes a stated coverage or hypothesis gap, or stop with explicit uncertainty.", toolID, scope, when)
}

func (orchestrator *Orchestrator) policyReplanGuidance(filter investigationtools.Filter, snapshot application.InvestigationSnapshot, toolID string) string {
	scope := snapshot.Investigation.Request().Scope
	bounds, available := orchestrator.catalog.ToolBounds(filter, investigationtools.ToolID(toolID))
	if !available {
		return fmt.Sprintf("The previous proposal %s is not an available tool for this investigation and was rejected without executing. Select a tool from the available list, or stop with explicit uncertainty.", toolID)
	}
	return fmt.Sprintf("The previous proposal %s violated the reviewed tool policy and was rejected without executing. %s accepts at most %d targets of kind %s, one call may span at most %s of time, and every target and the whole window must lie inside the investigation scope %s to %s. Propose a call inside those bounds, split a longer period into separate calls, select a different tool, or stop with explicit uncertainty.",
		toolID, toolID, bounds.MaxTargets, strings.Join(bounds.EntityKinds, ", "), bounds.MaxWindow.String(), scope.Start.UTC().Format(time.RFC3339), scope.End.UTC().Format(time.RFC3339))
}

// duplicateReplanGuidance names the rejected invocation in the server-authored
// state summary. It never echoes model prose, only the catalog tool identifier
// and the deterministic targets the controller itself resolved.
func duplicateReplanGuidance(toolID string, calls []investigationtools.Call) string {
	scope := "the requested targets"
	if targets := rejectedTargets(calls); len(targets) > 0 {
		scope = strings.Join(targets, ", ")
	}
	return fmt.Sprintf("The previous proposal %s over %s repeated an observation already committed to durable evidence and was rejected without executing. Do not propose it again. Either select a different tool, a different target, or a different time window that closes a stated coverage or hypothesis gap, or stop with explicit uncertainty.", toolID, scope)
}

// nextNovelBatch returns the first deterministically split batch that is worth
// executing, together with the digest that remains its execution idempotency
// key. When nothing is novel it also reports when the proposal becomes
// admissible again, which is meaningful only for a diagnostic.
func (orchestrator *Orchestrator) nextNovelBatch(ctx context.Context, investigationID domain.InvestigationID, clusterID domain.ClusterID, filter investigationtools.Filter, bounds investigationtools.Bounds, calls []investigationtools.Call) (investigationtools.Call, domain.SHA256, time.Time, bool, error) {
	var earliestStale time.Time
	for _, call := range calls {
		canonical, err := orchestrator.catalog.CanonicalCallKey(filter, call)
		if err != nil {
			return investigationtools.Call{}, domain.SHA256{}, time.Time{}, false, err
		}
		digest := domain.ChecksumSHA256([]byte(canonical))
		if bounds.Diagnostic {
			staleAt, current, err := orchestrator.diagnosticIsCurrent(ctx, investigationID, clusterID, call, bounds)
			if err != nil {
				return investigationtools.Call{}, domain.SHA256{}, time.Time{}, false, err
			}
			if current {
				if earliestStale.IsZero() || staleAt.Before(earliestStale) {
					earliestStale = staleAt
				}
				continue
			}
			return call, digest, time.Time{}, true, nil
		}
		seen, err := orchestrator.duplicates.HasInvestigationActionDigest(ctx, investigationID, digest)
		if err != nil {
			return investigationtools.Call{}, domain.SHA256{}, time.Time{}, false, fmt.Errorf("check duplicate model action: %w", err)
		}
		if seen {
			continue
		}
		if clusterStore, ok := orchestrator.duplicates.(ClusterDuplicateCallStore); ok {
			seen, err = clusterStore.HasClusterInvestigationActionDigest(ctx, clusterID, digest)
			if err != nil {
				return investigationtools.Call{}, domain.SHA256{}, time.Time{}, false, fmt.Errorf("check cluster duplicate model action: %w", err)
			}
			if seen {
				continue
			}
		}
		return call, digest, time.Time{}, true, nil
	}
	return investigationtools.Call{}, domain.SHA256{}, earliestStale, false, nil
}

// diagnosticIsCurrent reports whether every requested target already holds a
// successful result from this definition inside its declared interval, and if
// so, when the set stops being current.
//
// Targets are judged as a set. One target without a current result admits the
// whole batch: re-probing an already fresh neighbour is cheap, and splitting
// the set would carry two observation times for one logical observation.
//
// A store that cannot answer the recency question leaves every target stale
// and the action is admitted. The diagnostic grant is what bounds execution;
// this rule only suppresses work that would observe state which has not moved.
func (orchestrator *Orchestrator) diagnosticIsCurrent(ctx context.Context, investigationID domain.InvestigationID, clusterID domain.ClusterID, call investigationtools.Call, bounds investigationtools.Bounds) (time.Time, bool, error) {
	if bounds.MinimumReexecutionInterval <= 0 || len(call.Targets) == 0 {
		return time.Time{}, false, nil
	}
	notBefore := orchestrator.clock.Now().Add(-bounds.MinimumReexecutionInterval)
	observed := map[string]time.Time{}
	merge := func(values map[string]time.Time) {
		for target, at := range values {
			if existing, ok := observed[target]; !ok || at.After(existing) {
				observed[target] = at
			}
		}
	}
	if store, ok := orchestrator.duplicates.(DiagnosticFreshnessStore); ok {
		values, err := store.LatestInvestigationDiagnostics(ctx, investigationID, string(call.ToolID), call.Targets, notBefore)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("check diagnostic freshness: %w", err)
		}
		merge(values)
	}
	if store, ok := orchestrator.duplicates.(ClusterDiagnosticFreshnessStore); ok {
		values, err := store.LatestClusterDiagnostics(ctx, clusterID, string(call.ToolID), call.Targets, notBefore)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("check cluster diagnostic freshness: %w", err)
		}
		merge(values)
	}
	var oldest time.Time
	for _, target := range call.Targets {
		at, ok := observed[target]
		if !ok || !at.After(notBefore) {
			return time.Time{}, false, nil
		}
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	return oldest.Add(bounds.MinimumReexecutionInterval).UTC(), true, nil
}

func nextPlannedAction(actions []modelprovider.PlannedAction) (modelprovider.PlannedAction, bool) {
	for _, action := range actions {
		if action.Priority == 1 {
			return action, true
		}
	}
	return modelprovider.PlannedAction{}, false
}

func (orchestrator *Orchestrator) Synthesize(ctx context.Context, snapshot application.InvestigationSnapshot) (application.InvestigationSynthesis, error) {
	_, modelContext, _, err := orchestrator.inputs(ctx, snapshot)
	if err != nil {
		return application.InvestigationSynthesis{}, err
	}
	request := synthesisRequest(snapshot, modelContext, orchestrator.config.SynthesisPrompt)
	callKey := fmt.Sprintf("investigation/%s/synthesis/%d", snapshot.Investigation.Request().ID, snapshot.Investigation.Version())
	var contextManifest contextbudget.Manifest
	if orchestrator.budgets != nil {
		request, contextManifest, modelContext, err = orchestrator.prepareSynthesisWithinAllowance(ctx, snapshot, callKey, modelContext)
		if err != nil {
			return application.InvestigationSynthesis{}, err
		}
	}
	if err := orchestrator.reserveModelCall(ctx, snapshot, application.ModelCallSynthesis, callKey); err != nil {
		return application.InvestigationSynthesis{}, err
	}
	result, callErr := orchestrator.provider.Synthesize(ctx, request)
	if callErr != nil {
		if ctx.Err() != nil {
			return application.InvestigationSynthesis{}, ctx.Err()
		}
		metadata, trace := modelFailureDetails(callErr)
		payloadReferences, recordErr := orchestrator.recordModelPayloads(ctx, snapshot, application.ModelCallSynthesis, callKey, trace)
		if recordErr != nil {
			return application.InvestigationSynthesis{}, recordErr
		}
		reason := safeModelFailureReason(callErr)
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallSynthesis, callKey, metadata, application.ModelCallRejected, reason, orchestrator.config.SynthesisPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationSynthesis{}, auditErr
		}
		if fallbackEligibleSynthesisFailure(reason) {
			findings, fallbackErr := orchestrator.deterministicSynthesisFallback(snapshot, modelContext)
			if fallbackErr != nil {
				return application.InvestigationSynthesis{}, fallbackErr
			}
			return application.InvestigationSynthesis{Findings: findings, ModelTokens: metadata.InputTokens + metadata.OutputTokens, CostMicros: metadata.CostMicros, Disposition: application.SynthesisSafeFallback}, nil
		}
		return application.InvestigationSynthesis{}, fmt.Errorf("model synthesis call failed: %w", callErr)
	}
	if orchestrator.budgets != nil && result.Metadata.InputTokens > 0 {
		if observeErr := orchestrator.budgets.Observe(ctx, contextManifest, result.Metadata.InputTokens); observeErr != nil && !errors.Is(observeErr, contextbudget.ErrEstimatorUnderrun) {
			return application.InvestigationSynthesis{}, fmt.Errorf("record token calibration: %w", observeErr)
		}
	}
	payloadReferences, err := orchestrator.recordModelPayloads(ctx, snapshot, application.ModelCallSynthesis, callKey, result.Trace)
	if err != nil {
		return application.InvestigationSynthesis{}, err
	}
	if err := result.ValidateFor(request); err != nil {
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallSynthesis, callKey, result.Metadata, application.ModelCallRejected, "INVALID_MODEL_OUTPUT", orchestrator.config.SynthesisPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationSynthesis{}, auditErr
		}
		findings, fallbackErr := orchestrator.deterministicSynthesisFallback(snapshot, modelContext)
		if fallbackErr != nil {
			return application.InvestigationSynthesis{}, fallbackErr
		}
		return application.InvestigationSynthesis{Findings: findings, ModelTokens: result.Metadata.InputTokens + result.Metadata.OutputTokens, CostMicros: result.Metadata.CostMicros, Disposition: application.SynthesisSafeFallback}, nil
	}
	if err := orchestrator.validateMetadata(result.Metadata); err != nil {
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallSynthesis, callKey, result.Metadata, application.ModelCallRejected, "UNEXPECTED_MODEL_CONFIGURATION", orchestrator.config.SynthesisPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationSynthesis{}, auditErr
		}
		return application.InvestigationSynthesis{}, err
	}
	if result.Metadata.Outcome == modelprovider.OutcomeRefused {
		if err := orchestrator.audit(ctx, snapshot, application.ModelCallSynthesis, callKey, result.Metadata, application.ModelCallRejected, "MODEL_REFUSED", orchestrator.config.SynthesisPrompt, payloadReferences); err != nil {
			return application.InvestigationSynthesis{}, err
		}
		findings, fallbackErr := orchestrator.deterministicSynthesisFallback(snapshot, modelContext)
		if fallbackErr != nil {
			return application.InvestigationSynthesis{}, fallbackErr
		}
		return application.InvestigationSynthesis{Findings: findings, ModelTokens: result.Metadata.InputTokens + result.Metadata.OutputTokens, CostMicros: result.Metadata.CostMicros, Disposition: application.SynthesisSafeFallback}, nil
	}
	findings, omissions, err := orchestrator.mapSynthesisFindings(result.Response, snapshot, modelContext)
	if err != nil {
		if auditErr := orchestrator.audit(ctx, snapshot, application.ModelCallSynthesis, callKey, result.Metadata, application.ModelCallRejected, "SYNTHESIS_MAPPING_REJECTED", orchestrator.config.SynthesisPrompt, payloadReferences); auditErr != nil {
			return application.InvestigationSynthesis{}, auditErr
		}
		return application.InvestigationSynthesis{}, err
	}
	if err := orchestrator.audit(ctx, snapshot, application.ModelCallSynthesis, callKey, result.Metadata, application.ModelCallSucceeded, "", orchestrator.config.SynthesisPrompt, payloadReferences); err != nil {
		return application.InvestigationSynthesis{}, err
	}
	disposition := application.SynthesisValidatedPartial
	complete := synthesisCompletionEligible(request, result.Response, findings)
	if snapshot.Investigation.Request().Purpose == domain.InvestigationPurposeRepairPlan {
		complete = repairProposalCompletionEligible(snapshot, request, result.Response, findings, omissions)
	}
	if complete {
		disposition = application.SynthesisValidatedComplete
	}
	sections, err := orchestrator.mapSynthesisSections(result.Response, snapshot)
	if err != nil {
		return application.InvestigationSynthesis{}, err
	}
	actionCard, err := orchestrator.mapPrimaryActionCard(result.Response, snapshot)
	if err != nil {
		return application.InvestigationSynthesis{}, err
	}
	// Merged after the completion gates have read `omissions`, which carry what
	// the model answered and the domain refused. The context drops below are a
	// different fact about the same report and are recorded, not re-litigated:
	// the repair gate already refuses completion on Coverage.EvidenceOmitted, so
	// folding them in earlier would change which proposals complete, which is a
	// separate decision from stating why a report is thin.
	omissions = domain.MergeReportOmissions(omissions, contextReportOmissions(modelContext, snapshot.Investigation.Request().ID)...)
	return application.InvestigationSynthesis{Findings: findings, Sections: sections, Omissions: omissions, ActionCard: actionCard, ModelTokens: result.Metadata.InputTokens + result.Metadata.OutputTokens, CostMicros: result.Metadata.CostMicros, Disposition: disposition}, nil
}

// contextReportOmissions records what the context builder dropped before the
// synthesis call, so a report thinned by a full context says so.
//
// A report used to name only the statements the domain refused after the model
// answered. Everything lost on the way in -- evidence past the item limit,
// evidence and hypotheses cut to fit the encoded ceiling, evidence trimmed to
// the provider's input allowance -- reached the operator as nothing at all. A
// run over ten warnings that fitted two of them into the context produced a
// report indistinguishable from one that had considered all ten and found
// eight unremarkable. The reader cannot tell a quiet cluster from a full
// context without this.
//
// Lossless reductions and scope trims are excluded: the evidence they name is
// still represented in what the model read.
func contextReportOmissions(context investigationcontext.Context, investigationID domain.InvestigationID) []domain.ReportOmission {
	var omissions []domain.ReportOmission
	for _, omission := range context.Omissions {
		if !investigationcontext.OmissionLosesInformation(omission) {
			continue
		}
		reason := ""
		switch omission.Reason {
		case investigationcontext.OmissionItemLimit:
			reason = domain.OmissionContextItemLimit
		case investigationcontext.OmissionEncodedSizeLimit:
			reason = domain.OmissionContextSizeLimit
		case investigationcontext.OmissionProviderAllowance:
			reason = domain.OmissionProviderInputAllowance
		default:
			continue
		}
		omissions = domain.MergeReportOmissions(omissions, domain.ReportOmission{InvestigationID: investigationID, Kind: omission.Kind, Reason: reason, Count: omission.Count})
	}
	return omissions
}

// synthesisCompletionEligible is deliberately stricter than schema validity.
// It permits terminal promotion only for a complete provider-validated report
// over every requested target, with no tool failures and with durable forms of
// the factual assessment, explanation, and operator next step. Rejected,
// refused, and deterministic fallback responses never call this gate.
//
// Time completeness is judged on interrogation, not on data density. Requiring
// observed values at every instant would pin every investigation built on event
// evidence to PARTIAL, because a quiet period legitimately yields no values;
// requiring the requested windows to tile the scope, answered by evidence that
// covered its whole declared target set, asks the question that actually
// matters. Every other gate here stays as strict as before.
func synthesisCompletionEligible(request modelprovider.SynthesisRequest, response modelprovider.SynthesisResponse, findings []domain.Finding) bool {
	if len(request.Evidence) == 0 || len(request.Coverage.TargetsMissed) != 0 || len(request.Coverage.ToolFailures) != 0 || len(request.Coverage.ExpectedTargets) == 0 || len(request.Coverage.MissingTargets) != 0 || !request.Coverage.RequestedTimeComplete {
		return false
	}
	for _, entityID := range request.Scope.EntityIDs {
		if !slices.Contains(request.Coverage.TargetsChecked, entityID) {
			return false
		}
	}
	if len(response.WhatIsHappening) == 0 || len(response.Timeline) == 0 || len(response.LikelyExplanations) == 0 || len(response.WhatRemainsUnknown) == 0 || len(response.SuggestedNextSteps) == 0 || len(response.Coverage) == 0 {
		return false
	}
	hasObservation, hasHypothesis, hasRecommendation := false, false, false
	for _, finding := range findings {
		switch finding.Kind {
		case domain.FindingObservation:
			hasObservation = hasObservation || len(finding.EvidenceIDs) > 0
		case domain.FindingHypothesis:
			hasHypothesis = hasHypothesis || len(finding.EvidenceIDs) > 0
		case domain.FindingRecommendation:
			hasRecommendation = true
		}
	}
	return hasObservation && hasHypothesis && hasRecommendation
}

// fallbackEligibleSynthesisFailure reports whether a failed synthesis call
// should resolve to the deterministic report instead of failing the run.
//
// Every INVALID_RESPONSE stage means the provider answered but its content is
// unusable: the output was truncated by the token cap, it did not decode, or it
// did not satisfy semantic validation. In all three the evidence is already
// gathered and the safe fallback can publish it, which is exactly what that
// path exists for. Only semantic validation was eligible, so a report truncated
// by the output cap -- the failure a larger evidence set makes more likely --
// discarded an entire investigation instead. Transport and HTTP status failures
// stay fatal, because there the provider never produced a report at all.
func fallbackEligibleSynthesisFailure(reason string) bool {
	return strings.HasPrefix(reason, "INVALID_RESPONSE")
}

func safeModelFailureReason(err error) string {
	type safeReason interface{ SafeReasonCode() string }
	var classified safeReason
	if errors.As(err, &classified) {
		if reason := classified.SafeReasonCode(); reason != "" {
			return reason
		}
	}
	return "PROVIDER_ERROR"
}

func modelFailureDetails(err error) (modelprovider.CallMetadata, modelprovider.CallTrace) {
	type metadataSource interface {
		ModelCallMetadata() (modelprovider.CallMetadata, bool)
	}
	type traceSource interface {
		ModelCallTrace() modelprovider.CallTrace
	}
	var metadata modelprovider.CallMetadata
	var withMetadata metadataSource
	if errors.As(err, &withMetadata) {
		metadata, _ = withMetadata.ModelCallMetadata()
	}
	var trace modelprovider.CallTrace
	var withTrace traceSource
	if errors.As(err, &withTrace) {
		trace = withTrace.ModelCallTrace()
	}
	return metadata, trace
}

func (orchestrator *Orchestrator) recordModelPayloads(ctx context.Context, snapshot application.InvestigationSnapshot, kind application.ModelCallKind, callKey string, trace modelprovider.CallTrace) (modelPayloadReferences, error) {
	if orchestrator.payloads == nil {
		return modelPayloadReferences{}, nil
	}
	request := snapshot.Investigation.Request()
	occurredAt := orchestrator.clock.Now()
	result := modelPayloadReferences{}
	if len(trace.Input) != 0 {
		id, err := orchestrator.payloads.RecordModelPayload(ctx, application.ModelPayloadEvidence{InvestigationID: request.ID, ClusterID: request.ClusterID, CallKey: callKey, Kind: kind, Role: application.ModelPayloadInput, Payload: trace.Input, OccurredAt: occurredAt})
		if err != nil {
			return modelPayloadReferences{}, fmt.Errorf("record model input evidence: %w", err)
		}
		result.input = id
	}
	if len(trace.Output) != 0 {
		id, err := orchestrator.payloads.RecordModelPayload(ctx, application.ModelPayloadEvidence{InvestigationID: request.ID, ClusterID: request.ClusterID, CallKey: callKey, Kind: kind, Role: application.ModelPayloadOutput, Payload: trace.Output, OccurredAt: occurredAt})
		if err != nil {
			return modelPayloadReferences{}, fmt.Errorf("record model output evidence: %w", err)
		}
		result.output = id
	}
	return result, nil
}

func (orchestrator *Orchestrator) reserveModelCall(ctx context.Context, snapshot application.InvestigationSnapshot, kind application.ModelCallKind, callKey string) error {
	now := orchestrator.clock.Now()
	request := snapshot.Investigation.Request()
	if err := orchestrator.reservations.ReserveModelCall(ctx, request.ID, request.ClusterID, callKey, kind, now, now.Add(orchestrator.config.ModelCallReservationTTL)); err != nil {
		return fmt.Errorf("reserve model call before provider request: %w", err)
	}
	return nil
}

func (orchestrator *Orchestrator) inputs(ctx context.Context, snapshot application.InvestigationSnapshot) (investigationtools.Filter, investigationcontext.Context, []modelprovider.AvailableTool, error) {
	filter, err := orchestrator.resolveAuthorityFilter(ctx, snapshot)
	if err != nil {
		return investigationtools.Filter{}, investigationcontext.Context{}, nil, err
	}
	input, err := orchestrator.contexts.InvestigationContext(ctx, snapshot)
	if err != nil {
		return investigationtools.Filter{}, investigationcontext.Context{}, nil, err
	}
	if orchestrator.contextEngine != nil {
		input, _, err = orchestrator.contextEngine.Prepare(ctx, snapshot, input)
		if err != nil {
			return investigationtools.Filter{}, investigationcontext.Context{}, nil, err
		}
	}
	built, err := orchestrator.builder.Build(input)
	if err != nil {
		return investigationtools.Filter{}, investigationcontext.Context{}, nil, err
	}
	schemas, err := orchestrator.catalog.AvailableSchemas(filter)
	if err != nil {
		return investigationtools.Filter{}, investigationcontext.Context{}, nil, err
	}
	tools := make([]modelprovider.AvailableTool, 0, len(schemas))
	for _, schema := range schemas {
		tools = append(tools, modelprovider.AvailableTool{ToolID: string(schema.ToolID), Description: schema.Description, ArgumentSchema: slices.Clone(schema.ArgumentSchema), SchemaVersion: schema.SchemaVersion, ReadOnly: schema.ReadOnly, Diagnostic: schema.Diagnostic, MaximumFanOut: schema.MaximumFanOut, CostWeight: schema.CostWeight})
	}
	return filter, built, tools, nil
}

func (orchestrator *Orchestrator) resolveAuthorityFilter(ctx context.Context, snapshot application.InvestigationSnapshot) (investigationtools.Filter, error) {
	filter, err := orchestrator.authority.ResolveInvestigationAuthority(ctx, snapshot)
	if err != nil {
		return investigationtools.Filter{}, err
	}
	request := snapshot.Investigation.Request()
	if filter.ClusterID != request.ClusterID || filter.Scope.Validate() != nil || filter.Scope.EntityKind != request.Scope.EntityKind || !slices.Equal(filter.Scope.EntityIDs, request.Scope.EntityIDs) || !filter.Scope.Start.Equal(request.Scope.Start) || !filter.Scope.End.Equal(request.Scope.End) {
		return investigationtools.Filter{}, fmt.Errorf("resolved model authority does not match persisted investigation scope")
	}
	// The authority resolver owns cluster, actor, and scope reach. Spendable
	// budget is the controller's to decide, and it is decided here so a run with
	// no diagnostic grant never sees a diagnostic tool: the refusal costs no
	// provider call and no replan.
	budget, usage := request.Budget, snapshot.Investigation.Usage()
	filter.AllowDiagnostics = budget.MaxDiagnosticCalls-usage.DiagnosticCalls > 0
	return filter, nil
}

func (orchestrator *Orchestrator) retrieveMemory(ctx context.Context, snapshot application.InvestigationSnapshot, request modelprovider.PlanningRequest, selection contextbudget.Selection) (modelprovider.PlanningRequest, contextbudget.Selection) {
	if orchestrator.memory == nil || orchestrator.memoryMode == clustermemory.ModeDisabled {
		return request, selection
	}
	now := orchestrator.clock.Now()
	result, err := orchestrator.memory.Retrieve(ctx, clustermemory.Query{
		ClusterID: snapshot.Investigation.Request().ClusterID,
		Text:      request.Question, EntityIDs: slices.Clone(request.Scope.EntityIDs), ValidAt: now,
		MaximumAge: 90 * 24 * time.Hour, Limit: 12, TokenAllowance: 8_000,
	})
	if err != nil {
		selection.FallbackState = "MEMORY_UNAVAILABLE"
		selection.ExclusionReasons = map[string]int{"retrieval_failure": 1}
		return request, selection
	}
	selection.CandidateCount, selection.RetrievalLatency = result.Candidates, result.Latency
	selection.IndexVersion, selection.FallbackState = result.IndexVersion, result.Fallback
	selection.ShadowOnly = orchestrator.memoryMode == clustermemory.ModeShadow
	if selection.ShadowOnly {
		return request, selection
	}
	for _, entry := range result.Entries {
		evidenceIDs := make([]string, 0, len(entry.Citations))
		for _, citation := range entry.Citations {
			evidenceIDs = append(evidenceIDs, string(citation.EvidenceID))
		}
		// Uncited hypotheses and gaps remain observable in the projection but do
		// not enter a provider prompt.
		if len(evidenceIDs) == 0 {
			continue
		}
		request.Memory = append(request.Memory, modelprovider.MemoryContext{
			MemoryID: entry.ID, TrustClass: string(entry.Trust), Statement: entry.Summary,
			SourceInvestigationID: string(entry.SourceInvestigationID), EntityIDs: slices.Clone(entry.EntityIDs),
			EvidenceIDs: evidenceIDs, ValidFrom: entry.ValidFrom, Stale: entry.Freshness == "STALE",
		})
	}
	return request, selection
}

func (orchestrator *Orchestrator) audit(ctx context.Context, snapshot application.InvestigationSnapshot, kind application.ModelCallKind, key string, metadata modelprovider.CallMetadata, outcome application.ModelCallOutcome, reason, prompt string, payloads ...modelPayloadReferences) error {
	id, err := orchestrator.ids.NewID()
	if err != nil {
		return err
	}
	provider, model, config := orchestrator.config.Provider, orchestrator.config.Model, orchestrator.config.ModelConfigVersion
	if metadata.Provider != "" {
		provider, model, config = metadata.Provider, metadata.Model, metadata.ConfigurationID
	}
	audit := application.ModelCallAudit{CallID: id, CallKey: key, InvestigationID: snapshot.Investigation.Request().ID, ClusterID: snapshot.Investigation.Request().ClusterID, Kind: kind, Provider: provider, Model: model, ModelConfigVersion: config, PromptSchemaVersion: prompt, ToolSchemaVersion: orchestrator.config.ToolSchemaVersion, InputTokens: metadata.InputTokens, OutputTokens: metadata.OutputTokens, CostMicros: metadata.CostMicros, Latency: metadata.Latency, Outcome: outcome, ReasonCode: reason, OccurredAt: orchestrator.clock.Now()}
	if len(payloads) > 0 {
		audit.InputEvidenceID, audit.OutputEvidenceID = payloads[0].input, payloads[0].output
	}
	if err := orchestrator.audits.AppendModelCallAudit(ctx, audit); err != nil {
		return fmt.Errorf("append required model call audit: %w", err)
	}
	status := application.ModelCallFailedState
	if outcome == application.ModelCallSucceeded {
		status = application.ModelCallSucceededState
	}
	if outcome == application.ModelCallRejected {
		status = application.ModelCallRejectedState
	}
	if err := orchestrator.reservations.CompleteModelCall(ctx, snapshot.Investigation.Request().ID, key, status, orchestrator.clock.Now()); err != nil {
		return fmt.Errorf("complete model call reservation: %w", err)
	}
	return nil
}

func (orchestrator *Orchestrator) validateMetadata(metadata modelprovider.CallMetadata) error {
	if metadata.Provider != orchestrator.config.Provider || metadata.Model != orchestrator.config.Model || metadata.ConfigurationID != orchestrator.config.ModelConfigVersion {
		return fmt.Errorf("model provider returned unexpected effective configuration")
	}
	return nil
}

func planningRequest(snapshot application.InvestigationSnapshot, context investigationcontext.Context, tools []modelprovider.AvailableTool, config Config) modelprovider.PlanningRequest {
	request := snapshot.Investigation.Request()
	budget, usage := request.Budget, snapshot.Investigation.Usage()
	factoredTools, sharedArguments := factorToolSchemas(tools)
	return modelprovider.PlanningRequest{SchemaVersion: modelprovider.PlanningSchemaVersion, InvestigationID: string(request.ID), Question: context.Header.Question, Scope: modelScope(request.Scope, request.ClusterID), StateSummary: "Select one novel read-only observation that closes an explicit coverage or hypothesis gap, or stop with explicit uncertainty. Never repeat a prior action that added no new evidence. A proposal larger than the per-action fan-out limit is executed in deterministic batches; continue until the success criteria are resolved or a hard safety limit prevents progress.", SuccessCriteria: slices.Clone(context.Header.SuccessCriteria), RemainingBudget: modelprovider.RemainingBudget{Decisions: budget.MaxDecisions - usage.Decisions, ToolCalls: budget.MaxToolCalls - usage.ToolCalls, DiagnosticCalls: budget.MaxDiagnosticCalls - usage.DiagnosticCalls, PrivilegedCalls: budget.MaxPrivilegedCalls - usage.PrivilegedCalls, FanOut: budget.MaxFanOut, ModelTokens: budget.MaxModelTokens - usage.ModelTokens, CostMicros: budget.MaxCostMicros - usage.CostMicros}, AvailableTools: factoredTools, SharedToolArguments: sharedArguments, Evidence: modelEvidence(context), Hypotheses: modelHypotheses(snapshot), PriorActions: modelPriorActions(snapshot, context), Coverage: modelCoverage(context, request.Scope), PromptVersion: config.PlanningPrompt, ToolSchemaVersion: config.ToolSchemaVersion, CheckpointDigest: context.CheckpointDigest, DeltaFromVersion: context.DeltaFromVersion, ContextMode: "STATELESS"}
}

func factorToolSchemas(tools []modelprovider.AvailableTool) ([]modelprovider.AvailableTool, []byte) {
	result := slices.Clone(tools)
	if len(result) == 0 || len(result[0].ArgumentSchema) == 0 {
		return result, nil
	}
	shared, err := commonPromptToolSchema(result[0].ArgumentSchema)
	if err != nil {
		return result, nil
	}
	for _, tool := range result[1:] {
		candidate, normalizeErr := commonPromptToolSchema(tool.ArgumentSchema)
		if normalizeErr != nil || !slices.Equal(shared, candidate) {
			return result, nil
		}
	}
	for index := range result {
		result[index].ResponseArgumentSchema = slices.Clone(result[index].ArgumentSchema)
		result[index].ArgumentSchema = nil
	}
	return result, slices.Clone(shared)
}

func commonPromptToolSchema(raw json.RawMessage) ([]byte, error) {
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tool schema properties are missing")
	}
	targets, ok := properties["targets"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tool target schema is missing")
	}
	// The per-tool maximum is already sent as maximum_fan_out and is enforced
	// again by the authoritative catalog. Removing only this repeated prompt
	// keyword makes the common targets/start/end contract byte-identical.
	delete(targets, "maxItems")
	return json.Marshal(schema)
}

func modelPriorActions(snapshot application.InvestigationSnapshot, context investigationcontext.Context) []modelprovider.PriorAction {
	availableEvidence := make(map[domain.EvidenceID]struct{}, len(context.Evidence))
	for _, evidence := range context.Evidence {
		availableEvidence[evidence.EvidenceID] = struct{}{}
	}
	result := make([]modelprovider.PriorAction, 0, len(snapshot.PriorActions))
	for _, action := range snapshot.PriorActions {
		// Pre-M9 scripted actions may not have carried an invocation scope. They
		// remain durable audit history but cannot safely become model authority.
		if len(action.Targets) == 0 || action.Start.IsZero() || action.End.Before(action.Start) {
			continue
		}
		evidenceIDs := make([]string, 0, len(action.EvidenceIDs))
		for _, evidenceID := range action.EvidenceIDs {
			if _, available := availableEvidence[evidenceID]; available {
				evidenceIDs = append(evidenceIDs, string(evidenceID))
			}
		}
		result = append(result, modelprovider.PriorAction{
			ActionDigest: action.Digest.String(),
			ToolID:       action.ToolID,
			Outcome:      action.Outcome,
			Targets:      slices.Clone(action.Targets),
			Start:        action.Start,
			End:          action.End,
			EvidenceIDs:  evidenceIDs,
		})
	}
	return result
}

const synthesisAllowanceOmissionReason = investigationcontext.OmissionProviderAllowance

// prepareSynthesisWithinAllowance runs the provider input preflight and, for a
// repair plan, trims evidence until the request fits. The returned context is
// the one the request was built from, so citation mapping sees only evidence
// the model was actually given.
func (orchestrator *Orchestrator) prepareSynthesisWithinAllowance(ctx context.Context, snapshot application.InvestigationSnapshot, callKey string, modelContext investigationcontext.Context) (modelprovider.SynthesisRequest, contextbudget.Manifest, investigationcontext.Context, error) {
	request := synthesisRequest(snapshot, modelContext, orchestrator.config.SynthesisPrompt)
	for {
		prepared, manifest, err := orchestrator.budgets.PrepareSynthesis(ctx, snapshot, callKey, request)
		if err == nil {
			return prepared, manifest, modelContext, nil
		}
		trimmed, ok := trimSynthesisEvidenceForAllowance(snapshot, modelContext, err)
		if !ok {
			return modelprovider.SynthesisRequest{}, contextbudget.Manifest{}, modelContext, err
		}
		modelContext = trimmed
		request = synthesisRequest(snapshot, modelContext, orchestrator.config.SynthesisPrompt)
	}
}

// trimSynthesisEvidenceForAllowance drops the last non-required evidence block
// from a repair plan whose synthesis request exceeds the provider input
// allowance. The encoded-context limit and the token allowance are separate
// checks, so a warning set can pass the first and still fail the second. Each
// omission is recorded, which keeps the proposal partial rather than complete.
// PrepareSynthesis persists nothing before the allowance check, so retrying
// with the trimmed context has no side effects.
func trimSynthesisEvidenceForAllowance(snapshot application.InvestigationSnapshot, context investigationcontext.Context, cause error) (investigationcontext.Context, bool) {
	if snapshot.Investigation.Request().Purpose != domain.InvestigationPurposeRepairPlan || !errors.Is(cause, contextbudget.ErrAllowanceExceeded) {
		return context, false
	}
	index := context.OptionalEvidenceRemovalIndex()
	if index < 0 {
		return context, false
	}
	removed := context.Evidence[index]
	context.Evidence = slices.Delete(slices.Clone(context.Evidence), index, index+1)
	context.Omissions = slices.Clone(context.Omissions)
	for position := range context.Omissions {
		omission := &context.Omissions[position]
		if omission.Kind == investigationcontext.OmissionKindEvidence && omission.Reason == synthesisAllowanceOmissionReason {
			omission.Count++
			if len(omission.SampleIDs) < 16 {
				omission.SampleIDs = append(slices.Clone(omission.SampleIDs), string(removed.EvidenceID))
			}
			omission.EntityIDs = append(slices.Clone(omission.EntityIDs), removed.EntityIDs...)
			slices.Sort(omission.EntityIDs)
			omission.EntityIDs = slices.Compact(omission.EntityIDs)
			return context, true
		}
	}
	context.Omissions = append(context.Omissions, investigationcontext.Omission{Kind: investigationcontext.OmissionKindEvidence, Count: 1, SampleIDs: []string{string(removed.EvidenceID)}, EntityIDs: slices.Clone(removed.EntityIDs), Reason: synthesisAllowanceOmissionReason})
	return context, true
}

func synthesisRequest(snapshot application.InvestigationSnapshot, context investigationcontext.Context, prompt string) modelprovider.SynthesisRequest {
	request := snapshot.Investigation.Request()
	evidence := modelEvidence(context)
	findings := make([]modelprovider.ValidatedFinding, 0, len(snapshot.Findings))
	for _, finding := range snapshot.Findings {
		ids, counter := evidenceStrings(finding.EvidenceIDs), evidenceStrings(finding.CounterEvidenceIDs)
		findings = append(findings, modelprovider.ValidatedFinding{FindingID: string(finding.ID), Kind: string(finding.Kind), Statement: finding.Statement, EntityIDs: slices.Clone(finding.EntityIDs), Severity: finding.Severity, Confidence: finding.Confidence, EvidenceIDs: ids, CounterEvidenceIDs: counter})
	}
	coverage := modelCoverage(context, request.Scope)
	coverage.StopReason = string(snapshot.RequestedStop)
	return modelprovider.SynthesisRequest{SchemaVersion: modelprovider.SynthesisSchemaVersion, InvestigationID: string(request.ID), Question: context.Header.Question, Scope: modelScope(request.Scope, request.ClusterID), Outcome: string(snapshot.RequestedOutcome), Evidence: evidence, Hypotheses: modelHypotheses(snapshot), Findings: findings, Coverage: coverage, PromptVersion: prompt, CheckpointDigest: context.CheckpointDigest, DeltaFromVersion: context.DeltaFromVersion, ContextMode: "STATELESS"}
}

func modelScope(scope domain.InvestigationScope, cluster domain.ClusterID) modelprovider.Scope {
	return modelprovider.Scope{ClusterID: string(cluster), EntityKind: scope.EntityKind, EntityIDs: slices.Clone(scope.EntityIDs), Start: scope.Start, End: scope.End}
}

func modelEvidence(context investigationcontext.Context) []modelprovider.EvidenceContext {
	result := make([]modelprovider.EvidenceContext, 0, len(context.Evidence))
	for _, evidence := range context.Evidence {
		result = append(result, modelprovider.EvidenceContext{EvidenceID: string(evidence.EvidenceID), EntityIDs: slices.Clone(evidence.EntityIDs), ObservedFrom: evidence.ObservedFrom, ObservedTo: evidence.ObservedTo, Status: string(evidence.Status), Source: evidence.Source, Summary: evidence.UntrustedSummary, UntrustedData: evidence.UntrustedExcerpt, Truncated: evidence.SummaryTruncated || evidence.ExcerptTruncated, ExpectedTargets: modelCoverageTargets(evidence.ExpectedTargets), ObservedTargets: modelCoverageTargets(evidence.ObservedTargets), MissingTargets: modelCoverageTargets(evidence.MissingTargets), ExpectedFrom: evidence.ExpectedFrom, ExpectedTo: evidence.ExpectedTo, TimeComplete: evidence.TimeComplete})
	}
	return result
}

func modelCoverage(context investigationcontext.Context, scope domain.InvestigationScope) modelprovider.Coverage {
	expected, observed := map[modelprovider.CoverageTarget]struct{}{}, map[modelprovider.CoverageTarget]struct{}{}
	representedEntities := map[string]bool{}
	scopeEntities := map[string]bool{}
	for _, entity := range scope.EntityIDs {
		scopeEntities[entity] = true
	}
	scopedObserved, sources := map[string]struct{}{}, []string{}
	scopeKind := modelScopeCoverageKind(scope.EntityKind)
	intervals, requested := []coverageInterval{}, []coverageInterval{}
	for _, evidence := range context.Evidence {
		for _, entity := range evidence.EntityIDs {
			representedEntities[entity] = true
		}
		for _, target := range modelCoverageTargets(evidence.ExpectedTargets) {
			expected[target] = struct{}{}
		}
		for _, target := range modelCoverageTargets(evidence.ObservedTargets) {
			observed[target] = struct{}{}
			if scopeKind == "" || target.Kind == scopeKind {
				scopedObserved[target.ID] = struct{}{}
			}
		}
		if !slices.Contains(sources, evidence.Source) {
			sources = append(sources, evidence.Source)
		}
		if len(evidence.ObservedTargets) > 0 {
			intervals = append(intervals, coverageInterval{evidence.ObservedFrom, evidence.ObservedTo})
		}
		// COMPLETE and NO_DATA are the only statuses the evidence domain lets
		// claim complete target coverage, so only they authoritatively answer for
		// the window that was requested. NO_DATA is verified absence, which is a
		// real answer for event evidence and the case observed density loses.
		if evidence.Status == domain.EvidenceComplete || evidence.Status == domain.EvidenceNoData {
			requested = append(requested, coverageInterval{evidence.ExpectedFrom, evidence.ExpectedTo})
		}
	}
	result := modelprovider.Coverage{ExpectedFrom: scope.Start, ExpectedTo: scope.End, Sources: sources, EvidenceSelected: len(context.Evidence)}
	for _, omission := range context.Omissions {
		if omission.Kind != investigationcontext.OmissionKindEvidence {
			continue
		}
		// Both reductions are lossless projections of the same evidence rather
		// than dropped information, so they are reported as reduced, not omitted.
		if omission.Reason == investigationcontext.OmissionRedundantFingerprint || omission.Reason == investigationcontext.OmissionCoalescedSamples {
			result.EvidenceReduced += omission.Count
			continue
		}
		result.EvidenceOmitted += omission.Count
		for _, entity := range omission.EntityIDs {
			// Partial thinning remains visible in the omission rows and count.
			// This field identifies entities that lost every selected item.
			if scopeEntities[entity] && !representedEntities[entity] && !slices.Contains(result.EvidenceOmittedEntities, entity) {
				result.EvidenceOmittedEntities = append(result.EvidenceOmittedEntities, entity)
			}
		}
	}
	slices.Sort(result.EvidenceOmittedEntities)
	if len(result.EvidenceOmittedEntities) > 0 {
		result.EvidenceOmittedNote = "Evidence for these entities was collected and committed to the durable ledger, then dropped because it did not fit this context. Their state is unknown to you rather than uncollected: report them as unassessed, and do not treat re-running collection as the remedy."
	}
	for target := range expected {
		result.ExpectedTargets = append(result.ExpectedTargets, target)
	}
	for target := range observed {
		result.ObservedTargets = append(result.ObservedTargets, target)
	}
	sortCoverageTargets(result.ExpectedTargets)
	sortCoverageTargets(result.ObservedTargets)
	observedSet := map[modelprovider.CoverageTarget]struct{}{}
	for _, target := range result.ObservedTargets {
		observedSet[target] = struct{}{}
	}
	for _, target := range result.ExpectedTargets {
		if _, ok := observedSet[target]; !ok {
			result.MissingTargets = append(result.MissingTargets, target)
		}
	}
	for _, id := range scope.EntityIDs {
		if _, ok := scopedObserved[id]; ok {
			result.TargetsChecked = append(result.TargetsChecked, id)
		} else {
			result.TargetsMissed = append(result.TargetsMissed, id)
		}
	}
	if len(intervals) > 0 {
		slices.SortFunc(intervals, func(a, b coverageInterval) int {
			if a.start.Equal(b.start) {
				return a.end.Compare(b.end)
			}
			return a.start.Compare(b.start)
		})
		result.ObservedFrom, result.ObservedTo = intervals[0].start, intervals[0].end
		for _, item := range intervals[1:] {
			if item.start.Before(result.ObservedFrom) {
				result.ObservedFrom = item.start
			}
			if item.end.After(result.ObservedTo) {
				result.ObservedTo = item.end
			}
		}
		cursor := scope.Start
		for _, item := range intervals {
			if item.start.After(cursor) {
				break
			}
			if item.end.After(cursor) {
				cursor = item.end
			}
		}
		result.TimeComplete = !cursor.Before(scope.End)
	}
	result.RequestedTimeComplete = tiles(requested, scope.Start, scope.End)
	return result
}

type coverageInterval struct{ start, end time.Time }

// tiles reports whether the union of intervals covers [start, end] with no gap.
// Sorting by start and advancing a cursor is enough: a gap appears exactly when
// the next interval begins after everything seen so far ended.
func tiles(values []coverageInterval, start, end time.Time) bool {
	if len(values) == 0 {
		return false
	}
	ordered := slices.Clone(values)
	slices.SortFunc(ordered, func(a, b coverageInterval) int { return a.start.Compare(b.start) })
	cursor := start
	for _, value := range ordered {
		if value.start.After(cursor) {
			return false
		}
		if value.end.After(cursor) {
			cursor = value.end
		}
	}
	return !cursor.Before(end)
}

func modelScopeCoverageKind(kind string) string {
	switch strings.ToLower(kind) {
	case "cluster":
		return "CLUSTER"
	case "node":
		return "NODE"
	case "gpu":
		return "GPU"
	case "source":
		return "SOURCE"
	default:
		return ""
	}
}

func modelCoverageTargets(values []investigationcontext.CoverageTarget) []modelprovider.CoverageTarget {
	result := make([]modelprovider.CoverageTarget, len(values))
	for index, target := range values {
		result[index] = modelprovider.CoverageTarget{Kind: string(target.Kind), ID: string(target.ID)}
	}
	return result
}

func sortCoverageTargets(values []modelprovider.CoverageTarget) {
	slices.SortFunc(values, func(a, b modelprovider.CoverageTarget) int {
		if a.Kind != b.Kind {
			return strings.Compare(a.Kind, b.Kind)
		}
		return strings.Compare(a.ID, b.ID)
	})
}

func modelHypotheses(snapshot application.InvestigationSnapshot) []modelprovider.HypothesisContext {
	entries := snapshot.Hypotheses.Entries()
	result := make([]modelprovider.HypothesisContext, 0, len(entries))
	for _, item := range entries {
		result = append(result, modelprovider.HypothesisContext{HypothesisID: string(item.ID), Statement: item.Statement, Status: string(item.Status), Confidence: item.Confidence, SupportingEvidence: evidenceStrings(item.SupportingEvidence), ContradictingEvidence: evidenceStrings(item.ContradictingEvidence), UnresolvedTests: slices.Clone(item.UnresolvedTests)})
	}
	return result
}

func (orchestrator *Orchestrator) mapHypotheses(updates []modelprovider.HypothesisUpdate, snapshot application.InvestigationSnapshot) ([]domain.Hypothesis, error) {
	versions := map[string]int{}
	for _, current := range snapshot.Hypotheses.Entries() {
		versions[string(current.ID)] = current.Version
	}
	result := make([]domain.Hypothesis, 0, len(updates))
	for _, update := range updates {
		hypothesisID := update.HypothesisID
		if hypothesisID == modelprovider.NewHypothesisID {
			id, err := orchestrator.ids.NewID()
			if err != nil {
				return nil, fmt.Errorf("allocate hypothesis ID: %w", err)
			}
			hypothesisID = "hypothesis-" + id
		}
		result = append(result, domain.Hypothesis{ID: domain.HypothesisID(hypothesisID), InvestigationID: snapshot.Investigation.Request().ID, Statement: update.Statement, Status: domain.HypothesisStatus(update.Status), Confidence: update.Confidence, SupportingEvidence: domainEvidence(update.SupportingEvidence), ContradictingEvidence: domainEvidence(update.ContradictingEvidence), UnresolvedTests: slices.Clone(update.UnresolvedTests), Version: versions[hypothesisID] + 1})
	}
	return result, nil
}

func mapStop(reason modelprovider.PlanningStopReason) (domain.InvestigationStatus, domain.InvestigationStopReason) {
	switch reason {
	case modelprovider.StopSuccessCriteriaMet:
		return domain.InvestigationCompleted, domain.StopSuccessCriteriaMet
	case modelprovider.StopAccessUnavailable:
		return domain.InvestigationBlocked, domain.StopAccessUnavailable
	case modelprovider.StopSourceUnavailable:
		return domain.InvestigationBlocked, domain.StopSourceUnavailable
	case modelprovider.StopBudgetExceeded:
		return domain.InvestigationPartial, domain.StopBudgetExceeded
	default:
		return domain.InvestigationPartial, domain.StopNoUsefulAction
	}
}

func (orchestrator *Orchestrator) mapSynthesisFindings(response modelprovider.SynthesisResponse, snapshot application.InvestigationSnapshot, context investigationcontext.Context) ([]domain.Finding, []domain.ReportOmission, error) {
	entities := map[string][]string{}
	for _, evidence := range context.Evidence {
		entities[string(evidence.EvidenceID)] = slices.Clone(evidence.EntityIDs)
	}
	type candidate struct {
		kind              domain.FindingKind
		statement         string
		severity          string
		confidence        *float64
		evidence, counter []string
	}
	candidates := []candidate{}
	for _, item := range response.WhatIsHappening {
		candidates = append(candidates, candidate{kind: domain.FindingObservation, statement: item.Statement, severity: item.Severity, evidence: item.EvidenceIDs})
	}
	for _, item := range response.LikelyExplanations {
		confidence := item.Confidence
		candidates = append(candidates, candidate{kind: domain.FindingHypothesis, statement: item.Statement, severity: item.Severity, confidence: &confidence, evidence: item.EvidenceIDs, counter: item.CounterEvidenceIDs})
	}
	for _, item := range response.SuggestedNextSteps {
		candidates = append(candidates, candidate{kind: domain.FindingRecommendation, statement: item.Statement, severity: item.Severity, evidence: item.EvidenceIDs})
	}
	// A finding is judged against the durable ledger, not against the context it
	// was written from, so build its entity list from what the cited evidence
	// actually covers in the ledger. Assigning every entity a citation merely
	// mentions produces claims the domain then rejects, and one rejected finding
	// used to fail the whole transition and discard the entire report.
	ledger := snapshot.Evidence
	result := make([]domain.Finding, 0, len(candidates))
	var omissions []domain.ReportOmission
	for _, item := range candidates {
		ids := []string{}
		for _, evidenceID := range item.evidence {
			for _, id := range entities[evidenceID] {
				if slices.Contains(ids, id) {
					continue
				}
				if item.kind != domain.FindingRecommendation && !ledger.Covers(domain.EvidenceID(evidenceID), id) {
					continue
				}
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 && item.kind == domain.FindingRecommendation {
			ids = slices.Clone(snapshot.Investigation.Request().Scope.EntityIDs)
		}
		if len(ids) == 0 {
			// Nothing the citations observed supports this statement about any
			// entity. Dropping it is the same judgement the domain would make;
			// counting it is what stops the report being silently lossy.
			omissions = domain.MergeReportOmissions(omissions, domain.ReportOmission{InvestigationID: snapshot.Investigation.Request().ID, Kind: string(item.kind), Reason: domain.OmissionNoSupportedEntity, Count: 1})
			continue
		}
		id, err := orchestrator.ids.NewID()
		if err != nil {
			return nil, nil, err
		}
		result = append(result, domain.Finding{ID: domain.FindingID(id), InvestigationID: snapshot.Investigation.Request().ID, Kind: item.kind, Statement: item.statement, EntityIDs: ids, Severity: boundedFindingSeverity(item.severity, item.evidence, ledger), Confidence: item.confidence, EvidenceIDs: domainEvidence(item.evidence), CounterEvidenceIDs: domainEvidence(item.counter), Status: domain.FindingCurrent})
	}
	return result, omissions, nil
}

// mapPrimaryActionCard promotes exactly one synthesis recommendation into the
// operational contract of the report. The first recommendation is the
// provider's primary ordered next step; subsequent recommendations remain
// citation-validated findings but cannot create ambiguous ownership.
func (orchestrator *Orchestrator) mapPrimaryActionCard(response modelprovider.SynthesisResponse, snapshot application.InvestigationSnapshot) (*domain.ActionCard, error) {
	if len(response.SuggestedNextSteps) == 0 {
		return nil, nil
	}
	primary := response.SuggestedNextSteps[0]
	evidenceIDs := make([]domain.EvidenceID, 0, len(primary.EvidenceIDs))
	for _, raw := range primary.EvidenceIDs {
		id := domain.EvidenceID(raw)
		if snapshot.Evidence.Contains(id) && !slices.Contains(evidenceIDs, id) {
			evidenceIDs = append(evidenceIDs, id)
		}
	}
	targets := make([]string, 0)
	for _, id := range evidenceIDs {
		for _, entry := range snapshot.Evidence.Entries() {
			if entry.EvidenceID != id {
				continue
			}
			for _, target := range entry.EntityIDs {
				if !slices.Contains(targets, target) {
					targets = append(targets, target)
				}
			}
		}
	}
	if len(targets) == 0 {
		targets = slices.Clone(snapshot.Investigation.Request().Scope.EntityIDs)
	}
	gaps := make([]string, 0, len(response.WhatRemainsUnknown))
	for _, unknown := range response.WhatRemainsUnknown {
		if statement := strings.TrimSpace(unknown.Statement); statement != "" {
			gaps = append(gaps, statement)
		}
	}
	rationale := "Primary next step selected from the investigation synthesis."
	if len(response.WhatIsHappening) > 0 && strings.TrimSpace(response.WhatIsHappening[0].Statement) != "" {
		rationale = response.WhatIsHappening[0].Statement
	}
	id, err := orchestrator.ids.NewID()
	if err != nil {
		return nil, fmt.Errorf("allocate action-card ID: %w", err)
	}
	card, err := domain.NewActionCard(domain.ActionCardID("action-card-"+id), snapshot.Investigation, snapshot.Evidence, domain.ActionCardInput{
		Owner: inferActionOwner(primary.Statement), Action: primary.Statement,
		Urgency: actionUrgency(primary.Severity), Targets: targets, Rationale: rationale,
		EvidenceIDs: evidenceIDs, BlockingGaps: gaps,
		EscalationCondition: "Escalate if the action cannot be completed safely or the observed condition persists after completion.",
	})
	if err != nil {
		return nil, fmt.Errorf("map primary action card: %w", err)
	}
	return &card, nil
}

func inferActionOwner(action string) domain.ActionOwner {
	value := strings.ToLower(action)
	switch {
	case strings.Contains(value, "rma"), strings.Contains(value, "replace"), strings.Contains(value, "physical"), strings.Contains(value, "datacenter"), strings.Contains(value, "data center"):
		return domain.ActionOwnerDatacenterOperations
	case strings.Contains(value, "workload"), strings.Contains(value, "application"), strings.Contains(value, "job "), strings.HasPrefix(value, "job"):
		return domain.ActionOwnerWorkloadOwner
	case strings.Contains(value, "prometheus"), strings.Contains(value, "exporter"), strings.Contains(value, "telemetry"), strings.Contains(value, "metric"):
		return domain.ActionOwnerMonitoring
	case strings.Contains(value, "drain"), strings.Contains(value, "reboot"), strings.Contains(value, "reset"), strings.Contains(value, "node"), strings.Contains(value, "gpu"):
		return domain.ActionOwnerClusterOperations
	default:
		return domain.ActionOwnerSherlock
	}
}

func actionUrgency(severity string) domain.ActionUrgency {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return domain.ActionUrgencyImmediate
	case "WARNING":
		return domain.ActionUrgencyNextShift
	case "INFO":
		return domain.ActionUrgencyPlanned
	default:
		return domain.ActionUrgencyMonitor
	}
}

// boundedFindingSeverity lets the model propose a severity and then bounds it
// deterministically. Severity decides operational action -- RMA, drain,
// monitor, ignore -- so the model, which holds the reasoning context, may
// propose it, but it must not be the only thing standing between a sentence
// and someone draining a node.
//
// The bound available today is a ceiling on evidence quality, not the floor on
// signal criticality the design originally imagined: investigation evidence
// carries no health-signal severity, so there is nothing to raise a finding
// *up* to. What can be enforced is that a claim is never more alarming than
// the data under it. CRITICAL asserts a fault is happening now, which requires
// at least one cited COMPLETE evidence entry; proposed on partial, absent, or
// uncited data it is demoted to WARNING rather than dropped, because the
// concern is usually real even when the support for it is not conclusive.
//
// An unrecognized or missing proposal becomes UNKNOWN, never INFO. Silence is
// not a clean bill of health, and rendering it as one is the failure this step
// exists to correct.
func boundedFindingSeverity(proposed string, citations []string, ledger domain.EvidenceLedger) string {
	severity := domain.HealthSeverity(proposed)
	if domain.ValidateFindingSeverity(proposed) != nil {
		return string(domain.HealthSeverityUnknown)
	}
	if severity != domain.HealthSeverityCritical {
		return string(severity)
	}
	for _, evidenceID := range citations {
		for _, entry := range ledger.Entries() {
			if entry.EvidenceID == domain.EvidenceID(evidenceID) && entry.Status == domain.EvidenceComplete {
				return string(domain.HealthSeverityCritical)
			}
		}
	}
	return string(domain.HealthSeverityWarning)
}

// mapSynthesisSections carries the timeline, the unknowns, and the coverage
// statement into durable state. The controller already requires all three to be
// non-empty before an investigation may complete and pays tokens to produce
// them; until now the mapper read only three of the six response fields and the
// rest were dropped before any operator saw them.
//
// Citations are passed through as the model wrote them and resolved against the
// durable ledger by ReportSection.Validate. Unlike findings, no entity list is
// derived here: a timeline entry is anchored to an instant and an unknown is a
// statement about what the evidence does not cover, so the entity-coverage
// filter that findings use would drop precisely the entries worth keeping.
func (orchestrator *Orchestrator) mapSynthesisSections(response modelprovider.SynthesisResponse, snapshot application.InvestigationSnapshot) ([]domain.ReportSection, error) {
	investigationID := snapshot.Investigation.Request().ID
	sections := make([]domain.ReportSection, 0, len(response.Timeline)+len(response.WhatRemainsUnknown)+len(response.Coverage))
	appendSection := func(kind domain.ReportSectionKind, ordinal int, statement string, observedAt *time.Time, evidenceIDs []string) error {
		id, err := orchestrator.ids.NewID()
		if err != nil {
			return err
		}
		sections = append(sections, domain.ReportSection{ID: domain.ReportSectionID(id), InvestigationID: investigationID, Kind: kind, Ordinal: ordinal, Statement: statement, ObservedAt: observedAt, EvidenceIDs: domainEvidence(evidenceIDs)})
		return nil
	}
	for index, entry := range response.Timeline {
		observedAt := entry.ObservedAt.UTC()
		if err := appendSection(domain.ReportSectionTimeline, index, entry.Statement, &observedAt, entry.EvidenceIDs); err != nil {
			return nil, err
		}
	}
	for index, entry := range response.WhatRemainsUnknown {
		if err := appendSection(domain.ReportSectionUnknown, index, entry.Statement, nil, entry.EvidenceIDs); err != nil {
			return nil, err
		}
	}
	for index, entry := range response.Coverage {
		if err := appendSection(domain.ReportSectionCoverage, index, entry.Statement, nil, entry.EvidenceIDs); err != nil {
			return nil, err
		}
	}
	return sections, nil
}

// deterministicSynthesisFallback publishes only facts already validated into
// the bounded context. It never interprets excerpts or promotes a model's
// rejected output, and every observation cites its source evidence.
func (orchestrator *Orchestrator) deterministicSynthesisFallback(snapshot application.InvestigationSnapshot, context investigationcontext.Context) ([]domain.Finding, error) {
	if len(context.Evidence) == 0 {
		return nil, fmt.Errorf("cannot synthesize a cited fallback without evidence")
	}
	request := snapshot.Investigation.Request()
	findings := make([]domain.Finding, 0, len(context.Evidence)+1)
	for _, evidence := range context.Evidence {
		id, err := orchestrator.ids.NewID()
		if err != nil {
			return nil, err
		}
		statement := fmt.Sprintf("Committed %s evidence has status %s for the requested targets from %s through %s.", evidence.Source, evidence.Status, evidence.ObservedFrom.UTC().Format(time.RFC3339Nano), evidence.ObservedTo.UTC().Format(time.RFC3339Nano))
		findings = append(findings, domain.Finding{ID: domain.FindingID(id), InvestigationID: request.ID, Kind: domain.FindingObservation, Statement: statement, EntityIDs: slices.Clone(evidence.EntityIDs), Severity: "INFO", EvidenceIDs: []domain.EvidenceID{evidence.EvidenceID}, Status: domain.FindingCurrent})
	}
	id, err := orchestrator.ids.NewID()
	if err != nil {
		return nil, err
	}
	findings = append(findings, domain.Finding{ID: domain.FindingID(id), InvestigationID: request.ID, Kind: domain.FindingRecommendation, Statement: "Treat the cited observations as bounded evidence only; collect a later reviewed sample before attributing event onset or root cause.", EntityIDs: slices.Clone(request.Scope.EntityIDs), Severity: "INFO", Status: domain.FindingCurrent})
	return findings, nil
}

func evidenceStrings(values []domain.EvidenceID) []string {
	result := make([]string, len(values))
	for i := range values {
		result[i] = string(values[i])
	}
	return result
}
func domainEvidence(values []string) []domain.EvidenceID {
	result := make([]domain.EvidenceID, len(values))
	for i := range values {
		result[i] = domain.EvidenceID(values[i])
	}
	return result
}

func domainArguments(values []investigationtools.ArgumentValue) []domain.InvestigationArgument {
	result := make([]domain.InvestigationArgument, len(values))
	for index, value := range values {
		result[index] = domain.InvestigationArgument{Name: value.Name, Kind: string(value.Kind), String: value.String, Integer: value.Integer, Boolean: value.Boolean, Timestamp: value.Timestamp, StringList: slices.Clone(value.StringList)}
	}
	return result
}

// StaticAuthority is useful for a deployment whose authenticated actor and
// collector capabilities are fixed for one worker invocation.
type StaticAuthority struct {
	Actor   []auth.Capability
	Cluster []investigationtools.ClusterCapability
}

func (authority StaticAuthority) ResolveInvestigationAuthority(_ context.Context, snapshot application.InvestigationSnapshot) (investigationtools.Filter, error) {
	request := snapshot.Investigation.Request()
	return investigationtools.Filter{ClusterID: request.ClusterID, ActorCapabilities: slices.Clone(authority.Actor), ClusterCapabilities: slices.Clone(authority.Cluster), Scope: request.Scope}, nil
}

type EvidenceContextLoader interface {
	LoadInvestigationEvidenceContext(context.Context, application.InvestigationSnapshot) ([]investigationcontext.EvidenceInput, error)
}

// LedgerContextSource provides a safe minimum context and can optionally load
// bounded normalized evidence projections. It never loads raw artifacts.
type LedgerContextSource struct{ Loader EvidenceContextLoader }

func (source LedgerContextSource) InvestigationContext(ctx context.Context, snapshot application.InvestigationSnapshot) (investigationcontext.Input, error) {
	request := snapshot.Investigation.Request()
	input := investigationcontext.Input{InvestigationID: request.ID, ClusterID: request.ClusterID, Question: request.Question, Scope: request.Scope, SuccessCriteria: slices.Clone(request.SuccessCriteria)}
	if source.Loader != nil {
		loaded, err := source.Loader.LoadInvestigationEvidenceContext(ctx, snapshot)
		if err != nil {
			return investigationcontext.Input{}, err
		}
		input.Evidence = loaded
	} else {
		for _, entry := range snapshot.Evidence.Entries() {
			targets := scopeEvidenceTargets(request.Scope, entry.EntityIDs)
			input.Evidence = append(input.Evidence, investigationcontext.EvidenceInput{EvidenceID: entry.EvidenceID, Status: domain.EvidenceComplete, EntityIDs: slices.Clone(entry.EntityIDs), ObservedFrom: request.Scope.Start, ObservedTo: request.Scope.End, CollectedAt: entry.RecordedAt.UTC(), Source: "investigation-ledger", Summary: "Validated evidence is available under this evidence ID.", Priority: 1, Coverage: domain.EvidenceCoverage{Expected: targets, Covered: slices.Clone(targets)}, ExpectedFrom: request.Scope.Start, ExpectedTo: request.Scope.End})
		}
	}
	protected := map[domain.EvidenceID]struct{}{}
	for _, hypothesis := range snapshot.Hypotheses.Entries() {
		for _, id := range append(slices.Clone(hypothesis.SupportingEvidence), hypothesis.ContradictingEvidence...) {
			protected[id] = struct{}{}
		}
	}
	for _, finding := range snapshot.Findings {
		for _, id := range append(slices.Clone(finding.EvidenceIDs), finding.CounterEvidenceIDs...) {
			protected[id] = struct{}{}
		}
	}
	for index := range input.Evidence {
		_, input.Evidence[index].Protected = protected[input.Evidence[index].EvidenceID]
		// Every current warning stays a distinct item in a repair plan, but none is
		// mandatory: a warning set larger than the encoded limit is compacted with
		// recorded omissions, which keeps the proposal partial instead of failing.
		if request.Purpose == domain.InvestigationPurposeRepairPlan {
			input.Evidence[index].KeepDistinct = true
			input.Evidence[index].PreserveClusterCoverage = true
		}
	}
	for _, hypothesis := range snapshot.Hypotheses.Entries() {
		input.Hypotheses = append(input.Hypotheses, investigationcontext.HypothesisInput{ID: hypothesis.ID, Status: hypothesis.Status, Statement: hypothesis.Statement, SupportingEvidence: slices.Clone(hypothesis.SupportingEvidence), ContradictingEvidence: slices.Clone(hypothesis.ContradictingEvidence)})
	}
	return input, nil
}

func scopeEvidenceTargets(scope domain.InvestigationScope, ids []string) []domain.EvidenceTarget {
	kind := domain.EvidenceTargetCluster
	switch strings.ToLower(scope.EntityKind) {
	case "node":
		kind = domain.EvidenceTargetNode
	case "gpu":
		kind = domain.EvidenceTargetGPU
	case "source":
		kind = domain.EvidenceTargetSource
	}
	result := make([]domain.EvidenceTarget, len(ids))
	for index, id := range ids {
		result[index] = domain.EvidenceTarget{Kind: kind, ID: domain.EvidenceTargetID(id)}
	}
	return result
}

var _ application.InvestigationPlanner = (*Orchestrator)(nil)
var _ application.InvestigationSynthesizer = (*Orchestrator)(nil)
