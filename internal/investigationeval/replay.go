package investigationeval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigation"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

const ReplaySchemaVersion = "sherlock.investigation-replay/v1"

// ReplaySuite contains provider responses and independently reviewed contracts.
// Candidate results are deliberately absent: RunReplay derives them by calling
// the real provider-neutral model and investigation orchestration boundaries.
type ReplaySuite struct {
	SchemaVersion string       `json:"schema_version"`
	SuiteID       string       `json:"suite_id"`
	Description   string       `json:"description"`
	Thresholds    Thresholds   `json:"thresholds"`
	Cases         []ReplayCase `json:"cases"`
}

type ReplayCase struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Question    string    `json:"question"`
	ClusterID   string    `json:"cluster_id"`
	EntityKind  string    `json:"entity_kind"`
	EntityIDs   []string  `json:"entity_ids"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	Contract    Contract  `json:"contract"`
	// DiagnosticTools names the allowed tools this case replays as remote
	// executions rather than as reads over committed evidence. It exists so a
	// fixture can prove the governing invariant: a diagnostic result is an
	// ordinary evidence envelope and must grade identically to a metric result.
	DiagnosticTools []string             `json:"diagnostic_tools,omitempty"`
	PlanningSteps   []ReplayPlanningStep `json:"planning_steps"`
	Synthesis       ReplaySynthesisStep  `json:"synthesis"`
}

type ReplayPlanningStep struct {
	Response modelprovider.PlanningResponse `json:"response"`
	Usage    ReplayUsage                    `json:"usage"`
	Evidence []ReplayEvidence               `json:"evidence"`
}

type ReplaySynthesisStep struct {
	Response modelprovider.SynthesisResponse `json:"response"`
	Usage    ReplayUsage                     `json:"usage"`
}

type ReplayUsage struct {
	InputTokens   int64 `json:"input_tokens"`
	OutputTokens  int64 `json:"output_tokens"`
	CostMicros    int64 `json:"cost_micros"`
	LatencyMillis int64 `json:"latency_millis"`
}

type ReplayEvidence struct {
	EvidenceID      string         `json:"evidence_id"`
	Status          string         `json:"status"`
	EntityIDs       []string       `json:"entity_ids"`
	ObservedFrom    time.Time      `json:"observed_from"`
	ObservedTo      time.Time      `json:"observed_to"`
	Source          string         `json:"source"`
	Summary         string         `json:"summary"`
	Excerpt         string         `json:"excerpt,omitempty"`
	ExpectedTargets []ReplayTarget `json:"expected_targets"`
	ObservedTargets []ReplayTarget `json:"observed_targets"`
}

type ReplayTarget struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

func LoadReplayFile(path string) (ReplaySuite, error) {
	file, err := os.Open(path)
	if err != nil {
		return ReplaySuite{}, fmt.Errorf("open replay suite: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	decoder.DisallowUnknownFields()
	var suite ReplaySuite
	if err := decoder.Decode(&suite); err != nil {
		return ReplaySuite{}, fmt.Errorf("decode replay suite: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ReplaySuite{}, fmt.Errorf("decode replay suite: trailing JSON value")
	}
	if err := suite.validate(); err != nil {
		return ReplaySuite{}, err
	}
	return suite, nil
}

func (suite ReplaySuite) validate() error {
	if suite.SchemaVersion != ReplaySchemaVersion || !validID(suite.SuiteID) || suite.Description == "" {
		return fmt.Errorf("replay suite identity is invalid")
	}
	if err := suite.Thresholds.validate(); err != nil {
		return err
	}
	if len(suite.Cases) == 0 || len(suite.Cases) > 100 {
		return fmt.Errorf("replay suite must contain between 1 and 100 cases")
	}
	seen := map[string]struct{}{}
	for index, replayCase := range suite.Cases {
		if !validID(replayCase.ID) || replayCase.Description == "" || replayCase.Question == "" || !validID(replayCase.ClusterID) || !validID(replayCase.EntityKind) || len(replayCase.EntityIDs) == 0 || replayCase.Start.IsZero() || !replayCase.End.After(replayCase.Start) || len(replayCase.PlanningSteps) < 2 {
			return fmt.Errorf("replay case %d identity or bounds are invalid", index)
		}
		if _, exists := seen[replayCase.ID]; exists {
			return fmt.Errorf("duplicate replay case %q", replayCase.ID)
		}
		seen[replayCase.ID] = struct{}{}
		if err := (Case{ID: replayCase.ID, Description: replayCase.Description, Contract: replayCase.Contract, Candidate: placeholderCandidate(replayCase.Contract)}).validate(); err != nil {
			return fmt.Errorf("replay case %d contract: %w", index, err)
		}
		for stepIndex, step := range replayCase.PlanningSteps {
			if err := step.Usage.validate(); err != nil {
				return fmt.Errorf("replay case %d planning step %d: %w", index, stepIndex, err)
			}
			// A non-final turn must propose exactly one action. Evidence may be
			// absent because the controller can reject a proposal and replan; the
			// replay run then requires evidence from the turn it actually acted on.
			if stepIndex < len(replayCase.PlanningSteps)-1 && (step.Response.Stop || len(step.Response.Actions) != 1) {
				return fmt.Errorf("replay case %d planning action step %d is invalid", index, stepIndex)
			}
			if stepIndex == len(replayCase.PlanningSteps)-1 && !step.Response.Stop {
				return fmt.Errorf("replay case %d final planning step must stop", index)
			}
		}
		if err := replayCase.Synthesis.Usage.validate(); err != nil {
			return fmt.Errorf("replay case %d synthesis: %w", index, err)
		}
	}
	return nil
}

func placeholderCandidate(contract Contract) Candidate {
	tools := make([]ToolCall, len(contract.RequiredTools))
	for index, tool := range contract.RequiredTools {
		tools[index] = ToolCall{ToolID: tool}
	}
	outcome := contract.ExpectedOutcome
	if outcome == "" {
		outcome = "PARTIAL"
	}
	unknowns := slices.Clone(contract.RequiredUnknowns)
	return Candidate{ToolCalls: tools, Outcome: outcome, Unknowns: unknowns}
}

func (usage ReplayUsage) validate() error {
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.CostMicros < 0 || usage.LatencyMillis < 0 {
		return fmt.Errorf("replay usage cannot be negative")
	}
	return nil
}

// RunReplay executes every recorded response through FakeProvider and the real
// Orchestrator, then grades the derived candidates with the ordinary evaluator.
func RunReplay(ctx context.Context, suite ReplaySuite) (Summary, error) {
	if err := suite.validate(); err != nil {
		return Summary{}, err
	}
	cases := make([]Case, 0, len(suite.Cases))
	for _, replayCase := range suite.Cases {
		candidate, err := runReplayCase(ctx, replayCase)
		if err != nil {
			return Summary{}, fmt.Errorf("replay case %s: %w", replayCase.ID, err)
		}
		cases = append(cases, Case{ID: replayCase.ID, Description: replayCase.Description, Contract: replayCase.Contract, Candidate: candidate})
	}
	return Evaluate(Suite{SchemaVersion: SchemaVersion, SuiteID: suite.SuiteID, Description: suite.Description, Thresholds: suite.Thresholds, Cases: cases})
}

func runReplayCase(ctx context.Context, replayCase ReplayCase) (Candidate, error) {
	const providerName, modelName, configID = "fixture", "recorded-m96-v1", "m96-replay-v1"
	planning := make([]modelprovider.PlanningStep, len(replayCase.PlanningSteps))
	for index, step := range replayCase.PlanningSteps {
		planning[index] = modelprovider.PlanningStep{Result: modelprovider.PlanningResult{Response: step.Response, Metadata: replayMetadata(step.Usage, providerName, modelName, configID)}}
	}
	provider, err := modelprovider.NewFakeProvider(planning, []modelprovider.SynthesisStep{{Result: modelprovider.SynthesisResult{Response: replayCase.Synthesis.Response, Metadata: replayMetadata(replayCase.Synthesis.Usage, providerName, modelName, configID)}}})
	if err != nil {
		return Candidate{}, err
	}
	definitions := make([]investigationtools.Definition, 0, len(replayCase.Contract.AllowedTools))
	capabilities := make([]investigationtools.ClusterCapability, 0, len(replayCase.Contract.AllowedTools))
	for _, tool := range replayCase.Contract.AllowedTools {
		capability := investigationtools.ClusterCapability("replay." + tool)
		capabilities = append(capabilities, capability)
		definition := investigationtools.Definition{SchemaVersion: investigationtools.SchemaVersion, ID: investigationtools.ToolID(tool), Description: "Read precommitted replay evidence for " + tool, Operation: investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{domain.ClusterID(replayCase.ClusterID)}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{capability}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{replayCase.EntityKind}, MaxTargets: 256, MaxWindow: replayCase.End.Sub(replayCase.Start)}, Timeout: time.Second, CostWeight: 1}
		if slices.Contains(replayCase.DiagnosticTools, tool) {
			definition.Description = "Observe live state for " + tool
			definition.Operation, definition.MinimumReexecutionInterval = investigationtools.OperationDiagnostic, time.Minute
		}
		definitions = append(definitions, definition)
	}
	catalog, err := investigationtools.NewCatalog(definitions)
	if err != nil {
		return Candidate{}, err
	}
	builder, err := investigationcontext.NewBuilder(investigationcontext.DefaultLimits())
	if err != nil {
		return Candidate{}, err
	}
	contextSource := &replayContextSource{values: map[domain.EvidenceID]ReplayEvidence{}}
	audits := &replayAuditStore{reservations: map[string]application.ModelCallReservationStatus{}}
	duplicates := &replayDuplicateStore{seen: map[domain.SHA256]struct{}{}}
	clock := replayClock{now: replayCase.End.Add(time.Minute)}
	ids := &replayIDs{}
	orchestrator, err := investigation.NewOrchestrator(provider, catalog, investigation.StaticAuthority{Actor: []auth.Capability{auth.CapabilityInvestigationsRun}, Cluster: capabilities}, duplicates, contextSource, builder, audits, clock, ids, investigation.Config{Provider: providerName, Model: modelName, ModelConfigVersion: configID, PlanningPrompt: "planning-v2", SynthesisPrompt: "synthesis-v2", ToolSchemaVersion: "catalog-v1", ModelCallReservationTTL: time.Minute})
	if err != nil {
		return Candidate{}, err
	}
	request := domain.InvestigationRequest{ID: domain.InvestigationID("replay-" + replayCase.ID), IncidentID: domain.IncidentID("incident-" + replayCase.ID), ClusterID: domain.ClusterID(replayCase.ClusterID), Question: replayCase.Question, RequestedBy: "m96-evaluator", IdempotencyKey: "m96-" + replayCase.ID, Scope: domain.InvestigationScope{EntityKind: replayCase.EntityKind, EntityIDs: slices.Clone(replayCase.EntityIDs), Start: replayCase.Start, End: replayCase.End}, SuccessCriteria: []string{"produce the independently reviewed evidence-supported outcome"}, Budget: domain.InvestigationBudget{MaxDecisions: 32, MaxToolCalls: 31, MaxDiagnosticCalls: len(replayCase.DiagnosticTools) * 8, MaxFanOut: 4096, MaxModelTokens: 1_000_000, MaxCostMicros: 1_000_000}, RequestedAt: replayCase.End, Deadline: replayCase.End.Add(time.Hour)}
	investigationState, err := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{}, nil, 1)
	if err != nil {
		return Candidate{}, err
	}
	snapshot := application.InvestigationSnapshot{Investigation: investigationState}
	usage := domain.InvestigationBudgetUsage{}
	evidenceEntries := []domain.InvestigationEvidence{}
	candidate := Candidate{}
	// One decision can consume more than one recorded planning turn: when the
	// controller rejects a proposal it replans in place, so recorded turns are
	// driven by what the provider actually served rather than by a fixed
	// one-turn-per-decision assumption.
	consumed, decisions := 0, 0
	for consumed < len(replayCase.PlanningSteps) {
		admitted := len(candidate.ToolCalls)
		decision, err := orchestrator.Decide(ctx, snapshot)
		if err != nil {
			return Candidate{}, err
		}
		served := len(provider.PlanningCalls()) - consumed
		if served < 1 {
			return Candidate{}, fmt.Errorf("decision %d served no recorded planning turn", decisions+1)
		}
		// Every turn of one decision, including a replan, must still see the
		// durable prior actions and evidence admitted before that decision.
		for offset, call := range provider.PlanningCalls()[consumed : consumed+served] {
			if len(call.PriorActions) != admitted || (admitted > 0 && len(call.Evidence) < admitted) {
				return Candidate{}, fmt.Errorf("planning call %d lost durable prior-action or evidence context", consumed+offset+1)
			}
		}
		turns := replayCase.PlanningSteps[consumed : consumed+served]
		for offset, turn := range turns {
			// Only the turn a decision acts on may carry evidence; a rejected
			// turn produced no durable observation.
			if offset < len(turns)-1 && len(turn.Evidence) > 0 {
				return Candidate{}, fmt.Errorf("rejected planning turn %d cannot carry evidence", consumed+offset+1)
			}
			candidate.LatencyMillis += turn.Usage.LatencyMillis
		}
		step := turns[len(turns)-1]
		consumed += served
		decisions++
		candidate.ModelTokens += decision.ModelTokens
		candidate.CostMicros += decision.CostMicros
		usage.Decisions++
		usage.ModelTokens += decision.ModelTokens
		usage.CostMicros += decision.CostMicros
		if decision.Stop {
			if consumed != len(replayCase.PlanningSteps) {
				return Candidate{}, fmt.Errorf("replay stopped with %d recorded planning turns unconsumed", len(replayCase.PlanningSteps)-consumed)
			}
			snapshot.RequestedOutcome, snapshot.RequestedStop = decision.Outcome, decision.Reason
			break
		}
		if consumed == len(replayCase.PlanningSteps) {
			return Candidate{}, fmt.Errorf("final replay decision did not stop")
		}
		if decision.Action == nil {
			return Candidate{}, fmt.Errorf("decision %d produced no action", decisions)
		}
		if len(step.Evidence) == 0 {
			return Candidate{}, fmt.Errorf("admitted planning turn %d recorded no evidence", consumed)
		}
		// Record the full invocation so redundancy is graded on what the
		// controller actually admitted, not on the tool identifier alone.
		candidate.ToolCalls = append(candidate.ToolCalls, ToolCall{ToolID: decision.Action.ToolID, Targets: slices.Clone(decision.Action.Targets), Start: decision.Action.Start.UTC().Format(time.RFC3339), End: decision.Action.End.UTC().Format(time.RFC3339)})
		usage.ToolCalls++
		usage.FanOut += decision.Action.FanOut
		evidenceIDs := make([]domain.EvidenceID, 0, len(step.Evidence))
		for _, value := range step.Evidence {
			entry, input, err := replayEvidenceValues(value, request, replayCase.End.Add(time.Minute))
			if err != nil {
				return Candidate{}, err
			}
			evidenceEntries = append(evidenceEntries, entry)
			contextSource.values[entry.EvidenceID] = input
			evidenceIDs = append(evidenceIDs, entry.EvidenceID)
		}
		duplicates.seen[decision.Action.Digest] = struct{}{}
		snapshot.PriorActions = append(snapshot.PriorActions, application.InvestigationActionHistory{Digest: decision.Action.Digest, ToolID: decision.Action.ToolID, Outcome: "SUCCEEDED", Targets: slices.Clone(decision.Action.Targets), Start: decision.Action.Start, End: decision.Action.End, EvidenceIDs: evidenceIDs})
		investigationState, err = domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", usage, nil, decisions+1)
		if err != nil {
			return Candidate{}, err
		}
		ledger, err := domain.NewEvidenceLedger(evidenceEntries, investigationState)
		if err != nil {
			return Candidate{}, err
		}
		snapshot.Investigation, snapshot.Evidence = investigationState, ledger
	}
	investigationState, err = domain.ReconstituteInvestigation(request, domain.InvestigationSynthesizing, "", usage, nil, decisions+2)
	if err != nil {
		return Candidate{}, err
	}
	snapshot.Investigation = investigationState
	synthesis, err := orchestrator.Synthesize(ctx, snapshot)
	if err != nil {
		return Candidate{}, err
	}
	candidate.ModelTokens += synthesis.ModelTokens
	candidate.CostMicros += synthesis.CostMicros
	candidate.LatencyMillis += replayCase.Synthesis.Usage.LatencyMillis
	for _, finding := range synthesis.Findings {
		if len(finding.EvidenceIDs) == 0 {
			continue
		}
		ids := make([]string, len(finding.EvidenceIDs))
		for index, id := range finding.EvidenceIDs {
			ids[index] = string(id)
		}
		candidate.Findings = append(candidate.Findings, Finding{Statement: finding.Statement, EvidenceIDs: ids})
	}
	// Report content is read from the durable sections the orchestrator mapped,
	// not from the recorded response. Reading the fixture back would assert only
	// that the fixture matches itself: the mapping could be deleted outright and
	// every case would still pass.
	for _, section := range synthesis.Sections {
		switch section.Kind {
		case domain.ReportSectionTimeline:
			observedAt := ""
			if section.ObservedAt != nil {
				observedAt = section.ObservedAt.UTC().Format(time.RFC3339Nano)
			}
			ids := make([]string, len(section.EvidenceIDs))
			for index, id := range section.EvidenceIDs {
				ids[index] = string(id)
			}
			candidate.Timeline = append(candidate.Timeline, CandidateTimelineEntry{ObservedAt: observedAt, Statement: section.Statement, EvidenceIDs: ids})
		case domain.ReportSectionUnknown:
			candidate.Unknowns = append(candidate.Unknowns, section.Statement)
		case domain.ReportSectionCoverage:
			candidate.Coverage = append(candidate.Coverage, section.Statement)
		}
	}
	// Severity is graded from the durable findings, so a report that collapses
	// every finding to one level fails its distribution requirement.
	for _, finding := range synthesis.Findings {
		candidate.Severities = append(candidate.Severities, finding.Severity)
	}
	candidate.Outcome, candidate.StopReason = replayTerminal(snapshot.RequestedOutcome, snapshot.RequestedStop, synthesis.Disposition)
	planningCalls := provider.PlanningCalls()
	if len(planningCalls) != len(replayCase.PlanningSteps) {
		return Candidate{}, fmt.Errorf("provider recorded %d planning calls, want %d", len(planningCalls), len(replayCase.PlanningSteps))
	}
	synthesisCalls := provider.SynthesisCalls()
	if len(synthesisCalls) != 1 || len(synthesisCalls[0].Evidence) != len(evidenceEntries) {
		return Candidate{}, fmt.Errorf("synthesis did not receive the complete replay evidence ledger")
	}
	if err := audits.validateComplete(len(replayCase.PlanningSteps) + 1); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

func replayMetadata(usage ReplayUsage, provider, model, config string) modelprovider.CallMetadata {
	return modelprovider.CallMetadata{Provider: provider, Model: model, ConfigurationID: config, InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens, CostMicros: usage.CostMicros, Latency: time.Duration(usage.LatencyMillis) * time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}
}

func replayTerminal(outcome domain.InvestigationStatus, reason domain.InvestigationStopReason, disposition application.InvestigationSynthesisDisposition) (string, string) {
	if disposition == application.SynthesisValidatedComplete && ((outcome == domain.InvestigationCompleted && reason == domain.StopSuccessCriteriaMet) || (outcome == domain.InvestigationPartial && reason == domain.StopNoUsefulAction)) {
		return string(domain.InvestigationCompleted), string(domain.StopSuccessCriteriaMet)
	}
	if outcome == domain.InvestigationCompleted {
		return string(domain.InvestigationPartial), string(domain.StopNoUsefulAction)
	}
	return string(outcome), string(reason)
}

func replayEvidenceValues(value ReplayEvidence, request domain.InvestigationRequest, recordedAt time.Time) (domain.InvestigationEvidence, ReplayEvidence, error) {
	status := domain.EvidenceStatus(value.Status)
	entry := domain.InvestigationEvidence{EvidenceID: domain.EvidenceID(value.EvidenceID), InvestigationID: request.ID, ClusterID: request.ClusterID, EntityIDs: slices.Clone(value.EntityIDs), Status: status, ObservedStart: value.ObservedFrom, ObservedEnd: value.ObservedTo, RecordedAt: recordedAt}
	if err := entry.ValidateFor(mustReplayInvestigation(request)); err != nil {
		return domain.InvestigationEvidence{}, ReplayEvidence{}, err
	}
	return entry, value, nil
}

func mustReplayInvestigation(request domain.InvestigationRequest) domain.Investigation {
	value, _ := domain.ReconstituteInvestigation(request, domain.InvestigationPlanning, "", domain.InvestigationBudgetUsage{}, nil, 1)
	return value
}

type replayContextSource struct {
	values map[domain.EvidenceID]ReplayEvidence
}

func (source *replayContextSource) InvestigationContext(_ context.Context, snapshot application.InvestigationSnapshot) (investigationcontext.Input, error) {
	request := snapshot.Investigation.Request()
	input := investigationcontext.Input{InvestigationID: request.ID, ClusterID: request.ClusterID, Question: request.Question, Scope: request.Scope, SuccessCriteria: slices.Clone(request.SuccessCriteria)}
	for _, entry := range snapshot.Evidence.Entries() {
		value, ok := source.values[entry.EvidenceID]
		if !ok {
			return investigationcontext.Input{}, fmt.Errorf("replay evidence %s is unavailable", entry.EvidenceID)
		}
		expected, observed := replayTargets(value.ExpectedTargets), replayTargets(value.ObservedTargets)
		input.Evidence = append(input.Evidence, investigationcontext.EvidenceInput{EvidenceID: entry.EvidenceID, Status: entry.Status, EntityIDs: slices.Clone(entry.EntityIDs), ObservedFrom: entry.ObservedStart, ObservedTo: entry.ObservedEnd, CollectedAt: entry.RecordedAt, Source: value.Source, Summary: value.Summary, Excerpt: value.Excerpt, Priority: 1, Coverage: domain.EvidenceCoverage{Expected: expected, Covered: observed}, ExpectedFrom: request.Scope.Start, ExpectedTo: request.Scope.End})
	}
	for _, hypothesis := range snapshot.Hypotheses.Entries() {
		input.Hypotheses = append(input.Hypotheses, investigationcontext.HypothesisInput{ID: hypothesis.ID, Status: hypothesis.Status, Statement: hypothesis.Statement, SupportingEvidence: slices.Clone(hypothesis.SupportingEvidence), ContradictingEvidence: slices.Clone(hypothesis.ContradictingEvidence)})
	}
	return input, nil
}

func replayTargets(values []ReplayTarget) []domain.EvidenceTarget {
	result := make([]domain.EvidenceTarget, len(values))
	for index, value := range values {
		result[index] = domain.EvidenceTarget{Kind: domain.EvidenceTargetKind(value.Kind), ID: domain.EvidenceTargetID(value.ID)}
	}
	return result
}

type replayDuplicateStore struct{ seen map[domain.SHA256]struct{} }

func (store *replayDuplicateStore) HasInvestigationActionDigest(_ context.Context, _ domain.InvestigationID, digest domain.SHA256) (bool, error) {
	_, exists := store.seen[digest]
	return exists, nil
}

type replayAuditStore struct {
	mu           sync.Mutex
	reservations map[string]application.ModelCallReservationStatus
	audits       []application.ModelCallAudit
}

func (store *replayAuditStore) ReserveModelCall(_ context.Context, _ domain.InvestigationID, _ domain.ClusterID, key string, _ application.ModelCallKind, _, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.reservations[key]; exists {
		return application.ErrModelCallAlreadyAttempted
	}
	store.reservations[key] = application.ModelCallReserved
	return nil
}

func (store *replayAuditStore) CompleteModelCall(_ context.Context, _ domain.InvestigationID, key string, status application.ModelCallReservationStatus, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.reservations[key]; !exists {
		return fmt.Errorf("model call reservation is missing")
	}
	store.reservations[key] = status
	return nil
}

func (store *replayAuditStore) AppendModelCallAudit(_ context.Context, audit application.ModelCallAudit) error {
	if err := audit.Validate(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.audits = append(store.audits, audit)
	return nil
}

func (store *replayAuditStore) validateComplete(want int) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.audits) != want || len(store.reservations) != want {
		return fmt.Errorf("model audit completeness mismatch: audits=%d reservations=%d want=%d", len(store.audits), len(store.reservations), want)
	}
	// A rejected call is a legitimate terminal state: the controller refuses a
	// proposal, such as a duplicate, and replans. Every reservation must still
	// be closed, and nothing may fail or expire with an unknown outcome.
	for key, status := range store.reservations {
		if status != application.ModelCallSucceededState && status != application.ModelCallRejectedState {
			return fmt.Errorf("model call %s ended in %s", key, status)
		}
	}
	for _, audit := range store.audits {
		if audit.Outcome == application.ModelCallRejected && audit.ReasonCode == "" {
			return fmt.Errorf("rejected model call %s recorded no reason code", audit.CallKey)
		}
	}
	return nil
}

type replayClock struct{ now time.Time }

func (clock replayClock) Now() time.Time { return clock.now }

type replayIDs struct {
	mu   sync.Mutex
	next int
}

func (ids *replayIDs) NewID() (string, error) {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	ids.next++
	return fmt.Sprintf("m96-%d", ids.next), nil
}
