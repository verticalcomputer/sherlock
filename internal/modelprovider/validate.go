package modelprovider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"
)

type ResponseValidationStage string

const (
	ResponseStructuredDecode   ResponseValidationStage = "STRUCTURED_DECODE"
	ResponseSemanticValidation ResponseValidationStage = "SEMANTIC_VALIDATION"
)

// ResponseValidationError distinguishes safe validation stages without
// carrying model output across the provider boundary.
type ResponseValidationError struct {
	Stage ResponseValidationStage
	err   error
}

func (err *ResponseValidationError) Error() string {
	if err == nil {
		return "model response validation failed"
	}
	return "model response validation failed at " + string(err.Stage)
}

func (err *ResponseValidationError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.err
}

func DecodePlanningRequest(data []byte) (PlanningRequest, error) {
	var value PlanningRequest
	if err := decodeStrict(data, &value); err != nil {
		return PlanningRequest{}, fmt.Errorf("decode planning request: %w", err)
	}
	if err := value.Validate(); err != nil {
		return PlanningRequest{}, err
	}
	return value, nil
}

func DecodePlanningResponse(data []byte, request PlanningRequest) (PlanningResponse, error) {
	var value PlanningResponse
	if err := decodeStrict(data, &value); err != nil {
		return PlanningResponse{}, &ResponseValidationError{Stage: ResponseStructuredDecode, err: err}
	}
	if len(request.Evidence) == 0 {
		for index := range value.HypothesisUpdates {
			value.HypothesisUpdates[index].SupportingEvidence = canonicalizeNoEvidenceSentinel(value.HypothesisUpdates[index].SupportingEvidence)
			value.HypothesisUpdates[index].ContradictingEvidence = canonicalizeNoEvidenceSentinel(value.HypothesisUpdates[index].ContradictingEvidence)
		}
	}
	for index := range value.HypothesisUpdates {
		value.HypothesisUpdates[index].ContradictingEvidence = removeCitationOverlap(value.HypothesisUpdates[index].SupportingEvidence, value.HypothesisUpdates[index].ContradictingEvidence)
	}
	if err := value.ValidateFor(request); err != nil {
		return PlanningResponse{}, &ResponseValidationError{Stage: ResponseSemanticValidation, err: err}
	}
	return value, nil
}

func DecodeSynthesisRequest(data []byte) (SynthesisRequest, error) {
	var value SynthesisRequest
	if err := decodeStrict(data, &value); err != nil {
		return SynthesisRequest{}, fmt.Errorf("decode synthesis request: %w", err)
	}
	if err := value.Validate(); err != nil {
		return SynthesisRequest{}, err
	}
	return value, nil
}

func DecodeSynthesisResponse(data []byte, request SynthesisRequest) (SynthesisResponse, error) {
	var value SynthesisResponse
	if err := decodeStrict(data, &value); err != nil {
		return SynthesisResponse{}, &ResponseValidationError{Stage: ResponseStructuredDecode, err: err}
	}
	if len(request.Evidence) == 0 {
		canonicalizeNoEvidenceSynthesis(&value)
	}
	for index := range value.LikelyExplanations {
		value.LikelyExplanations[index].CounterEvidenceIDs = removeCitationOverlap(value.LikelyExplanations[index].EvidenceIDs, value.LikelyExplanations[index].CounterEvidenceIDs)
	}
	if err := value.ValidateFor(request); err != nil {
		return SynthesisResponse{}, &ResponseValidationError{Stage: ResponseSemanticValidation, err: err}
	}
	return value, nil
}

func canonicalizeNoEvidenceSentinel(values []string) []string {
	if len(values) == 0 {
		return values
	}
	for _, value := range values {
		if value != NoEvidenceCitationSentinel {
			return values
		}
	}
	return []string{}
}

// removeCitationOverlap deterministically preserves the model's supporting
// relationship when it assigned the same committed evidence both roles. The
// immutable audit payload retains the provider's exact response; only the
// decoded, domain-bound value is repaired before strict semantic validation.
func removeCitationOverlap(supporting, contradicting []string) []string {
	if len(supporting) == 0 || len(contradicting) == 0 {
		return contradicting
	}
	support := make(map[string]struct{}, len(supporting))
	for _, evidenceID := range supporting {
		support[evidenceID] = struct{}{}
	}
	result := make([]string, 0, len(contradicting))
	for _, evidenceID := range contradicting {
		if _, overlaps := support[evidenceID]; !overlaps {
			result = append(result, evidenceID)
		}
	}
	return result
}

func canonicalizeNoEvidenceSynthesis(value *SynthesisResponse) {
	for index := range value.WhatIsHappening {
		value.WhatIsHappening[index].EvidenceIDs = canonicalizeNoEvidenceSentinel(value.WhatIsHappening[index].EvidenceIDs)
	}
	for index := range value.Timeline {
		value.Timeline[index].EvidenceIDs = canonicalizeNoEvidenceSentinel(value.Timeline[index].EvidenceIDs)
	}
	for index := range value.LikelyExplanations {
		value.LikelyExplanations[index].EvidenceIDs = canonicalizeNoEvidenceSentinel(value.LikelyExplanations[index].EvidenceIDs)
		value.LikelyExplanations[index].CounterEvidenceIDs = canonicalizeNoEvidenceSentinel(value.LikelyExplanations[index].CounterEvidenceIDs)
	}
	for index := range value.WhatRemainsUnknown {
		value.WhatRemainsUnknown[index].EvidenceIDs = canonicalizeNoEvidenceSentinel(value.WhatRemainsUnknown[index].EvidenceIDs)
	}
	for index := range value.SuggestedNextSteps {
		value.SuggestedNextSteps[index].EvidenceIDs = canonicalizeNoEvidenceSentinel(value.SuggestedNextSteps[index].EvidenceIDs)
	}
	for index := range value.Coverage {
		value.Coverage[index].EvidenceIDs = canonicalizeNoEvidenceSentinel(value.Coverage[index].EvidenceIDs)
	}
}

func decodeStrict(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxDocumentBytes {
		return fmt.Errorf("document size is invalid")
	}
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return fmt.Errorf("document has invalid JSON structure")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field") {
			return fmt.Errorf("document contains an unknown field")
		}
		return fmt.Errorf("document does not match the structured schema")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("document must contain exactly one JSON value")
	}
	return nil
}

func (request PlanningRequest) Validate() error {
	if request.SchemaVersion != PlanningSchemaVersion {
		return fmt.Errorf("unsupported planning schema version %d", request.SchemaVersion)
	}
	if !validToken(request.InvestigationID) || !validText(request.Question, 4096) || !validText(request.StateSummary, 4096) || !validToken(request.PromptVersion) || !validToken(request.ToolSchemaVersion) {
		return fmt.Errorf("planning request identity or text is invalid")
	}
	if (request.ContextMode != "" && request.ContextMode != "STATELESS") || request.DeltaFromVersion < 0 || (request.CheckpointDigest != "" && (len(request.CheckpointDigest) != 64 || !validToken(request.CheckpointDigest))) {
		return fmt.Errorf("planning context lineage is invalid")
	}
	if err := request.Scope.validate(); err != nil {
		return err
	}
	if request.PriorActionsOmitted < 0 || len(request.SuccessCriteria) == 0 || len(request.SuccessCriteria) > 32 || len(request.AvailableTools) > 64 || len(request.Evidence) > 256 || len(request.Hypotheses) > 128 || len(request.PriorActions) > 256 || len(request.Memory) > 12 {
		return fmt.Errorf("planning request collection bounds are invalid")
	}
	if request.RemainingBudget.Decisions < 0 || request.RemainingBudget.ToolCalls < 0 || request.RemainingBudget.DiagnosticCalls < 0 || request.RemainingBudget.PrivilegedCalls < 0 || request.RemainingBudget.FanOut < 0 || request.RemainingBudget.ModelTokens < 0 || request.RemainingBudget.CostMicros < 0 {
		return fmt.Errorf("remaining budget cannot be negative")
	}
	for _, value := range request.SuccessCriteria {
		if !validText(value, 512) {
			return fmt.Errorf("success criterion is invalid")
		}
	}
	toolIDs := map[string]struct{}{}
	if len(request.SharedToolArguments) != 0 && !validJSONObject(request.SharedToolArguments, 128<<10) {
		return fmt.Errorf("shared tool arguments are invalid")
	}
	for _, tool := range request.AvailableTools {
		if err := tool.validate(); err != nil {
			return err
		}
		if _, exists := toolIDs[tool.ToolID]; exists {
			return fmt.Errorf("available tool IDs must be unique")
		}
		toolIDs[tool.ToolID] = struct{}{}
	}
	evidenceIDs := map[string]struct{}{}
	for _, evidence := range request.Evidence {
		if err := evidence.validate(request.Scope); err != nil {
			return err
		}
		if _, exists := evidenceIDs[evidence.EvidenceID]; exists {
			return fmt.Errorf("evidence IDs must be unique")
		}
		evidenceIDs[evidence.EvidenceID] = struct{}{}
	}
	for _, hypothesis := range request.Hypotheses {
		if err := hypothesis.validate(evidenceIDs); err != nil {
			return err
		}
	}
	for _, action := range request.PriorActions {
		if action.EvidenceOmitted < 0 || !validDigest(action.ActionDigest) || !validToken(action.ToolID) || !validToken(action.Outcome) || len(action.Targets) == 0 || action.Start.IsZero() || action.End.Before(action.Start) {
			return fmt.Errorf("prior action is invalid")
		}
		if err := validateScopeEntities(action.Targets, request.Scope.EntityIDs); err != nil || action.Start.Before(request.Scope.Start) || action.End.After(request.Scope.End) {
			return fmt.Errorf("prior action is outside the investigation scope")
		}
		if err := validateCitations(action.EvidenceIDs, evidenceIDs, false); err != nil {
			return fmt.Errorf("prior action evidence: %w", err)
		}
	}
	for _, memory := range request.Memory {
		if !validToken(memory.MemoryID) || !validToken(memory.TrustClass) || !validText(memory.Statement, 2048) || !validToken(memory.SourceInvestigationID) || len(memory.EntityIDs) == 0 || !uniqueValidTokens(memory.EntityIDs) || memory.ValidFrom.IsZero() || len(memory.EvidenceIDs) == 0 || !uniqueValidTokens(memory.EvidenceIDs) {
			return fmt.Errorf("planning memory context is invalid")
		}
	}
	if err := request.Coverage.validate(request.Scope); err != nil {
		return err
	}
	if request.Coverage.EvidenceSelected != len(request.Evidence) {
		return fmt.Errorf("planning coverage evidence count is inconsistent")
	}
	return nil
}

func (response PlanningResponse) ValidateFor(request PlanningRequest) error {
	if err := request.Validate(); err != nil {
		return fmt.Errorf("invalid planning request: %w", err)
	}
	if response.SchemaVersion != PlanningSchemaVersion || !validText(response.StateSummary, 4096) || len(response.Actions) > 16 || len(response.HypothesisUpdates) > 64 {
		return fmt.Errorf("planning response schema or bounds are invalid")
	}
	if response.Stop {
		if len(response.Actions) != 0 || response.StopReason == nil || !response.StopReason.valid() {
			return fmt.Errorf("stopping response requires a valid reason and no actions")
		}
	} else if response.StopReason != nil || len(response.Actions) == 0 {
		return fmt.Errorf("continuing response requires actions and no stop reason")
	}
	allowedTools := map[string]AvailableTool{}
	for _, tool := range request.AvailableTools {
		allowedTools[tool.ToolID] = tool
	}
	priorities := map[int]struct{}{}
	for _, action := range response.Actions {
		tool, exists := allowedTools[action.ToolID]
		if !exists || tool.ReadOnly == tool.Diagnostic {
			return fmt.Errorf("planned action uses an unavailable tool")
		}
		if action.Priority < 1 || action.Priority > len(response.Actions) || !validText(action.Purpose, 1024) || !validText(action.ExpectedInformation, 1024) || !validJSONObject(action.Arguments, 64<<10) {
			return fmt.Errorf("planned action is invalid")
		}
		if _, exists := priorities[action.Priority]; exists {
			return fmt.Errorf("planned action priorities must be unique")
		}
		priorities[action.Priority] = struct{}{}
	}
	evidenceIDs := evidenceIDSet(request.Evidence)
	existingHypotheses := make(map[string]struct{}, len(request.Hypotheses))
	for _, hypothesis := range request.Hypotheses {
		existingHypotheses[hypothesis.HypothesisID] = struct{}{}
	}
	updatedHypotheses := map[string]struct{}{}
	for _, update := range response.HypothesisUpdates {
		if !validToken(update.HypothesisID) || !validText(update.Statement, 2048) || !validHypothesisStatus(update.Status) || update.Confidence < 0 || update.Confidence > 1 || len(update.UnresolvedTests) > 32 {
			return fmt.Errorf("hypothesis update is invalid")
		}
		if update.HypothesisID != NewHypothesisID {
			if _, exists := existingHypotheses[update.HypothesisID]; !exists {
				return fmt.Errorf("hypothesis update must reference an existing ID or request a new server-owned ID")
			}
			if _, duplicate := updatedHypotheses[update.HypothesisID]; duplicate {
				return fmt.Errorf("hypothesis update is duplicated")
			}
			updatedHypotheses[update.HypothesisID] = struct{}{}
		}
		if err := validateCitations(update.SupportingEvidence, evidenceIDs, false); err != nil {
			return fmt.Errorf("hypothesis support: %w", err)
		}
		if err := validateCitations(update.ContradictingEvidence, evidenceIDs, false); err != nil {
			return fmt.Errorf("hypothesis contradiction: %w", err)
		}
		if update.Status == "SUPPORTED" && len(update.SupportingEvidence) == 0 {
			return fmt.Errorf("supported hypothesis requires supporting evidence")
		}
		if (update.Status == "WEAKENED" || update.Status == "REFUTED") && len(update.ContradictingEvidence) == 0 {
			return fmt.Errorf("weakened or refuted hypothesis requires contradicting evidence")
		}
		if overlaps(update.SupportingEvidence, update.ContradictingEvidence) {
			return fmt.Errorf("hypothesis evidence cannot support and contradict")
		}
		for _, test := range update.UnresolvedTests {
			if !validText(test, 512) {
				return fmt.Errorf("unresolved test is invalid")
			}
		}
	}
	return nil
}

func (reason PlanningStopReason) valid() bool {
	switch reason {
	case StopSuccessCriteriaMet, StopNoUsefulAction, StopAccessUnavailable, StopSourceUnavailable, StopBudgetExceeded:
		return true
	default:
		return false
	}
}

func (request SynthesisRequest) Validate() error {
	if request.SchemaVersion != SynthesisSchemaVersion || !validToken(request.InvestigationID) || !validText(request.Question, 4096) || !validToken(request.Outcome) || !validToken(request.PromptVersion) {
		return fmt.Errorf("synthesis request identity or schema is invalid")
	}
	if (request.ContextMode != "" && request.ContextMode != "STATELESS") || request.DeltaFromVersion < 0 || (request.CheckpointDigest != "" && (len(request.CheckpointDigest) != 64 || !validToken(request.CheckpointDigest))) {
		return fmt.Errorf("synthesis context lineage is invalid")
	}
	if err := request.Scope.validate(); err != nil {
		return err
	}
	if len(request.Evidence) > 256 || len(request.Hypotheses) > 128 || len(request.Findings) > 256 {
		return fmt.Errorf("synthesis request collection bounds are invalid")
	}
	evidenceIDs := map[string]struct{}{}
	for _, evidence := range request.Evidence {
		if err := evidence.validate(request.Scope); err != nil {
			return err
		}
		if _, exists := evidenceIDs[evidence.EvidenceID]; exists {
			return fmt.Errorf("evidence IDs must be unique")
		}
		evidenceIDs[evidence.EvidenceID] = struct{}{}
	}
	for _, hypothesis := range request.Hypotheses {
		if err := hypothesis.validate(evidenceIDs); err != nil {
			return err
		}
	}
	for _, finding := range request.Findings {
		if !validToken(finding.FindingID) || !validFindingKind(finding.Kind) || !validText(finding.Statement, 4096) || !validToken(finding.Severity) || len(finding.EntityIDs) == 0 || !uniqueValidTokens(finding.EntityIDs) {
			return fmt.Errorf("validated finding is invalid")
		}
		for _, id := range finding.EntityIDs {
			if !slices.Contains(request.Scope.EntityIDs, id) {
				return fmt.Errorf("validated finding is outside scope")
			}
		}
		if finding.Kind == "HYPOTHESIS" {
			if finding.Confidence == nil || *finding.Confidence < 0 || *finding.Confidence > 1 {
				return fmt.Errorf("hypothesis finding requires confidence")
			}
		} else if finding.Confidence != nil {
			return fmt.Errorf("confidence is only valid for hypothesis findings")
		}
		if err := validateCitations(finding.EvidenceIDs, evidenceIDs, finding.Kind != "RECOMMENDATION"); err != nil {
			return err
		}
		if err := validateCitations(finding.CounterEvidenceIDs, evidenceIDs, false); err != nil {
			return err
		}
		if overlaps(finding.EvidenceIDs, finding.CounterEvidenceIDs) {
			return fmt.Errorf("finding evidence cannot support and contradict")
		}
	}
	if err := request.Coverage.validate(request.Scope); err != nil {
		return err
	}
	if request.Coverage.EvidenceSelected != len(request.Evidence) {
		return fmt.Errorf("synthesis coverage evidence count is inconsistent")
	}
	return nil
}

func (response SynthesisResponse) ValidateFor(request SynthesisRequest) error {
	if err := request.Validate(); err != nil {
		return fmt.Errorf("invalid synthesis request: %w", err)
	}
	if response.SchemaVersion != SynthesisSchemaVersion || len(response.WhatIsHappening) > 128 || len(response.Timeline) > 256 || len(response.LikelyExplanations) > 128 || len(response.WhatRemainsUnknown) > 128 || len(response.SuggestedNextSteps) > 128 || len(response.Coverage) > 128 {
		return fmt.Errorf("synthesis response schema or bounds are invalid")
	}
	if len(response.WhatIsHappening)+len(response.Timeline)+len(response.LikelyExplanations)+len(response.WhatRemainsUnknown)+len(response.SuggestedNextSteps)+len(response.Coverage) == 0 {
		return fmt.Errorf("synthesis response must contain at least one section entry")
	}
	evidenceIDs := evidenceIDSet(request.Evidence)
	evidenceByID := make(map[string]EvidenceContext, len(request.Evidence))
	for _, evidence := range request.Evidence {
		evidenceByID[evidence.EvidenceID] = evidence
	}
	for _, statement := range response.WhatIsHappening {
		if err := statement.validate(evidenceIDs, true); err != nil {
			return err
		}
		if !validSynthesisSeverity(statement.Severity) {
			return fmt.Errorf("observation severity is invalid")
		}
	}
	for _, entry := range response.Timeline {
		if entry.ObservedAt.IsZero() || !validText(entry.Statement, 4096) {
			return fmt.Errorf("timeline entry is invalid")
		}
		if err := validateCitations(entry.EvidenceIDs, evidenceIDs, true); err != nil {
			return err
		}
		if !timelineTimestampSupported(entry, evidenceByID) {
			return fmt.Errorf("timeline timestamp is not supported by cited evidence")
		}
	}
	for _, explanation := range response.LikelyExplanations {
		if !validText(explanation.Statement, 4096) || explanation.Confidence < 0 || explanation.Confidence > 1 {
			return fmt.Errorf("explanation is invalid")
		}
		if !validSynthesisSeverity(explanation.Severity) {
			return fmt.Errorf("explanation severity is invalid")
		}
		if err := validateCitations(explanation.EvidenceIDs, evidenceIDs, true); err != nil {
			return err
		}
		if err := validateCitations(explanation.CounterEvidenceIDs, evidenceIDs, false); err != nil {
			return err
		}
		if overlaps(explanation.EvidenceIDs, explanation.CounterEvidenceIDs) {
			return fmt.Errorf("explanation evidence cannot support and contradict")
		}
	}
	for _, statement := range response.WhatRemainsUnknown {
		if err := statement.validate(evidenceIDs, true); err != nil {
			return err
		}
		if statement.Severity != "" {
			return fmt.Errorf("unknown statement must not carry a severity")
		}
	}
	for _, statement := range response.SuggestedNextSteps {
		if err := statement.validate(evidenceIDs, false); err != nil {
			return err
		}
		if !validSynthesisSeverity(statement.Severity) {
			return fmt.Errorf("next step severity is invalid")
		}
	}
	for _, statement := range response.Coverage {
		if err := statement.validate(evidenceIDs, true); err != nil {
			return err
		}
		if statement.Severity != "" {
			return fmt.Errorf("coverage statement must not carry a severity")
		}
	}
	return nil
}

func timelineTimestampSupported(entry TimelineEntry, evidenceByID map[string]EvidenceContext) bool {
	for _, evidenceID := range entry.EvidenceIDs {
		evidence, ok := evidenceByID[evidenceID]
		if ok && (entry.ObservedAt.Equal(evidence.ObservedFrom) || entry.ObservedAt.Equal(evidence.ObservedTo)) {
			return true
		}
	}
	return false
}

func (metadata CallMetadata) Validate() error {
	if !validToken(metadata.Provider) || !validToken(metadata.Model) || !validToken(metadata.ConfigurationID) || metadata.InputTokens < 0 || metadata.OutputTokens < 0 || metadata.CostMicros < 0 || metadata.Latency < 0 {
		return fmt.Errorf("model call metadata is invalid")
	}
	if metadata.Outcome != OutcomeSucceeded && metadata.Outcome != OutcomeRefused {
		return fmt.Errorf("unknown model outcome")
	}
	return nil
}

func (result PlanningResult) ValidateFor(request PlanningRequest) error {
	if err := result.Response.ValidateFor(request); err != nil {
		return err
	}
	return result.Metadata.Validate()
}
func (result SynthesisResult) ValidateFor(request SynthesisRequest) error {
	if err := result.Response.ValidateFor(request); err != nil {
		return err
	}
	return result.Metadata.Validate()
}

func (scope Scope) validate() error {
	if !validToken(scope.ClusterID) || !validToken(scope.EntityKind) || len(scope.EntityIDs) == 0 || len(scope.EntityIDs) > 256 || scope.Start.IsZero() || scope.End.IsZero() || scope.End.Before(scope.Start) || !uniqueValidTokens(scope.EntityIDs) {
		return fmt.Errorf("model scope is invalid")
	}
	return nil
}

func validateScopeEntities(values, allowed []string) error {
	if len(values) == 0 || !uniqueValidTokens(values) {
		return fmt.Errorf("scoped entities are invalid")
	}
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return fmt.Errorf("entity is outside the scope")
		}
	}
	return nil
}

func (tool AvailableTool) validate() error {
	if !validToken(tool.ToolID) || !validText(tool.Description, 2048) || !validToken(tool.SchemaVersion) || tool.ReadOnly == tool.Diagnostic || tool.MaximumFanOut < 1 || tool.CostWeight < 1 || !validJSONObject(tool.EffectiveArgumentSchema(), 128<<10) {
		return fmt.Errorf("available tool is invalid or declares no reviewed operation class")
	}
	return nil
}

func (evidence EvidenceContext) validate(scope Scope) error {
	if !validToken(evidence.EvidenceID) || !uniqueValidTokens(evidence.EntityIDs) || len(evidence.EntityIDs) == 0 || evidence.ObservedFrom.IsZero() || evidence.ObservedTo.IsZero() || evidence.ObservedTo.Before(evidence.ObservedFrom) || evidence.ExpectedFrom.IsZero() || evidence.ExpectedTo.Before(evidence.ExpectedFrom) || !validToken(evidence.Status) || !validToken(evidence.Source) || !validText(evidence.Summary, 4096) || len(evidence.UntrustedData) > 16<<10 || strings.ContainsRune(evidence.UntrustedData, '\x00') {
		return fmt.Errorf("evidence context is invalid")
	}
	for _, id := range evidence.EntityIDs {
		if !slices.Contains(scope.EntityIDs, id) {
			return fmt.Errorf("evidence context is outside scope")
		}
	}
	if err := validateCoverageTargetSets(evidence.ExpectedTargets, evidence.ObservedTargets, evidence.MissingTargets); err != nil {
		return err
	}
	if len(evidence.ExpectedTargets) == 0 {
		return fmt.Errorf("evidence expected coverage is required")
	}
	wantTimeComplete := !evidence.ObservedFrom.After(evidence.ExpectedFrom) && !evidence.ObservedTo.Before(evidence.ExpectedTo)
	if evidence.TimeComplete != wantTimeComplete {
		return fmt.Errorf("evidence time coverage is inconsistent")
	}
	return nil
}

func (hypothesis HypothesisContext) validate(evidenceIDs map[string]struct{}) error {
	if !validToken(hypothesis.HypothesisID) || !validText(hypothesis.Statement, 2048) || !validHypothesisStatus(hypothesis.Status) || hypothesis.Confidence < 0 || hypothesis.Confidence > 1 || len(hypothesis.UnresolvedTests) > 32 || hypothesis.UnresolvedTestsOmitted < 0 || hypothesis.UnresolvedTestsOmitted > 32-len(hypothesis.UnresolvedTests) {
		return fmt.Errorf("hypothesis context is invalid")
	}
	for _, test := range hypothesis.UnresolvedTests {
		if !validText(test, 512) {
			return fmt.Errorf("hypothesis unresolved test is invalid")
		}
	}
	if err := validateCitations(hypothesis.SupportingEvidence, evidenceIDs, false); err != nil {
		return err
	}
	if err := validateCitations(hypothesis.ContradictingEvidence, evidenceIDs, false); err != nil {
		return err
	}
	if hypothesis.Status == "SUPPORTED" && len(hypothesis.SupportingEvidence) == 0 {
		return fmt.Errorf("supported hypothesis requires supporting evidence")
	}
	if (hypothesis.Status == "WEAKENED" || hypothesis.Status == "REFUTED") && len(hypothesis.ContradictingEvidence) == 0 {
		return fmt.Errorf("weakened or refuted hypothesis requires contradicting evidence")
	}
	if overlaps(hypothesis.SupportingEvidence, hypothesis.ContradictingEvidence) {
		return fmt.Errorf("hypothesis evidence cannot support and contradict")
	}
	return nil
}

func (coverage Coverage) validate(scope Scope) error {
	if coverage.HypothesesOmitted < 0 || len(coverage.TargetsChecked)+len(coverage.TargetsMissed) > 256 || len(coverage.Sources) > 64 || len(coverage.ToolFailures) > 128 || !uniqueValidTokens(coverage.TargetsChecked) || !uniqueValidTokens(coverage.TargetsMissed) || overlaps(coverage.TargetsChecked, coverage.TargetsMissed) || !uniqueValidTokens(coverage.Sources) || coverage.EvidenceSelected < 0 || coverage.EvidenceReduced < 0 || coverage.EvidenceOmitted < 0 || coverage.EvidenceSelected+coverage.EvidenceReduced+coverage.EvidenceOmitted > 256 {
		return fmt.Errorf("coverage is invalid")
	}
	for _, id := range append(slices.Clone(coverage.TargetsChecked), coverage.TargetsMissed...) {
		if !slices.Contains(scope.EntityIDs, id) {
			return fmt.Errorf("coverage is outside scope")
		}
	}
	for _, failure := range coverage.ToolFailures {
		if !validText(failure, 512) {
			return fmt.Errorf("tool failure is invalid")
		}
	}
	if coverage.StopReason != "" && !validToken(coverage.StopReason) {
		return fmt.Errorf("coverage stop reason is invalid")
	}
	if coverage.ExpectedFrom.IsZero() || !coverage.ExpectedFrom.Equal(scope.Start) || !coverage.ExpectedTo.Equal(scope.End) || coverage.ExpectedTo.Before(coverage.ExpectedFrom) {
		return fmt.Errorf("coverage expected window is invalid")
	}
	if err := validateCoverageTargetSets(coverage.ExpectedTargets, coverage.ObservedTargets, coverage.MissingTargets); err != nil {
		return err
	}
	if coverage.EvidenceSelected > 0 && len(coverage.ExpectedTargets) == 0 {
		return fmt.Errorf("selected evidence requires expected coverage")
	}
	observedIDs := map[string]struct{}{}
	scopeKind := coverageScopeKind(scope.EntityKind)
	for _, target := range coverage.ObservedTargets {
		if scopeKind == "" || target.Kind == scopeKind {
			observedIDs[target.ID] = struct{}{}
		}
	}
	for _, id := range coverage.TargetsChecked {
		if _, ok := observedIDs[id]; !ok {
			return fmt.Errorf("checked scope target was not observed")
		}
	}
	for _, id := range coverage.TargetsMissed {
		if _, ok := observedIDs[id]; ok {
			return fmt.Errorf("missed scope target was observed")
		}
	}
	if coverage.ObservedFrom.IsZero() != coverage.ObservedTo.IsZero() || (!coverage.ObservedFrom.IsZero() && coverage.ObservedTo.Before(coverage.ObservedFrom)) {
		return fmt.Errorf("coverage observed window is invalid")
	}
	if coverage.TimeComplete && (coverage.ObservedFrom.IsZero() || coverage.ObservedFrom.After(coverage.ExpectedFrom) || coverage.ObservedTo.Before(coverage.ExpectedTo)) {
		return fmt.Errorf("coverage time completeness is invalid")
	}
	if coverage.RequestedTimeComplete && coverage.EvidenceSelected < 1 {
		return fmt.Errorf("coverage cannot claim requested time completeness without evidence")
	}
	return nil
}

func coverageScopeKind(kind string) string {
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

func validateCoverageTargetSets(expected, observed, missing []CoverageTarget) error {
	if len(expected) > 512 || len(observed) > 512 || len(missing) > 512 {
		return fmt.Errorf("coverage target bounds are invalid")
	}
	expectedSet, observedSet, missingSet := map[CoverageTarget]struct{}{}, map[CoverageTarget]struct{}{}, map[CoverageTarget]struct{}{}
	for _, target := range expected {
		if !validCoverageTarget(target) {
			return fmt.Errorf("expected coverage target is invalid")
		}
		if _, ok := expectedSet[target]; ok {
			return fmt.Errorf("expected coverage target is duplicated")
		}
		expectedSet[target] = struct{}{}
	}
	for _, target := range observed {
		if !validCoverageTarget(target) {
			return fmt.Errorf("observed coverage target is invalid")
		}
		if _, ok := expectedSet[target]; !ok {
			return fmt.Errorf("observed coverage target was not expected")
		}
		if _, ok := observedSet[target]; ok {
			return fmt.Errorf("observed coverage target is duplicated")
		}
		observedSet[target] = struct{}{}
	}
	for _, target := range missing {
		if !validCoverageTarget(target) {
			return fmt.Errorf("missing coverage target is invalid")
		}
		if _, ok := expectedSet[target]; !ok {
			return fmt.Errorf("missing coverage target was not expected")
		}
		if _, ok := observedSet[target]; ok {
			return fmt.Errorf("coverage target cannot be observed and missing")
		}
		if _, ok := missingSet[target]; ok {
			return fmt.Errorf("missing coverage target is duplicated")
		}
		missingSet[target] = struct{}{}
	}
	if len(missingSet) != len(expectedSet)-len(observedSet) {
		return fmt.Errorf("missing coverage targets are incomplete")
	}
	for target := range expectedSet {
		_, seen := observedSet[target]
		_, absent := missingSet[target]
		if seen == absent {
			return fmt.Errorf("expected coverage target classification is inconsistent")
		}
	}
	return nil
}

func validCoverageTarget(target CoverageTarget) bool {
	switch target.Kind {
	case "CLUSTER", "NODE", "GPU", "SOURCE":
	default:
		return false
	}
	return validToken(target.ID)
}

func (statement CitedStatement) validate(evidenceIDs map[string]struct{}, required bool) error {
	if !validText(statement.Statement, 4096) {
		return fmt.Errorf("synthesis statement is invalid")
	}
	return validateCitations(statement.EvidenceIDs, evidenceIDs, required)
}

func evidenceIDSet(evidence []EvidenceContext) map[string]struct{} {
	result := make(map[string]struct{}, len(evidence))
	for _, entry := range evidence {
		result[entry.EvidenceID] = struct{}{}
	}
	return result
}
func validateCitations(ids []string, allowed map[string]struct{}, required bool) error {
	if required && len(ids) == 0 {
		return fmt.Errorf("evidence citation is required")
	}
	seen := map[string]struct{}{}
	for _, id := range ids {
		if _, ok := allowed[id]; !ok {
			return fmt.Errorf("evidence citation is unknown")
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("evidence citations must be unique")
		}
		seen[id] = struct{}{}
	}
	return nil
}
func overlaps(left, right []string) bool {
	for _, value := range left {
		if slices.Contains(right, value) {
			return true
		}
	}
	return false
}
func uniqueValidTokens(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if !validToken(value) {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
func validToken(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._:/@+-", r)) {
			return false
		}
	}
	return true
}
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}
func validJSONObject(value json.RawMessage, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	if rejectDuplicateObjectKeys(value) != nil {
		return false
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&object) != nil || object == nil {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}
func validHypothesisStatus(status string) bool {
	return status == "PROPOSED" || status == "SUPPORTED" || status == "WEAKENED" || status == "REFUTED" || status == "UNRESOLVED"
}

// Severity tokens mirror domain.HealthSeverity. This package is the provider
// boundary and carries no domain dependency by design, so the vocabulary is
// restated here; the orchestrator binds the two together.
func validSynthesisSeverity(value string) bool {
	return value == "UNKNOWN" || value == "INFO" || value == "WARNING" || value == "CRITICAL"
}

func validFindingKind(kind string) bool {
	return kind == "OBSERVATION" || kind == "DERIVED_SIGNAL" || kind == "HYPOTHESIS" || kind == "RECOMMENDATION"
}

func rejectDuplicateObjectKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := walkJSONValue(decoder, token); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("document must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key must be a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate JSON object key")
			}
			keys[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkJSONValue(decoder, value); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkJSONValue(decoder, value); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	want := json.Delim('}')
	if delimiter == '[' {
		want = ']'
	}
	if closing != want {
		return fmt.Errorf("unexpected JSON closing delimiter")
	}
	return nil
}
