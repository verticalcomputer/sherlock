// Package modelprovider defines Sherlock's provider-neutral, structured model
// boundary. Provider SDK values and unrestricted model text must not cross it.
package modelprovider

import (
	"context"
	"encoding/json"
	"time"
)

const (
	PlanningSchemaVersion  = 1
	SynthesisSchemaVersion = 1
	MaxDocumentBytes       = 1 << 20
)

type Scope struct {
	ClusterID  string    `json:"cluster_id"`
	EntityKind string    `json:"entity_kind"`
	EntityIDs  []string  `json:"entity_ids"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
}

type RemainingBudget struct {
	Decisions       int   `json:"decisions"`
	ToolCalls       int   `json:"tool_calls"`
	DiagnosticCalls int   `json:"diagnostic_calls"`
	PrivilegedCalls int   `json:"privileged_calls"`
	FanOut          int   `json:"fan_out"`
	ModelTokens     int64 `json:"model_tokens"`
	CostMicros      int64 `json:"cost_micros"`
}

// AvailableTool is a controller-filtered domain operation. ArgumentSchema is
// JSON Schema, not a provider-specific function declaration.
type AvailableTool struct {
	ToolID                 string          `json:"tool_id"`
	Description            string          `json:"description"`
	ArgumentSchema         json.RawMessage `json:"argument_schema,omitempty"`
	ResponseArgumentSchema json.RawMessage `json:"-"`
	SchemaVersion          string          `json:"schema_version"`
	// ReadOnly and Diagnostic are exclusive and exactly one must hold. A tool
	// that declares neither is not a reviewed operation class and is refused,
	// so the boundary keeps failing closed as the catalog grows.
	ReadOnly         bool `json:"read_only"`
	Diagnostic       bool `json:"diagnostic"`
	RequiresApproval bool `json:"requires_approval"`
	MaximumFanOut    int  `json:"maximum_fan_out"`
	CostWeight       int  `json:"cost_weight"`
}

func (tool AvailableTool) EffectiveArgumentSchema() json.RawMessage {
	if len(tool.ResponseArgumentSchema) != 0 {
		return tool.ResponseArgumentSchema
	}
	return tool.ArgumentSchema
}

// EvidenceContext is a bounded, redacted representation. Content is
// deliberately named untrusted_data so providers cannot confuse it with
// controller instructions.
type EvidenceContext struct {
	EvidenceID      string           `json:"evidence_id"`
	EntityIDs       []string         `json:"entity_ids"`
	ObservedFrom    time.Time        `json:"observed_from"`
	ObservedTo      time.Time        `json:"observed_to"`
	Status          string           `json:"status"`
	Source          string           `json:"source"`
	Summary         string           `json:"summary"`
	UntrustedData   string           `json:"untrusted_data,omitempty"`
	Truncated       bool             `json:"truncated"`
	ExpectedTargets []CoverageTarget `json:"expected_targets"`
	ObservedTargets []CoverageTarget `json:"observed_targets"`
	MissingTargets  []CoverageTarget `json:"missing_targets"`
	ExpectedFrom    time.Time        `json:"expected_from"`
	ExpectedTo      time.Time        `json:"expected_to"`
	TimeComplete    bool             `json:"time_complete"`
}

type CoverageTarget struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type HypothesisContext struct {
	HypothesisID             string   `json:"hypothesis_id"`
	Statement                string   `json:"statement"`
	Status                   string   `json:"status"`
	Confidence               float64  `json:"confidence"`
	SupportingEvidence       []string `json:"supporting_evidence_ids"`
	ContradictingEvidence    []string `json:"contradicting_evidence_ids"`
	UnresolvedTests          []string `json:"unresolved_tests"`
	StatementTruncated       bool     `json:"statement_truncated,omitempty"`
	UnresolvedTestsOmitted   int      `json:"unresolved_tests_omitted,omitempty"`
	UnresolvedTestsTruncated bool     `json:"unresolved_tests_truncated,omitempty"`
}

type PriorAction struct {
	ActionDigest string    `json:"action_digest"`
	ToolID       string    `json:"tool_id"`
	Outcome      string    `json:"outcome"`
	Targets      []string  `json:"targets"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
	EvidenceIDs  []string  `json:"evidence_ids"`
	// Recorded results excluded from this model context, not a failed or empty run.
	EvidenceOmitted int `json:"evidence_omitted,omitempty"`
}

// MemoryContext is untrusted, derived prior knowledge. It may guide action
// selection, but its citations must be re-observed as current evidence before
// Sherlock publishes a factual finding.
type MemoryContext struct {
	MemoryID              string    `json:"memory_id"`
	TrustClass            string    `json:"trust_class"`
	Statement             string    `json:"untrusted_statement"`
	SourceInvestigationID string    `json:"source_investigation_id"`
	EntityIDs             []string  `json:"entity_ids"`
	EvidenceIDs           []string  `json:"evidence_ids"`
	ValidFrom             time.Time `json:"valid_from"`
	Stale                 bool      `json:"stale"`
}

// NewHypothesisID asks Sherlock to allocate a durable hypothesis identifier.
// Existing hypotheses must be updated using the exact ID supplied in the
// planning request; the provider never invents a new persistent identity.
const NewHypothesisID = "new_hypothesis"

type PlanningRequest struct {
	SchemaVersion       int                 `json:"schema_version"`
	InvestigationID     string              `json:"investigation_id"`
	Question            string              `json:"question"`
	Scope               Scope               `json:"scope"`
	StateSummary        string              `json:"state_summary"`
	SuccessCriteria     []string            `json:"success_criteria"`
	RemainingBudget     RemainingBudget     `json:"remaining_budget"`
	AvailableTools      []AvailableTool     `json:"available_tools"`
	SharedToolArguments json.RawMessage     `json:"shared_tool_arguments,omitempty"`
	Evidence            []EvidenceContext   `json:"evidence"`
	Hypotheses          []HypothesisContext `json:"hypotheses"`
	PriorActions        []PriorAction       `json:"prior_actions"`
	PriorActionsOmitted int                 `json:"prior_actions_omitted,omitempty"`
	Memory              []MemoryContext     `json:"cluster_memory,omitempty"`
	Coverage            Coverage            `json:"coverage"`
	PromptVersion       string              `json:"prompt_version"`
	ToolSchemaVersion   string              `json:"tool_schema_version"`
	CheckpointDigest    string              `json:"checkpoint_digest,omitempty"`
	DeltaFromVersion    int                 `json:"delta_from_version,omitempty"`
	ContextMode         string              `json:"context_mode,omitempty"`
}

type HypothesisUpdate struct {
	HypothesisID          string   `json:"hypothesis_id"`
	Statement             string   `json:"statement"`
	Status                string   `json:"status"`
	Confidence            float64  `json:"confidence"`
	SupportingEvidence    []string `json:"supporting_evidence_ids"`
	ContradictingEvidence []string `json:"contradicting_evidence_ids"`
	UnresolvedTests       []string `json:"unresolved_tests"`
}

type PlannedAction struct {
	ToolID              string          `json:"tool_id"`
	Arguments           json.RawMessage `json:"arguments"`
	Purpose             string          `json:"purpose"`
	ExpectedInformation string          `json:"expected_information"`
	Priority            int             `json:"priority"`
}

type PlanningStopReason string

const (
	StopSuccessCriteriaMet PlanningStopReason = "SUCCESS_CRITERIA_MET"
	StopNoUsefulAction     PlanningStopReason = "NO_USEFUL_ACTION"
	StopAccessUnavailable  PlanningStopReason = "ACCESS_UNAVAILABLE"
	StopSourceUnavailable  PlanningStopReason = "SOURCE_UNAVAILABLE"
	StopBudgetExceeded     PlanningStopReason = "BUDGET_EXCEEDED"
)

type PlanningResponse struct {
	SchemaVersion     int                 `json:"schema_version"`
	StateSummary      string              `json:"state_summary"`
	HypothesisUpdates []HypothesisUpdate  `json:"hypothesis_updates"`
	Actions           []PlannedAction     `json:"actions"`
	Stop              bool                `json:"stop"`
	StopReason        *PlanningStopReason `json:"stop_reason"`
}

type ValidatedFinding struct {
	FindingID          string   `json:"finding_id"`
	Kind               string   `json:"kind"`
	Statement          string   `json:"statement"`
	EntityIDs          []string `json:"entity_ids"`
	Severity           string   `json:"severity"`
	Confidence         *float64 `json:"confidence"`
	EvidenceIDs        []string `json:"evidence_ids"`
	CounterEvidenceIDs []string `json:"counter_evidence_ids"`
}

type Coverage struct {
	HypothesesOmitted int              `json:"hypotheses_omitted,omitempty"`
	TargetsChecked    []string         `json:"targets_checked"`
	TargetsMissed     []string         `json:"targets_missed"`
	ExpectedTargets   []CoverageTarget `json:"expected_targets"`
	ObservedTargets   []CoverageTarget `json:"observed_targets"`
	MissingTargets    []CoverageTarget `json:"missing_targets"`
	ExpectedFrom      time.Time        `json:"expected_from"`
	ExpectedTo        time.Time        `json:"expected_to"`
	ObservedFrom      time.Time        `json:"observed_from,omitempty"`
	ObservedTo        time.Time        `json:"observed_to,omitempty"`
	// TimeComplete reports observed data density: evidence values exist across
	// the whole requested period. Event evidence is sparse by nature, so a quiet
	// window never satisfies it even when the period was fully checked.
	TimeComplete bool `json:"time_complete"`
	// RequestedTimeComplete reports authoritative interrogation instead: the
	// windows actually asked for, by evidence that answered for its whole
	// declared coverage, tile the investigation scope. Verified absence counts.
	RequestedTimeComplete bool `json:"requested_time_complete"`
	EvidenceSelected      int  `json:"evidence_selected"`
	EvidenceReduced       int  `json:"evidence_reduced"`
	EvidenceOmitted       int  `json:"evidence_omitted"`
	// EvidenceOmittedEntities names the scope entities whose evidence was
	// collected and then dropped on the way into this context.
	//
	// Without it a count is unactionable. A ten-node pass reported sixteen
	// omissions; two nodes arrived carrying only an all-N/A retired-page
	// reading, and the report concluded their diagnostics had not run and
	// asked an operator to re-collect evidence that was already committed.
	// An entity named here has data in the ledger that this context could not
	// carry, which is a different problem with a different remedy from a
	// diagnostic that never ran or failed.
	EvidenceOmittedEntities []string `json:"evidence_omitted_entities,omitempty"`
	// EvidenceOmittedNote states what the entity list means, in the request
	// itself rather than in the prompt, so the meaning travels with the data
	// and cannot drift from it across prompt versions.
	EvidenceOmittedNote string   `json:"evidence_omitted_note,omitempty"`
	Sources             []string `json:"sources"`
	ToolFailures        []string `json:"tool_failures"`
	StopReason          string   `json:"stop_reason,omitempty"`
}

type SynthesisRequest struct {
	SchemaVersion    int                 `json:"schema_version"`
	InvestigationID  string              `json:"investigation_id"`
	Question         string              `json:"question"`
	Scope            Scope               `json:"scope"`
	Outcome          string              `json:"outcome"`
	Evidence         []EvidenceContext   `json:"evidence"`
	Hypotheses       []HypothesisContext `json:"hypotheses"`
	Findings         []ValidatedFinding  `json:"validated_findings"`
	Coverage         Coverage            `json:"coverage"`
	PromptVersion    string              `json:"prompt_version"`
	CheckpointDigest string              `json:"checkpoint_digest,omitempty"`
	DeltaFromVersion int                 `json:"delta_from_version,omitempty"`
	ContextMode      string              `json:"context_mode,omitempty"`
}

// Severity is proposed by the model only where it is meaningful. Statements of
// what remains unknown and of coverage carry none: absent data has no
// seriousness of its own, and inviting a severity there would produce a number
// with nothing behind it.
type CitedStatement struct {
	Statement   string   `json:"statement"`
	Severity    string   `json:"severity,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type TimelineEntry struct {
	ObservedAt  time.Time `json:"observed_at"`
	Statement   string    `json:"statement"`
	EvidenceIDs []string  `json:"evidence_ids"`
}

type Explanation struct {
	Statement          string   `json:"statement"`
	Severity           string   `json:"severity,omitempty"`
	Confidence         float64  `json:"confidence"`
	EvidenceIDs        []string `json:"evidence_ids"`
	CounterEvidenceIDs []string `json:"counter_evidence_ids"`
}

type SynthesisResponse struct {
	SchemaVersion      int              `json:"schema_version"`
	WhatIsHappening    []CitedStatement `json:"what_is_happening"`
	Timeline           []TimelineEntry  `json:"timeline"`
	LikelyExplanations []Explanation    `json:"likely_explanations"`
	WhatRemainsUnknown []CitedStatement `json:"what_remains_unknown"`
	SuggestedNextSteps []CitedStatement `json:"suggested_next_steps"`
	Coverage           []CitedStatement `json:"investigation_coverage"`
}

type ModelOutcome string

const (
	OutcomeSucceeded ModelOutcome = "SUCCEEDED"
	OutcomeRefused   ModelOutcome = "REFUSED"
)

// NoEvidenceCitationSentinel is a provider-schema placeholder, never an
// evidence identifier. Decoders remove it only when the request has no
// evidence; any other invented citation still fails semantic validation.
const NoEvidenceCitationSentinel = "no_evidence_available"

// CallMetadata is safe operational metadata. It intentionally has no field
// for raw prompts, raw responses, provider errors, or credentials.
type CallMetadata struct {
	Provider        string        `json:"provider"`
	Model           string        `json:"model"`
	ConfigurationID string        `json:"configuration_id"`
	InputTokens     int64         `json:"input_tokens"`
	OutputTokens    int64         `json:"output_tokens"`
	CostMicros      int64         `json:"cost_micros"`
	Latency         time.Duration `json:"latency"`
	Outcome         ModelOutcome  `json:"outcome"`
}

// CallTrace carries the exact credential-free request body sent to the model
// endpoint and the structured output text returned by it. It is transient and
// must only be handed to the immutable audit-evidence recorder.
type CallTrace struct {
	Input  []byte
	Output []byte
}

type PlanningResult struct {
	Response PlanningResponse `json:"response"`
	Metadata CallMetadata     `json:"metadata"`
	Trace    CallTrace        `json:"-"`
}

type SynthesisResult struct {
	Response SynthesisResponse `json:"response"`
	Metadata CallMetadata      `json:"metadata"`
	Trace    CallTrace         `json:"-"`
}

// Provider implementations must enforce request deadlines, return only safe
// classified errors, and validate structured provider output before returning.
// They must not expose provider SDK types, prompts, or raw response bodies.
type Provider interface {
	Plan(context.Context, PlanningRequest) (PlanningResult, error)
	Synthesize(context.Context, SynthesisRequest) (SynthesisResult, error)
}
