// Package investigationeval grades versioned, offline investigation fixtures.
//
// The evaluator deliberately has no model, network, clock, or database
// dependency. A fixture separates the incident contract from the candidate
// output so the output cannot declare its own claims or citations valid.
package investigationeval

const (
	SchemaVersion    = "sherlock.investigation-eval/v1"
	EvaluatorVersion = "2"
)

type Suite struct {
	SchemaVersion string     `json:"schema_version"`
	SuiteID       string     `json:"suite_id"`
	Description   string     `json:"description"`
	Thresholds    Thresholds `json:"thresholds"`
	Cases         []Case     `json:"cases"`
}

// Thresholds use basis points for rates, avoiding platform-dependent floating
// point formatting and boundary comparisons. Ten thousand basis points is 100%.
type Thresholds struct {
	ToolChoiceMinBP        int   `json:"tool_choice_min_bp"`
	EvidenceCoverageMinBP  int   `json:"evidence_coverage_min_bp"`
	CitationValidityMinBP  int   `json:"citation_validity_min_bp"`
	UnsupportedClaimsMaxBP int   `json:"unsupported_claims_max_bp"`
	MutationRefusalMinBP   int   `json:"mutation_refusal_min_bp"`
	PartialDataMinBP       int   `json:"partial_data_min_bp"`
	LatencyMaxMillis       int64 `json:"latency_max_millis"`
	CostMaxMicros          int64 `json:"cost_max_micros"`
	TerminalOutcomeMinBP   int   `json:"terminal_outcome_min_bp,omitempty"`
	// RedundantCallsMaxBP bounds the share of candidate tool calls that repeat
	// an identical invocation. The zero value forbids any repetition, which is
	// the controller's own rule.
	RedundantCallsMaxBP int `json:"redundant_calls_max_bp,omitempty"`
	// ReportQualityMinBP bounds the share of cases whose report carries the
	// content the run already paid to produce: a timeline, a statement of what
	// remains unknown, a coverage statement, and severities that distinguish a
	// serious finding from a routine one. Without this gate a report can lose
	// all of it and every other measure still passes, which is exactly how it
	// went unnoticed.
	ReportQualityMinBP int `json:"report_quality_min_bp,omitempty"`
}

type Case struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Contract    Contract  `json:"contract"`
	Candidate   Candidate `json:"candidate"`
}

// Contract is the human-reviewed ground truth for one synthetic or redacted
// incident. SupportedClaims maps exact factual statements to their minimum
// evidence set. Findings outside this closed set are unsupported.
type Contract struct {
	RequiredTools     []string         `json:"required_tools"`
	AllowedTools      []string         `json:"allowed_tools"`
	AvailableEvidence []string         `json:"available_evidence"`
	RequiredEvidence  []string         `json:"required_evidence"`
	SupportedClaims   []SupportedClaim `json:"supported_claims"`
	MutationRequests  []string         `json:"mutation_requests"`
	ExpectPartial     bool             `json:"expect_partial"`
	RequiredUnknowns  []string         `json:"required_unknowns"`
	// MinTimelineEntries requires the report to say when things happened.
	MinTimelineEntries int `json:"min_timeline_entries,omitempty"`
	// RequireUnknowns demands an explicit statement of what the run does not
	// know, whatever its outcome. RequiredUnknowns is graded only for a case
	// that expects partial data, so a complete-looking run could previously
	// state nothing at all about its own limits.
	RequireUnknowns bool `json:"require_unknowns,omitempty"`
	// RequireCoverage demands an explicit statement of how far the run reached.
	RequireCoverage bool `json:"require_coverage,omitempty"`
	// MinSeverityCounts asserts a severity distribution: at least n findings at
	// each named severity. It fails a report that collapses every finding to one
	// level, which is what a hardcoded severity produces.
	MinSeverityCounts  map[string]int `json:"min_severity_counts,omitempty"`
	LatencyLimitMillis int64          `json:"latency_limit_millis"`
	CostLimitMicros    int64          `json:"cost_limit_micros"`
	ExpectedOutcome    string         `json:"expected_outcome,omitempty"`
	ExpectedStopReason string         `json:"expected_stop_reason,omitempty"`
}

type SupportedClaim struct {
	Statement        string   `json:"statement"`
	RequiredEvidence []string `json:"required_evidence"`
}

type Candidate struct {
	ToolCalls      []ToolCall `json:"tool_calls"`
	Findings       []Finding  `json:"findings"`
	RefusedActions []string   `json:"refused_actions"`
	Outcome        string     `json:"outcome"`
	StopReason     string     `json:"stop_reason,omitempty"`
	Unknowns       []string   `json:"unknowns"`
	// Timeline, Coverage, and Severities are derived from what the run actually
	// produced, never from the contract, or the grade would assert only that the
	// fixture matches itself.
	Timeline      []CandidateTimelineEntry `json:"timeline,omitempty"`
	Coverage      []string                 `json:"coverage,omitempty"`
	Severities    []string                 `json:"severities,omitempty"`
	LatencyMillis int64                    `json:"latency_millis"`
	CostMicros    int64                    `json:"cost_micros"`
	ModelTokens   int64                    `json:"model_tokens"`
}

// ToolCall records one candidate invocation. Targets and the time window are
// optional so earlier fixtures keep their meaning, but a fixture that supplies
// them is graded on the full invocation: the controller rejects only an exact
// repeat, and deterministic fan-out batches of one tool are not redundant.
type ToolCall struct {
	ToolID  string   `json:"tool_id"`
	Targets []string `json:"targets,omitempty"`
	Start   string   `json:"start,omitempty"`
	End     string   `json:"end,omitempty"`
}

// CandidateTimelineEntry is one durable timeline entry as the report would
// render it. The instant is what makes a timeline worth having, so it is
// graded rather than the statement alone.
type CandidateTimelineEntry struct {
	ObservedAt  string   `json:"observed_at"`
	Statement   string   `json:"statement"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type Finding struct {
	Statement   string   `json:"statement"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Summary struct {
	SchemaVersion    string       `json:"schema_version"`
	EvaluatorVersion string       `json:"evaluator_version"`
	SuiteID          string       `json:"suite_id"`
	Passed           bool         `json:"passed"`
	CaseCount        int          `json:"case_count"`
	Totals           Totals       `json:"totals"`
	Gates            []GateResult `json:"gates"`
	Cases            []CaseResult `json:"cases"`
}

type Totals struct {
	ToolCalls     int   `json:"tool_calls"`
	Findings      int   `json:"findings"`
	ModelTokens   int64 `json:"model_tokens"`
	LatencyMillis int64 `json:"latency_millis"`
	CostMicros    int64 `json:"cost_micros"`
}

type GateResult struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Actual    int64  `json:"actual"`
	Threshold int64  `json:"threshold"`
	Unit      string `json:"unit"`
	Passed    bool   `json:"passed"`
}

type CaseResult struct {
	ID                      string         `json:"id"`
	Passed                  bool           `json:"passed"`
	ToolChoicePassed        bool           `json:"tool_choice_passed"`
	EvidenceRequired        int            `json:"evidence_required"`
	EvidenceCovered         int            `json:"evidence_covered"`
	CitationsChecked        int            `json:"citations_checked"`
	CitationsValid          int            `json:"citations_valid"`
	Findings                int            `json:"findings"`
	ToolCalls               int            `json:"tool_calls"`
	RedundantCalls          int            `json:"redundant_calls"`
	UnsupportedClaims       int            `json:"unsupported_claims"`
	MutationRefusalRequired bool           `json:"mutation_refusal_required"`
	MutationRefusalPassed   bool           `json:"mutation_refusal_passed"`
	PartialDataRequired     bool           `json:"partial_data_required"`
	PartialDataPassed       bool           `json:"partial_data_passed"`
	LatencyMillis           int64          `json:"latency_millis"`
	CostMicros              int64          `json:"cost_micros"`
	TerminalOutcomeRequired bool           `json:"terminal_outcome_required,omitempty"`
	TerminalOutcomePassed   bool           `json:"terminal_outcome_passed,omitempty"`
	TimelineEntries         int            `json:"timeline_entries"`
	UnknownsReported        int            `json:"unknowns_reported"`
	CoverageStatements      int            `json:"coverage_statements"`
	SeverityCounts          map[string]int `json:"severity_counts,omitempty"`
	ReportQualityRequired   bool           `json:"report_quality_required,omitempty"`
	ReportQualityPassed     bool           `json:"report_quality_passed,omitempty"`
	Violations              []string       `json:"violations"`
}
