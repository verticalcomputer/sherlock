// Package pilotacceptance validates immutable live investigation evidence and
// a named admin review without contacting a deployment or provider.
package pilotacceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	RunSchemaVersion     = "sherlock.investigation-pilot-run/v1"
	ReviewSchemaVersion  = "sherlock.investigation-pilot-review/v1"
	SummarySchemaVersion = "sherlock.investigation-pilot-closeout/v1"
	maximumDocumentBytes = 2 << 20
)

type RunRecord struct {
	SchemaVersion          string      `json:"schema_version"`
	PilotID                string      `json:"pilot_id"`
	InvestigationID        string      `json:"investigation_id"`
	IncidentID             string      `json:"incident_id"`
	ClusterID              string      `json:"cluster_id"`
	Environment            string      `json:"environment"`
	Provider               string      `json:"provider"`
	Model                  string      `json:"model"`
	ModelConfigVersion     string      `json:"model_config_version"`
	DeploymentID           string      `json:"deployment_id"`
	Region                 string      `json:"region"`
	PlanningPromptVersion  string      `json:"planning_prompt_version"`
	SynthesisPromptVersion string      `json:"synthesis_prompt_version"`
	ToolSchemaVersion      string      `json:"tool_schema_version"`
	StartedAt              time.Time   `json:"started_at"`
	CompletedAt            time.Time   `json:"completed_at"`
	Scope                  Scope       `json:"scope"`
	Outcome                string      `json:"outcome"`
	StopReason             string      `json:"stop_reason"`
	Limits                 Limits      `json:"limits"`
	Usage                  Usage       `json:"usage"`
	Actions                []Action    `json:"actions"`
	Evidence               []Evidence  `json:"evidence"`
	Findings               []Finding   `json:"findings"`
	ModelCalls             []ModelCall `json:"model_calls"`
	Exports                []Export    `json:"exports"`
	Safety                 Safety      `json:"safety"`
}

type Scope struct {
	EntityKind string    `json:"entity_kind"`
	EntityIDs  []string  `json:"entity_ids"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
}

type Usage struct {
	Decisions          int   `json:"decisions"`
	ToolCalls          int   `json:"tool_calls"`
	ModelCalls         int   `json:"model_calls"`
	ModelTokens        int64 `json:"model_tokens"`
	CostMicros         int64 `json:"cost_micros"`
	ModelLatencyMillis int64 `json:"model_latency_millis"`
}

type Limits struct {
	MaxModelTokens        int64 `json:"max_model_tokens"`
	MaxCostMicros         int64 `json:"max_cost_micros"`
	MaxModelLatencyMillis int64 `json:"max_model_latency_millis"`
}

type Action struct {
	Digest      string   `json:"digest"`
	ToolID      string   `json:"tool_id"`
	ReadOnly    bool     `json:"read_only"`
	Privileged  bool     `json:"privileged"`
	Targets     []string `json:"targets"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Evidence struct {
	EvidenceID      string    `json:"evidence_id"`
	Status          string    `json:"status"`
	Source          string    `json:"source"`
	ObservedFrom    time.Time `json:"observed_from"`
	ObservedTo      time.Time `json:"observed_to"`
	ExpectedTargets []Target  `json:"expected_targets"`
	ObservedTargets []Target  `json:"observed_targets"`
	MissingTargets  []Target  `json:"missing_targets"`
	TimeComplete    bool      `json:"time_complete"`
}

type Target struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type Finding struct {
	Kind        string   `json:"kind"`
	Statement   string   `json:"statement"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type ModelCall struct {
	CallKey       string `json:"call_key"`
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	InputTokens   int64  `json:"input_tokens"`
	OutputTokens  int64  `json:"output_tokens"`
	CostMicros    int64  `json:"cost_micros"`
	LatencyMillis int64  `json:"latency_millis"`
}

type Export struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference"`
	SHA256    string `json:"sha256"`
}

type Safety struct {
	ReadOnlyToolsOnly              bool `json:"read_only_tools_only"`
	NoDuplicateActions             bool `json:"no_duplicate_actions"`
	NoCredentialExposure           bool `json:"no_credential_exposure"`
	NoUnrestrictedArtifactExposure bool `json:"no_unrestricted_artifact_exposure"`
	AllFactualClaimsCited          bool `json:"all_factual_claims_cited"`
	CoverageExplicit               bool `json:"coverage_explicit"`
	TerminalStateEvidenceSupported bool `json:"terminal_state_evidence_supported"`
	InterruptionAndRestartSafe     bool `json:"interruption_and_restart_safe"`
}

type Review struct {
	SchemaVersion     string          `json:"schema_version"`
	ReviewID          string          `json:"review_id"`
	PilotID           string          `json:"pilot_id"`
	RunSHA256         string          `json:"run_sha256"`
	ReviewerID        string          `json:"reviewer_id"`
	ReviewerRole      string          `json:"reviewer_role"`
	ReviewedAt        time.Time       `json:"reviewed_at"`
	Decision          string          `json:"decision"`
	Useful            bool            `json:"useful"`
	EvidenceTrusted   bool            `json:"evidence_trusted"`
	TerminalCorrect   bool            `json:"terminal_correct"`
	SafetyAccepted    bool            `json:"safety_accepted"`
	UsabilityAccepted bool            `json:"usability_accepted"`
	Notes             string          `json:"notes"`
	Findings          []ReviewFinding `json:"findings"`
	Approvals         []Approval      `json:"approvals"`
}

type ReviewFinding struct {
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	Resolution string `json:"resolution"`
}

type Approval struct {
	Kind       string    `json:"kind"`
	ApproverID string    `json:"approver_id"`
	ApprovedAt time.Time `json:"approved_at"`
	Reference  string    `json:"reference"`
}

type Summary struct {
	SchemaVersion string  `json:"schema_version"`
	PilotID       string  `json:"pilot_id"`
	RunSHA256     string  `json:"run_sha256"`
	Passed        bool    `json:"passed"`
	Checks        []Check `json:"checks"`
}

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

func LoadRun(path string) (RunRecord, []byte, error) {
	var value RunRecord
	raw, err := loadStrict(path, &value)
	return value, raw, err
}

func LoadReview(path string) (Review, error) {
	var value Review
	_, err := loadStrict(path, &value)
	return value, err
}

func LoadExport(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pilot export: %w", err)
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximumDocumentBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumDocumentBytes {
		return nil, fmt.Errorf("pilot export is empty or exceeds the bounded size")
	}
	return payload, nil
}

func loadStrict(path string, destination any) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pilot document: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumDocumentBytes+1))
	if err != nil || len(raw) > maximumDocumentBytes {
		return nil, fmt.Errorf("pilot document exceeds the bounded size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, fmt.Errorf("decode pilot document: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("decode pilot document: trailing JSON value")
	}
	return raw, nil
}

func Evaluate(runRaw []byte, run RunRecord, review Review, exportPayloads map[string][]byte) Summary {
	digest := sha256.Sum256(runRaw)
	digestText := hex.EncodeToString(digest[:])
	summary := Summary{SchemaVersion: SummarySchemaVersion, PilotID: run.PilotID, RunSHA256: digestText, Passed: true}
	add := func(name, detail string, passed bool) {
		summary.Checks = append(summary.Checks, Check{Name: name, Passed: passed, Detail: detail})
		summary.Passed = summary.Passed && passed
	}
	add("run_identity", "versioned pilot and investigation identity", validRunIdentity(run))
	add("live_provider", "non-fixture deployment, region, and model attribution", validLiveProvider(run))
	add("bounded_scope", "bounded entity and time scope", validScope(run.Scope, run.StartedAt, run.CompletedAt))
	evidenceOK, evidenceIDs := validEvidence(run.Evidence, run.Scope)
	add("action_novelty", "distinct read-only unprivileged evidence-class actions", validActions(run.Actions, run.Scope.EntityIDs) && validActionEvidenceLinks(run.Actions, evidenceIDs))
	add("evidence_provenance", "typed source, target, status, and time coverage", evidenceOK)
	add("cited_report", "cited observation and hypothesis plus recommendation", validFindings(run.Findings, evidenceIDs))
	add("usage_audit", "successful unique model calls reconcile usage within approved ceilings", validUsage(run.Limits, run.Usage, run.Actions, run.ModelCalls))
	add("release_exports", "supplied investigation, model-audit, and evidence exports match SHA-256", validExports(run.Exports, exportPayloads))
	add("terminal_semantics", "terminal outcome and reason agree with evidence coverage", validTerminal(run.Outcome, run.StopReason, run.Evidence))
	add("safety_assertions", "all required no-mutation and no-exposure assertions", validSafety(run.Safety))
	add("immutable_review", "operator review references the exact run SHA-256", review.SchemaVersion == ReviewSchemaVersion && review.PilotID == run.PilotID && review.RunSHA256 == digestText && validToken(review.ReviewID) && validToken(review.ReviewerID) && review.ReviewedAt.After(run.CompletedAt))
	add("operator_acceptance", "named operator accepted usefulness, evidence, terminal, safety, and usability", validOperatorReview(review))
	add("named_approvals", "admin security, data governance, and operations approvals", validApprovals(review.Approvals, review.ReviewedAt))
	return summary
}

func MarshalSummary(summary Summary) ([]byte, error) {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode pilot closeout summary: %w", err)
	}
	return append(data, '\n'), nil
}

func validRunIdentity(run RunRecord) bool {
	return run.SchemaVersion == RunSchemaVersion && validToken(run.PilotID) && validToken(run.InvestigationID) && validToken(run.IncidentID) && validToken(run.ClusterID) && run.Environment == "PILOT" && !run.StartedAt.IsZero() && run.CompletedAt.After(run.StartedAt)
}

func validLiveProvider(run RunRecord) bool {
	provider := strings.ToLower(run.Provider)
	return validToken(run.Provider) && provider != "fixture" && provider != "fake" && !strings.Contains(provider, "recorded") && validToken(run.Model) && validToken(run.ModelConfigVersion) && validToken(run.DeploymentID) && validToken(run.Region) && validToken(run.PlanningPromptVersion) && validToken(run.SynthesisPromptVersion) && validToken(run.ToolSchemaVersion)
}

func validScope(scope Scope, started, completed time.Time) bool {
	if !validToken(scope.EntityKind) || !uniqueTokens(scope.EntityIDs) || len(scope.EntityIDs) > 256 || scope.Start.IsZero() || !scope.End.After(scope.Start) || scope.End.After(completed) || started.After(completed) || completed.Sub(started) > 2*time.Hour {
		return false
	}
	return scope.End.Sub(scope.Start) <= 24*time.Hour
}

func validActions(actions []Action, scoped []string) bool {
	if len(actions) < 2 || len(actions) > 32 {
		return false
	}
	digests, tools := map[string]struct{}{}, map[string]struct{}{}
	scope := stringSet(scoped)
	for _, action := range actions {
		if len(action.Digest) != sha256.Size*2 || !validHex(action.Digest) || !validToken(action.ToolID) || !action.ReadOnly || action.Privileged || !uniqueTokens(action.Targets) || len(action.EvidenceIDs) == 0 || !uniqueTokens(action.EvidenceIDs) {
			return false
		}
		if _, exists := digests[action.Digest]; exists {
			return false
		}
		digests[action.Digest] = struct{}{}
		tools[action.ToolID] = struct{}{}
		for _, target := range action.Targets {
			if _, ok := scope[target]; !ok {
				return false
			}
		}
	}
	return len(tools) >= 2
}

func validActionEvidenceLinks(actions []Action, evidence map[string]struct{}) bool {
	for _, action := range actions {
		for _, evidenceID := range action.EvidenceIDs {
			if _, exists := evidence[evidenceID]; !exists {
				return false
			}
		}
	}
	return true
}

func validEvidence(values []Evidence, scope Scope) (bool, map[string]struct{}) {
	ids, sources := map[string]struct{}{}, map[string]struct{}{}
	for _, value := range values {
		if !validToken(value.EvidenceID) || !validToken(value.Source) || value.ObservedFrom.Before(scope.Start) || value.ObservedTo.After(scope.End) || value.ObservedTo.Before(value.ObservedFrom) || len(value.ExpectedTargets) == 0 {
			return false, nil
		}
		if _, exists := ids[value.EvidenceID]; exists {
			return false, nil
		}
		ids[value.EvidenceID], sources[value.Source] = struct{}{}, struct{}{}
		expected, observed, missing := targetSet(value.ExpectedTargets), targetSet(value.ObservedTargets), targetSet(value.MissingTargets)
		if expected == nil || observed == nil || missing == nil || overlapsTarget(observed, missing) || len(observed)+len(missing) != len(expected) {
			return false, nil
		}
		for target := range observed {
			if _, ok := expected[target]; !ok {
				return false, nil
			}
		}
		for target := range missing {
			if _, ok := expected[target]; !ok {
				return false, nil
			}
		}
		switch value.Status {
		case "COMPLETE", "NO_DATA":
			if len(missing) != 0 || !value.TimeComplete {
				return false, nil
			}
		case "PARTIAL":
			if len(missing) == 0 && value.TimeComplete {
				return false, nil
			}
		case "UNAVAILABLE":
			if len(observed) != 0 || len(missing) == 0 {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	return len(values) >= 2 && len(sources) >= 2, ids
}

func validFindings(findings []Finding, evidence map[string]struct{}) bool {
	kinds := map[string]bool{}
	for _, finding := range findings {
		if len(strings.TrimSpace(finding.Statement)) < 8 || len(finding.Statement) > 4096 || (len(finding.EvidenceIDs) > 0 && !uniqueTokens(finding.EvidenceIDs)) {
			return false
		}
		switch finding.Kind {
		case "OBSERVATION", "HYPOTHESIS":
			if len(finding.EvidenceIDs) == 0 {
				return false
			}
		case "RECOMMENDATION":
		default:
			return false
		}
		for _, id := range finding.EvidenceIDs {
			if _, exists := evidence[id]; !exists {
				return false
			}
		}
		kinds[finding.Kind] = true
	}
	return kinds["OBSERVATION"] && kinds["HYPOTHESIS"] && kinds["RECOMMENDATION"]
}

func validUsage(limits Limits, usage Usage, actions []Action, calls []ModelCall) bool {
	if limits.MaxModelTokens < 1 || limits.MaxModelTokens > 1_000_000 || limits.MaxCostMicros < 1 || limits.MaxCostMicros > 1_000_000 || limits.MaxModelLatencyMillis < 1 || limits.MaxModelLatencyMillis > int64((10*time.Minute)/time.Millisecond) || usage.Decisions < len(actions)+1 || usage.ToolCalls != len(actions) || usage.ModelCalls != len(calls) || usage.ModelTokens < 0 || usage.CostMicros < 0 || usage.ModelLatencyMillis < 0 || usage.ModelTokens > limits.MaxModelTokens || usage.CostMicros > limits.MaxCostMicros || usage.ModelLatencyMillis > limits.MaxModelLatencyMillis || len(calls) < len(actions)+2 {
		return false
	}
	keys := map[string]struct{}{}
	var tokens, cost, latency int64
	for _, call := range calls {
		if !validToken(call.CallKey) || (call.Kind != "PLANNING" && call.Kind != "SYNTHESIS") || call.Status != "SUCCEEDED" || call.InputTokens < 0 || call.OutputTokens < 0 || call.CostMicros < 0 || call.LatencyMillis < 0 {
			return false
		}
		if _, exists := keys[call.CallKey]; exists {
			return false
		}
		keys[call.CallKey] = struct{}{}
		tokens += call.InputTokens + call.OutputTokens
		cost += call.CostMicros
		latency += call.LatencyMillis
	}
	return tokens == usage.ModelTokens && cost == usage.CostMicros && latency == usage.ModelLatencyMillis
}

func validExports(exports []Export, payloads map[string][]byte) bool {
	required := map[string]bool{"INVESTIGATION_SNAPSHOT": false, "MODEL_AUDIT": false, "EVIDENCE_MANIFEST": false}
	for _, export := range exports {
		if _, exists := required[export.Kind]; !exists || required[export.Kind] || !validToken(export.Reference) || len(export.SHA256) != sha256.Size*2 || !validHex(export.SHA256) {
			return false
		}
		payload, exists := payloads[export.Kind]
		if !exists || len(payload) == 0 || len(payload) > maximumDocumentBytes {
			return false
		}
		digest := sha256.Sum256(payload)
		if hex.EncodeToString(digest[:]) != export.SHA256 {
			return false
		}
		required[export.Kind] = true
	}
	for _, present := range required {
		if !present {
			return false
		}
	}
	return true
}

func validTerminal(outcome, reason string, evidence []Evidence) bool {
	hasGap := false
	for _, value := range evidence {
		hasGap = hasGap || value.Status == "PARTIAL" || value.Status == "UNAVAILABLE" || len(value.MissingTargets) > 0 || !value.TimeComplete
	}
	switch outcome {
	case "COMPLETED":
		return reason == "SUCCESS_CRITERIA_MET" && !hasGap
	case "PARTIAL":
		return reason == "NO_USEFUL_ACTION" || reason == "BUDGET_EXCEEDED" || reason == "POLICY_EXHAUSTED"
	case "BLOCKED":
		return reason == "ACCESS_UNAVAILABLE" || reason == "SOURCE_UNAVAILABLE"
	default:
		return false
	}
}

func validSafety(value Safety) bool {
	return value.ReadOnlyToolsOnly && value.NoDuplicateActions && value.NoCredentialExposure && value.NoUnrestrictedArtifactExposure && value.AllFactualClaimsCited && value.CoverageExplicit && value.TerminalStateEvidenceSupported && value.InterruptionAndRestartSafe
}

func validOperatorReview(review Review) bool {
	if review.Decision != "ACCEPTED" || !validToken(review.ReviewerRole) || !review.Useful || !review.EvidenceTrusted || !review.TerminalCorrect || !review.SafetyAccepted || !review.UsabilityAccepted || strings.TrimSpace(review.Notes) == "" {
		return false
	}
	for _, finding := range review.Findings {
		if !validToken(finding.ID) || (finding.Severity != "LOW" && finding.Severity != "MEDIUM" && finding.Severity != "HIGH" && finding.Severity != "CRITICAL") || finding.Status != "CLOSED" || strings.TrimSpace(finding.Resolution) == "" {
			return false
		}
	}
	return true
}

func validApprovals(approvals []Approval, reviewedAt time.Time) bool {
	required := map[string]bool{"SECURITY": false, "DATA_GOVERNANCE": false, "OPERATIONS": false}
	for _, approval := range approvals {
		if _, exists := required[approval.Kind]; !exists || required[approval.Kind] || !validToken(approval.ApproverID) || approval.ApprovedAt.IsZero() || approval.ApprovedAt.After(reviewedAt) || strings.TrimSpace(approval.Reference) == "" {
			return false
		}
		required[approval.Kind] = true
	}
	for _, present := range required {
		if !present {
			return false
		}
	}
	return true
}

func targetSet(values []Target) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		if (value.Kind != "CLUSTER" && value.Kind != "NODE" && value.Kind != "GPU" && value.Kind != "SOURCE") || !validToken(value.ID) {
			return nil
		}
		key := value.Kind + ":" + value.ID
		if _, exists := result[key]; exists {
			return nil
		}
		result[key] = struct{}{}
	}
	return result
}

func overlapsTarget(left, right map[string]struct{}) bool {
	for key := range left {
		if _, exists := right[key]; exists {
			return true
		}
	}
	return false
}

func uniqueTokens(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if !validToken(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func validHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func validToken(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || slices.Contains([]rune{'-', '_', '.', '/', ':'}, character) {
			continue
		}
		return false
	}
	return true
}
