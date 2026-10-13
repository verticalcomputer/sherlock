package investigationeval

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func LoadFile(path string) (Suite, error) {
	file, err := os.Open(path)
	if err != nil {
		return Suite{}, fmt.Errorf("open evaluation suite: %w", err)
	}
	defer file.Close()
	return Load(file)
}

func Load(reader io.Reader) (Suite, error) {
	decoder := json.NewDecoder(io.LimitReader(reader, 4<<20))
	decoder.DisallowUnknownFields()
	var suite Suite
	if err := decoder.Decode(&suite); err != nil {
		return Suite{}, fmt.Errorf("decode evaluation suite: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Suite{}, fmt.Errorf("decode evaluation suite: trailing JSON value")
		}
		return Suite{}, fmt.Errorf("decode evaluation suite: %w", err)
	}
	if err := suite.Validate(); err != nil {
		return Suite{}, err
	}
	return suite, nil
}

func (suite Suite) Validate() error {
	if suite.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported evaluation schema %q", suite.SchemaVersion)
	}
	if !validID(suite.SuiteID) || strings.TrimSpace(suite.Description) == "" {
		return fmt.Errorf("evaluation suite identity is invalid")
	}
	if err := suite.Thresholds.validate(); err != nil {
		return err
	}
	if len(suite.Cases) == 0 || len(suite.Cases) > 1000 {
		return fmt.Errorf("evaluation suite must contain between 1 and 1000 cases")
	}
	seen := make(map[string]struct{}, len(suite.Cases))
	for index, evalCase := range suite.Cases {
		if err := evalCase.validate(); err != nil {
			return fmt.Errorf("case %d: %w", index, err)
		}
		if _, exists := seen[evalCase.ID]; exists {
			return fmt.Errorf("duplicate evaluation case %q", evalCase.ID)
		}
		seen[evalCase.ID] = struct{}{}
	}
	return nil
}

func (thresholds Thresholds) validate() error {
	rates := []int{thresholds.ToolChoiceMinBP, thresholds.EvidenceCoverageMinBP, thresholds.CitationValidityMinBP, thresholds.UnsupportedClaimsMaxBP, thresholds.MutationRefusalMinBP, thresholds.PartialDataMinBP, thresholds.TerminalOutcomeMinBP, thresholds.RedundantCallsMaxBP}
	for _, rate := range rates {
		if rate < 0 || rate > 10000 {
			return fmt.Errorf("evaluation rate thresholds must be between 0 and 10000 basis points")
		}
	}
	if thresholds.LatencyMaxMillis < 0 || thresholds.CostMaxMicros < 0 {
		return fmt.Errorf("evaluation resource thresholds cannot be negative")
	}
	return nil
}

func (evalCase Case) validate() error {
	if !validID(evalCase.ID) || strings.TrimSpace(evalCase.Description) == "" {
		return fmt.Errorf("evaluation case identity is invalid")
	}
	contract := evalCase.Contract
	if len(contract.RequiredTools) == 0 || len(contract.AllowedTools) == 0 {
		return fmt.Errorf("required and allowed tools cannot be empty")
	}
	if err := uniqueIDs("required tools", contract.RequiredTools); err != nil {
		return err
	}
	if err := uniqueIDs("allowed tools", contract.AllowedTools); err != nil {
		return err
	}
	allowed := toSet(contract.AllowedTools)
	for _, tool := range contract.RequiredTools {
		if _, ok := allowed[tool]; !ok {
			return fmt.Errorf("required tool %q is not allowed", tool)
		}
	}
	if err := uniqueIDs("available evidence", contract.AvailableEvidence); err != nil {
		return err
	}
	if err := uniqueIDs("required evidence", contract.RequiredEvidence); err != nil {
		return err
	}
	available := toSet(contract.AvailableEvidence)
	for _, evidenceID := range contract.RequiredEvidence {
		if _, ok := available[evidenceID]; !ok {
			return fmt.Errorf("required evidence %q is unavailable", evidenceID)
		}
	}
	claims := make(map[string]struct{}, len(contract.SupportedClaims))
	for _, claim := range contract.SupportedClaims {
		if strings.TrimSpace(claim.Statement) == "" {
			return fmt.Errorf("supported claim statement is empty")
		}
		if _, exists := claims[claim.Statement]; exists {
			return fmt.Errorf("duplicate supported claim %q", claim.Statement)
		}
		claims[claim.Statement] = struct{}{}
		if len(claim.RequiredEvidence) == 0 {
			return fmt.Errorf("supported claim %q requires no evidence", claim.Statement)
		}
		if err := uniqueIDs("claim evidence", claim.RequiredEvidence); err != nil {
			return err
		}
		for _, evidenceID := range claim.RequiredEvidence {
			if _, ok := available[evidenceID]; !ok {
				return fmt.Errorf("claim cites unavailable evidence %q", evidenceID)
			}
		}
	}
	if err := uniqueIDs("mutation requests", contract.MutationRequests); err != nil {
		return err
	}
	if err := uniqueStrings("required unknowns", contract.RequiredUnknowns); err != nil {
		return err
	}
	if contract.ExpectPartial && len(contract.RequiredUnknowns) == 0 {
		return fmt.Errorf("partial case requires explicit unknowns")
	}
	if contract.LatencyLimitMillis < 0 || contract.CostLimitMicros < 0 {
		return fmt.Errorf("case resource limits cannot be negative")
	}
	if contract.ExpectedOutcome != "" && contract.ExpectedOutcome != "COMPLETED" && contract.ExpectedOutcome != "PARTIAL" && contract.ExpectedOutcome != "BLOCKED" {
		return fmt.Errorf("expected outcome %q is invalid", contract.ExpectedOutcome)
	}
	if contract.ExpectedStopReason != "" {
		validReason := false
		for _, reason := range []string{"SUCCESS_CRITERIA_MET", "NO_USEFUL_ACTION", "BUDGET_EXCEEDED", "APPROVAL_DENIED", "APPROVAL_EXPIRED", "ACCESS_UNAVAILABLE", "SOURCE_UNAVAILABLE", "POLICY_EXHAUSTED"} {
			validReason = validReason || contract.ExpectedStopReason == reason
		}
		if !validReason {
			return fmt.Errorf("expected stop reason %q is invalid", contract.ExpectedStopReason)
		}
	}
	if evalCase.Candidate.LatencyMillis < 0 || evalCase.Candidate.CostMicros < 0 || evalCase.Candidate.ModelTokens < 0 {
		return fmt.Errorf("candidate resource use cannot be negative")
	}
	for _, call := range evalCase.Candidate.ToolCalls {
		if !validID(call.ToolID) {
			return fmt.Errorf("candidate tool ID is invalid")
		}
		if err := uniqueIDs("candidate tool targets", call.Targets); err != nil {
			return err
		}
		// The invocation window is optional, but a fixture that records one must
		// record both bounds so the redundancy key is comparable across calls.
		if (call.Start == "") != (call.End == "") {
			return fmt.Errorf("candidate tool call window must set both bounds")
		}
		if call.Start != "" {
			start, err := time.Parse(time.RFC3339, call.Start)
			if err != nil {
				return fmt.Errorf("candidate tool call start is invalid")
			}
			end, err := time.Parse(time.RFC3339, call.End)
			if err != nil {
				return fmt.Errorf("candidate tool call end is invalid")
			}
			if !end.After(start) {
				return fmt.Errorf("candidate tool call window must be increasing")
			}
		}
	}
	if err := uniqueIDs("refused actions", evalCase.Candidate.RefusedActions); err != nil {
		return err
	}
	if err := uniqueStrings("candidate unknowns", evalCase.Candidate.Unknowns); err != nil {
		return err
	}
	for _, finding := range evalCase.Candidate.Findings {
		if strings.TrimSpace(finding.Statement) == "" {
			return fmt.Errorf("candidate finding is empty")
		}
		if err := uniqueIDs("finding evidence", finding.EvidenceIDs); err != nil {
			return err
		}
	}
	switch evalCase.Candidate.Outcome {
	case "COMPLETED", "PARTIAL", "BLOCKED":
	default:
		return fmt.Errorf("candidate outcome %q is invalid", evalCase.Candidate.Outcome)
	}
	return nil
}

func uniqueIDs(label string, values []string) error {
	for _, value := range values {
		if !validID(value) {
			return fmt.Errorf("%s contains invalid ID %q", label, value)
		}
	}
	return uniqueStrings(label, values)
}

func uniqueStrings(label string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s contains an empty value", label)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' || char == ':' {
			continue
		}
		return false
	}
	return true
}

func toSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
