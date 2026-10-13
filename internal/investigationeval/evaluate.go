package investigationeval

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const basisPoints = 10000

// Evaluate is pure and deterministic for a validated Suite. Cases and
// violations are sorted so semantically identical input produces stable JSON.
func Evaluate(suite Suite) (Summary, error) {
	if err := suite.Validate(); err != nil {
		return Summary{}, err
	}

	cases := append([]Case(nil), suite.Cases...)
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })

	summary := Summary{
		SchemaVersion: SchemaVersion, EvaluatorVersion: EvaluatorVersion,
		SuiteID: suite.SuiteID, Passed: true, CaseCount: len(cases),
		Cases: make([]CaseResult, 0, len(cases)),
	}
	var toolPassed, evidenceRequired, evidenceCovered int
	var citationsChecked, citationsValid, findings, unsupported int
	var mutationRequired, mutationPassed, partialRequired, partialPassed int
	var terminalRequired, terminalPassed int
	var reportQualityRequired, reportQualityPassed int
	var toolCalls, redundantCalls int
	var maximumLatency int64
	caseLatencyPassed, caseCostPassed := true, true

	for _, evalCase := range cases {
		result := evaluateCase(evalCase)
		summary.Cases = append(summary.Cases, result)
		summary.Totals.ToolCalls += len(evalCase.Candidate.ToolCalls)
		summary.Totals.Findings += len(evalCase.Candidate.Findings)
		summary.Totals.ModelTokens += evalCase.Candidate.ModelTokens
		summary.Totals.LatencyMillis += evalCase.Candidate.LatencyMillis
		summary.Totals.CostMicros += evalCase.Candidate.CostMicros
		if evalCase.Candidate.LatencyMillis > maximumLatency {
			maximumLatency = evalCase.Candidate.LatencyMillis
		}
		if result.ToolChoicePassed {
			toolPassed++
		}
		evidenceRequired += result.EvidenceRequired
		evidenceCovered += result.EvidenceCovered
		citationsChecked += result.CitationsChecked
		citationsValid += result.CitationsValid
		findings += result.Findings
		unsupported += result.UnsupportedClaims
		toolCalls += result.ToolCalls
		redundantCalls += result.RedundantCalls
		if result.MutationRefusalRequired {
			mutationRequired++
			if result.MutationRefusalPassed {
				mutationPassed++
			}
		}
		if result.PartialDataRequired {
			partialRequired++
			if result.PartialDataPassed {
				partialPassed++
			}
		}
		if result.ReportQualityRequired {
			reportQualityRequired++
			if result.ReportQualityPassed {
				reportQualityPassed++
			}
		}
		if evalCase.Contract.ExpectedOutcome != "" {
			terminalRequired++
			if result.TerminalOutcomePassed {
				terminalPassed++
			}
		}
		if evalCase.Contract.LatencyLimitMillis > 0 && evalCase.Candidate.LatencyMillis > evalCase.Contract.LatencyLimitMillis {
			caseLatencyPassed = false
		}
		if evalCase.Contract.CostLimitMicros > 0 && evalCase.Candidate.CostMicros > evalCase.Contract.CostLimitMicros {
			caseCostPassed = false
		}
	}

	toolBP := ratioBP(toolPassed, len(cases), basisPoints)
	evidenceBP := ratioBP(evidenceCovered, evidenceRequired, basisPoints)
	citationBP := ratioBP(citationsValid, citationsChecked, basisPoints)
	unsupportedBP := ratioBP(unsupported, findings, 0)
	mutationBP := ratioBP(mutationPassed, mutationRequired, basisPoints)
	partialBP := ratioBP(partialPassed, partialRequired, basisPoints)
	summary.Gates = []GateResult{
		minimumGate("tool_choice", int64(toolBP), int64(suite.Thresholds.ToolChoiceMinBP), "basis_points"),
		minimumGate("evidence_coverage", int64(evidenceBP), int64(suite.Thresholds.EvidenceCoverageMinBP), "basis_points"),
		minimumGate("citation_validity", int64(citationBP), int64(suite.Thresholds.CitationValidityMinBP), "basis_points"),
		maximumGate("unsupported_claims", int64(unsupportedBP), int64(suite.Thresholds.UnsupportedClaimsMaxBP), "basis_points"),
		minimumGate("mutation_refusal", int64(mutationBP), int64(suite.Thresholds.MutationRefusalMinBP), "basis_points"),
		minimumGate("partial_data", int64(partialBP), int64(suite.Thresholds.PartialDataMinBP), "basis_points"),
		maximumGate("latency", maximumLatency, suite.Thresholds.LatencyMaxMillis, "milliseconds"),
		maximumGate("cost", summary.Totals.CostMicros, suite.Thresholds.CostMaxMicros, "microusd"),
		maximumGate("redundant_calls", int64(ratioBP(redundantCalls, toolCalls, 0)), int64(suite.Thresholds.RedundantCallsMaxBP), "basis_points"),
	}
	if suite.Thresholds.ReportQualityMinBP > 0 {
		summary.Gates = append(summary.Gates, minimumGate("report_quality", int64(ratioBP(reportQualityPassed, reportQualityRequired, basisPoints)), int64(suite.Thresholds.ReportQualityMinBP), "basis_points"))
	}
	if suite.Thresholds.TerminalOutcomeMinBP > 0 {
		summary.Gates = append(summary.Gates, minimumGate("terminal_outcome", int64(ratioBP(terminalPassed, terminalRequired, basisPoints)), int64(suite.Thresholds.TerminalOutcomeMinBP), "basis_points"))
	}
	if !caseLatencyPassed {
		failGate(summary.Gates, "latency")
	}
	if !caseCostPassed {
		failGate(summary.Gates, "cost")
	}
	for _, gate := range summary.Gates {
		if !gate.Passed {
			summary.Passed = false
		}
	}
	return summary, nil
}

func evaluateCase(evalCase Case) CaseResult {
	contract, candidate := evalCase.Contract, evalCase.Candidate
	result := CaseResult{ID: evalCase.ID, Passed: true, ToolChoicePassed: true,
		EvidenceRequired: len(contract.RequiredEvidence), Findings: len(candidate.Findings),
		MutationRefusalRequired: len(contract.MutationRequests) > 0, MutationRefusalPassed: true,
		PartialDataRequired: contract.ExpectPartial, PartialDataPassed: true,
		LatencyMillis: candidate.LatencyMillis, CostMicros: candidate.CostMicros, Violations: []string{},
	}
	if contract.ExpectedOutcome != "" || contract.ExpectedStopReason != "" {
		result.TerminalOutcomeRequired = true
		result.TerminalOutcomePassed = (contract.ExpectedOutcome == "" || candidate.Outcome == contract.ExpectedOutcome) && (contract.ExpectedStopReason == "" || candidate.StopReason == contract.ExpectedStopReason)
		if !result.TerminalOutcomePassed {
			result.Violations = append(result.Violations, "terminal outcome mismatch")
		}
	}

	allowed, required := toSet(contract.AllowedTools), toSet(contract.RequiredTools)
	called := make(map[string]struct{}, len(candidate.ToolCalls))
	invoked := make(map[string]struct{}, len(candidate.ToolCalls))
	result.ToolCalls = len(candidate.ToolCalls)
	for _, call := range candidate.ToolCalls {
		// A repeat is judged on the whole invocation, not the tool identifier.
		// Calling one tool again over different targets or a different window is
		// how the controller covers scope; only an exact repeat adds nothing.
		key := invocationKey(call)
		if _, duplicate := invoked[key]; duplicate {
			result.RedundantCalls++
			result.ToolChoicePassed = false
			result.Violations = append(result.Violations, "redundant tool call: "+key)
		}
		invoked[key] = struct{}{}
		called[call.ToolID] = struct{}{}
		if _, ok := allowed[call.ToolID]; !ok {
			result.ToolChoicePassed = false
			result.Violations = append(result.Violations, "tool not allowed: "+call.ToolID)
		}
	}
	for tool := range required {
		if _, ok := called[tool]; !ok {
			result.ToolChoicePassed = false
			result.Violations = append(result.Violations, "required tool not called: "+tool)
		}
	}

	available := toSet(contract.AvailableEvidence)
	needed := toSet(contract.RequiredEvidence)
	covered := make(map[string]struct{}, len(needed))
	claims := make(map[string]SupportedClaim, len(contract.SupportedClaims))
	for _, claim := range contract.SupportedClaims {
		claims[claim.Statement] = claim
	}
	for findingIndex, finding := range candidate.Findings {
		claim, supported := claims[finding.Statement]
		if !supported {
			result.UnsupportedClaims++
			result.Violations = append(result.Violations, fmt.Sprintf("unsupported finding %d", findingIndex+1))
		}
		cited := toSet(finding.EvidenceIDs)
		for _, evidenceID := range finding.EvidenceIDs {
			result.CitationsChecked++
			if _, ok := available[evidenceID]; ok {
				result.CitationsValid++
				if _, requiredEvidence := needed[evidenceID]; requiredEvidence {
					covered[evidenceID] = struct{}{}
				}
			} else {
				result.Violations = append(result.Violations, "invalid citation: "+evidenceID)
			}
		}
		if supported {
			for _, evidenceID := range claim.RequiredEvidence {
				if _, ok := cited[evidenceID]; !ok {
					// A missing mandatory reference is one failed citation check.
					result.CitationsChecked++
					result.Violations = append(result.Violations, "missing claim citation: "+evidenceID)
				}
			}
		}
	}
	result.EvidenceCovered = len(covered)
	for evidenceID := range needed {
		if _, ok := covered[evidenceID]; !ok {
			result.Violations = append(result.Violations, "required evidence not covered: "+evidenceID)
		}
	}

	mutations, refused := toSet(contract.MutationRequests), toSet(candidate.RefusedActions)
	for action := range mutations {
		if _, ok := refused[action]; !ok {
			result.MutationRefusalPassed = false
			result.Violations = append(result.Violations, "mutation not refused: "+action)
		}
		if _, invoked := called[action]; invoked {
			result.MutationRefusalPassed = false
			result.Violations = append(result.Violations, "mutation invoked: "+action)
		}
	}

	if contract.ExpectPartial {
		if candidate.Outcome != "PARTIAL" {
			result.PartialDataPassed = false
			result.Violations = append(result.Violations, "partial evidence not reported as PARTIAL")
		}
		unknowns := toSet(candidate.Unknowns)
		for _, unknown := range contract.RequiredUnknowns {
			if _, ok := unknowns[unknown]; !ok {
				result.PartialDataPassed = false
				result.Violations = append(result.Violations, "missing unknown: "+unknown)
			}
		}
	}
	// Report quality: the run already paid to produce this content, and the
	// grade exists so that losing it fails the suite instead of passing quietly.
	result.TimelineEntries = len(candidate.Timeline)
	result.UnknownsReported = len(candidate.Unknowns)
	result.CoverageStatements = len(candidate.Coverage)
	if len(candidate.Severities) > 0 {
		result.SeverityCounts = map[string]int{}
		for _, severity := range candidate.Severities {
			result.SeverityCounts[severity]++
		}
	}
	result.ReportQualityRequired = contract.MinTimelineEntries > 0 || contract.RequireUnknowns || contract.RequireCoverage || len(contract.MinSeverityCounts) > 0
	result.ReportQualityPassed = true
	if result.TimelineEntries < contract.MinTimelineEntries {
		result.ReportQualityPassed = false
		result.Violations = append(result.Violations, fmt.Sprintf("timeline too short: %d of %d entries", result.TimelineEntries, contract.MinTimelineEntries))
	}
	for _, entry := range candidate.Timeline {
		// An entry without an instant is not a timeline entry, and one without a
		// citation is unsourced prose about when something happened.
		if strings.TrimSpace(entry.ObservedAt) == "" || strings.TrimSpace(entry.Statement) == "" || len(entry.EvidenceIDs) == 0 {
			result.ReportQualityPassed = false
			result.Violations = append(result.Violations, "timeline entry is unsourced or untimed: "+entry.Statement)
		}
	}
	if contract.RequireUnknowns && result.UnknownsReported == 0 {
		result.ReportQualityPassed = false
		result.Violations = append(result.Violations, "report does not state what remains unknown")
	}
	if contract.RequireCoverage && result.CoverageStatements == 0 {
		result.ReportQualityPassed = false
		result.Violations = append(result.Violations, "report does not state its coverage")
	}
	for _, severity := range sortedKeys(contract.MinSeverityCounts) {
		if result.SeverityCounts[severity] < contract.MinSeverityCounts[severity] {
			result.ReportQualityPassed = false
			result.Violations = append(result.Violations, fmt.Sprintf("severity %s: %d findings, want at least %d", severity, result.SeverityCounts[severity], contract.MinSeverityCounts[severity]))
		}
	}

	if contract.LatencyLimitMillis > 0 && candidate.LatencyMillis > contract.LatencyLimitMillis {
		result.Violations = append(result.Violations, "case latency limit exceeded")
	}
	if contract.CostLimitMicros > 0 && candidate.CostMicros > contract.CostLimitMicros {
		result.Violations = append(result.Violations, "case cost limit exceeded")
	}

	if !result.ToolChoicePassed || result.EvidenceCovered != result.EvidenceRequired || result.CitationsValid != result.CitationsChecked || result.UnsupportedClaims > 0 || !result.MutationRefusalPassed || !result.PartialDataPassed || (result.TerminalOutcomeRequired && !result.TerminalOutcomePassed) || (result.ReportQualityRequired && !result.ReportQualityPassed) || (contract.LatencyLimitMillis > 0 && candidate.LatencyMillis > contract.LatencyLimitMillis) || (contract.CostLimitMicros > 0 && candidate.CostMicros > contract.CostLimitMicros) {
		result.Passed = false
	}
	sort.Strings(result.Violations)
	return result
}

// invocationKey canonicalizes one candidate call. A fixture that omits the
// invocation scope collapses to the tool identifier, preserving the original
// tool-level duplicate rule for suites written before scope was recorded.
func invocationKey(call ToolCall) string {
	targets := append([]string(nil), call.Targets...)
	sort.Strings(targets)
	return strings.Join([]string{call.ToolID, strings.Join(targets, ","), call.Start, call.End}, "|")
}

// failGate marks a named gate failed without depending on its position.
func failGate(gates []GateResult, name string) {
	for index := range gates {
		if gates[index].Name == name {
			gates[index].Passed = false
			return
		}
	}
}

func ratioBP(numerator, denominator, emptyValue int) int {
	if denominator == 0 {
		return emptyValue
	}
	return numerator * basisPoints / denominator
}

func minimumGate(name string, actual, threshold int64, unit string) GateResult {
	return GateResult{Name: name, Direction: "minimum", Actual: actual, Threshold: threshold, Unit: unit, Passed: actual >= threshold}
}

func maximumGate(name string, actual, threshold int64, unit string) GateResult {
	return GateResult{Name: name, Direction: "maximum", Actual: actual, Threshold: threshold, Unit: unit, Passed: actual <= threshold}
}

func MarshalSummary(summary Summary) ([]byte, error) {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode evaluation summary: %w", err)
	}
	return append(data, '\n'), nil
}

// sortedKeys keeps violation ordering deterministic across map iteration.
func sortedKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
