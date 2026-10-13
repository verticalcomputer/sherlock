package m11acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
)

const SchemaVersion = 1

type Turn struct {
	Turn                        int      `json:"turn"`
	InputArtifactSHA256         string   `json:"input_artifact_sha256"`
	OutputArtifactSHA256        string   `json:"output_artifact_sha256"`
	ManifestSHA256              string   `json:"manifest_sha256"`
	EstimatorVersion            string   `json:"estimator_version"`
	CalibrationFactorMillionths int64    `json:"calibration_factor_millionths"`
	ActualInputTokens           int64    `json:"actual_input_tokens"`
	ConservativeInputEstimate   int64    `json:"conservative_input_estimate"`
	OutputTokens                int64    `json:"output_tokens"`
	SelectedEvidenceIDs         []string `json:"selected_evidence_ids"`
	RequiredEvidenceIDs         []string `json:"required_evidence_ids"`
	DiagnosisCriticalIDs        []string `json:"diagnosis_critical_evidence_ids"`
	CitationValid               bool     `json:"citation_valid"`
	DuplicateExactAction        bool     `json:"duplicate_exact_action"`
}

type Fixture struct {
	SchemaVersion       int    `json:"schema_version"`
	InvestigationID     string `json:"investigation_id"`
	BaselineTotalTokens int64  `json:"baseline_total_tokens"`
	BaselineCostMicros  int64  `json:"baseline_cost_micros"`
	CandidateCostMicros int64  `json:"candidate_cost_micros"`
	TerminalParity      bool   `json:"terminal_parity"`
	StatelessRecovery   bool   `json:"stateless_recovery"`
	ProviderIDsExposed  bool   `json:"provider_ids_exposed"`
	Turns               []Turn `json:"turns"`
}

type Gate struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}
type Summary struct {
	SchemaVersion        int     `json:"schema_version"`
	FixtureSHA256        string  `json:"fixture_sha256"`
	InvestigationID      string  `json:"investigation_id"`
	TotalTokens          int64   `json:"total_tokens"`
	CostReductionPercent float64 `json:"cost_reduction_percent"`
	Gates                []Gate  `json:"gates"`
	Passed               bool    `json:"passed"`
}

func Evaluate(encoded []byte, expectedDigest string) (Summary, error) {
	digest := sha256.Sum256(encoded)
	actualDigest := hex.EncodeToString(digest[:])
	if expectedDigest == "" || expectedDigest != actualDigest {
		return Summary{}, fmt.Errorf("M11 fixture digest mismatch: actual=%s", actualDigest)
	}
	var fixture Fixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		return Summary{}, fmt.Errorf("decode M11 fixture: %w", err)
	}
	if fixture.SchemaVersion != SchemaVersion || fixture.InvestigationID == "" || len(fixture.Turns) != 6 || fixture.BaselineTotalTokens != 211831 || fixture.BaselineCostMicros != 1241030 {
		return Summary{}, fmt.Errorf("M11 fixture baseline or identity is invalid")
	}
	summary := Summary{SchemaVersion: SchemaVersion, FixtureSHA256: actualDigest, InvestigationID: fixture.InvestigationID}
	bounded, conservative, artifacts, calibration, recall, citations, duplicates := true, true, true, true, true, true, true
	for index, turn := range fixture.Turns {
		if turn.Turn != index+1 || !validDigest(turn.InputArtifactSHA256) || !validDigest(turn.OutputArtifactSHA256) || !validDigest(turn.ManifestSHA256) {
			artifacts = false
		}
		if turn.EstimatorVersion == "" || turn.CalibrationFactorMillionths < 1_000_000 || turn.CalibrationFactorMillionths > 3_000_000 {
			calibration = false
		}
		if turn.ActualInputTokens <= 0 || turn.ActualInputTokens > 20000 {
			bounded = false
		}
		if turn.ConservativeInputEstimate < turn.ActualInputTokens {
			conservative = false
		}
		if !containsAll(turn.SelectedEvidenceIDs, turn.RequiredEvidenceIDs) || !containsAll(turn.SelectedEvidenceIDs, turn.DiagnosisCriticalIDs) {
			recall = false
		}
		citations = citations && turn.CitationValid
		duplicates = duplicates && !turn.DuplicateExactAction
		summary.TotalTokens += turn.ActualInputTokens + turn.OutputTokens
	}
	bounded = bounded && summary.TotalTokens <= 120000
	cost := fixture.CandidateCostMicros >= 0 && fixture.CandidateCostMicros*100 <= fixture.BaselineCostMicros*65
	if fixture.BaselineCostMicros > 0 {
		summary.CostReductionPercent = 100 * (1 - float64(fixture.CandidateCostMicros)/float64(fixture.BaselineCostMicros))
	}
	summary.Gates = []Gate{{"frozen_artifacts", artifacts, "six digest-pinned input/output/manifest triples"}, {"bounded_tokens", bounded, "at most 20k input per turn and 120k total"}, {"conservative_estimator", conservative, "actual input never exceeds admission"}, {"calibration_metadata", calibration, "versioned factor is recorded for every turn"}, {"critical_evidence_recall", recall, "all required and diagnosis-critical evidence selected"}, {"citation_validity", citations, "all reviewed citations valid"}, {"duplicate_actions", duplicates, "zero duplicate exact actions"}, {"terminal_parity", fixture.TerminalParity, "reviewed terminal semantics preserved"}, {"stateless_recovery", fixture.StatelessRecovery, "provider state deletion rebuilt the same next-call state"}, {"provider_id_privacy", !fixture.ProviderIDsExposed, "opaque provider IDs absent from public output"}, {"cost_reduction", cost, "at least 35 percent against the frozen deployment baseline"}}
	summary.Passed = true
	for _, gate := range summary.Gates {
		summary.Passed = summary.Passed && gate.Passed
	}
	return summary, nil
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
func containsAll(values, required []string) bool {
	for _, value := range required {
		if !slices.Contains(values, value) {
			return false
		}
	}
	return true
}
