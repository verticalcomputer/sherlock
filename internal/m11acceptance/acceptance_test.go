package m11acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestEvaluateRequiresPinnedCompleteSixTurnEvidence(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixture := Fixture{SchemaVersion: 1, InvestigationID: "investigation-fixture", BaselineTotalTokens: 211831, BaselineCostMicros: 1241030, CandidateCostMicros: 700000, TerminalParity: true, StatelessRecovery: true}
	for turn := 1; turn <= 6; turn++ {
		fixture.Turns = append(fixture.Turns, Turn{Turn: turn, InputArtifactSHA256: digest, OutputArtifactSHA256: digest, ManifestSHA256: digest, EstimatorVersion: "json-bytes-ceil-div4-v1", CalibrationFactorMillionths: 1_600_000, ActualInputTokens: 15000, ConservativeInputEstimate: 16000, OutputTokens: 1000, SelectedEvidenceIDs: []string{"ev-1"}, RequiredEvidenceIDs: []string{"ev-1"}, DiagnosisCriticalIDs: []string{"ev-1"}, CitationValid: true})
	}
	encoded, _ := json.Marshal(fixture)
	checksum := sha256.Sum256(encoded)
	summary, err := Evaluate(encoded, hex.EncodeToString(checksum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Passed || summary.TotalTokens != 96000 {
		t.Fatalf("summary=%+v", summary)
	}
	fixture.Turns[2].ConservativeInputEstimate = 14000
	encoded, _ = json.Marshal(fixture)
	checksum = sha256.Sum256(encoded)
	summary, err = Evaluate(encoded, hex.EncodeToString(checksum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Passed {
		t.Fatal("estimator underrun passed")
	}
}
