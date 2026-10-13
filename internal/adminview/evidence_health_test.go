package adminview

import (
	"strings"
	"testing"
)

func TestClassifyEvidenceStreamRequiresExpectedInventory(t *testing.T) {
	stream := EvidenceStreamHealth{Status: "PARTIAL"}
	classifyEvidenceStream(&stream, "NONE")
	if !strings.Contains(stream.Condition, "expected-inventory") || !strings.Contains(stream.RecommendedAction, "application or configuration change") {
		t.Fatalf("stream=%+v", stream)
	}
}

func TestClassifyEvidenceStreamNamesConcreteMissingTargetRepair(t *testing.T) {
	expected, returned := 2, 1
	stream := EvidenceStreamHealth{Status: "PARTIAL", MissingTargets: []string{"GPU:GPU-2"}, SeriesExpected: &expected, SeriesReturned: &returned}
	classifyEvidenceStream(&stream, "NONE")
	if stream.Condition != "incomplete target coverage" || !strings.Contains(stream.RecommendedAction, "listed targets") {
		t.Fatalf("stream=%+v", stream)
	}
}

func TestDecodeEvidenceTargetsOmitsLegacyFabricatedClusterTarget(t *testing.T) {
	targets, err := decodeEvidenceTargetLabels([]byte(`[{"Kind":"CLUSTER","ID":"pilot-cluster"},{"Kind":"GPU","ID":"GPU-1"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "GPU:GPU-1" {
		t.Fatalf("targets=%v", targets)
	}
}

func TestClassifyUnavailableDiagnosticRequiresApplicationRepair(t *testing.T) {
	stream := EvidenceStreamHealth{Status: "UNAVAILABLE"}
	classifyEvidenceStream(&stream, "NONE")
	if !strings.Contains(stream.Condition, "no safe failure reason") || !strings.Contains(stream.RecommendedAction, "application or configuration change") || stream.SafeFailureReason == "" {
		t.Fatalf("stream=%+v", stream)
	}
}

func TestDiagnosticFailureReasonSurvivesHealthClassification(t *testing.T) {
	stream := EvidenceStreamHealth{Status: "UNAVAILABLE", FailureCode: "TARGET_ROLE_UNAVAILABLE", SafeFailureReason: "No confirmed inventory role."}
	classifyEvidenceStream(&stream, "NONE")
	if stream.FailureCode != "TARGET_ROLE_UNAVAILABLE" || stream.SafeFailureReason != "No confirmed inventory role." || strings.Contains(stream.Condition, "no safe failure") {
		t.Fatalf("stream=%+v", stream)
	}
}
