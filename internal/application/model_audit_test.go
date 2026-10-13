package application

import (
	"testing"
	"time"
)

func TestModelCallAuditRejectsUnsafeOrContentBearingMetadata(t *testing.T) {
	valid := validModelCallAudit()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	unsafe := valid
	unsafe.Model = "model with raw prompt"
	if err := unsafe.Validate(); err == nil {
		t.Fatal("unsafe free-form metadata was accepted")
	}
	failed := valid
	failed.Outcome = ModelCallFailed
	if err := failed.Validate(); err == nil {
		t.Fatal("failed call without reason code was accepted")
	}
	failed.ReasonCode = "DEADLINE_EXCEEDED"
	if err := failed.Validate(); err != nil {
		t.Fatal(err)
	}
}

func validModelCallAudit() ModelCallAudit {
	return ModelCallAudit{
		CallID: "call-1", CallKey: "investigation/inv-1/plan/2",
		InvestigationID: "inv-1", ClusterID: "cluster-1", Kind: ModelCallPlanning,
		Provider: "fixture", Model: "planner-v1", ModelConfigVersion: "config-v1",
		PromptSchemaVersion: "prompt-v1", ToolSchemaVersion: "tools-v1",
		InputTokens: 10, OutputTokens: 5, Latency: time.Millisecond,
		Outcome: ModelCallSucceeded, OccurredAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	}
}

func TestModelCallAuditRequiresInputEvidenceBeforeOutputEvidence(t *testing.T) {
	audit := validModelCallAudit()
	audit.Outcome = ModelCallRejected
	audit.ReasonCode = "INVALID_RESPONSE_SEMANTIC_VALIDATION"
	audit.OutputEvidenceID = "evidence-output"
	if err := audit.Validate(); err == nil {
		t.Fatal("accepted model output evidence without the corresponding input evidence")
	}
	audit.InputEvidenceID = "evidence-input"
	if err := audit.Validate(); err != nil {
		t.Fatalf("rejected paired model payload evidence: %v", err)
	}
}
