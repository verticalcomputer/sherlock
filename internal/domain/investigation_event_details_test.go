package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestInvestigationEventDetailsRejectUntrustedText(t *testing.T) {
	valid := InvestigationEvent{ID: "event", InvestigationID: "investigation", Sequence: 2, Kind: InvestigationEventStateChanged, From: InvestigationExecuting, To: InvestigationBlocked, OccurredAt: time.Now(), Details: InvestigationEventDetails{StopReason: StopAccessUnavailable, FailureCode: "REPAIR_WARNING_SNAPSHOT_INVALID", FailureStage: "EXECUTION"}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*InvestigationEvent){
		func(e *InvestigationEvent) { e.Details.StopReason = "host text" },
		func(e *InvestigationEvent) { e.Details.FailureCode = "host text" },
		func(e *InvestigationEvent) { e.Details.FailureStage = "host text" },
		func(e *InvestigationEvent) { e.Details.StopReason = "" },
		func(e *InvestigationEvent) { e.Details.FailureStage = "" },
		func(e *InvestigationEvent) { e.To = InvestigationSynthesizing },
	} {
		candidate := valid
		mutate(&candidate)
		if candidate.Validate() == nil {
			t.Fatalf("accepted invalid event: %+v", candidate)
		}
	}
	var historical InvestigationEventDetails
	if err := json.Unmarshal([]byte(`{}`), &historical); err != nil {
		t.Fatal(err)
	}
	valid.Details = historical
	if err := valid.Validate(); err != nil {
		t.Fatalf("historical empty payload rejected: %v", err)
	}
}
