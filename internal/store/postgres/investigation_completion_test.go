package postgres

import (
	"testing"
	"time"
)

func TestDiagnosticCausalOrderUsesOnlyServerOwnedTimestamps(t *testing.T) {
	finalized := time.Date(2026, 8, 27, 6, 15, 23, 70_000_000, time.UTC)
	evidence := finalized.Add(5 * time.Millisecond)
	action := evidence.Add(5 * time.Millisecond)
	if !diagnosticCausalOrder(finalized, evidence, action) {
		t.Fatal("ordered PostgreSQL persistence markers were rejected")
	}
}

func TestDiagnosticCausalOrderRejectsMissingOrInvertedMarkers(t *testing.T) {
	base := time.Date(2026, 8, 27, 6, 15, 23, 70_000_000, time.UTC)
	tests := []struct {
		name                        string
		finalized, evidence, action time.Time
	}{
		{name: "missing finalization", evidence: base, action: base},
		{name: "evidence before finalization", finalized: base.Add(time.Microsecond), evidence: base, action: base.Add(2 * time.Microsecond)},
		{name: "action before evidence", finalized: base, evidence: base.Add(2 * time.Microsecond), action: base.Add(time.Microsecond)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if diagnosticCausalOrder(test.finalized, test.evidence, test.action) {
				t.Fatal("invalid causal markers were admitted")
			}
		})
	}
}
