package investigation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/contextbudget"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
)

type allowanceManifestMemory struct{ values []contextbudget.Manifest }

func (sink *allowanceManifestMemory) RecordContextManifest(_ context.Context, value contextbudget.Manifest) error {
	sink.values = append(sink.values, value)
	return nil
}

func allowanceOrchestrator(t *testing.T, now time.Time, sink contextbudget.Sink) *Orchestrator {
	t.Helper()
	orchestrator := newTestOrchestrator(t, diagnosticPlanningProvider(t, "gpu.ecc_counters.v1"), &auditMemory{}, &duplicateMemory{}, now)
	manager, err := contextbudget.New(contextbudget.Config{MaximumInputTokens: 1024}, contextbudget.JSONHeuristicEstimator{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.budgets = manager
	return orchestrator
}

func allowanceContext(now time.Time, count int, required map[int]bool) investigationcontext.Context {
	context := investigationcontext.Context{Header: investigationcontext.TrustedHeader{Question: "Combined repair plan"}}
	for n := 0; n < count; n++ {
		context.Evidence = append(context.Evidence, investigationcontext.EvidenceBlock{
			EvidenceID: domain.EvidenceID(fmt.Sprintf("warning-%02d", n)), Status: domain.EvidenceUnavailable,
			EntityIDs: []string{"cluster-a"}, Source: fmt.Sprintf("diagnostic-%02d:gpu.ecc_counters", n),
			ObservedFrom: now.Add(-time.Minute), ObservedTo: now, CollectedAt: now, ExpectedFrom: now.Add(-time.Minute), ExpectedTo: now,
			UntrustedExcerpt: strings.Repeat("x", 600), Required: required[n],
		})
	}
	return context
}

// A repair plan's warning set passed the encoded-context limit and then failed
// PROVIDER_INPUT_EXCEEDS_ALLOWANCE before any model call. It must instead drop
// the lowest-priority warnings, record them, and keep the plan partial.
func TestRepairPlanSynthesisTrimsEvidenceToProviderAllowance(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	sink := &allowanceManifestMemory{}
	orchestrator := allowanceOrchestrator(t, now, sink)
	full := allowanceContext(now, 12, map[int]bool{0: true})

	request, manifest, trimmed, err := orchestrator.prepareSynthesisWithinAllowance(context.Background(), repairSnapshot(t, now), "call-1", full)
	if err != nil {
		t.Fatalf("trimmed synthesis preparation failed: %v", err)
	}
	dropped := len(full.Evidence) - len(trimmed.Evidence)
	if dropped < 1 || len(trimmed.Evidence) < 1 || trimmed.Evidence[0].EvidenceID != "warning-00" {
		t.Fatalf("kept %d of %d warnings, first=%v", len(trimmed.Evidence), len(full.Evidence), trimmed.Evidence)
	}
	if len(trimmed.Omissions) != 1 || trimmed.Omissions[0].Kind != "EVIDENCE" || trimmed.Omissions[0].Reason != synthesisAllowanceOmissionReason || trimmed.Omissions[0].Count != dropped {
		t.Fatalf("omissions = %+v, dropped %d", trimmed.Omissions, dropped)
	}
	if request.Coverage.EvidenceOmitted != dropped || len(request.Evidence) != len(trimmed.Evidence) {
		t.Fatalf("request evidence=%d omitted=%d, want %d kept and %d omitted", len(request.Evidence), request.Coverage.EvidenceOmitted, len(trimmed.Evidence), dropped)
	}
	if manifest.EstimatedInputTokens > manifest.AllowanceTokens || len(sink.values) != 1 {
		t.Fatalf("manifest estimated=%d allowance=%d recorded=%d", manifest.EstimatedInputTokens, manifest.AllowanceTokens, len(sink.values))
	}
	if len(full.Evidence) != 12 || len(full.Omissions) != 0 {
		t.Fatalf("trimming mutated the caller's context: evidence=%d omissions=%d", len(full.Evidence), len(full.Omissions))
	}
}

func TestSynthesisAllowanceTrimmingIsLimitedToOmittableRepairEvidence(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)

	ordinary := &allowanceManifestMemory{}
	if _, _, kept, err := allowanceOrchestrator(t, now, ordinary).prepareSynthesisWithinAllowance(context.Background(), planningSnapshot(t, now), "call-1", allowanceContext(now, 12, nil)); !errors.Is(err, contextbudget.ErrAllowanceExceeded) || len(kept.Evidence) != 12 || len(ordinary.values) != 0 {
		t.Fatalf("ordinary investigation err=%v kept=%d manifests=%d", err, len(kept.Evidence), len(ordinary.values))
	}

	required := map[int]bool{}
	for n := 0; n < 12; n++ {
		required[n] = true
	}
	mandatory := &allowanceManifestMemory{}
	if _, _, kept, err := allowanceOrchestrator(t, now, mandatory).prepareSynthesisWithinAllowance(context.Background(), repairSnapshot(t, now), "call-1", allowanceContext(now, 12, required)); !errors.Is(err, contextbudget.ErrAllowanceExceeded) || len(kept.Evidence) != 12 || len(mandatory.values) != 0 {
		t.Fatalf("required evidence err=%v kept=%d manifests=%d", err, len(kept.Evidence), len(mandatory.values))
	}

	unrelated := errors.New("load token calibration: unavailable")
	if _, ok := trimSynthesisEvidenceForAllowance(repairSnapshot(t, now), allowanceContext(now, 3, nil), unrelated); ok {
		t.Fatal("a non-allowance failure trimmed evidence")
	}
}
