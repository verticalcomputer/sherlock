package investigationcontext

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestRetrievalQuestionChangesSelectedEvidence(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	storage := evidenceCandidate(now, "a-storage", "observations", false)
	storage.Summary = "Filesystem capacity exhausted; storage writes failed."
	thermal := evidenceCandidate(now, "z-thermal", "observations", false)
	thermal.Summary = "GPU thermal slowdown asserted; cooling temperature increased."
	query := RetrievalQuery{ClusterID: "cluster-a", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now, CommittedBefore: now.Add(time.Minute), AllowanceTokens: 4000, MaximumPerClass: 1}
	for _, tc := range []struct {
		text string
		want domain.EvidenceID
	}{
		{"Why is thermal slowdown happening?", thermal.EvidenceID},
		{"Are storage writes failing?", storage.EvidenceID},
		{"", storage.EvidenceID},
	} {
		t.Run(tc.text, func(t *testing.T) {
			query.Text = tc.text
			for _, candidates := range [][]EvidenceInput{{storage, thermal}, {thermal, storage}} {
				result, err := SelectEvidence(candidates, query)
				if err != nil {
					t.Fatal(err)
				}
				if got := selectedIDs(result.Selected); !slices.Equal(got, []domain.EvidenceID{tc.want}) {
					t.Fatalf("selected %v, want %s", got, tc.want)
				}
			}
		})
	}
}

func TestEngineUsesUnresolvedHypothesisForRetrieval(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	snapshot := checkpointSnapshot(t, now)
	ledger, err := domain.NewHypothesisLedger([]domain.Hypothesis{{ID: "h-1", InvestigationID: "inv-1", Statement: "Investigate the cause", Status: domain.HypothesisUnresolved, UnresolvedTests: []string{"thermal slowdown"}, Version: 1}}, snapshot.Evidence, snapshot.Investigation)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Hypotheses = ledger
	input := checkpointInput(now)
	input.Evidence[0].Summary = "GPU thermal slowdown observed."
	input.Evidence[1].Summary = "Filesystem storage capacity observed."
	config := DefaultEngineConfig()
	config.MaximumPerClass = 1
	engine, err := NewEngine(config, &checkpointMemory{})
	if err != nil {
		t.Fatal(err)
	}
	prepared, record, err := engine.Prepare(context.Background(), snapshot, input)
	if err != nil {
		t.Fatal(err)
	}
	if got := selectedIDs(prepared.Evidence); !slices.Equal(got, []domain.EvidenceID{"ev-2"}) {
		t.Fatalf("selected %v; unresolved test should select thermal evidence", got)
	}
	if !slices.Equal(record.Selected, []string{"ev-2"}) {
		t.Fatalf("selection audit: %+v", record)
	}
}

func TestBuilderFallbackUsesQuestionForRetrieval(t *testing.T) {
	input := baseInput()
	input.Question = "Why is thermal slowdown occurring?"
	storage := input.Evidence[0]
	storage.KeepDistinct = true
	storage.Summary = "Filesystem storage capacity observed."
	thermal := storage
	thermal.EvidenceID = "z-thermal"
	thermal.Summary = "GPU thermal slowdown observed."
	input.Evidence = []EvidenceInput{storage, thermal}
	limits := DefaultLimits()
	limits.MaxEvidence = 1
	result, err := mustBuilder(t, limits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].EvidenceID != thermal.EvidenceID {
		t.Fatalf("unexpected evidence: %+v", result.Evidence)
	}
}

func TestQueryMatchIsBoundedAndCountsDistinctWholeTerms(t *testing.T) {
	for _, tc := range []struct {
		name, query, summary, excerpt string
		summaryCap, excerptCap        int
		want                          int64
	}{
		{name: "case and punctuation", query: "Why THERMAL-slowdown?", summary: "thermal slowdown", want: 1000},
		{name: "partial overlap", query: "thermal slowdown", summary: "thermal", want: 500},
		{name: "repetition", query: "thermal thermal slowdown", summary: "thermal thermal", excerpt: "thermal thermal", want: 500},
		{name: "whole terms", query: "heat", summary: "heartbeat overheating", want: 0},
		{name: "unicode", query: "TEMPÉRATURE", summary: "température", want: 1000},
		{name: "summary projection", query: "thermal", summary: "normal thermal", summaryCap: 6, want: 0},
		{name: "excerpt projection", query: "thermal", excerpt: "normal thermal", excerptCap: 6, want: 0},
		{name: "excerpt", query: "thermal", summary: "normal", excerpt: "thermal", want: 1000},
		{name: "stop words only", query: "why is the", summary: "why is the", want: 0},
		{name: "search bound", query: "thermal", summary: strings.Repeat("x", maxSearchFieldBytes) + " thermal", want: 0},
		{name: "query bound", query: strings.Repeat(" ", maxQueryBytes) + "thermal", summary: "thermal", want: 0},
		{name: "long token", query: strings.Repeat("x", maxQueryTermBytes+1), summary: strings.Repeat("x", maxQueryTermBytes+1), want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := EvidenceInput{EvidenceID: "thermal", Source: "thermal", Summary: tc.summary, Excerpt: tc.excerpt}
			query := RetrievalQuery{MaxSummaryBytes: tc.summaryCap, MaxExcerptBytes: tc.excerptCap}
			if got := queryMatchScore(item, query, queryTerms(tc.query)); got != tc.want {
				t.Fatalf("score %d, want %d", got, tc.want)
			}
		})
	}
	var many strings.Builder
	for i := range maxQueryTerms + 10 {
		fmt.Fprintf(&many, "term%d ", i)
	}
	if terms := queryTerms(many.String()); len(terms) != maxQueryTerms {
		t.Fatalf("unbounded terms: %d", len(terms))
	}
}

func TestQueryMatchCannotAdmitUnauthorizedEvidence(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	query := RetrievalQuery{ClusterID: "cluster-a", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now, CommittedBefore: now.Add(time.Minute), AllowanceTokens: 4000, Text: "thermal slowdown"}
	for _, tc := range []struct {
		name   string
		change func(*EvidenceInput)
		reason ExclusionReason
	}{
		{"foreign cluster", func(e *EvidenceInput) { e.ClusterID = "other" }, ExcludeCluster},
		{"foreign node", func(e *EvidenceInput) { e.EntityIDs = []string{"other"} }, ExcludeScope},
		{"future commit", func(e *EvidenceInput) { e.CommittedAt = now.Add(time.Hour) }, ExcludeCommitBoundary},
		{"outside time", func(e *EvidenceInput) {
			e.ObservedFrom = now.Add(-3 * time.Hour)
			e.ObservedTo = now.Add(-2 * time.Hour)
		}, ExcludeTime},
		{"not citable", func(e *EvidenceInput) { e.CitationEligible = false }, ExcludeAuthority},
		{"superseded", func(e *EvidenceInput) { e.Superseded = true }, ExcludeSuperseded},
		{"not retained", func(e *EvidenceInput) { e.Retained = false }, ExcludeRetention},
		{"missing artifact", func(e *EvidenceInput) { e.Excerpt = "thermal slowdown"; e.ArtifactAvailable = false }, ExcludeArtifactAvailability},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowed := evidenceCandidate(now, "allowed", "observations", false)
			denied := evidenceCandidate(now, "denied", "observations", false)
			denied.Summary = "thermal slowdown"
			tc.change(&denied)
			result, err := SelectEvidence([]EvidenceInput{denied, allowed}, query)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(selectedIDs(result.Selected), []domain.EvidenceID{"allowed"}) || len(result.Exclusions) != 1 || result.Exclusions[0].Reason != tc.reason {
				t.Fatalf("unexpected selection: %+v", result)
			}
		})
	}
}

func TestQueryMatchPreservesMandatoryEvidenceAndEntityCoverage(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	mandatory := evidenceCandidate(now, "required", "observations", false)
	mandatory.Protected = true
	mandatory.Summary = "Filesystem state observed."
	first := evidenceCandidate(now, "first", "observations", false)
	first.Summary = "thermal slowdown"
	second := evidenceCandidate(now, "second", "observations", false)
	second.EntityIDs = []string{"node-2"}
	second.Summary = "Filesystem state observed."
	second.Coverage = domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "node-2"}}, Covered: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "node-2"}}}
	query := RetrievalQuery{ClusterID: "cluster-a", EntityIDs: []string{"node-1", "node-2"}, Start: now.Add(-time.Hour), End: now, CommittedBefore: now.Add(time.Minute), AllowanceTokens: 4000, MaximumPerClass: 1, Text: "thermal slowdown"}
	result, err := SelectEvidence([]EvidenceInput{first, second, mandatory}, query)
	if err != nil {
		t.Fatal(err)
	}
	if got := selectedIDs(result.Selected); !slices.Equal(got, []domain.EvidenceID{"required", "second"}) {
		t.Fatalf("query match displaced required evidence or entity coverage: %v", got)
	}
}
