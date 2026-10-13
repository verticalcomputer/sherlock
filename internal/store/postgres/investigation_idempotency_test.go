package postgres

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestInvestigationRequestHashCoversSemanticInput(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	request := domain.InvestigationRequest{
		ID: "generated-a", IncidentID: "incident-1", ClusterID: "cluster-1", Question: "why",
		RequestedBy: "actor-1", IdempotencyKey: "key-1",
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now},
		SuccessCriteria: []string{"explain"},
		Budget:          domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 3, MaxFanOut: 4},
		RequestedAt:     now, Deadline: now.Add(time.Hour),
	}
	want, err := investigationRequestHash(request)
	if err != nil {
		t.Fatal(err)
	}
	retry := request
	retry.RequestedAt = now.Add(time.Minute)
	if got, err := investigationRequestHash(retry); err != nil || got != want {
		t.Fatalf("retry hash = %x, %v; want %x", got, err, want)
	}
	changed := request
	changed.Scope.EntityIDs = []string{"node-2"}
	if got, err := investigationRequestHash(changed); err != nil || got == want {
		t.Fatalf("changed request hash = %x, %v; want a different hash", got, err)
	}
}
