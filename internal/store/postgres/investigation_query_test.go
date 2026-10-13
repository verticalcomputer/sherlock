package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestInvestigationEvidenceOperationFilterFailsClosedBeforeQuery(t *testing.T) {
	store := &InvestigationStore{}
	now := time.Now().UTC()
	base := []domain.EvidenceOperationID{"slurm.jobs.v1"}
	tests := [][]domain.EvidenceOperationID{
		nil,
		{""},
		{"slurm.jobs.v1", "slurm.jobs.v1"},
		append(base, make([]domain.EvidenceOperationID, 32)...),
	}
	for index, operations := range tests {
		if _, _, err := store.FindInvestigationEvidenceByOperations(context.Background(), "inv-1", "cluster-a", []string{"node-1"}, now.Add(-time.Hour), now, now, operations, 10); err == nil {
			t.Fatalf("case %d accepted operations=%v", index, operations)
		}
	}
}
