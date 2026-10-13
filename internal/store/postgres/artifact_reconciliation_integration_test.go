//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestEvidenceArtifactReconciliationRoundTrip(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	collections, _ := storepg.NewCollectionStore(pool)
	evidence, _ := storepg.NewEvidenceStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("reconcile-cluster-" + suffix)
	sourceID := domain.SourceID("reconcile-source-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "Reconciliation cluster", sourceID, "Reconciliation source"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	payload := []byte("artifact reconciliation fixture")
	reference, err := domain.NewArtifactReference(domain.ChecksumSHA256(payload), int64(len(payload)), "text/plain", domain.ArtifactUncompressed, "parser-v1", domain.RedactionSummary{PolicyVersion: "redaction-v1"}, domain.ArtifactRetentionStandard)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{
		ID: domain.EvidenceID("reconcile-evidence-" + suffix), SchemaVersion: 1, ClusterID: clusterID,
		Status: domain.EvidenceComplete, Source: domain.EvidenceSourceReference{SourceID: sourceID, Operation: "fixture", DefinitionVersion: "v1", Reference: "fixture://reconciliation"},
		TimeRange: domain.EvidenceTimeRange{Start: now.Add(-time.Minute), End: now}, CollectedAt: now,
		Coverage: domain.EvidenceCoverage{
			Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetSource, ID: domain.EvidenceTargetID(sourceID)}},
			Covered:  []domain.EvidenceTarget{{Kind: domain.EvidenceTargetSource, ID: domain.EvidenceTargetID(sourceID)}},
		}, Artifact: &reference,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created, err := evidence.CreateEvidence(ctx, envelope); err != nil || !created {
		t.Fatalf("create evidence: created=%t err=%v", created, err)
	}
	investigations, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	entries, more, err := investigations.FindInvestigationEvidence(ctx, domain.InvestigationID("lookup-investigation-"+suffix), clusterID, []string{string(sourceID)}, now.Add(-time.Hour), now, now.Add(time.Minute), 10)
	if err != nil || more || len(entries) != 1 || entries[0].EvidenceID != envelope.ID() || len(entries[0].EntityIDs) != 1 || entries[0].EntityIDs[0] != string(sourceID) {
		t.Fatalf("lookup entries=%+v more=%t err=%v", entries, more, err)
	}
	candidates, err := evidence.ListArtifactReconciliationCandidates(ctx, now.Add(time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, candidate := range candidates {
		if candidate.EvidenceID != envelope.ID() {
			continue
		}
		found = true
		if candidate.Condition != domain.ArtifactPending || candidate.Reference != reference {
			t.Fatalf("candidate=%+v", candidate)
		}
	}
	if !found {
		t.Fatal("new pending artifact was not selected for reconciliation")
	}
	for _, condition := range []domain.ArtifactAvailability{domain.ArtifactUnavailable, domain.ArtifactCorrupt, domain.ArtifactAvailable} {
		if err := evidence.SetArtifactAvailability(ctx, envelope.ID(), reference.ArtifactID, condition); err != nil {
			t.Fatal(err)
		}
		availability, ok, err := evidence.ArtifactAvailability(ctx, envelope.ID())
		if err != nil || !ok || availability.Condition != condition {
			t.Fatalf("condition=%s availability=%+v ok=%t err=%v", condition, availability, ok, err)
		}
	}
}
