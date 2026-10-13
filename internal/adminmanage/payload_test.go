package adminmanage

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fakeEvidenceLoader struct {
	envelope  domain.EvidenceEnvelope
	condition domain.ArtifactAvailability
	found     bool
	err       error
}

func (loader fakeEvidenceLoader) LoadEvidence(context.Context, domain.EvidenceID) (domain.EvidenceEnvelope, domain.ArtifactAvailability, bool, error) {
	return loader.envelope, loader.condition, loader.found, loader.err
}

type fakeArtifactReader struct {
	payload []byte
	err     error
}

func (reader fakeArtifactReader) Read(context.Context, domain.ArtifactReference) ([]byte, error) {
	return reader.payload, reader.err
}

func TestEvidencePayloadReaderReturnsAvailableRedactedArtifact(t *testing.T) {
	content := []byte(`{"question":"why","secret":"[REDACTED]"}`)
	reference, err := domain.NewArtifactReference(domain.ChecksumSHA256(content), int64(len(content)), "application/json", domain.ArtifactUncompressed, "model-io-v1", domain.RedactionSummary{PolicyVersion: "model-io-redaction-v1", MatchCount: 1}, domain.ArtifactRetentionExtended)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	target := domain.EvidenceTarget{Kind: domain.EvidenceTargetCluster, ID: "cluster-1"}
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{
		ID: "model-io-1", SchemaVersion: domain.EvidenceSchemaVersion, ClusterID: "cluster-1", Status: domain.EvidenceComplete,
		Source:    domain.EvidenceSourceReference{SourceID: "model-source", Operation: "model_input", DefinitionVersion: "model-io-v1", Reference: "model-call:one:input"},
		TimeRange: domain.EvidenceTimeRange{Start: now, End: now}, CollectedAt: now,
		Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}, Covered: []domain.EvidenceTarget{target}}, Artifact: &reference,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewEvidencePayloadReader(fakeEvidenceLoader{envelope: envelope, condition: domain.ArtifactAvailable, found: true}, fakeArtifactReader{payload: content})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := reader.ReadModelPayload(t.Context(), "model-io-1")
	if err != nil || payload.Availability != PayloadAvailable || payload.Content != string(content) || payload.MediaType != "application/json" {
		t.Fatalf("payload=%+v err=%v", payload, err)
	}
}

func TestEvidencePayloadReaderDistinguishesMissingPayload(t *testing.T) {
	reader, err := NewEvidencePayloadReader(fakeEvidenceLoader{}, fakeArtifactReader{})
	if err != nil {
		t.Fatal(err)
	}
	missing, err := reader.ReadModelPayload(t.Context(), "")
	if err != nil || missing.Availability != PayloadNotRecorded {
		t.Fatalf("missing=%+v err=%v", missing, err)
	}
	unavailable, err := reader.ReadModelPayload(t.Context(), "model-io-missing")
	if err != nil || unavailable.Availability != PayloadUnavailable || unavailable.EvidenceID != "model-io-missing" {
		t.Fatalf("unavailable=%+v err=%v", unavailable, err)
	}
}
