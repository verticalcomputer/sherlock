package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type evidenceMemoryStore struct {
	values       map[domain.EvidenceID]domain.EvidenceEnvelope
	availability map[domain.EvidenceID]domain.EvidenceArtifactAvailability
}

func (store *evidenceMemoryStore) CreateEvidence(_ context.Context, envelope domain.EvidenceEnvelope) (bool, error) {
	if prior, ok := store.values[envelope.ID()]; ok {
		if !prior.Equal(envelope) {
			return false, ErrEvidenceConflict
		}
		return false, nil
	}
	store.values[envelope.ID()] = envelope
	if reference, ok := envelope.Artifact(); ok {
		store.availability[envelope.ID()] = domain.EvidenceArtifactAvailability{EvidenceID: envelope.ID(), ArtifactID: reference.ArtifactID, Condition: domain.ArtifactPending}
	}
	return true, nil
}

func (store *evidenceMemoryStore) MarkArtifactAvailable(_ context.Context, evidenceID domain.EvidenceID, artifactID domain.ArtifactID) error {
	availability, ok := store.availability[evidenceID]
	if !ok || availability.ArtifactID != artifactID {
		return ErrEvidenceConflict
	}
	availability.Condition = domain.ArtifactAvailable
	store.availability[evidenceID] = availability
	return nil
}

func (store *evidenceMemoryStore) ArtifactAvailability(_ context.Context, evidenceID domain.EvidenceID) (domain.EvidenceArtifactAvailability, bool, error) {
	availability, ok := store.availability[evidenceID]
	return availability, ok, nil
}

type artifactSpy struct {
	events      []string
	promoteErr  error
	stagedBytes []byte
}

func (spy *artifactSpy) Stage(_ context.Context, evidenceID domain.EvidenceID, reference domain.ArtifactReference, payload []byte) (StagedArtifact, error) {
	spy.events = append(spy.events, "stage")
	spy.stagedBytes = append([]byte(nil), payload...)
	return StagedArtifact{ID: "temp-1", EvidenceID: evidenceID, Reference: reference}, nil
}
func (spy *artifactSpy) Promote(_ context.Context, _ StagedArtifact) error {
	spy.events = append(spy.events, "promote")
	return spy.promoteErr
}
func (spy *artifactSpy) Discard(_ context.Context, _ StagedArtifact) error {
	spy.events = append(spy.events, "discard")
	return nil
}

func TestEvidenceRecorderCreatesOnceAndPromotesVerifiedArtifact(t *testing.T) {
	payload := []byte("raw dcgm response")
	envelope := testEvidenceEnvelope(t, "ev-1", payload)
	evidence := newEvidenceMemoryStore()
	objects := &artifactSpy{}
	recorder, err := NewEvidenceRecorder(evidence, objects, 1024)
	if err != nil {
		t.Fatal(err)
	}

	first, err := recorder.Record(context.Background(), RecordEvidence{Envelope: envelope, RawArtifact: payload})
	if err != nil {
		t.Fatal(err)
	}
	if first.PreviouslyRecorded || !first.ArtifactAvailable {
		t.Fatalf("unexpected first outcome: %#v", first)
	}
	second, err := recorder.Record(context.Background(), RecordEvidence{Envelope: envelope, RawArtifact: payload})
	if err != nil {
		t.Fatal(err)
	}
	if !second.PreviouslyRecorded || !second.ArtifactAvailable {
		t.Fatalf("unexpected replay outcome: %#v", second)
	}
	if got := len(evidence.values); got != 1 {
		t.Fatalf("stored %d envelopes, want one", got)
	}
	if got := evidence.availability[envelope.ID()].Condition; got != domain.ArtifactAvailable {
		t.Fatalf("artifact availability = %q, want AVAILABLE", got)
	}
	if string(objects.stagedBytes) != string(payload) {
		t.Fatal("artifact store did not receive exact bytes")
	}
}

func TestEvidenceRecorderRejectsArtifactBeforeIO(t *testing.T) {
	payload := []byte("raw dcgm response")
	envelope := testEvidenceEnvelope(t, "ev-1", payload)
	evidence := newEvidenceMemoryStore()
	objects := &artifactSpy{}
	recorder, _ := NewEvidenceRecorder(evidence, objects, 1024)

	_, err := recorder.Record(context.Background(), RecordEvidence{Envelope: envelope, RawArtifact: []byte("changed")})
	if !errors.Is(err, ErrArtifactChecksumMismatch) {
		t.Fatalf("got %v, want checksum mismatch", err)
	}
	if len(objects.events) != 0 || len(evidence.values) != 0 {
		t.Fatal("invalid artifact crossed an I/O port")
	}
}

func TestEvidenceRecorderKeepsEnvelopeWhenPromotionFails(t *testing.T) {
	payload := []byte("raw dcgm response")
	envelope := testEvidenceEnvelope(t, "ev-1", payload)
	evidence := newEvidenceMemoryStore()
	objects := &artifactSpy{promoteErr: errors.New("object service unavailable")}
	recorder, _ := NewEvidenceRecorder(evidence, objects, 1024)

	outcome, err := recorder.Record(context.Background(), RecordEvidence{Envelope: envelope, RawArtifact: payload})
	if err == nil || outcome.ArtifactAvailable {
		t.Fatalf("unexpected promotion result: %#v, %v", outcome, err)
	}
	if _, ok := evidence.values[envelope.ID()]; !ok {
		t.Fatal("promotion failure removed the immutable envelope")
	}
	if got := evidence.availability[envelope.ID()].Condition; got != domain.ArtifactPending {
		t.Fatalf("failed promotion availability = %q, want PENDING", got)
	}
}

func TestEvidenceArtifactLookupExposesExplicitConditions(t *testing.T) {
	payload := []byte("raw dcgm response")
	envelope := testEvidenceEnvelope(t, "ev-1", payload)
	evidence := newEvidenceMemoryStore()
	if _, err := evidence.CreateEvidence(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	availability := evidence.availability[envelope.ID()]
	availability.Condition = domain.ArtifactCorrupt
	evidence.availability[envelope.ID()] = availability
	lookup, err := NewEvidenceArtifactLookup(evidence)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := lookup.Get(context.Background(), envelope.ID())
	if err != nil || !found || got.Condition != domain.ArtifactCorrupt {
		t.Fatalf("availability lookup = %#v, %t, %v", got, found, err)
	}
	if _, found, err := lookup.Get(context.Background(), "missing"); err != nil || found {
		t.Fatalf("missing availability found=%t err=%v", found, err)
	}
}

func newEvidenceMemoryStore() *evidenceMemoryStore {
	return &evidenceMemoryStore{
		values:       make(map[domain.EvidenceID]domain.EvidenceEnvelope),
		availability: make(map[domain.EvidenceID]domain.EvidenceArtifactAvailability),
	}
}

func testEvidenceEnvelope(t *testing.T, id domain.EvidenceID, payload []byte) domain.EvidenceEnvelope {
	t.Helper()
	reference, err := domain.NewArtifactReference(domain.ChecksumSHA256(payload), int64(len(payload)), "application/json", domain.ArtifactUncompressed, "dcgm-v1", domain.RedactionSummary{PolicyVersion: "redaction-v1"}, domain.ArtifactRetentionStandard)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{
		ID: id, SchemaVersion: domain.EvidenceSchemaVersion, ClusterID: "cluster-1", Status: domain.EvidenceComplete,
		Source:    domain.EvidenceSourceReference{SourceID: "dcgm-1", RunID: "run-1", Operation: "gpu.xid", DefinitionVersion: "v1", Reference: "query:xid"},
		TimeRange: domain.EvidenceTimeRange{Start: now, End: now.Add(time.Minute)}, CollectedAt: now.Add(2 * time.Minute),
		Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetGPU, ID: "GPU-1"}}, Covered: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetGPU, ID: "GPU-1"}}},
		Artifact: &reference,
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
