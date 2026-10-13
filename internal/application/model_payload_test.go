package application

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type modelPayloadSourceSpy struct {
	cluster domain.ClusterID
	source  domain.SourceID
}

func (spy *modelPayloadSourceSpy) EnsureModelAuditSource(_ context.Context, cluster domain.ClusterID, source domain.SourceID) error {
	spy.cluster, spy.source = cluster, source
	return nil
}

func TestModelPayloadRecorderCreatesRedactedImmutableEvidence(t *testing.T) {
	evidence := newEvidenceMemoryStore()
	objects := &artifactSpy{}
	writer, err := NewEvidenceRecorder(evidence, objects, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	sources := &modelPayloadSourceSpy{}
	recorder, err := NewModelPayloadRecorder(sources, writer, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 16, 0, 0, 0, time.UTC)
	id, err := recorder.RecordModelPayload(context.Background(), ModelPayloadEvidence{
		InvestigationID: "investigation-1", ClusterID: "cluster-1", CallKey: "investigation/investigation-1/synthesis/10",
		Kind: ModelCallSynthesis, Role: ModelPayloadOutput, OccurredAt: now,
		Payload: []byte(`{"api_key":"runtime-secret","statement":"Bearer abc.def and shk_live_private"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || sources.cluster != "cluster-1" || sources.source == "" || len(evidence.values) != 1 {
		t.Fatalf("id=%q source=%q/%q evidence=%d", id, sources.cluster, sources.source, len(evidence.values))
	}
	envelope := evidence.values[id]
	artifact, ok := envelope.Artifact()
	if !ok || envelope.Source().Operation != "model_synthesis_output" || artifact.RetentionClass != domain.ArtifactRetentionExtended || artifact.Redactions.MatchCount != 3 {
		t.Fatalf("envelope=%+v artifact=%+v", envelope, artifact)
	}
	stored := string(objects.stagedBytes)
	if strings.Contains(stored, "runtime-secret") || strings.Contains(stored, "abc.def") || strings.Contains(stored, "shk_live_private") || strings.Count(stored, "[REDACTED]") != 3 {
		t.Fatalf("payload was not safely redacted: %s", stored)
	}
	if _, err := recorder.RecordModelPayload(context.Background(), ModelPayloadEvidence{InvestigationID: "investigation-1", ClusterID: "cluster-1", CallKey: "investigation/investigation-1/synthesis/10", Kind: ModelCallSynthesis, Role: ModelPayloadOutput, OccurredAt: now, Payload: []byte(`{"api_key":"runtime-secret","statement":"Bearer abc.def and shk_live_private"}`)}); err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
}

func TestModelPayloadRecorderRejectsOversizeBeforeStorage(t *testing.T) {
	evidence := newEvidenceMemoryStore()
	writer, _ := NewEvidenceRecorder(evidence, &artifactSpy{}, 1024)
	recorder, _ := NewModelPayloadRecorder(&modelPayloadSourceSpy{}, writer, 4)
	_, err := recorder.RecordModelPayload(context.Background(), ModelPayloadEvidence{InvestigationID: "investigation-1", ClusterID: "cluster-1", CallKey: "investigation/investigation-1/planning/2", Kind: ModelCallPlanning, Role: ModelPayloadInput, OccurredAt: time.Now(), Payload: []byte("12345")})
	if err == nil || len(evidence.values) != 0 {
		t.Fatalf("oversize payload stored: err=%v evidence=%d", err, len(evidence.values))
	}
}
