package domain

import (
	"testing"
	"time"
)

func TestEvidenceEnvelopePreservesExactImmutableProvenance(t *testing.T) {
	payload := []byte("bounded raw evidence")
	artifact, err := NewArtifactReference(
		ChecksumSHA256(payload), int64(len(payload)), "application/json", ArtifactUncompressed,
		"dcgm-v1", RedactionSummary{PolicyVersion: "redaction-v1", MatchCount: 2}, ArtifactRetentionStandard,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := []EvidenceTarget{{Kind: EvidenceTargetGPU, ID: "GPU-abc"}, {Kind: EvidenceTargetGPU, ID: "GPU-def"}}
	covered := []EvidenceTarget{{Kind: EvidenceTargetGPU, ID: "GPU-abc"}}
	start := time.Date(2026, 8, 19, 10, 0, 0, 0, time.FixedZone("source", 5*60*60+30*60))
	envelope, err := CreateEvidenceEnvelope(NewEvidenceEnvelope{
		ID: "ev_01", SchemaVersion: EvidenceSchemaVersion, ClusterID: "cluster-1", Status: EvidencePartial,
		Source:    EvidenceSourceReference{SourceID: "dcgm-1", RunID: "run-1", Operation: "gpu.xid_events", DefinitionVersion: "1.2.0", Reference: "prometheus-query:dcgm-xid"},
		TimeRange: EvidenceTimeRange{Start: start, End: start.Add(time.Hour)}, CollectedAt: start.Add(time.Hour + time.Minute),
		Coverage: EvidenceCoverage{Expected: expected, Covered: covered}, Artifact: &artifact,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mutating constructor inputs and accessor results cannot change the envelope.
	expected[0].ID = "mutated"
	covered[0].ID = "mutated"
	readCoverage := envelope.Coverage()
	readCoverage.Expected[0].ID = "also-mutated"
	if got := envelope.Coverage().Expected[0].ID; got != "GPU-abc" {
		t.Fatalf("envelope coverage was mutated: %q", got)
	}
	if envelope.TimeRange().Start.Location() != time.UTC || envelope.CollectedAt().Location() != time.UTC {
		t.Fatal("evidence timestamps were not normalized to UTC")
	}
	if got, ok := envelope.Artifact(); !ok || got != artifact {
		t.Fatalf("unexpected artifact reference: %#v, %t", got, ok)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatalf("stored envelope is invalid: %v", err)
	}
}

func TestEvidenceEnvelopeRejectsFalseCoverageClaims(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	base := NewEvidenceEnvelope{
		ID: "ev_01", SchemaVersion: EvidenceSchemaVersion, ClusterID: "cluster-1", Status: EvidenceComplete,
		Source:    EvidenceSourceReference{SourceID: "dcgm-1", Operation: "gpu.health", DefinitionVersion: "v1", Reference: "query:health"},
		TimeRange: EvidenceTimeRange{Start: now, End: now.Add(time.Minute)}, CollectedAt: now.Add(2 * time.Minute),
		Coverage: EvidenceCoverage{Expected: []EvidenceTarget{{Kind: EvidenceTargetNode, ID: "node-1"}}},
	}
	if _, err := CreateEvidenceEnvelope(base); err == nil {
		t.Fatal("complete evidence accepted incomplete coverage")
	}
	base.Status = EvidenceUnavailable
	base.Coverage.Covered = append([]EvidenceTarget(nil), base.Coverage.Expected...)
	if _, err := CreateEvidenceEnvelope(base); err == nil {
		t.Fatal("unavailable evidence accepted covered targets")
	}
	base.Status = EvidencePartial
	base.Coverage.Covered = []EvidenceTarget{{Kind: EvidenceTargetNode, ID: "node-outside-scope"}}
	if _, err := CreateEvidenceEnvelope(base); err == nil {
		t.Fatal("coverage accepted an out-of-scope target")
	}
}

func TestEvidenceEnvelopeCanonicalizesPostgreSQLTimestampPrecision(t *testing.T) {
	observed := time.Date(2026, 8, 20, 10, 0, 0, 123456789, time.FixedZone("source", 5*60*60+30*60))
	envelope, err := CreateEvidenceEnvelope(NewEvidenceEnvelope{
		ID: "evidence-time", SchemaVersion: EvidenceSchemaVersion, ClusterID: "cluster-1", Status: EvidenceComplete,
		Source:    EvidenceSourceReference{SourceID: "source-1", Operation: "gpu.snapshot", DefinitionVersion: "1", Reference: "synthetic"},
		TimeRange: EvidenceTimeRange{Start: observed, End: observed}, CollectedAt: observed.Add(time.Nanosecond),
		Coverage: EvidenceCoverage{
			Expected: []EvidenceTarget{{Kind: EvidenceTargetGPU, ID: "gpu-1"}},
			Covered:  []EvidenceTarget{{Kind: EvidenceTargetGPU, ID: "gpu-1"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := observed.UTC().Truncate(time.Microsecond)
	if envelope.TimeRange().Start != want || envelope.TimeRange().End != want || envelope.CollectedAt() != want {
		t.Fatalf("timestamps were not canonicalized: range=%+v collected=%s", envelope.TimeRange(), envelope.CollectedAt())
	}
}

func TestArtifactReferenceRequiresContentAddress(t *testing.T) {
	checksum := ChecksumSHA256([]byte("evidence"))
	reference, err := NewArtifactReference(checksum, 8, "text/plain", ArtifactGZIP, "parser-v1", RedactionSummary{PolicyVersion: "policy-v1"}, ArtifactRetentionShort)
	if err != nil {
		t.Fatal(err)
	}
	if want := ArtifactID("sha256:" + checksum.String()); reference.ArtifactID != want {
		t.Fatalf("artifact ID = %q, want %q", reference.ArtifactID, want)
	}
	reference.ArtifactID = "arbitrary-key"
	if err := ValidateArtifactReference(reference); err == nil {
		t.Fatal("arbitrary object key was accepted")
	}
	if _, err := ParseSHA256("abcd"); err == nil {
		t.Fatal("short checksum was accepted")
	}
}
