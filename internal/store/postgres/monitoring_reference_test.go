package postgres

import (
	"github.com/verticalcomputer/sherlock/internal/monitoring"
	"testing"
	"time"
)

func TestMonitoringPreservedReferenceEqualityUsesInstantsAcrossRestart(t *testing.T) {
	instant := time.Now()
	ref := monitoring.EvidenceRef{ObservationID: "observation", RunID: "run", ObservedAt: instant, CollectedAt: instant.Add(time.Second), CompletedAt: instant.Add(time.Second)}
	persisted := ref
	persisted.ObservedAt = ref.ObservedAt.Round(0).In(time.FixedZone("other-process-zone", -7*3600))
	persisted.CollectedAt = ref.CollectedAt.Round(0).UTC()
	persisted.CompletedAt = ref.CompletedAt.Round(0).UTC()
	if !monitoringRefsEqual(ref, persisted) {
		t.Fatal("same evidence instant rejected after time zone/monotonic metadata change")
	}
	snapshot := MonitoringEvidenceSnapshot{Reference: persisted}
	if _, err := monitoringTransitionSnapshots(monitoring.Transition{Evidence: []monitoring.EvidenceRef{ref}}, []MonitoringEvidenceSnapshot{snapshot}); err != nil {
		t.Fatal(err)
	}
	state := monitoring.State{SourceCursor: &ref}
	if _, err := monitoringStateCache(state, []MonitoringEvidenceSnapshot{snapshot}, nil); err != nil {
		t.Fatal(err)
	}
	different := persisted
	different.ObservedAt = different.ObservedAt.Add(time.Nanosecond)
	if monitoringRefsEqual(ref, different) {
		t.Fatal("changed immutable instant accepted")
	}
	different = persisted
	different.RunID = "foreign"
	if monitoringRefsEqual(ref, different) {
		t.Fatal("changed immutable run accepted")
	}
}
