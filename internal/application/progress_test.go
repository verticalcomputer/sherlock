package application

import (
	"math"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestValidateProgressEvidence(t *testing.T) {
	now := time.Date(2026, 9, 27, 10, 0, 0, 123456789, time.UTC)
	value := 12.0
	good := ProgressEvidence{
		RunID: "run-1", TemplateID: "trainer.tokens", TemplateRevision: 1,
		Observation: domain.ProgressObservation{
			SchemaVersion: 1, ClusterID: "cluster", SourceID: "source",
			Job:    domain.JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: now, Attempt: 1},
			Cohort: "model-a", State: domain.ProgressMeasured, Unit: "tokens", Committed: &value,
			ResetEpoch: "checkpoint-1", SourceAt: now, EffectiveAt: now, ObservedAt: now,
		},
	}
	validated, err := ValidateProgressEvidence(good)
	if err != nil {
		t.Fatal(err)
	}
	if validated.Observation.Job.SubmitAt.Nanosecond() != 123456000 || validated.Observation.ObservedAt.Nanosecond() != 123456000 {
		t.Fatalf("timestamps not canonicalized: %+v", validated.Observation)
	}
	for label, change := range map[string]func(*ProgressEvidence){
		"empty run":       func(e *ProgressEvidence) { e.RunID = "" },
		"unsafe template": func(e *ProgressEvidence) { e.TemplateID = "other metric" },
		"revision":        func(e *ProgressEvidence) { e.TemplateRevision = 0 },
		"nan":             func(e *ProgressEvidence) { v := math.NaN(); e.Observation.Committed = &v },
		"infinity":        func(e *ProgressEvidence) { v := math.Inf(1); e.Observation.Committed = &v },
		"negative":        func(e *ProgressEvidence) { v := -1.0; e.Observation.Committed = &v },
		"missing value":   func(e *ProgressEvidence) { e.Observation.Committed = nil },
	} {
		t.Run(label, func(t *testing.T) {
			invalid := good
			change(&invalid)
			if _, err := ValidateProgressEvidence(invalid); err == nil {
				t.Fatal("invalid progress evidence accepted")
			}
		})
	}
}
