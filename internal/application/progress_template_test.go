package application

import (
	"math"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestProgressTemplateExactSeries(t *testing.T) {
	now := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	template := ProgressTemplate{ID: "trainer.images", Revision: 1, ClusterID: "cluster", SourceID: "prom",
		MetricName: "training_committed_images_total", SchedulerNamespace: "slurm", Cohort: "resnet", Unit: "images",
		JobIDLabel: "job_id", SubmitAtLabel: "submit_at", AttemptLabel: "attempt", ResetEpochLabel: "reset_epoch",
		StaticLabels: map[string]string{"exporter": "training"}, MaxAge: 2 * time.Minute}
	series := ProgressSeries{Labels: map[string]string{"__name__": template.MetricName, "job_id": "42",
		"submit_at": now.Add(-time.Hour).Format(time.RFC3339Nano), "attempt": "1", "reset_epoch": "checkpoint-1", "exporter": "training"},
		Value: 80, SourceAt: now.Add(-time.Second)}
	evidence, err := DecodeProgressSeries(template, "run-1", series, now)
	if err != nil || evidence.Observation.Job.JobID != "42" || evidence.Observation.Committed == nil || *evidence.Observation.Committed != 80 ||
		evidence.Observation.Cohort != domain.ProgressCohort("resnet") {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	if _, admitted := ReviewedProgressTemplate(template.ID, template.Revision); admitted {
		t.Fatal("fixture template must not be production-enrolled")
	}
	for label, change := range map[string]func(*ProgressSeries){
		"wrong metric":             func(s *ProgressSeries) { s.Labels["__name__"] = "other_total" },
		"wrong static":             func(s *ProgressSeries) { s.Labels["exporter"] = "other" },
		"unexpected label":         func(s *ProgressSeries) { s.Labels["tenant_query"] = "up" },
		"missing attempt":          func(s *ProgressSeries) { delete(s.Labels, "attempt") },
		"missing epoch":            func(s *ProgressSeries) { delete(s.Labels, "reset_epoch") },
		"reused id without submit": func(s *ProgressSeries) { s.Labels["submit_at"] = "" },
		"stale":                    func(s *ProgressSeries) { s.SourceAt = now.Add(-3 * time.Minute) },
		"future":                   func(s *ProgressSeries) { s.SourceAt = now.Add(3 * time.Second) },
		"negative":                 func(s *ProgressSeries) { s.Value = -1 },
		"nan":                      func(s *ProgressSeries) { s.Value = math.NaN() },
	} {
		t.Run(label, func(t *testing.T) {
			bad := series
			bad.Labels = make(map[string]string, len(series.Labels))
			for key, value := range series.Labels {
				bad.Labels[key] = value
			}
			change(&bad)
			if _, err := DecodeProgressSeries(template, "run-2", bad, now); err == nil {
				t.Fatal("unreviewed series accepted")
			}
		})
	}
	template.AttemptLabel = template.JobIDLabel
	if err := ValidateProgressTemplate(template); err == nil {
		t.Fatal("duplicate identity label accepted")
	}
}
