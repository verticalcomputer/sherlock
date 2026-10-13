package application

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

var progressMetricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]{0,127}$`)
var progressLabelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`)

// ProgressTemplate is a code-reviewed, immutable metric contract. Only a
// template returned by ReviewedProgressTemplate may be used by a production
// collector; validation alone does not grant enrollment authority.
type ProgressTemplate struct {
	ID                 string
	Revision           int
	ClusterID          domain.ClusterID
	SourceID           domain.SourceID
	MetricName         string
	SchedulerNamespace domain.SchedulerNamespace
	Cohort             domain.ProgressCohort
	Unit               domain.ProgressUnit
	JobIDLabel         string
	SubmitAtLabel      string
	AttemptLabel       string
	ResetEpochLabel    string
	StaticLabels       map[string]string
	MaxAge             time.Duration
}

// ReviewedProgressTemplate remains empty until a real application counter,
// label shape and workload owner have been reviewed. It is deliberately not
// populated from a tenant-provided query or environment variable.
func ReviewedProgressTemplate(string, int) (ProgressTemplate, bool) {
	return ProgressTemplate{}, false
}

func ValidateProgressTemplate(template ProgressTemplate) error {
	if !validProgressIdentifier(template.ID, 128) || template.Revision < 1 || template.ClusterID == "" || template.SourceID == "" ||
		!progressMetricName.MatchString(template.MetricName) || template.SchedulerNamespace == "" ||
		!validProgressIdentifier(string(template.Cohort), 128) || !validProgressIdentifier(string(template.Unit), 128) ||
		template.MaxAge < time.Second || template.MaxAge > 10*time.Minute {
		return fmt.Errorf("progress template identity, unit or age is invalid")
	}
	seen := map[string]bool{"__name__": true}
	for _, label := range []string{template.JobIDLabel, template.SubmitAtLabel, template.AttemptLabel, template.ResetEpochLabel} {
		if !progressLabelName.MatchString(label) || seen[label] {
			return fmt.Errorf("progress template identity labels are invalid or repeated")
		}
		seen[label] = true
	}
	for label, value := range template.StaticLabels {
		if !progressLabelName.MatchString(label) || seen[label] || !validProgressIdentifier(value, 256) {
			return fmt.Errorf("progress template static labels are invalid or repeated")
		}
		seen[label] = true
	}
	return nil
}

type ProgressSeries struct {
	Labels   map[string]string
	Value    float64
	SourceAt time.Time
}

// DecodeProgressSeries refuses unexpected labels, non-finite counters and
// stale/future samples. SubmitAt uses RFC3339Nano so reused scheduler job IDs
// remain separate even if the exporter restarts.
func DecodeProgressSeries(template ProgressTemplate, runID string, series ProgressSeries, receivedAt time.Time) (ProgressEvidence, error) {
	if err := ValidateProgressTemplate(template); err != nil {
		return ProgressEvidence{}, err
	}
	if receivedAt.IsZero() || series.SourceAt.IsZero() || series.SourceAt.After(receivedAt.Add(2*time.Second)) ||
		receivedAt.Sub(series.SourceAt) > template.MaxAge || math.IsNaN(series.Value) || math.IsInf(series.Value, 0) || series.Value < 0 {
		return ProgressEvidence{}, fmt.Errorf("progress sample is stale, future, or non-finite")
	}
	if len(series.Labels) != 5+len(template.StaticLabels) || series.Labels["__name__"] != template.MetricName {
		return ProgressEvidence{}, fmt.Errorf("progress sample does not match reviewed metric or label set")
	}
	for label, value := range template.StaticLabels {
		if series.Labels[label] != value {
			return ProgressEvidence{}, fmt.Errorf("progress static label mismatch")
		}
	}
	jobID := series.Labels[template.JobIDLabel]
	submitAt, err := time.Parse(time.RFC3339Nano, series.Labels[template.SubmitAtLabel])
	if err != nil {
		return ProgressEvidence{}, fmt.Errorf("progress submit time is invalid")
	}
	attempt, err := strconv.Atoi(series.Labels[template.AttemptLabel])
	if err != nil {
		return ProgressEvidence{}, fmt.Errorf("progress attempt is invalid")
	}
	evidence := ProgressEvidence{RunID: runID, TemplateID: template.ID, TemplateRevision: template.Revision,
		Observation: domain.ProgressObservation{
			SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: template.ClusterID, SourceID: template.SourceID,
			Job:    domain.JobIdentity{SchedulerNamespace: template.SchedulerNamespace, JobID: domain.SchedulerJobID(jobID), SubmitAt: submitAt, Attempt: attempt},
			Cohort: template.Cohort, State: domain.ProgressMeasured, Unit: template.Unit, Committed: &series.Value,
			ResetEpoch: domain.ProgressResetEpoch(series.Labels[template.ResetEpochLabel]),
			SourceAt:   series.SourceAt, EffectiveAt: series.SourceAt, ObservedAt: receivedAt,
		}}
	return ValidateProgressEvidence(evidence)
}
