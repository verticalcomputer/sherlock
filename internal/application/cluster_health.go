package application

import (
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ClusterCondition keeps independently sourced conclusions separate. UNKNOWN
// is evidence absence, never a healthy or zero-valued observation.
type ClusterCondition string

const (
	ConditionHealthy     ClusterCondition = "HEALTHY"
	ConditionDegraded    ClusterCondition = "DEGRADED"
	ConditionUnavailable ClusterCondition = "UNAVAILABLE"
	ConditionUnknown     ClusterCondition = "UNKNOWN"
	ConditionIdle        ClusterCondition = "IDLE"
	ConditionStalled     ClusterCondition = "STALLED"
)

type ClusterCapacityView struct {
	Condition          ClusterCondition `json:"condition"`
	ExpectedNodes      *int64           `json:"expected_nodes"`
	ExpectedGPUs       *int64           `json:"expected_gpus"`
	ObservedNodes      *int64           `json:"observed_nodes"`
	ObservedGPUs       *int64           `json:"observed_gpus"`
	ExpectedRevisionID string           `json:"expected_revision_id,omitempty"`
	ObservedRevisionID string           `json:"observed_revision_id,omitempty"`
}

type ClusterMonitoringView struct {
	CollectorCondition ClusterCondition `json:"collector_condition"`
	FreshnessCondition ClusterCondition `json:"freshness_condition"`
	CoverageCondition  ClusterCondition `json:"coverage_condition"`
	SupportCondition   ClusterCondition `json:"support_condition"`
	ExpectedCollectors int64            `json:"expected_collectors"`
	FreshCollectors    int64            `json:"fresh_collectors"`
	FreshSources       int64            `json:"fresh_sources"`
	StaleSources       int64            `json:"stale_sources"`
	SourcesWithoutData int64            `json:"sources_without_data"`
	CompleteStreams    int64            `json:"complete_streams"`
	PartialStreams     int64            `json:"partial_streams"`
	NoDataStreams      int64            `json:"no_data_streams"`
	UnavailableStreams int64            `json:"unavailable_streams"`
	HistoricalStreams  int64            `json:"historical_streams"`
	ExpectedOperations int64            `json:"expected_operations"`
	FreshOperations    int64            `json:"fresh_operations"`
	LateOperations     int64            `json:"late_operations"`
	FailedOperations   int64            `json:"failed_operations"`
}

// ClusterHealthView is the versioned, read-only GP-08 projection shared by
// administrator and tenant reads. The legacy public health fields coexist with
// this view during the compatibility window.
type ClusterHealthView struct {
	SchemaVersion int                   `json:"schema_version"`
	ClusterID     domain.ClusterID      `json:"cluster_id"`
	GeneratedAt   time.Time             `json:"generated_at"`
	WindowStart   time.Time             `json:"window_start"`
	WindowEnd     time.Time             `json:"window_end"`
	Capacity      ClusterCapacityView   `json:"capacity"`
	Monitoring    ClusterMonitoringView `json:"monitoring"`
	Workload      ClusterCondition      `json:"workload_condition"`
	Progress      domain.ProgressState  `json:"progress_state"`
	Attention     []string              `json:"attention"`
}

type ClusterHealthFacts struct {
	ClusterID                                                             domain.ClusterID
	At, WindowStart                                                       time.Time
	ExpectedNodes, ExpectedGPUs, ObservedNodes, ObservedGPUs              *int64
	ExpectedRevisionID, ObservedRevisionID                                string
	ExpectedCollectors, FreshCollectors                                   int64
	FreshSources, StaleSources, SourcesWithoutData                        int64
	CompleteStreams, PartialStreams, NoDataStreams, UnavailableStreams    int64
	HistoricalStreams                                                     int64
	ExpectedOperations, FreshOperations, LateOperations, FailedOperations int64
	// Workload counts are nil unless a source proves current allocation
	// coverage. Neither GPU utilization nor process liveness supplies them.
	ActiveWorkloads, StalledWorkloads *int64
	Progress                          domain.ProgressState
}

func ProjectClusterHealth(f ClusterHealthFacts) (ClusterHealthView, error) {
	if f.ClusterID == "" || f.At.IsZero() || f.WindowStart.IsZero() || !f.At.After(f.WindowStart) {
		return ClusterHealthView{}, fmt.Errorf("invalid cluster health window")
	}
	counts := []int64{f.ExpectedCollectors, f.FreshCollectors, f.FreshSources, f.StaleSources,
		f.SourcesWithoutData, f.CompleteStreams, f.PartialStreams, f.NoDataStreams, f.UnavailableStreams, f.HistoricalStreams,
		f.ExpectedOperations, f.FreshOperations, f.LateOperations, f.FailedOperations}
	for _, value := range counts {
		if value < 0 {
			return ClusterHealthView{}, fmt.Errorf("negative cluster health count")
		}
	}
	for _, value := range []*int64{f.ExpectedNodes, f.ExpectedGPUs, f.ObservedNodes, f.ObservedGPUs, f.ActiveWorkloads, f.StalledWorkloads} {
		if value != nil && *value < 0 {
			return ClusterHealthView{}, fmt.Errorf("negative cluster health count")
		}
	}
	if f.StalledWorkloads != nil && f.ActiveWorkloads != nil && *f.StalledWorkloads > *f.ActiveWorkloads {
		return ClusterHealthView{}, fmt.Errorf("inconsistent cluster health counts")
	}
	if f.FreshOperations > f.ExpectedOperations || f.LateOperations > f.ExpectedOperations || f.FailedOperations > f.ExpectedOperations {
		return ClusterHealthView{}, fmt.Errorf("inconsistent collection operation counts")
	}
	if f.Progress == "" {
		f.Progress = domain.ProgressUnmeasured
	}
	if err := f.Progress.Validate(); err != nil {
		return ClusterHealthView{}, err
	}
	view := ClusterHealthView{SchemaVersion: 1, ClusterID: f.ClusterID, GeneratedAt: f.At.UTC(),
		WindowStart: f.WindowStart.UTC(), WindowEnd: f.At.UTC(),
		Capacity: ClusterCapacityView{Condition: ConditionUnknown, ExpectedNodes: f.ExpectedNodes,
			ExpectedGPUs: f.ExpectedGPUs, ObservedNodes: f.ObservedNodes, ObservedGPUs: f.ObservedGPUs,
			ExpectedRevisionID: f.ExpectedRevisionID, ObservedRevisionID: f.ObservedRevisionID},
		Monitoring: ClusterMonitoringView{ExpectedCollectors: f.ExpectedCollectors, FreshCollectors: f.FreshCollectors,
			FreshSources: f.FreshSources, StaleSources: f.StaleSources, SourcesWithoutData: f.SourcesWithoutData,
			CompleteStreams: f.CompleteStreams, PartialStreams: f.PartialStreams, NoDataStreams: f.NoDataStreams,
			UnavailableStreams: f.UnavailableStreams, HistoricalStreams: f.HistoricalStreams},
		Workload: ConditionUnknown, Progress: f.Progress, Attention: []string{}}
	if f.ExpectedNodes != nil && f.ExpectedGPUs != nil && f.ObservedNodes != nil && f.ObservedGPUs != nil {
		view.Capacity.Condition = ConditionHealthy
		if *f.ObservedNodes != *f.ExpectedNodes || *f.ObservedGPUs != *f.ExpectedGPUs {
			view.Capacity.Condition = ConditionDegraded
			view.Attention = append(view.Attention, "CAPACITY_MISMATCH")
		}
	}
	view.Monitoring.CollectorCondition = ConditionUnknown
	view.Monitoring.SupportCondition = ConditionUnknown
	if f.ExpectedCollectors > 0 {
		view.Monitoring.CollectorCondition = ConditionHealthy
		if f.FreshCollectors < f.ExpectedCollectors {
			view.Monitoring.CollectorCondition = ConditionUnavailable
			view.Attention = append(view.Attention, "COLLECTOR_MISSING")
		}
	}
	view.Monitoring.FreshnessCondition = ConditionUnknown
	if f.FreshSources > 0 {
		view.Monitoring.FreshnessCondition = ConditionHealthy
	}
	if f.StaleSources > 0 || f.SourcesWithoutData > 0 {
		view.Monitoring.FreshnessCondition = ConditionDegraded
		view.Attention = append(view.Attention, "SOURCE_NOT_FRESH")
	}
	view.Monitoring.ExpectedOperations = f.ExpectedOperations
	view.Monitoring.FreshOperations = f.FreshOperations
	view.Monitoring.LateOperations = f.LateOperations
	view.Monitoring.FailedOperations = f.FailedOperations
	if f.ExpectedOperations > 0 {
		view.Monitoring.FreshnessCondition = ConditionHealthy
		if f.LateOperations > 0 || f.FailedOperations > 0 || f.FreshOperations < f.ExpectedOperations {
			view.Monitoring.FreshnessCondition = ConditionDegraded
			view.Attention = append(view.Attention, "SCHEDULE_NOT_FRESH")
		}
	}
	view.Monitoring.CoverageCondition = ConditionUnknown
	if f.CompleteStreams > 0 {
		view.Monitoring.CoverageCondition = ConditionHealthy
	}
	if f.PartialStreams+f.NoDataStreams+f.UnavailableStreams > 0 {
		view.Monitoring.CoverageCondition = ConditionDegraded
		view.Attention = append(view.Attention, "METRIC_COVERAGE_GAP")
	}
	if f.HistoricalStreams > 0 {
		view.Attention = append(view.Attention, "HISTORICAL_EVIDENCE")
	}
	if f.ActiveWorkloads != nil {
		switch {
		case *f.ActiveWorkloads == 0:
			view.Workload = ConditionIdle
		case f.StalledWorkloads != nil && *f.StalledWorkloads > 0 && f.Progress == domain.ProgressMeasured:
			view.Workload = ConditionStalled
			view.Attention = append(view.Attention, "WORKLOAD_STALLED")
		case f.StalledWorkloads != nil && f.Progress == domain.ProgressMeasured:
			view.Workload = ConditionHealthy
		}
	}
	return view, nil
}
