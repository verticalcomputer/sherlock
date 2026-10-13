package application

import (
	"slices"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestProjectClusterHealthSeparatesMissingCollectorCapacityMetricAndWorkload(t *testing.T) {
	count := func(value int64) *int64 { return &value }
	now := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	base := ClusterHealthFacts{ClusterID: "cluster", At: now, WindowStart: now.Add(-time.Hour),
		ExpectedNodes: count(2), ExpectedGPUs: count(16), ObservedNodes: count(2), ObservedGPUs: count(16),
		ExpectedCollectors: 1, FreshCollectors: 1, FreshSources: 1, CompleteStreams: 1,
		ActiveWorkloads: count(0), Progress: domain.ProgressUnmeasured}
	cases := []struct {
		name                                                    string
		change                                                  func(*ClusterHealthFacts)
		wantCapacity, wantCollector, wantCoverage, wantWorkload ClusterCondition
		attention                                               string
	}{
		{"healthy idle", func(*ClusterHealthFacts) {}, ConditionHealthy, ConditionHealthy, ConditionHealthy, ConditionIdle, ""},
		{"missing collector", func(f *ClusterHealthFacts) { f.FreshCollectors = 0 }, ConditionHealthy, ConditionUnavailable, ConditionHealthy, ConditionIdle, "COLLECTOR_MISSING"},
		{"missing node", func(f *ClusterHealthFacts) { f.ObservedNodes = count(1); f.ObservedGPUs = count(8) }, ConditionDegraded, ConditionHealthy, ConditionHealthy, ConditionIdle, "CAPACITY_MISMATCH"},
		{"failed metric", func(f *ClusterHealthFacts) { f.CompleteStreams = 0; f.UnavailableStreams = 1 }, ConditionHealthy, ConditionHealthy, ConditionDegraded, ConditionIdle, "METRIC_COVERAGE_GAP"},
		{"busy stalled", func(f *ClusterHealthFacts) {
			f.ActiveWorkloads = count(1)
			f.StalledWorkloads = count(1)
			f.Progress = domain.ProgressMeasured
		}, ConditionHealthy, ConditionHealthy, ConditionHealthy, ConditionStalled, "WORKLOAD_STALLED"},
		{"busy unmeasured", func(f *ClusterHealthFacts) { f.ActiveWorkloads = count(1) }, ConditionHealthy, ConditionHealthy, ConditionHealthy, ConditionUnknown, ""},
		{"unknown workload", func(f *ClusterHealthFacts) { f.ActiveWorkloads = nil }, ConditionHealthy, ConditionHealthy, ConditionHealthy, ConditionUnknown, ""},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			facts := base
			item.change(&facts)
			view, err := ProjectClusterHealth(facts)
			if err != nil {
				t.Fatal(err)
			}
			if view.Capacity.Condition != item.wantCapacity || view.Monitoring.CollectorCondition != item.wantCollector ||
				view.Monitoring.CoverageCondition != item.wantCoverage || view.Workload != item.wantWorkload {
				t.Fatalf("separate conditions lost: %+v", view)
			}
			if item.attention != "" && !slices.Contains(view.Attention, item.attention) {
				t.Fatalf("attention=%v", view.Attention)
			}
			if view.SchemaVersion != 1 || view.Progress != facts.Progress {
				t.Fatalf("version/progress=%+v", view)
			}
		})
	}
}

func TestProjectClusterHealthMissingEvidenceDoesNotInventCapacityOrWork(t *testing.T) {
	now := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	view, err := ProjectClusterHealth(ClusterHealthFacts{ClusterID: "cluster", At: now, WindowStart: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if view.Capacity.Condition != ConditionUnknown || view.Capacity.ExpectedGPUs != nil || view.Capacity.ObservedGPUs != nil ||
		view.Monitoring.CollectorCondition != ConditionUnknown || view.Workload != ConditionUnknown || view.Progress != domain.ProgressUnmeasured {
		t.Fatalf("unknown evidence fabricated: %+v", view)
	}
}
