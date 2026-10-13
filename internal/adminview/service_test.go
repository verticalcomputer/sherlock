package adminview

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDashboardWireContractUsesExplicitSnakeCase(t *testing.T) {
	value := Dashboard{GeneratedAt: time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC), Clusters: []ClusterSummary{{ClusterID: "cluster-a", Overall: StateDegraded}}}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"generated_at"`) || !strings.Contains(text, `"cluster_id"`) || strings.Contains(text, "GeneratedAt") {
		t.Fatalf("unexpected wire contract: %s", text)
	}
	var decoded Dashboard
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Clusters) != 1 || decoded.Clusters[0].ClusterID != "cluster-a" {
		t.Fatalf("round trip = %+v", decoded)
	}
}

type repositoryStub struct {
	clusters []ClusterSummary
	hasMore  bool
	err      error
	query    Query
	calls    int
}

func (stub *repositoryStub) Load(_ context.Context, query Query) ([]ClusterSummary, bool, error) {
	stub.calls++
	stub.query = query
	return stub.clusters, stub.hasMore, stub.err
}

func TestSnapshotAppliesBoundsAndClassifiesOperationalStates(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.FixedZone("test", 5*60*60+30*60))
	lastContact := now.Add(-time.Minute)
	repository := &repositoryStub{
		hasMore: true,
		clusters: []ClusterSummary{{
			ClusterID:   "cluster-a",
			DisplayName: "Cluster A",
			Resources:   ResourceSummary{ObservedNodes: 10, ObservedGPUs: 80, GPUUtilizationPercent: floatPointer(61.5), GPUUtilizationSamples: 80},
			Connectivity: ConnectivitySummary{
				Collectors: 1, ActiveCollectors: 1, FreshCollectors: 1,
				Sources: 2, AvailableSources: 1, UnavailableSources: 1,
				LastCollectorContact: &lastContact,
			},
			Freshness:      FreshnessSummary{FreshSources: 1, StaleSources: 1},
			Queue:          QueueSummary{DiagnosticBlocked: 1, Overdue: 2},
			Investigations: InvestigationSummary{Active: 1, Blocked: 1},
			ModelUsage:     ModelUsageSummary{Calls: 2, Succeeded: 1, Failed: 1},
			Evidence:       EvidenceCoverageSummary{CurrentTotal: 3, CurrentComplete: 2, CurrentPartial: 1, Total: 3, Complete: 2, Partial: 1},
			Audit:          AuditSummary{Events: 2, Allowed: 1, DeniedOrFailed: 1},
		}},
	}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	dashboard, err := service.Snapshot(context.Background(), Query{})
	if err != nil {
		t.Fatal(err)
	}
	if repository.query.At.Location() != time.UTC || !repository.query.At.Equal(now) {
		t.Fatalf("query time was not normalized to UTC: %v", repository.query.At)
	}
	if repository.query.Limit != DefaultLimit || repository.query.Window != DefaultWindow || repository.query.FreshFor != DefaultFreshFor {
		t.Fatalf("defaults not applied: %+v", repository.query)
	}
	if !dashboard.HasMore || len(dashboard.Clusters) != 1 {
		t.Fatalf("unexpected dashboard page: %+v", dashboard)
	}
	cluster := dashboard.Clusters[0]
	if cluster.Overall != StateDegraded || cluster.Connectivity.State != StateDegraded ||
		cluster.Freshness.State != StateDegraded || cluster.Queue.State != StateDegraded ||
		cluster.Investigations.State != StateDegraded || cluster.ModelUsage.State != StateDegraded ||
		cluster.Evidence.State != StateDegraded || cluster.Audit.State != StateDegraded || cluster.Resources.State != StateHealthy {
		t.Fatalf("degraded dimensions were not preserved: %+v", cluster)
	}
	if !dashboard.WindowStart.Equal(now.UTC().Add(-DefaultWindow)) || !dashboard.WindowEnd.Equal(now) {
		t.Fatalf("unexpected dashboard window: %v - %v", dashboard.WindowStart, dashboard.WindowEnd)
	}
}

func TestSnapshotKeepsUnavailableAndNoDataDistinct(t *testing.T) {
	repository := &repositoryStub{clusters: []ClusterSummary{
		{ClusterID: "unavailable", Connectivity: ConnectivitySummary{Collectors: 1, ActiveCollectors: 1, StaleCollectors: 1}, Freshness: FreshnessSummary{StaleSources: 1}, Evidence: EvidenceCoverageSummary{CurrentTotal: 1, CurrentUnavailable: 1, Total: 1, Unavailable: 1}},
		{ClusterID: "empty"},
	}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := service.Snapshot(context.Background(), Query{At: time.Now(), Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if dashboard.Clusters[0].Overall != StateUnavailable || dashboard.Clusters[0].Freshness.State != StateUnavailable || dashboard.Clusters[0].Evidence.State != StateUnavailable {
		t.Fatalf("unavailable evidence was softened: %+v", dashboard.Clusters[0])
	}
	if dashboard.Clusters[1].Overall != StateNoData || dashboard.Clusters[1].Connectivity.State != StateNoData || dashboard.Clusters[1].ModelUsage.State != StateNoData {
		t.Fatalf("missing evidence was not explicit: %+v", dashboard.Clusters[1])
	}
}

func TestSharedHealthMarksOldWarningHistorical(t *testing.T) {
	now := time.Date(2026, 9, 27, 18, 0, 0, 0, time.UTC)
	repository := &repositoryStub{clusters: []ClusterSummary{{ClusterID: "cluster-a", Evidence: EvidenceCoverageSummary{
		CurrentTotal: 1, CurrentUnavailable: 1,
		CurrentStreams: []EvidenceStreamHealth{{Status: "UNAVAILABLE", LatestAttempt: now.Add(-time.Hour)}},
	}}}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := service.Snapshot(context.Background(), Query{At: now, ClusterID: "cluster-a", Limit: 1, FreshFor: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	view := dashboard.Clusters[0].Health
	if view.Monitoring.CoverageCondition != "UNKNOWN" || view.Monitoring.HistoricalStreams != 1 ||
		len(view.Attention) != 1 || view.Attention[0] != "HISTORICAL_EVIDENCE" {
		t.Fatalf("old warning became current health: %+v", view)
	}
}

func TestSnapshotRejectsUnboundedQueriesBeforeRepositoryCall(t *testing.T) {
	tests := []Query{
		{Limit: MaxLimit + 1},
		{Limit: 1, Offset: MaxOffset + 1},
		{Limit: 1, Window: MaxWindow + time.Second},
		{Limit: 1, FreshFor: MaxFreshFor + time.Second},
		{Limit: 1, ClusterID: "bad/id"},
	}
	for _, query := range tests {
		repository := &repositoryStub{}
		service, err := NewService(repository)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Snapshot(context.Background(), query); err == nil {
			t.Fatalf("expected invalid query rejection: %+v", query)
		}
		if repository.calls != 0 {
			t.Fatalf("repository called for invalid query: %+v", query)
		}
	}
}

func floatPointer(value float64) *float64 { return &value }

func TestSnapshotWrapsRepositoryFailure(t *testing.T) {
	sentinel := errors.New("database unavailable")
	service, err := NewService(&repositoryStub{err: sentinel})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Snapshot(context.Background(), Query{Limit: 1})
	if !errors.Is(err, sentinel) {
		t.Fatalf("repository error not preserved: %v", err)
	}
}

func TestAdminModelsDoNotExposeSensitivePayloadFields(t *testing.T) {
	forbidden := []string{"secret", "credential", "token", "prompt", "response", "output", "artifactbody", "payload", "actor"}
	var inspect func(reflect.Type)
	inspect = func(kind reflect.Type) {
		if kind.Kind() == reflect.Pointer {
			kind = kind.Elem()
		}
		if kind.Kind() != reflect.Struct || kind == reflect.TypeOf(time.Time{}) {
			return
		}
		for index := 0; index < kind.NumField(); index++ {
			field := kind.Field(index)
			name := strings.ToLower(field.Name)
			for _, word := range forbidden {
				if strings.Contains(name, word) {
					t.Fatalf("sensitive field %s.%s crosses admin view boundary", kind.Name(), field.Name)
				}
			}
			inspect(field.Type)
		}
	}
	inspect(reflect.TypeOf(Dashboard{}))
}
