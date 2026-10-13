package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/events"
	contract "github.com/verticalcomputer/sherlock/sdk/go"
)

type apiClock struct{ value time.Time }

func (clock apiClock) Now() time.Time { return clock.value }

type apiAuthenticator struct{ principal auth.Principal }

func (authenticator apiAuthenticator) Authenticate(context.Context, []byte) (auth.Principal, error) {
	return authenticator.principal, nil
}

type apiReader struct{ clusterGets int }

func (reader *apiReader) GetCluster(_ context.Context, clusterID domain.ClusterID) (application.ClusterProjection, bool, error) {
	reader.clusterGets++
	return application.ClusterProjection{ID: clusterID, DisplayName: "Test cluster", CreatedAt: time.Unix(1, 0)}, true, nil
}
func (*apiReader) ListSources(_ context.Context, clusterID domain.ClusterID, _ application.SourceFilters, _, _ int, at time.Time, _ time.Duration) ([]application.SourceProjection, bool, error) {
	last := at.Add(-time.Second)
	return []application.SourceProjection{{ID: "source-a", ClusterID: clusterID, Kind: "prometheus", DisplayName: "Prometheus", Availability: "AVAILABLE", Freshness: domain.FreshnessFresh, LastAttemptAt: &last, LastSuccessAt: &last}}, false, nil
}
func (*apiReader) ListObservations(context.Context, domain.ClusterID, application.ObservationFilters, int, int) ([]application.ObservationProjection, bool, error) {
	return nil, false, nil
}
func (*apiReader) ListGPUSummaries(context.Context, domain.ClusterID, application.GPUFilters, int, int, time.Time, time.Duration) ([]application.GPUSummaryProjection, bool, error) {
	return nil, false, nil
}
func (*apiReader) ListCollectionRuns(context.Context, domain.ClusterID, application.CollectionRunFilters, int, int) ([]application.CollectionRunProjection, bool, error) {
	return nil, false, nil
}
func (*apiReader) ListEvidence(context.Context, domain.ClusterID, application.EvidenceFilters, int, int) ([]application.EvidenceProjection, bool, error) {
	return nil, false, nil
}
func (*apiReader) GetEvidence(context.Context, domain.ClusterID, domain.EvidenceID) (application.EvidenceProjection, bool, error) {
	return application.EvidenceProjection{}, false, nil
}
func (*apiReader) GetHealth(_ context.Context, clusterID domain.ClusterID, at time.Time, _ time.Duration) (application.HealthProjection, bool, error) {
	return application.HealthProjection{ClusterID: clusterID, CollectionStatus: domain.ResultNoData, Freshness: domain.FreshnessUnknown, Availability: "UNKNOWN", GeneratedAt: at}, true, nil
}

type apiEvents struct{}

func (apiEvents) ListAfter(context.Context, domain.ClusterID, events.ID, int) (events.Page, error) {
	return events.Page{}, nil
}
func (apiEvents) WaitAfter(ctx context.Context, _ domain.ClusterID, _ events.ID, _ int, _ time.Duration) (events.Page, error) {
	<-ctx.Done()
	return events.Page{}, ctx.Err()
}

func newTestServer(t *testing.T, reader *apiReader) http.Handler {
	t.Helper()
	clock := apiClock{value: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	queries, err := application.NewPublicQueries(reader, clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewServer(apiAuthenticator{principal: auth.Principal{KeyID: "key", ClusterID: "cluster-a", Capabilities: []auth.Capability{auth.CapabilityClusterRead, auth.CapabilityTelemetryRead}}}, queries, apiEvents{}, clock, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestGeneratedClientRetrievesRealHandlerStates(t *testing.T) {
	service := httptest.NewServer(newTestServer(t, &apiReader{}))
	defer service.Close()
	client, err := contract.NewClient(service.URL+"/api/v1", "shk_test", service.Client())
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := client.ListClusters(context.Background(), contract.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters.Data) != 1 || clusters.Data[0].ClusterID != "cluster-a" || clusters.Data[0].CollectionStatus != contract.CollectionStatusNoData {
		t.Fatalf("unexpected cluster response: %+v", clusters)
	}
	sources, err := client.ListSources(context.Background(), "cluster-a", contract.ListOptions{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources.Data) != 1 || sources.Data[0].Freshness != contract.FreshnessFresh {
		t.Fatalf("unexpected source response: %+v", sources)
	}
	health, err := client.GetHealth(context.Background(), "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if health.CollectionStatus != contract.CollectionStatusNoData || health.Freshness != contract.FreshnessUnknown {
		t.Fatalf("no-data semantics lost: %+v", health)
	}
}

func TestCrossClusterScopeFailsBeforeQuery(t *testing.T) {
	reader := &apiReader{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cluster-b/sources", nil)
	request.Header.Set("Authorization", "Bearer shk_test")
	response := httptest.NewRecorder()
	newTestServer(t, reader).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if reader.clusterGets != 0 {
		t.Fatalf("cross-cluster request reached query layer %d times", reader.clusterGets)
	}
}

func TestMissingBearerIsProblemJSON(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
	response := httptest.NewRecorder()
	newTestServer(t, &apiReader{}).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("unexpected problem response: code=%d type=%s", response.Code, response.Header().Get("Content-Type"))
	}
}

func TestLastEventIDUsesPublicOpaquePrefix(t *testing.T) {
	id, err := parseLastEventID("evt_42")
	if err != nil || id != 42 {
		t.Fatalf("parse Last-Event-ID: id=%d err=%v", id, err)
	}
	if _, err := parseLastEventID("42"); err == nil {
		t.Fatal("expected unprefixed event ID to be rejected")
	}
}
