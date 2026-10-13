//go:build integration

package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type m4Clock struct{ at time.Time }

func (clock m4Clock) Now() time.Time { return clock.at }

func TestM4PublicQueriesEnforceClusterScopeFiltersAndState(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	collections, _ := storepg.NewCollectionStore(pool)
	reader, _ := storepg.NewPublicQueryStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterA, clusterB := domain.ClusterID("m4-query-a-"+suffix), domain.ClusterID("m4-query-b-"+suffix)
	sourceA, sourceB := domain.SourceID("m4-source-a-"+suffix), domain.SourceID("m4-source-b-"+suffix)
	if err := collections.EnsureSource(ctx, clusterA, "M4 A", sourceA, "Prometheus A"); err != nil {
		t.Fatal(err)
	}
	if err := collections.EnsureSource(ctx, clusterB, "M4 B", sourceB, "Prometheus B"); err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	result := domain.CollectionResult{Task: domain.CollectionTask{RunID: domain.RunID("m4-run-" + suffix), ClusterID: clusterA, SourceID: sourceA, Query: domain.QueryGPUUtilization, ScheduledFor: observed, Deadline: observed.Add(10 * time.Second), MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "m4/query/" + suffix}, Status: domain.ResultSucceeded, StartedAt: observed, CompletedAt: observed.Add(time.Second), Coverage: domain.Coverage{SeriesReturned: 1, Complete: true}, Observations: []domain.Observation{{ID: domain.ObservationID("m4-observation-" + suffix), SchemaVersion: 1, ClusterID: clusterA, SourceID: sourceA, Kind: "gpu_utilization", EntityKey: "node/comp001/gpu/0", Metric: "DCGM_FI_DEV_GPU_UTIL", Labels: []domain.Label{{Name: "gpu", Value: "0"}}, Value: 72, Unit: "percent", ObservedAt: observed, CollectedAt: observed.Add(time.Second), SourceReference: "prometheus:dcgm_gpu_utilization"}}}
	if inserted, err := collections.RecordResult(ctx, result); err != nil || !inserted {
		t.Fatalf("record result inserted=%v err=%v", inserted, err)
	}
	queries, err := application.NewPublicQueries(reader, m4Clock{at: observed.Add(30 * time.Second)}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	items, page, err := queries.ListObservations(ctx, clusterA, application.ObservationFilters{Metric: "DCGM_FI_DEV_GPU_UTIL"}, application.PageRequest{Size: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Observation.ClusterID != clusterA || page.NextToken != "" {
		t.Fatalf("unexpected scoped observations: items=%+v page=%+v", items, page)
	}
	other, _, err := queries.ListObservations(ctx, clusterB, application.ObservationFilters{Metric: "DCGM_FI_DEV_GPU_UTIL"}, application.PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("cross-cluster observations leaked: %+v", other)
	}
	sources, _, err := queries.ListSources(ctx, clusterA, application.SourceFilters{Status: "AVAILABLE"}, application.PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].Freshness != domain.FreshnessFresh {
		t.Fatalf("source state lost: %+v", sources)
	}
	health, found, err := queries.GetHealth(ctx, clusterA)
	if err != nil || !found {
		t.Fatalf("health found=%v err=%v", found, err)
	}
	if health.CollectionStatus != domain.ResultSucceeded || health.Freshness != domain.FreshnessFresh {
		t.Fatalf("health semantics lost: %+v", health)
	}
}
