package application

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type publicQueryReaderStub struct {
	offset int
	limit  int
}

func (stub *publicQueryReaderStub) GetCluster(context.Context, domain.ClusterID) (ClusterProjection, bool, error) {
	return ClusterProjection{}, false, nil
}
func (stub *publicQueryReaderStub) ListSources(_ context.Context, _ domain.ClusterID, _ SourceFilters, limit, offset int, _ time.Time, _ time.Duration) ([]SourceProjection, bool, error) {
	stub.limit, stub.offset = limit, offset
	return []SourceProjection{{ID: "one"}}, true, nil
}
func (stub *publicQueryReaderStub) ListObservations(context.Context, domain.ClusterID, ObservationFilters, int, int) ([]ObservationProjection, bool, error) {
	return nil, false, nil
}
func (stub *publicQueryReaderStub) ListGPUSummaries(context.Context, domain.ClusterID, GPUFilters, int, int, time.Time, time.Duration) ([]GPUSummaryProjection, bool, error) {
	return nil, false, nil
}
func (stub *publicQueryReaderStub) ListCollectionRuns(context.Context, domain.ClusterID, CollectionRunFilters, int, int) ([]CollectionRunProjection, bool, error) {
	return nil, false, nil
}
func (stub *publicQueryReaderStub) ListEvidence(context.Context, domain.ClusterID, EvidenceFilters, int, int) ([]EvidenceProjection, bool, error) {
	return nil, false, nil
}
func (stub *publicQueryReaderStub) GetEvidence(context.Context, domain.ClusterID, domain.EvidenceID) (EvidenceProjection, bool, error) {
	return EvidenceProjection{}, false, nil
}
func (stub *publicQueryReaderStub) GetHealth(context.Context, domain.ClusterID, time.Time, time.Duration) (HealthProjection, bool, error) {
	return HealthProjection{}, false, nil
}

func TestPublicQueriesOpaquePaginationRoundTrip(t *testing.T) {
	reader := &publicQueryReaderStub{}
	queries, err := NewPublicQueries(reader, fixedClock{now: time.Unix(10, 0)}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, page, err := queries.ListSources(context.Background(), "cluster-a", SourceFilters{}, PageRequest{Size: 25})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextToken == "" || reader.limit != 25 || reader.offset != 0 {
		t.Fatalf("unexpected first page: token=%q limit=%d offset=%d", page.NextToken, reader.limit, reader.offset)
	}
	if _, _, err := queries.ListSources(context.Background(), "cluster-a", SourceFilters{}, PageRequest{Size: 25, Token: page.NextToken}); err != nil {
		t.Fatal(err)
	}
	if reader.offset != 1 {
		t.Fatalf("offset = %d, want 1", reader.offset)
	}
}

func TestPublicQueriesRejectsInvalidPaginationAndEmptyScope(t *testing.T) {
	queries, err := NewPublicQueries(&publicQueryReaderStub{}, fixedClock{now: time.Unix(10, 0)}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queries.ListSources(context.Background(), "cluster-a", SourceFilters{}, PageRequest{Token: "not-a-cursor"}); err == nil {
		t.Fatal("expected invalid cursor error")
	}
	if _, _, err := queries.ListObservations(context.Background(), "", ObservationFilters{}, PageRequest{}); err == nil {
		t.Fatal("expected empty cluster scope error")
	}
	if _, _, err := queries.ListGPUSummaries(context.Background(), "cluster-a", GPUFilters{}, PageRequest{Size: MaxPageSize + 1}); err == nil {
		t.Fatal("expected page-size error")
	}
}
