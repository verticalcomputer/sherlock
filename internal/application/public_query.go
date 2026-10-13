package application

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

type PageRequest struct {
	Size  int
	Token string
}

type PageInfo struct {
	NextToken string
}

type SourceFilters struct{ Status string }
type ObservationFilters struct {
	SourceID, EntityKey, Kind, Metric string
	ObservedAfter, ObservedBefore     *time.Time
}
type GPUFilters struct {
	NodeID string
	Health domain.HealthSignalType
}
type CollectionRunFilters struct {
	SourceID domain.SourceID
	Status   domain.ResultStatus
}
type EvidenceFilters struct {
	Status   domain.EvidenceStatus
	TargetID domain.EvidenceTargetID
}

type ClusterProjection struct {
	ID          domain.ClusterID
	DisplayName string
	CreatedAt   time.Time
}

type SourceProjection struct {
	ID              domain.SourceID
	ClusterID       domain.ClusterID
	Kind            string
	DisplayName     string
	Availability    string
	Freshness       domain.Freshness
	LastAttemptAt   *time.Time
	LastSuccessAt   *time.Time
	LastFailureCode *domain.FailureCode
}

type ObservationProjection struct {
	Observation domain.Observation
	RunID       domain.RunID
}

type GPUSummaryProjection struct {
	EntityKey     string
	SourceID      domain.SourceID
	Freshness     domain.Freshness
	LastSuccessAt time.Time
	Observations  []domain.Observation
	Signals       []domain.HealthSignal
}

type CollectionRunProjection struct {
	RunID        domain.RunID
	SourceID     domain.SourceID
	Query        domain.QueryKind
	Status       domain.ResultStatus
	ScheduledFor time.Time
	StartedAt    time.Time
	CompletedAt  time.Time
	Coverage     domain.Coverage
	Failures     []domain.CollectionFailure
}

type EvidenceProjection struct {
	Envelope             domain.EvidenceEnvelope
	ArtifactAvailability domain.ArtifactAvailability
}

type HealthProjection struct {
	ClusterID        domain.ClusterID
	CollectionStatus domain.ResultStatus
	Freshness        domain.Freshness
	Availability     string
	Coverage         domain.Coverage
	Signals          []domain.HealthSignal
	GeneratedAt      time.Time
	Shared           *ClusterHealthView
}

type PublicQueryReader interface {
	GetCluster(context.Context, domain.ClusterID) (ClusterProjection, bool, error)
	ListSources(context.Context, domain.ClusterID, SourceFilters, int, int, time.Time, time.Duration) ([]SourceProjection, bool, error)
	ListObservations(context.Context, domain.ClusterID, ObservationFilters, int, int) ([]ObservationProjection, bool, error)
	ListGPUSummaries(context.Context, domain.ClusterID, GPUFilters, int, int, time.Time, time.Duration) ([]GPUSummaryProjection, bool, error)
	ListCollectionRuns(context.Context, domain.ClusterID, CollectionRunFilters, int, int) ([]CollectionRunProjection, bool, error)
	ListEvidence(context.Context, domain.ClusterID, EvidenceFilters, int, int) ([]EvidenceProjection, bool, error)
	GetEvidence(context.Context, domain.ClusterID, domain.EvidenceID) (EvidenceProjection, bool, error)
	GetHealth(context.Context, domain.ClusterID, time.Time, time.Duration) (HealthProjection, bool, error)
}

type PublicQueries struct {
	reader   PublicQueryReader
	clock    Clock
	freshFor time.Duration
}

func NewPublicQueries(reader PublicQueryReader, clock Clock, freshFor time.Duration) (*PublicQueries, error) {
	if reader == nil || clock == nil {
		return nil, fmt.Errorf("public query dependencies are required")
	}
	if freshFor <= 0 || freshFor > 24*time.Hour {
		return nil, fmt.Errorf("public query freshness window must be in (0, 24h]")
	}
	return &PublicQueries{reader: reader, clock: clock, freshFor: freshFor}, nil
}

func (queries *PublicQueries) GetCluster(ctx context.Context, clusterID domain.ClusterID) (ClusterProjection, bool, error) {
	if clusterID == "" {
		return ClusterProjection{}, false, fmt.Errorf("cluster identifier is required")
	}
	return queries.reader.GetCluster(ctx, clusterID)
}

func (queries *PublicQueries) ListSources(ctx context.Context, clusterID domain.ClusterID, filters SourceFilters, page PageRequest) ([]SourceProjection, PageInfo, error) {
	if clusterID == "" {
		return nil, PageInfo{}, fmt.Errorf("cluster identifier is required")
	}
	offset, size, err := decodePage(page)
	if err != nil {
		return nil, PageInfo{}, err
	}
	items, more, err := queries.reader.ListSources(ctx, clusterID, filters, size, offset, queries.clock.Now().UTC(), queries.freshFor)
	return items, nextPage(offset, len(items), more), err
}

func (queries *PublicQueries) ListObservations(ctx context.Context, clusterID domain.ClusterID, filters ObservationFilters, page PageRequest) ([]ObservationProjection, PageInfo, error) {
	if clusterID == "" {
		return nil, PageInfo{}, fmt.Errorf("cluster identifier is required")
	}
	offset, size, err := decodePage(page)
	if err != nil {
		return nil, PageInfo{}, err
	}
	items, more, err := queries.reader.ListObservations(ctx, clusterID, filters, size, offset)
	return items, nextPage(offset, len(items), more), err
}

func (queries *PublicQueries) ListGPUSummaries(ctx context.Context, clusterID domain.ClusterID, filters GPUFilters, page PageRequest) ([]GPUSummaryProjection, PageInfo, error) {
	if clusterID == "" {
		return nil, PageInfo{}, fmt.Errorf("cluster identifier is required")
	}
	offset, size, err := decodePage(page)
	if err != nil {
		return nil, PageInfo{}, err
	}
	items, more, err := queries.reader.ListGPUSummaries(ctx, clusterID, filters, size, offset, queries.clock.Now().UTC(), queries.freshFor)
	return items, nextPage(offset, len(items), more), err
}

func (queries *PublicQueries) ListCollectionRuns(ctx context.Context, clusterID domain.ClusterID, filters CollectionRunFilters, page PageRequest) ([]CollectionRunProjection, PageInfo, error) {
	if clusterID == "" {
		return nil, PageInfo{}, fmt.Errorf("cluster identifier is required")
	}
	offset, size, err := decodePage(page)
	if err != nil {
		return nil, PageInfo{}, err
	}
	items, more, err := queries.reader.ListCollectionRuns(ctx, clusterID, filters, size, offset)
	return items, nextPage(offset, len(items), more), err
}

func (queries *PublicQueries) GetEvidence(ctx context.Context, clusterID domain.ClusterID, evidenceID domain.EvidenceID) (EvidenceProjection, bool, error) {
	if clusterID == "" || evidenceID == "" {
		return EvidenceProjection{}, false, fmt.Errorf("cluster and evidence identifiers are required")
	}
	return queries.reader.GetEvidence(ctx, clusterID, evidenceID)
}

func (queries *PublicQueries) ListEvidence(ctx context.Context, clusterID domain.ClusterID, filters EvidenceFilters, page PageRequest) ([]EvidenceProjection, PageInfo, error) {
	if clusterID == "" {
		return nil, PageInfo{}, fmt.Errorf("cluster identifier is required")
	}
	offset, size, err := decodePage(page)
	if err != nil {
		return nil, PageInfo{}, err
	}
	items, more, err := queries.reader.ListEvidence(ctx, clusterID, filters, size, offset)
	return items, nextPage(offset, len(items), more), err
}

func (queries *PublicQueries) GetHealth(ctx context.Context, clusterID domain.ClusterID) (HealthProjection, bool, error) {
	if clusterID == "" {
		return HealthProjection{}, false, fmt.Errorf("cluster identifier is required")
	}
	return queries.reader.GetHealth(ctx, clusterID, queries.clock.Now().UTC(), queries.freshFor)
}

type pageCursor struct {
	Version int `json:"v"`
	Offset  int `json:"o"`
}

func decodePage(page PageRequest) (int, int, error) {
	size := page.Size
	if size == 0 {
		size = DefaultPageSize
	}
	if size < 1 || size > MaxPageSize {
		return 0, 0, fmt.Errorf("page size must be between 1 and %d", MaxPageSize)
	}
	if page.Token == "" {
		return 0, size, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(page.Token)
	if err != nil {
		return 0, 0, fmt.Errorf("page token is invalid")
	}
	var cursor pageCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.Version != 1 || cursor.Offset < 0 {
		return 0, 0, fmt.Errorf("page token is invalid")
	}
	return cursor.Offset, size, nil
}

func nextPage(offset, returned int, more bool) PageInfo {
	if !more {
		return PageInfo{}
	}
	payload, _ := json.Marshal(pageCursor{Version: 1, Offset: offset + returned})
	return PageInfo{NextToken: base64.RawURLEncoding.EncodeToString(payload)}
}
