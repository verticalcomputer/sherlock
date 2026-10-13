package adminview

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	DefaultLimit    = 20
	MaxLimit        = 100
	MaxOffset       = 10_000
	DefaultWindow   = 24 * time.Hour
	MaxWindow       = 31 * 24 * time.Hour
	DefaultFreshFor = 5 * time.Minute
	MaxFreshFor     = 24 * time.Hour
)

// Repository is deliberately aggregate-only. Implementations must not return
// raw artifacts, prompts, model responses, diagnostic output, or actor IDs.
type Repository interface {
	Load(context.Context, Query) ([]ClusterSummary, bool, error)
}

type Service struct {
	repository        Repository
	now               func() time.Time
	gpuHealthFreshFor time.Duration
}

type ServiceOption func(*Service) error

// WithGPUHealthFreshness aligns the private page's condition policy with the
// public GPU API configuration. Field support keeps its own operation windows.
func WithGPUHealthFreshness(freshFor time.Duration) ServiceOption {
	return func(service *Service) error {
		if freshFor <= 0 {
			return fmt.Errorf("GPU health freshness must be positive")
		}
		service.gpuHealthFreshFor = freshFor
		return nil
	}
}

func NewService(repository Repository, options ...ServiceOption) (*Service, error) {
	if repository == nil {
		return nil, fmt.Errorf("admin view repository is required")
	}
	service := &Service{repository: repository, now: time.Now, gpuHealthFreshFor: application.DefaultGPUHealthThresholds().FreshFor}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("admin view service option is required")
		}
		if err := option(service); err != nil {
			return nil, err
		}
	}
	return service, nil
}

// Snapshot returns one bounded page of redacted operational summaries.
func (service *Service) Snapshot(ctx context.Context, query Query) (Dashboard, error) {
	query, err := service.normalize(query)
	if err != nil {
		return Dashboard{}, err
	}
	clusters, hasMore, err := service.repository.Load(ctx, query)
	if err != nil {
		return Dashboard{}, fmt.Errorf("load admin dashboard: %w", err)
	}
	for index := range clusters {
		classify(&clusters[index])
		cluster := &clusters[index]
		cluster.Health, err = projectSharedHealth(*cluster, query)
		if err != nil {
			return Dashboard{}, fmt.Errorf("project cluster health: %w", err)
		}
	}
	return Dashboard{
		GeneratedAt: query.At,
		WindowStart: query.At.Add(-query.Window),
		WindowEnd:   query.At,
		Clusters:    clusters,
		HasMore:     hasMore,
	}, nil
}

// projectSharedHealth is used by both the full administrator summary and the
// bounded tenant read. Evidence older than the requested window is historical
// activity outside this view, not a current stream or a current warning.
func projectSharedHealth(cluster ClusterSummary, query Query) (application.ClusterHealthView, error) {
	var complete, partial, noData, unavailable, historical int64
	for _, stream := range cluster.Evidence.CurrentStreams {
		if stream.LatestAttempt.IsZero() || stream.LatestAttempt.After(query.At) || stream.LatestAttempt.Before(query.At.Add(-query.Window)) {
			continue
		}
		if stream.LatestAttempt.Before(query.At.Add(-query.FreshFor)) {
			historical++
			continue
		}
		switch stream.Status {
		case "COMPLETE":
			complete++
		case "PARTIAL":
			partial++
		case "NO_DATA":
			noData++
		case "UNAVAILABLE":
			unavailable++
		}
	}
	return application.ProjectClusterHealth(application.ClusterHealthFacts{
		ClusterID: domain.ClusterID(cluster.ClusterID), At: query.At, WindowStart: query.At.Add(-query.Window),
		ExpectedNodes: cluster.Resources.ExpectedInventoryNodes, ExpectedGPUs: cluster.Resources.ExpectedInventoryGPUs,
		ObservedNodes: cluster.Resources.ObservedInventoryNodes, ObservedGPUs: cluster.Resources.ObservedInventoryGPUs,
		ExpectedRevisionID: cluster.Resources.ExpectedRevisionID, ObservedRevisionID: cluster.Resources.ObservedRevisionID,
		ExpectedCollectors: int64(len(cluster.ExpectedCollectorNames)), FreshCollectors: cluster.Connectivity.FreshCollectors,
		FreshSources: cluster.Freshness.FreshSources, StaleSources: cluster.Freshness.StaleSources,
		SourcesWithoutData: cluster.Freshness.SourcesWithoutData,
		CompleteStreams:    complete, PartialStreams: partial, NoDataStreams: noData,
		UnavailableStreams: unavailable, HistoricalStreams: historical,
		ExpectedOperations: cluster.Schedule.Expected, FreshOperations: cluster.Schedule.Fresh,
		LateOperations: cluster.Schedule.Late, FailedOperations: cluster.Schedule.Failed,
		Progress: domain.ProgressUnmeasured,
	})
}

func (service *Service) normalize(query Query) (Query, error) {
	if query.At.IsZero() {
		query.At = service.now()
	}
	query.At = query.At.UTC()
	if query.Window == 0 {
		query.Window = DefaultWindow
	}
	if query.FreshFor == 0 {
		query.FreshFor = DefaultFreshFor
	}
	if query.Limit == 0 {
		query.Limit = DefaultLimit
	}
	if query.Window < 0 || query.Window > MaxWindow {
		return Query{}, fmt.Errorf("admin view window must be between zero and %s", MaxWindow)
	}
	if query.FreshFor < 0 || query.FreshFor > MaxFreshFor {
		return Query{}, fmt.Errorf("admin view freshness must be between zero and %s", MaxFreshFor)
	}
	if query.Limit < 1 || query.Limit > MaxLimit {
		return Query{}, fmt.Errorf("admin view limit must be between 1 and %d", MaxLimit)
	}
	if query.Offset < 0 || query.Offset > MaxOffset {
		return Query{}, fmt.Errorf("admin view offset must be between 0 and %d", MaxOffset)
	}
	if query.ClusterID != "" && !validClusterID(query.ClusterID) {
		return Query{}, fmt.Errorf("admin view cluster ID is invalid")
	}
	return query, nil
}

func validClusterID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, character := range id {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func classify(cluster *ClusterSummary) {
	c := &cluster.Connectivity
	switch {
	case c.Collectors == 0:
		c.State = StateNoData
	case c.FreshCollectors == 0:
		c.State = StateUnavailable
	case c.StaleCollectors > 0 || c.UnavailableSources > 0 || c.UnknownSources > 0:
		c.State = StateDegraded
	default:
		c.State = StateHealthy
	}

	f := &cluster.Freshness
	switch {
	case f.FreshSources > 0 && f.StaleSources == 0 && f.SourcesWithoutData == 0:
		f.State = StateHealthy
	case f.FreshSources > 0:
		f.State = StateDegraded
	case f.StaleSources > 0:
		f.State = StateUnavailable
	default:
		f.State = StateNoData
	}

	q := &cluster.Queue
	if q.Overdue > 0 || q.DiagnosticBlocked > 0 {
		q.State = StateDegraded
	} else {
		q.State = StateHealthy
	}

	i := &cluster.Investigations
	switch {
	case i.Blocked > 0 || i.Partial > 0:
		i.State = StateDegraded
	case i.Active+i.Completed+i.Cancelled == 0:
		i.State = StateNoData
	default:
		i.State = StateHealthy
	}

	m := &cluster.ModelUsage
	switch {
	case m.Calls == 0:
		m.State = StateNoData
	case m.Failed > 0 || m.Rejected > 0:
		m.State = StateDegraded
	default:
		m.State = StateHealthy
	}

	e := &cluster.Evidence
	switch {
	case e.CurrentTotal == 0:
		e.State = StateNoData
	case e.CurrentComplete == 0 && (e.CurrentUnavailable > 0 || e.CurrentNoData > 0):
		e.State = StateUnavailable
	case e.CurrentPartial+e.CurrentNoData+e.CurrentUnavailable+e.CurrentArtifactsPending+e.CurrentArtifactsUnavailable+e.CurrentArtifactsCorrupt > 0:
		e.State = StateDegraded
	default:
		e.State = StateHealthy
	}

	a := &cluster.Audit
	switch {
	case a.Events == 0:
		a.State = StateNoData
	case a.DeniedOrFailed > 0:
		a.State = StateDegraded
	default:
		a.State = StateHealthy
	}

	r := &cluster.Resources
	switch {
	case r.Truncated:
		r.State = StateDegraded
	case r.ObservedNodes == 0:
		r.State = StateNoData
	case r.GPUUtilizationPercent == nil:
		r.State = StateDegraded
	case r.GPUUtilizationSamples < r.ObservedGPUs:
		r.State = StateDegraded
	default:
		r.State = StateHealthy
	}

	cluster.Overall = overallState(*cluster)
}

func overallState(cluster ClusterSummary) State {

	states := []State{
		cluster.Connectivity.State, cluster.Freshness.State, cluster.Queue.State,
		cluster.Investigations.State, cluster.ModelUsage.State, cluster.Evidence.State,
		cluster.Audit.State,
		cluster.Resources.State,
	}
	if cluster.Network.Enrolled && cluster.Network.State != "HEALTHY" {
		states = append(states, StateDegraded)
	}
	for _, state := range states {
		if state == StateUnavailable {
			return StateUnavailable
		}
	}
	for _, state := range states {
		if state == StateDegraded {
			return StateDegraded
		}
	}
	// An empty queue is healthy, but it must not disguise a cluster with no
	// telemetry or evidence at all.
	if cluster.Freshness.State == StateNoData && cluster.Evidence.State == StateNoData {
		return StateNoData
	}
	return StateHealthy
}
