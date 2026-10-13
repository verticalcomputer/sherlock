package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type PublicQueryStore struct {
	pool *pgxpool.Pool
}

func NewPublicQueryStore(pool *pgxpool.Pool) (*PublicQueryStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &PublicQueryStore{pool: pool}, nil
}

func (store *PublicQueryStore) GetCluster(ctx context.Context, clusterID domain.ClusterID) (application.ClusterProjection, bool, error) {
	var result application.ClusterProjection
	err := store.pool.QueryRow(ctx, `
		SELECT cluster_id, display_name, created_at
		FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL`, clusterID).
		Scan(&result.ID, &result.DisplayName, &result.CreatedAt)
	if err == pgx.ErrNoRows {
		return application.ClusterProjection{}, false, nil
	}
	if err != nil {
		return application.ClusterProjection{}, false, fmt.Errorf("read cluster %s: %w", clusterID, err)
	}
	result.CreatedAt = result.CreatedAt.UTC()
	return result, true, nil
}

func (store *PublicQueryStore) ListSources(ctx context.Context, clusterID domain.ClusterID, filters application.SourceFilters, limit, offset int, at time.Time, freshFor time.Duration) ([]application.SourceProjection, bool, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT source_id, cluster_id, kind, display_name, availability,
		       last_attempt_at, last_success_at, last_failure_code
		FROM sources WHERE cluster_id=$1 AND (
		  $4='' OR availability=$4 OR ($4='DEGRADED' AND availability='AVAILABLE' AND last_failure_code IS NOT NULL)
		)
		ORDER BY source_id LIMIT $2 OFFSET $3`, clusterID, limit+1, offset, filters.Status)
	if err != nil {
		return nil, false, fmt.Errorf("list sources for cluster %s: %w", clusterID, err)
	}
	defer rows.Close()
	items := make([]application.SourceProjection, 0, limit)
	for rows.Next() {
		var item application.SourceProjection
		var failure *string
		if err := rows.Scan(&item.ID, &item.ClusterID, &item.Kind, &item.DisplayName, &item.Availability, &item.LastAttemptAt, &item.LastSuccessAt, &failure); err != nil {
			return nil, false, fmt.Errorf("scan source projection: %w", err)
		}
		if item.LastAttemptAt != nil {
			value := item.LastAttemptAt.UTC()
			item.LastAttemptAt = &value
		}
		if item.LastSuccessAt != nil {
			value := item.LastSuccessAt.UTC()
			item.LastSuccessAt = &value
		}
		item.Freshness = domain.FreshnessAt(item.LastSuccessAt, at, freshFor)
		if failure != nil {
			code := domain.FailureCode(*failure)
			item.LastFailureCode = &code
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate source projections: %w", err)
	}
	return trimPage(items, limit)
}

func (store *PublicQueryStore) ListObservations(ctx context.Context, clusterID domain.ClusterID, filters application.ObservationFilters, limit, offset int) ([]application.ObservationProjection, bool, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT observation_id, run_id, cluster_id, source_id, schema_version,
		       kind, entity_key, metric, labels, value, unit, observed_at,
		       collected_at, source_reference
		FROM observations WHERE cluster_id=$1
		  AND ($4='' OR source_id=$4) AND ($5='' OR entity_key=$5)
		  AND ($6='' OR kind=$6) AND ($7='' OR metric=$7)
		  AND ($8::timestamptz IS NULL OR observed_at >= $8)
		  AND ($9::timestamptz IS NULL OR observed_at <= $9)
		ORDER BY observed_at DESC, observation_id DESC LIMIT $2 OFFSET $3`, clusterID, limit+1, offset, filters.SourceID, filters.EntityKey, filters.Kind, filters.Metric, filters.ObservedAfter, filters.ObservedBefore)
	if err != nil {
		return nil, false, fmt.Errorf("list observations for cluster %s: %w", clusterID, err)
	}
	defer rows.Close()
	items := make([]application.ObservationProjection, 0, limit)
	for rows.Next() {
		item, err := scanObservation(rows)
		if err != nil {
			return nil, false, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate observations: %w", err)
	}
	return trimPage(items, limit)
}

func (store *PublicQueryStore) ListGPUSummaries(ctx context.Context, clusterID domain.ClusterID, filters application.GPUFilters, limit, offset int, at time.Time, freshFor time.Duration) ([]application.GPUSummaryProjection, bool, error) {
	reader, err := adminview.NewPostgresStore(store.pool)
	if err != nil {
		return nil, false, err
	}
	summaries, err := reader.LoadGPUHealthSummaries(ctx, string(clusterID), at, freshFor)
	if err != nil {
		return nil, false, err
	}
	items := make([]application.GPUSummaryProjection, 0)
	for _, summary := range summaries {
		identity, ok := domain.ResolveGPUObservationIdentity(clusterID, summary.SourceID, domain.Observation{ClusterID: clusterID, SourceID: summary.SourceID, EntityKey: summary.EntityKey})
		if !ok || filters.NodeID != "" && filters.NodeID != string(identity.NodeID) {
			continue
		}
		if filters.Health != "" {
			matched := false
			for _, signal := range summary.Signals {
				if signal.Type == filters.Health {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		items = append(items, summary)
	}
	if offset >= len(items) {
		return []application.GPUSummaryProjection{}, false, nil
	}
	return trimPage(items[offset:], limit)
}

func (store *PublicQueryStore) ListCollectionRuns(ctx context.Context, clusterID domain.ClusterID, filters application.CollectionRunFilters, limit, offset int) ([]application.CollectionRunProjection, bool, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT run_id, source_id, query_kind, status, scheduled_for, started_at,
		       completed_at, series_expected, series_returned, bytes_read, coverage_complete
		FROM collection_runs WHERE cluster_id=$1
		  AND ($4='' OR source_id=$4) AND ($5='' OR status=$5)
		ORDER BY completed_at DESC, run_id DESC LIMIT $2 OFFSET $3`, clusterID, limit+1, offset, filters.SourceID, filters.Status)
	if err != nil {
		return nil, false, fmt.Errorf("list collection runs for cluster %s: %w", clusterID, err)
	}
	defer rows.Close()
	items := make([]application.CollectionRunProjection, 0, limit)
	for rows.Next() {
		var item application.CollectionRunProjection
		if err := rows.Scan(&item.RunID, &item.SourceID, &item.Query, &item.Status, &item.ScheduledFor, &item.StartedAt, &item.CompletedAt, &item.Coverage.SeriesExpected, &item.Coverage.SeriesReturned, &item.Coverage.BytesRead, &item.Coverage.Complete); err != nil {
			return nil, false, fmt.Errorf("scan collection run: %w", err)
		}
		failures, err := store.runFailures(ctx, item.RunID)
		if err != nil {
			return nil, false, err
		}
		item.Failures = failures
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate collection runs: %w", err)
	}
	return trimPage(items, limit)
}

func (store *PublicQueryStore) GetEvidence(ctx context.Context, clusterID domain.ClusterID, evidenceID domain.EvidenceID) (application.EvidenceProjection, bool, error) {
	var exists bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM evidence_envelopes WHERE evidence_id=$1 AND cluster_id=$2)`, evidenceID, clusterID).Scan(&exists); err != nil {
		return application.EvidenceProjection{}, false, fmt.Errorf("scope evidence %s: %w", evidenceID, err)
	}
	if !exists {
		return application.EvidenceProjection{}, false, nil
	}
	evidenceStore, _ := NewEvidenceStore(store.pool)
	envelope, availability, found, err := evidenceStore.LoadEvidence(ctx, evidenceID)
	if err != nil || !found {
		return application.EvidenceProjection{}, found, err
	}
	return application.EvidenceProjection{Envelope: envelope, ArtifactAvailability: availability}, true, nil
}

func (store *PublicQueryStore) ListEvidence(ctx context.Context, clusterID domain.ClusterID, filters application.EvidenceFilters, limit, offset int) ([]application.EvidenceProjection, bool, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT evidence_id FROM evidence_envelopes WHERE cluster_id=$1
		  AND ($4='' OR status=$4)
		  AND ($5='' OR coverage_expected @> jsonb_build_array(jsonb_build_object('ID',$5::text)) OR coverage_covered @> jsonb_build_array(jsonb_build_object('ID',$5::text)))
		ORDER BY collected_at DESC, evidence_id DESC LIMIT $2 OFFSET $3`, clusterID, limit+1, offset, filters.Status, filters.TargetID)
	if err != nil {
		return nil, false, fmt.Errorf("list evidence for cluster %s: %w", clusterID, err)
	}
	defer rows.Close()
	ids := make([]domain.EvidenceID, 0, limit+1)
	for rows.Next() {
		var id domain.EvidenceID
		if err := rows.Scan(&id); err != nil {
			return nil, false, fmt.Errorf("scan evidence identifier: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate evidence identifiers: %w", err)
	}
	more := len(ids) > limit
	if more {
		ids = ids[:limit]
	}
	items := make([]application.EvidenceProjection, 0, len(ids))
	for _, id := range ids {
		item, found, err := store.GetEvidence(ctx, clusterID, id)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, false, fmt.Errorf("evidence %s disappeared during listing", id)
		}
		items = append(items, item)
	}
	return items, more, nil
}

func (store *PublicQueryStore) GetHealth(ctx context.Context, clusterID domain.ClusterID, at time.Time, freshFor time.Duration) (application.HealthProjection, bool, error) {
	shared, err := store.sharedHealth(ctx, clusterID, at)
	if err != nil {
		return application.HealthProjection{}, false, err
	}
	var run application.CollectionRunProjection
	err = store.pool.QueryRow(ctx, `
		SELECT run_id, source_id, query_kind, status, scheduled_for, started_at,
		       completed_at, series_expected, series_returned, bytes_read, coverage_complete
		FROM collection_runs WHERE cluster_id=$1
		ORDER BY completed_at DESC, run_id DESC LIMIT 1`, clusterID).Scan(
		&run.RunID, &run.SourceID, &run.Query, &run.Status, &run.ScheduledFor,
		&run.StartedAt, &run.CompletedAt, &run.Coverage.SeriesExpected, &run.Coverage.SeriesReturned,
		&run.Coverage.BytesRead, &run.Coverage.Complete)
	if err == pgx.ErrNoRows {
		_, found, clusterErr := store.GetCluster(ctx, clusterID)
		if clusterErr != nil || !found {
			return application.HealthProjection{}, found, clusterErr
		}
		return application.HealthProjection{ClusterID: clusterID, CollectionStatus: domain.ResultNoData, Freshness: domain.FreshnessUnknown, Availability: "UNKNOWN", GeneratedAt: at, Shared: shared}, true, nil
	}
	if err != nil {
		return application.HealthProjection{}, false, fmt.Errorf("read cluster health run: %w", err)
	}
	result := domain.CollectionResult{Task: domain.CollectionTask{RunID: run.RunID, ClusterID: clusterID, SourceID: run.SourceID, Query: run.Query}, Status: run.Status, StartedAt: run.StartedAt, CompletedAt: run.CompletedAt, Coverage: run.Coverage}
	failures, err := store.runFailures(ctx, run.RunID)
	if err != nil {
		return application.HealthProjection{}, false, err
	}
	result.Failures = failures
	observations, err := store.runObservations(ctx, run.RunID, clusterID)
	if err != nil {
		return application.HealthProjection{}, false, err
	}
	result.Observations = observations
	signals, err := application.ProjectGPUHealth(result, at, application.DefaultGPUHealthThresholds())
	if err != nil {
		return application.HealthProjection{}, false, fmt.Errorf("project cluster health: %w", err)
	}
	var availability string
	var lastSuccess *time.Time
	if err := store.pool.QueryRow(ctx, `SELECT availability, last_success_at FROM sources WHERE source_id=$1 AND cluster_id=$2`, run.SourceID, clusterID).Scan(&availability, &lastSuccess); err != nil {
		return application.HealthProjection{}, false, fmt.Errorf("read health source state: %w", err)
	}
	return application.HealthProjection{ClusterID: clusterID, CollectionStatus: run.Status, Freshness: domain.FreshnessAt(lastSuccess, at, freshFor), Availability: availability, Coverage: run.Coverage, Signals: signals, GeneratedAt: at, Shared: shared}, true, nil
}

func (store *PublicQueryStore) sharedHealth(ctx context.Context, clusterID domain.ClusterID, at time.Time) (*application.ClusterHealthView, error) {
	repository, err := adminview.NewPostgresStore(store.pool)
	if err != nil {
		return nil, err
	}
	// The versioned shared view has one policy across administrator and tenant
	// reads. The public API's legacy freshFor setting still governs its older
	// health fields, but must not change this view's evidence classification.
	view, found, err := repository.SharedHealth(ctx, adminview.Query{At: at, ClusterID: string(clusterID), Limit: 1,
		Window: adminview.DefaultWindow, FreshFor: adminview.DefaultFreshFor})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &view, nil
}

func (store *PublicQueryStore) runFailures(ctx context.Context, runID domain.RunID) ([]domain.CollectionFailure, error) {
	rows, err := store.pool.Query(ctx, `SELECT code, retryable, target, safe_message FROM collection_failures WHERE run_id=$1 ORDER BY failure_id`, runID)
	if err != nil {
		return nil, fmt.Errorf("list failures for run %s: %w", runID, err)
	}
	defer rows.Close()
	var failures []domain.CollectionFailure
	for rows.Next() {
		var failure domain.CollectionFailure
		if err := rows.Scan(&failure.Code, &failure.Retryable, &failure.Target, &failure.Message); err != nil {
			return nil, fmt.Errorf("scan collection failure: %w", err)
		}
		failures = append(failures, failure)
	}
	return failures, rows.Err()
}

func (store *PublicQueryStore) runObservations(ctx context.Context, runID domain.RunID, clusterID domain.ClusterID) ([]domain.Observation, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT observation_id, run_id, cluster_id, source_id, schema_version,
		       kind, entity_key, metric, labels, value, unit, observed_at,
		       collected_at, source_reference
		FROM observations WHERE run_id=$1 AND cluster_id=$2 ORDER BY observation_id`, runID, clusterID)
	if err != nil {
		return nil, fmt.Errorf("list run observations: %w", err)
	}
	defer rows.Close()
	var observations []domain.Observation
	for rows.Next() {
		item, err := scanObservation(rows)
		if err != nil {
			return nil, err
		}
		observations = append(observations, item.Observation)
	}
	return observations, rows.Err()
}

type observationScanner interface {
	Scan(...any) error
}

func scanObservation(scanner observationScanner) (application.ObservationProjection, error) {
	var item application.ObservationProjection
	var labelsJSON []byte
	if err := scanner.Scan(&item.Observation.ID, &item.RunID, &item.Observation.ClusterID,
		&item.Observation.SourceID, &item.Observation.SchemaVersion, &item.Observation.Kind,
		&item.Observation.EntityKey, &item.Observation.Metric, &labelsJSON,
		&item.Observation.Value, &item.Observation.Unit, &item.Observation.ObservedAt,
		&item.Observation.CollectedAt, &item.Observation.SourceReference); err != nil {
		return application.ObservationProjection{}, fmt.Errorf("scan observation projection: %w", err)
	}
	if err := json.Unmarshal(labelsJSON, &item.Observation.Labels); err != nil {
		return application.ObservationProjection{}, fmt.Errorf("decode observation labels: %w", err)
	}
	return item, nil
}

func trimPage[T any](items []T, limit int) ([]T, bool, error) {
	if len(items) <= limit {
		return items, false, nil
	}
	return items[:limit], true, nil
}
