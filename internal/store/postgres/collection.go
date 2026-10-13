package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/events"
)

type CollectionStore struct {
	pool *pgxpool.Pool
}

func NewCollectionStore(pool *pgxpool.Pool) (*CollectionStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &CollectionStore{pool: pool}, nil
}

func (s *CollectionStore) EnsureSource(ctx context.Context, clusterID domain.ClusterID, clusterName string, sourceID domain.SourceID, sourceName string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin ensure source: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO clusters (cluster_id, display_name) VALUES ($1, $2) ON CONFLICT (cluster_id) DO NOTHING`, clusterID, clusterName); err != nil {
		return fmt.Errorf("ensure cluster %s: %w", clusterID, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO sources (source_id, cluster_id, kind, display_name) VALUES ($1, $2, 'prometheus', $3) ON CONFLICT (source_id) DO NOTHING`, sourceID, clusterID, sourceName); err != nil {
		return fmt.Errorf("ensure source %s: %w", sourceID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit ensure source: %w", err)
	}
	return nil
}

func (s *CollectionStore) RecordResult(ctx context.Context, result domain.CollectionResult) (bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin record result: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	inserted, err := recordResultTx(ctx, tx, result)
	if err != nil {
		return false, err
	}
	if !inserted {
		return false, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit collection result %s: %w", result.Task.RunID, err)
	}
	return true, nil
}

func recordResultTx(ctx context.Context, tx pgx.Tx, result domain.CollectionResult) (bool, error) {
	var jobID *string
	var bindingValid bool
	err := tx.QueryRow(ctx, `SELECT job_id,
		cluster_id=$2 AND source_id=$3 AND query_kind=$4 AND node_filter=$5 AND scheduled_for=$6
		FROM collection_run_jobs WHERE run_id=$1`, result.Task.RunID, result.Task.ClusterID,
		result.Task.SourceID, result.Task.Query, result.Task.Node, result.Task.ScheduledFor.UTC()).Scan(&jobID, &bindingValid)
	if err != nil && err != pgx.ErrNoRows {
		return false, fmt.Errorf("read collection job provenance: %w", err)
	}
	if err == nil && !bindingValid {
		return false, fmt.Errorf("collection result conflicts with bound job provenance")
	}
	result, err = normalizeDCGMResult(ctx, tx, result)
	if err != nil {
		return false, err
	}
	result, err = applyAuthoritativeCoverage(ctx, tx, result)
	if err != nil {
		return false, err
	}
	metricFields := result.Coverage.MetricFields
	if metricFields == nil {
		metricFields = []domain.DCGMFieldEvidence{}
	}
	encodedFields, err := json.Marshal(metricFields)
	if err != nil {
		return false, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO collection_runs (
			run_id, cluster_id, source_id, query_kind, idempotency_key, status,
			scheduled_for, started_at, completed_at, series_expected, series_returned, bytes_read, coverage_complete,
			range_start, range_end, range_step_seconds, job_id, metric_fields
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (idempotency_key) DO NOTHING`,
		result.Task.RunID, result.Task.ClusterID, result.Task.SourceID, result.Task.Query,
		result.Task.IdempotencyKey, result.Status, result.Task.ScheduledFor.UTC(), result.StartedAt.UTC(),
		result.CompletedAt.UTC(), result.Coverage.SeriesExpected, result.Coverage.SeriesReturned, result.Coverage.BytesRead, result.Coverage.Complete,
		rangeStart(result.Task.Range), rangeEnd(result.Task.Range), rangeStep(result.Task.Range), jobID, encodedFields)
	if err != nil {
		return false, fmt.Errorf("insert collection run %s: %w", result.Task.RunID, err)
	}
	if command.RowsAffected() == 0 {
		return false, nil
	}

	for _, failure := range result.Failures {
		if _, err := tx.Exec(ctx, `INSERT INTO collection_failures (run_id, code, retryable, target, safe_message) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, result.Task.RunID, failure.Code, failure.Retryable, failure.Target, failure.Message); err != nil {
			return false, fmt.Errorf("insert collection failure for run %s: %w", result.Task.RunID, err)
		}
	}

	if result.Status == domain.ResultSucceeded || result.Status == domain.ResultPartial {
		for _, observation := range result.Observations {
			labels, err := json.Marshal(observation.Labels)
			if err != nil {
				return false, fmt.Errorf("encode labels for observation %s: %w", observation.ID, err)
			}
			fingerprint := sampleFingerprint(observation)
			var semantics []byte
			if observation.Semantics != nil {
				semantics, err = json.Marshal(observation.Semantics)
				if err != nil {
					return false, err
				}
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO observations (
					observation_id, run_id, cluster_id, source_id, schema_version, kind,
					entity_key, metric, labels, value, unit, observed_at, collected_at,
					source_reference, sample_fingerprint, metric_semantics
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
				observation.ID, result.Task.RunID, observation.ClusterID, observation.SourceID,
				observation.SchemaVersion, observation.Kind, observation.EntityKey, observation.Metric,
				labels, observation.Value, observation.Unit, observation.ObservedAt.UTC(),
				observation.CollectedAt.UTC(), observation.SourceReference, fingerprint[:], semantics); err != nil {
				return false, fmt.Errorf("insert observation %s: %w", observation.ID, err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO current_projections (
					cluster_id, source_id, entity_key, metric, observation_id, observed_at, last_success_at, updated_at
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
				ON CONFLICT (cluster_id, source_id, entity_key, metric) DO UPDATE SET
					observation_id = EXCLUDED.observation_id,
					observed_at = EXCLUDED.observed_at,
					last_success_at = EXCLUDED.last_success_at,
					updated_at = EXCLUDED.updated_at
				WHERE current_projections.observed_at <= EXCLUDED.observed_at`,
				observation.ClusterID, observation.SourceID, observation.EntityKey, observation.Metric,
				observation.ID, observation.ObservedAt.UTC(), result.CompletedAt.UTC(), result.CompletedAt.UTC()); err != nil {
				return false, fmt.Errorf("update current projection for observation %s: %w", observation.ID, err)
			}
		}
	}
	if err := recordTargetInventoryTx(ctx, tx, result); err != nil {
		return false, err
	}

	if envelope, present, evidenceErr := domain.CollectionEvidenceForCollection(result); evidenceErr != nil {
		return false, evidenceErr
	} else if present {
		created, insertErr := insertEvidenceEnvelope(ctx, tx, envelope)
		if insertErr != nil {
			return false, insertErr
		}
		if !created {
			return false, fmt.Errorf("collection evidence %s conflicts with a distinct collection run", envelope.ID())
		}
	}

	available := sourceResponded(result)
	if available && result.Status != domain.ResultFailed {
		if _, err := tx.Exec(ctx, `UPDATE sources SET availability='AVAILABLE', last_attempt_at=$2, last_success_at=$2, last_failure_code=NULL WHERE source_id=$1`, result.Task.SourceID, result.CompletedAt.UTC()); err != nil {
			return false, fmt.Errorf("update available source %s: %w", result.Task.SourceID, err)
		}
	} else if available {
		var code domain.FailureCode = domain.FailureInternal
		if len(result.Failures) > 0 {
			code = result.Failures[0].Code
		}
		if _, err := tx.Exec(ctx, `UPDATE sources SET availability='AVAILABLE', last_attempt_at=$2, last_failure_code=$3 WHERE source_id=$1`, result.Task.SourceID, result.CompletedAt.UTC(), code); err != nil {
			return false, fmt.Errorf("update responding source %s: %w", result.Task.SourceID, err)
		}
	} else {
		var code domain.FailureCode = domain.FailureInternal
		if len(result.Failures) > 0 {
			code = result.Failures[0].Code
		}
		if _, err := tx.Exec(ctx, `UPDATE sources SET availability='UNAVAILABLE', last_attempt_at=$2, last_failure_code=$3 WHERE source_id=$1`, result.Task.SourceID, result.CompletedAt.UTC(), code); err != nil {
			return false, fmt.Errorf("update unavailable source %s: %w", result.Task.SourceID, err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO collection_events (run_id, event_type) VALUES ($1, 'collection.completed')`, result.Task.RunID); err != nil {
		return false, fmt.Errorf("insert collection event for run %s: %w", result.Task.RunID, err)
	}
	if _, err := events.AppendTx(ctx, tx, result.Task.ClusterID, events.CollectionUpdatedV1{
		RunID: result.Task.RunID, SourceID: result.Task.SourceID, Status: result.Status,
		CompletedAt: result.CompletedAt, CoverageComplete: result.Coverage.Complete,
	}); err != nil {
		return false, fmt.Errorf("append durable collection event for run %s: %w", result.Task.RunID, err)
	}
	var availability events.SourceAvailability
	var lastAttempt time.Time
	var lastSuccess *time.Time
	var lastFailure *domain.FailureCode
	if err := tx.QueryRow(ctx, `
		SELECT availability, last_attempt_at, last_success_at, last_failure_code
		FROM sources WHERE source_id=$1 AND cluster_id=$2`, result.Task.SourceID, result.Task.ClusterID).
		Scan(&availability, &lastAttempt, &lastSuccess, &lastFailure); err != nil {
		return false, fmt.Errorf("read updated source %s for durable event: %w", result.Task.SourceID, err)
	}
	if _, err := events.AppendTx(ctx, tx, result.Task.ClusterID, events.SourceUpdatedV1{
		SourceID: result.Task.SourceID, Availability: availability, LastAttemptAt: lastAttempt,
		LastSuccessAt: lastSuccess, LastFailureCode: lastFailure,
	}); err != nil {
		return false, fmt.Errorf("append durable source event for source %s: %w", result.Task.SourceID, err)
	}
	return true, nil
}

func applyAuthoritativeCoverage(ctx context.Context, tx pgx.Tx, result domain.CollectionResult) (domain.CollectionResult, error) {
	if len(domain.DCGMFields(result.Task.Query)) > 0 && result.Task.Range == nil {
		return result, nil
	}
	if result.Task.Query == domain.QuerySourceHealth && result.Coverage.Complete {
		// Prometheus `up` enumerates the source's current scrape targets. A
		// warning-free response is therefore an authoritative source-target
		// snapshot, including an authoritative empty snapshot.
		expected := result.Coverage.SeriesReturned
		result.Coverage.SeriesExpected = &expected
		result.Coverage.ExpectedTargets = observationTargets(result.Task.Query, result.Observations)
		return result, nil
	}
	kind := "gpu_identity"
	if result.Task.Query == domain.QuerySourceHealth {
		kind = "source_metric"
	} else if !result.Task.Query.IsGPU() {
		return result, nil
	}
	targets, err := loadCurrentInventoryTargets(ctx, tx, result, kind)
	if err != nil {
		return domain.CollectionResult{}, err
	}
	if len(targets) == 0 {
		return result, nil
	}
	result.Coverage.ExpectedTargets = targets
	series := expectedSeriesForTargets(result.Task.Query, targets)
	result.Coverage.SeriesExpected = &series
	return result, nil
}

func loadCurrentInventoryTargets(ctx context.Context, tx pgx.Tx, result domain.CollectionResult, kind string) ([]domain.EvidenceTarget, error) {
	if kind == "gpu_identity" {
		rows, err := tx.Query(ctx, `
			SELECT target_kind,target_id
			FROM collection_target_inventory
			WHERE cluster_id=$1 AND source_id=$2
			  AND ($3='' OR target_kind='NODE' AND target_id=$3 OR target_kind='GPU' AND node_id=$3)
			ORDER BY target_kind,target_id`, result.Task.ClusterID, result.Task.SourceID, result.Task.Node)
		if err != nil {
			return nil, fmt.Errorf("load expected evidence inventory: %w", err)
		}
		defer rows.Close()
		targets := make([]domain.EvidenceTarget, 0)
		for rows.Next() {
			var target domain.EvidenceTarget
			if err := rows.Scan(&target.Kind, &target.ID); err != nil {
				return nil, fmt.Errorf("scan expected evidence inventory: %w", err)
			}
			targets = append(targets, target)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate expected evidence inventory: %w", err)
		}
		return targets, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT o.labels, o.entity_key
		FROM current_projections p
		JOIN observations o ON o.observation_id=p.observation_id
		WHERE p.cluster_id=$1 AND p.source_id=$2 AND o.kind=$3
		ORDER BY o.entity_key, o.metric`, result.Task.ClusterID, result.Task.SourceID, kind)
	if err != nil {
		return nil, fmt.Errorf("load expected evidence inventory: %w", err)
	}
	defer rows.Close()
	seen := make(map[domain.EvidenceTarget]struct{})
	targets := make([]domain.EvidenceTarget, 0)
	for rows.Next() {
		var labelsJSON []byte
		var entityKey string
		if err := rows.Scan(&labelsJSON, &entityKey); err != nil {
			return nil, fmt.Errorf("scan expected evidence inventory: %w", err)
		}
		var labels []domain.Label
		if err := json.Unmarshal(labelsJSON, &labels); err != nil {
			return nil, fmt.Errorf("decode expected evidence inventory: %w", err)
		}
		if result.Task.Node != "" && !labelsNameNode(labels, result.Task.Node) {
			continue
		}
		observation := domain.Observation{SourceID: result.Task.SourceID, EntityKey: entityKey, Labels: labels}
		for _, target := range domain.CollectionObservationTargets(result.Task.Query, observation) {
			if _, exists := seen[target]; exists {
				continue
			}
			seen[target] = struct{}{}
			targets = append(targets, target)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expected evidence inventory: %w", err)
	}
	return targets, nil
}

func recordTargetInventoryTx(ctx context.Context, tx pgx.Tx, result domain.CollectionResult) error {
	if result.Task.Query != domain.QueryGPUIdentity || result.Status != domain.ResultSucceeded || !result.Coverage.Complete {
		return nil
	}
	for _, observation := range result.Observations {
		var nodeID string
		for _, target := range domain.CollectionObservationTargets(result.Task.Query, observation) {
			if target.Kind == domain.EvidenceTargetNode {
				nodeID = string(target.ID)
				break
			}
		}
		for _, target := range domain.CollectionObservationTargets(result.Task.Query, observation) {
			if _, err := tx.Exec(ctx, `
				INSERT INTO collection_target_inventory (
					cluster_id,source_id,target_kind,target_id,node_id,last_observed_at
				) VALUES ($1,$2,$3,$4,$5,$6)
				ON CONFLICT (cluster_id,source_id,target_kind,target_id) DO UPDATE SET
					node_id=EXCLUDED.node_id,last_observed_at=EXCLUDED.last_observed_at
				WHERE collection_target_inventory.last_observed_at <= EXCLUDED.last_observed_at`,
				result.Task.ClusterID, result.Task.SourceID, target.Kind, target.ID, nodeID, observation.ObservedAt.UTC()); err != nil {
				return fmt.Errorf("record expected evidence inventory: %w", err)
			}
		}
	}
	return nil
}

func labelsNameNode(labels []domain.Label, node string) bool {
	for _, label := range labels {
		if (label.Name == "Hostname" || label.Name == "hostname" || label.Name == "instance") && label.Value == node {
			return true
		}
	}
	return false
}

func observationTargets(query domain.QueryKind, observations []domain.Observation) []domain.EvidenceTarget {
	seen := make(map[domain.EvidenceTarget]struct{}, len(observations)*2)
	targets := make([]domain.EvidenceTarget, 0, len(observations)*2)
	for _, observation := range observations {
		for _, target := range domain.CollectionObservationTargets(query, observation) {
			if _, exists := seen[target]; exists {
				continue
			}
			seen[target] = struct{}{}
			targets = append(targets, target)
		}
	}
	return targets
}

func expectedSeriesForTargets(query domain.QueryKind, targets []domain.EvidenceTarget) int {
	if query == domain.QuerySourceHealth {
		count := 0
		for _, target := range targets {
			if target.Kind == domain.EvidenceTargetSource {
				count++
			}
		}
		return count
	}
	gpus := 0
	for _, target := range targets {
		if target.Kind == domain.EvidenceTargetGPU {
			gpus++
		}
	}
	seriesPerGPU := 1
	if fields := domain.DCGMFields(query); len(fields) > 0 {
		seriesPerGPU = len(fields)
	}
	return gpus * seriesPerGPU
}

func rangeStart(queryRange *domain.CollectionRange) *time.Time {
	if queryRange == nil {
		return nil
	}
	value := queryRange.Start.UTC()
	return &value
}

func rangeEnd(queryRange *domain.CollectionRange) *time.Time {
	if queryRange == nil {
		return nil
	}
	value := queryRange.End.UTC()
	return &value
}

func rangeStep(queryRange *domain.CollectionRange) *float64 {
	if queryRange == nil {
		return nil
	}
	value := queryRange.Step.Seconds()
	return &value
}

func sourceResponded(result domain.CollectionResult) bool {
	if result.Status != domain.ResultFailed || len(result.Failures) == 0 {
		return true
	}
	switch result.Failures[0].Code {
	case domain.FailureSourceUnavailable, domain.FailureDeadlineExceeded, domain.FailureUnauthorized:
		return false
	default:
		return true
	}
}

type SourceState struct {
	Availability string
	Freshness    domain.Freshness
	LastSuccess  *time.Time
}

func (s *CollectionStore) SourceState(ctx context.Context, sourceID domain.SourceID, at time.Time, freshFor time.Duration) (SourceState, error) {
	var state SourceState
	var lastSuccess *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT availability, last_success_at FROM sources WHERE source_id=$1`, sourceID).Scan(&state.Availability, &lastSuccess); err != nil {
		return SourceState{}, fmt.Errorf("read source %s state: %w", sourceID, err)
	}
	if lastSuccess != nil {
		utc := lastSuccess.UTC()
		state.LastSuccess = &utc
	}
	state.Freshness = domain.FreshnessAt(state.LastSuccess, at.UTC(), freshFor)
	return state, nil
}

func sampleFingerprint(observation domain.Observation) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(observation.EntityKey))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(observation.Metric))
	_, _ = hash.Write([]byte{0})
	for _, label := range observation.Labels {
		_, _ = hash.Write([]byte(label.Name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(label.Value))
		_, _ = hash.Write([]byte{0})
	}
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(observation.ObservedAt.UTC().UnixNano()))
	_, _ = hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], math.Float64bits(observation.Value))
	_, _ = hash.Write(number[:])
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type ProjectionState struct {
	ObservationID domain.ObservationID
	Freshness     domain.Freshness
	Availability  string
	LastSuccessAt time.Time
}

func (s *CollectionStore) Projection(ctx context.Context, clusterID domain.ClusterID, sourceID domain.SourceID, entityKey, metric string, at time.Time, freshFor time.Duration) (ProjectionState, error) {
	var state ProjectionState
	var lastSuccess time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT p.observation_id, p.last_success_at, s.availability
		FROM current_projections p JOIN sources s USING (source_id)
		WHERE p.cluster_id=$1 AND p.source_id=$2 AND p.entity_key=$3 AND p.metric=$4`,
		clusterID, sourceID, entityKey, metric).Scan(&state.ObservationID, &lastSuccess, &state.Availability)
	if err != nil {
		return ProjectionState{}, fmt.Errorf("read current projection: %w", err)
	}
	state.LastSuccessAt = lastSuccess.UTC()
	state.Freshness = domain.FreshnessAt(&state.LastSuccessAt, at.UTC(), freshFor)
	return state, nil
}
