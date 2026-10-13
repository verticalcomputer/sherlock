package adminview

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// PostgresStore reads operational aggregates from Sherlock's existing schema.
// It performs a fixed number of queries regardless of the requested page size.
type PostgresStore struct {
	pool *pgxpool.Pool
	// gpuSnapshot is set only on a private copy for an atomic, bounded GPU
	// field/condition read; the shared store and unrelated reads use the pool.
	gpuSnapshot pgx.Tx
}

func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("admin view PostgreSQL pool is required")
	}
	return &PostgresStore{pool: pool}, nil
}

// SharedHealth reads only the facts needed by the versioned health view. The
// administrator's full summary retains investigations, audit and historical
// evidence detail, but a tenant health read must not rank every retained
// evidence envelope just to report a bounded current-health window.
func (store *PostgresStore) SharedHealth(ctx context.Context, query Query) (application.ClusterHealthView, bool, error) {
	service, err := NewService(store)
	if err != nil {
		return application.ClusterHealthView{}, false, err
	}
	query, err = service.normalize(query)
	if err != nil || query.ClusterID == "" {
		return application.ClusterHealthView{}, false, fmt.Errorf("shared health requires a valid exact cluster ID")
	}
	var cluster ClusterSummary
	err = store.pool.QueryRow(ctx, `SELECT cluster_id, expected_collectors FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL`, query.ClusterID).
		Scan(&cluster.ClusterID, &cluster.ExpectedCollectorNames)
	if err == pgx.ErrNoRows {
		return application.ClusterHealthView{}, false, nil
	}
	if err != nil {
		return application.ClusterHealthView{}, false, fmt.Errorf("read shared health cluster: %w", err)
	}
	ids := []string{cluster.ClusterID}
	byID := map[string]*ClusterSummary{cluster.ClusterID: &cluster}
	if err := store.loadConnectivity(ctx, ids, byID, query.At.Add(-query.FreshFor)); err != nil {
		return application.ClusterHealthView{}, false, err
	}
	if err := store.loadInventoryCapacity(ctx, ids, byID, query.At); err != nil {
		return application.ClusterHealthView{}, false, err
	}
	if err := store.loadScheduleFreshness(ctx, ids, byID, query.At); err != nil {
		return application.ClusterHealthView{}, false, err
	}
	if err := store.loadSharedHealthEvidence(ctx, &cluster, query.At.Add(-query.Window), query.At); err != nil {
		return application.ClusterHealthView{}, false, err
	}
	view, err := projectSharedHealth(cluster, query)
	if err != nil {
		return application.ClusterHealthView{}, false, fmt.Errorf("project shared health: %w", err)
	}
	return view, true, nil
}

func (store *PostgresStore) loadSharedHealthEvidence(ctx context.Context, cluster *ClusterSummary, start, end time.Time) error {
	rows, err := store.pool.Query(ctx, `
		WITH stream_base AS (
			SELECT e.source_id,e.operation,e.status,e.collected_at,e.created_at,e.evidence_id,
				CASE WHEN e.run_id IS NOT NULL
					THEN 'collection:' || coalesce(nullif(w.node_filter,''),'cluster')
					ELSE 'targets:' || e.coverage_expected::text END AS scope_key
			FROM evidence_envelopes e
			LEFT JOIN collector_work_items w ON w.run_id=e.run_id
			WHERE e.cluster_id=$1 AND e.collected_at >= $2 AND e.collected_at <= $3
		), ranked AS (
			SELECT status,collected_at,
				row_number() OVER (PARTITION BY source_id,operation,scope_key
					ORDER BY collected_at DESC,created_at DESC,evidence_id DESC) AS stream_rank
			FROM stream_base
		)
		SELECT status,collected_at FROM ranked WHERE stream_rank=1`, cluster.ClusterID, start, end)
	if err != nil {
		return fmt.Errorf("load bounded shared health evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var stream EvidenceStreamHealth
		if err := rows.Scan(&stream.Status, &stream.LatestAttempt); err != nil {
			return fmt.Errorf("scan bounded shared health evidence: %w", err)
		}
		stream.LatestAttempt = stream.LatestAttempt.UTC()
		cluster.Evidence.CurrentStreams = append(cluster.Evidence.CurrentStreams, stream)
	}
	return rows.Err()
}

func (store *PostgresStore) Load(ctx context.Context, query Query) ([]ClusterSummary, bool, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT cluster_id, display_name, expected_collectors
		FROM clusters
		WHERE removed_at IS NULL AND ($3='' OR cluster_id=$3)
		ORDER BY cluster_id
		LIMIT $1 OFFSET $2`, query.Limit+1, query.Offset, query.ClusterID)
	if err != nil {
		return nil, false, fmt.Errorf("list dashboard clusters: %w", err)
	}
	defer rows.Close()

	clusters := make([]ClusterSummary, 0, query.Limit+1)
	for rows.Next() {
		var cluster ClusterSummary
		if err := rows.Scan(&cluster.ClusterID, &cluster.DisplayName, &cluster.ExpectedCollectorNames); err != nil {
			return nil, false, fmt.Errorf("scan dashboard cluster: %w", err)
		}
		clusters = append(clusters, cluster)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate dashboard clusters: %w", err)
	}
	hasMore := len(clusters) > query.Limit
	if hasMore {
		clusters = clusters[:query.Limit]
	}
	if len(clusters) == 0 {
		return clusters, hasMore, nil
	}

	ids := make([]string, len(clusters))
	byID := make(map[string]*ClusterSummary, len(clusters))
	for index := range clusters {
		ids[index] = clusters[index].ClusterID
		byID[clusters[index].ClusterID] = &clusters[index]
	}
	freshSince := query.At.Add(-query.FreshFor)
	windowStart := query.At.Add(-query.Window)
	if err := store.loadConnectivity(ctx, ids, byID, freshSince); err != nil {
		return nil, false, err
	}
	if err := store.loadResources(ctx, ids, byID, query.At, query.FreshFor); err != nil {
		return nil, false, err
	}
	if err := store.loadInventoryCapacity(ctx, ids, byID, query.At); err != nil {
		return nil, false, err
	}
	if err := store.loadScheduleFreshness(ctx, ids, byID, query.At); err != nil {
		return nil, false, err
	}
	if err := store.loadNetworkMonitoring(ctx, ids, byID, query.At); err != nil {
		return nil, false, err
	}
	if err := store.loadSlurmOperations(ctx, ids, byID, query.At); err != nil {
		return nil, false, err
	}
	if err := store.loadQueue(ctx, ids, byID, query.At); err != nil {
		return nil, false, err
	}
	if err := store.loadInvestigations(ctx, ids, byID, windowStart); err != nil {
		return nil, false, err
	}
	if err := store.loadModelUsage(ctx, ids, byID, windowStart); err != nil {
		return nil, false, err
	}
	if err := store.loadEvidence(ctx, ids, byID, windowStart, query.At); err != nil {
		return nil, false, err
	}
	if err := store.loadAudit(ctx, ids, byID, windowStart); err != nil {
		return nil, false, err
	}
	return clusters, hasMore, nil
}

// A schedule is fresh only when its newest due occurrence completed within a
// policy-derived allowance. PARTIAL/NO_DATA are timely but remain separate
// coverage conclusions; a recent failed run never becomes healthy through an
// older success.
func (store *PostgresStore) loadScheduleFreshness(ctx context.Context, ids []string, byID map[string]*ClusterSummary, at time.Time) error {
	rows, err := store.pool.Query(ctx, `
		SELECT d.cluster_id,
			count(*) AS expected,
			count(*) FILTER (WHERE latest.status IN ('SUCCEEDED','PARTIAL','NO_DATA')
				AND latest.scheduled_for >= $2 - make_interval(secs => GREATEST(60,2*d.interval_seconds + (d.timeout_ms+d.jitter_ms)/1000))) AS fresh,
			count(*) FILTER (WHERE latest.run_id IS NULL OR latest.scheduled_for < $2 - make_interval(secs => GREATEST(60,2*d.interval_seconds + (d.timeout_ms+d.jitter_ms)/1000))) AS late,
			count(*) FILTER (WHERE latest.status='FAILED') AS failed
		FROM desired_schedules d
		LEFT JOIN LATERAL (
			SELECT r.run_id,r.status,r.scheduled_for FROM collection_runs r
			WHERE r.cluster_id=d.cluster_id AND r.source_id=d.source_id
			AND r.query_kind=CASE WHEN d.mode='legacy' THEN d.legacy_query_kind ELSE d.operation END
			AND r.completed_at<=$2
			ORDER BY r.completed_at DESC,r.run_id DESC LIMIT 1
		) latest ON true
		WHERE d.cluster_id=ANY($1::text[]) AND d.enabled
		GROUP BY d.cluster_id`, ids, at)
	if err != nil {
		return fmt.Errorf("load schedule freshness: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var summary ScheduleSummary
		if err := rows.Scan(&id, &summary.Expected, &summary.Fresh, &summary.Late, &summary.Failed); err != nil {
			return fmt.Errorf("scan schedule freshness: %w", err)
		}
		byID[id].Schedule = summary
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate schedule freshness: %w", err)
	}
	return nil
}

// loadSlurmOperations shows the status of enabled typed Slurm schedules beside
// the envelope summary. It uses the same latest-run and freshness rules as the
// aggregate schedule projection, but does not reinterpret PARTIAL as complete.
func (store *PostgresStore) loadSlurmOperations(ctx context.Context, ids []string, byID map[string]*ClusterSummary, at time.Time) error {
	rows, err := store.pool.Query(ctx, `
		SELECT d.cluster_id,d.source_id,d.operation,
			coalesce(latest.status,'NOT_RUN'),latest.completed_at,
			coalesce(latest.status IN ('SUCCEEDED','PARTIAL','NO_DATA')
				AND latest.scheduled_for >= $2 - make_interval(secs => GREATEST(60,2*d.interval_seconds + (d.timeout_ms+d.jitter_ms)/1000)),false)
		FROM desired_schedules d
		LEFT JOIN LATERAL (
			SELECT r.status,r.scheduled_for,r.completed_at FROM collection_runs r
			WHERE r.cluster_id=d.cluster_id AND r.source_id=d.source_id AND r.query_kind=d.operation
			AND r.completed_at<=$2
			ORDER BY r.completed_at DESC,r.run_id DESC LIMIT 1
		) latest ON true
		WHERE d.cluster_id=ANY($1::text[]) AND d.enabled AND d.mode='durable'
			AND d.operation IN ('slurm.inventory.v1','slurm.snapshot.v1')
		ORDER BY d.cluster_id,d.source_id,d.operation`, ids, at)
	if err != nil {
		return fmt.Errorf("load Slurm operation status: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var status SlurmOperationStatus
		if err := rows.Scan(&id, &status.SourceID, &status.Operation, &status.Status,
			&status.LastCompletedAt, &status.Fresh); err != nil {
			return fmt.Errorf("scan Slurm operation status: %w", err)
		}
		normalizeTime(&status.LastCompletedAt)
		byID[id].SlurmOperations = append(byID[id].SlurmOperations, status)
	}
	return rows.Err()
}

// loadInventoryCapacity keeps expected and observed revision counts separate.
// Multiple simultaneously valid sources for one class are ambiguous and leave
// that class unknown rather than summing or arbitrarily choosing a source.
func (store *PostgresStore) loadInventoryCapacity(ctx context.Context, ids []string, byID map[string]*ClusterSummary, at time.Time) error {
	rows, err := store.pool.Query(ctx, `
		SELECT r.cluster_id,r.inventory_class,r.revision_id,
			count(DISTINCT e.stable_node_id) FILTER (WHERE e.entity_kind IN ('NODE','GPU')),
			count(DISTINCT e.physical_gpu_uuid) FILTER (WHERE e.entity_kind='GPU')
		FROM goodput_inventory_revisions r
		JOIN goodput_inventory_revision_validity v ON v.cluster_id=r.cluster_id AND v.revision_id=r.revision_id
		LEFT JOIN goodput_inventory_revision_entities e ON e.cluster_id=r.cluster_id AND e.revision_id=r.revision_id
		WHERE r.cluster_id=ANY($1::text[]) AND v.valid_from<=$2 AND (v.valid_to IS NULL OR v.valid_to>$2)
		GROUP BY r.cluster_id,r.inventory_class,r.revision_id
		ORDER BY r.cluster_id,r.inventory_class,r.revision_id`, ids, at)
	if err != nil {
		return fmt.Errorf("load cluster inventory capacity: %w", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var clusterID, class, revisionID string
		var nodes, gpus int64
		if err := rows.Scan(&clusterID, &class, &revisionID, &nodes, &gpus); err != nil {
			return fmt.Errorf("scan cluster inventory capacity: %w", err)
		}
		key := clusterID + "\x00" + class
		if seen[key] {
			resource := &byID[clusterID].Resources
			if class == "EXPECTED" {
				resource.ExpectedInventoryNodes, resource.ExpectedInventoryGPUs, resource.ExpectedRevisionID = nil, nil, ""
			}
			if class == "OBSERVED" {
				resource.ObservedInventoryNodes, resource.ObservedInventoryGPUs, resource.ObservedRevisionID = nil, nil, ""
			}
			continue
		}
		seen[key] = true
		resource := &byID[clusterID].Resources
		// A node-only revision proves its nodes, not that the cluster has no
		// GPUs. Zero GPU identities leave the GPU count unknown for either class.
		if class == "EXPECTED" {
			resource.ExpectedInventoryNodes, resource.ExpectedRevisionID = &nodes, revisionID
			if gpus > 0 {
				resource.ExpectedInventoryGPUs = &gpus
			}
		}
		if class == "OBSERVED" {
			resource.ObservedInventoryNodes, resource.ObservedRevisionID = &nodes, revisionID
			if gpus > 0 {
				resource.ObservedInventoryGPUs = &gpus
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate cluster inventory capacity: %w", err)
	}
	return nil
}

func (store *PostgresStore) loadConnectivity(ctx context.Context, ids []string, byID map[string]*ClusterSummary, freshSince time.Time) error {
	rows, err := store.pool.Query(ctx, `
		WITH selected AS (SELECT unnest($1::text[]) AS cluster_id),
		collector_counts AS (
			SELECT cluster_id,
				count(*) AS registered,
				count(*) FILTER (WHERE status='ACTIVE') AS active,
				coalesce(array_agg(display_name || ' (' || collector_id || ') · ' || status ORDER BY collector_id) FILTER (
					WHERE status<>'ACTIVE'
				), ARRAY[]::text[]) AS excluded_labels,
				max(last_heartbeat_at) FILTER (WHERE status='ACTIVE') AS last_contact
			FROM collectors WHERE cluster_id=ANY($1::text[]) GROUP BY cluster_id
		), expected_status AS (
			SELECT c.cluster_id, expected.name,
				active.collector_id AS active_id, active.last_heartbeat_at AS active_heartbeat,
				latest.collector_id AS latest_id, latest.status AS latest_status
			FROM clusters c
			CROSS JOIN LATERAL unnest(c.expected_collectors) AS expected(name)
			LEFT JOIN LATERAL (
				SELECT collector_id, last_heartbeat_at
				FROM collectors registered
				WHERE registered.cluster_id=c.cluster_id
				  AND lower(registered.display_name)=lower(expected.name)
				  AND registered.status='ACTIVE'
				ORDER BY registered.last_heartbeat_at DESC NULLS LAST, registered.created_at DESC
				LIMIT 1
			) active ON true
			LEFT JOIN LATERAL (
				SELECT collector_id, status
				FROM collectors registered
				WHERE registered.cluster_id=c.cluster_id
				  AND lower(registered.display_name)=lower(expected.name)
				ORDER BY registered.created_at DESC
				LIMIT 1
			) latest ON true
			WHERE c.cluster_id=ANY($1::text[])
		), expected_counts AS (
			SELECT cluster_id,
				count(*) AS expected,
				count(*) FILTER (WHERE active_id IS NOT NULL) AS active,
				count(*) FILTER (WHERE active_heartbeat >= $2) AS fresh,
				count(*) FILTER (WHERE active_heartbeat IS NULL OR active_heartbeat < $2) AS missing,
				coalesce(array_agg(name ORDER BY name) FILTER (
					WHERE active_heartbeat IS NULL OR active_heartbeat < $2
				), ARRAY[]::text[]) AS missing_ids,
				coalesce(array_agg(name || CASE
					WHEN active_id IS NOT NULL AND active_heartbeat IS NULL THEN ' (' || active_id || ') · NO HEARTBEAT'
					WHEN active_id IS NOT NULL THEN ' (' || active_id || ') · HEARTBEAT STALE'
					WHEN latest_id IS NOT NULL THEN ' (' || latest_id || ') · ' || latest_status
					ELSE ' · NEVER REGISTERED'
				END ORDER BY name) FILTER (
					WHERE active_heartbeat IS NULL OR active_heartbeat < $2
				), ARRAY[]::text[]) AS missing_labels
			FROM expected_status
			GROUP BY cluster_id
		), source_counts AS (
			SELECT cluster_id,
				count(*) FILTER (WHERE kind='prometheus') AS sources,
				count(*) FILTER (WHERE kind='prometheus' AND availability='AVAILABLE') AS available,
				count(*) FILTER (WHERE kind='prometheus' AND availability='UNAVAILABLE') AS unavailable,
				count(*) FILTER (WHERE kind='prometheus' AND availability='UNKNOWN') AS unknown,
				count(*) FILTER (WHERE kind='prometheus' AND last_success_at >= $2) AS fresh,
				count(*) FILTER (WHERE kind='prometheus' AND last_success_at IS NOT NULL AND last_success_at < $2) AS stale,
				count(*) FILTER (WHERE kind='prometheus' AND last_success_at IS NULL) AS without_data,
				coalesce(array_agg(display_name || ' (' || source_id || ', ' || kind || ') · ' ||
					CASE WHEN last_success_at IS NULL THEN 'NO DATA' ELSE 'STALE' END || ' · ' || availability ||
					CASE WHEN coalesce(last_failure_code,'')='' THEN '' ELSE ' · ' || last_failure_code END
					ORDER BY source_id) FILTER (WHERE kind='prometheus' AND (last_success_at IS NULL OR last_success_at < $2)), ARRAY[]::text[]) AS gap_labels,
				coalesce(array_agg(display_name || ' (' || source_id || ', ' || kind || ') · ON DEMAND · freshness not tracked'
					ORDER BY source_id) FILTER (WHERE kind<>'prometheus'), ARRAY[]::text[]) AS on_demand_labels,
				max(last_success_at) FILTER (WHERE kind='prometheus') AS last_success
			FROM sources WHERE cluster_id=ANY($1::text[]) GROUP BY cluster_id
		)
		SELECT s.cluster_id,
			coalesce(c.registered,0), coalesce(e.expected,0), coalesce(e.active,0), coalesce(e.fresh,0), coalesce(e.missing,0),
			coalesce(e.missing_ids, ARRAY[]::text[]), coalesce(e.missing_labels, ARRAY[]::text[]),
			coalesce(c.excluded_labels, ARRAY[]::text[]), c.last_contact,
			coalesce(src.sources,0), coalesce(src.available,0), coalesce(src.unavailable,0), coalesce(src.unknown,0),
			coalesce(src.gap_labels, ARRAY[]::text[]), coalesce(src.on_demand_labels, ARRAY[]::text[]),
			coalesce(src.fresh,0), coalesce(src.stale,0), coalesce(src.without_data,0), src.last_success
		FROM selected s
		LEFT JOIN collector_counts c USING (cluster_id)
		LEFT JOIN expected_counts e USING (cluster_id)
		LEFT JOIN source_counts src USING (cluster_id)`, ids, freshSince)
	if err != nil {
		return fmt.Errorf("load dashboard connectivity: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		cluster := ClusterSummary{}
		if err := rows.Scan(&id,
			&cluster.Connectivity.RegisteredCollectors, &cluster.Connectivity.Collectors, &cluster.Connectivity.ActiveCollectors,
			&cluster.Connectivity.FreshCollectors, &cluster.Connectivity.StaleCollectors,
			&cluster.Connectivity.MissingCollectorNames, &cluster.Connectivity.MissingCollectorLabels,
			&cluster.Connectivity.ExcludedCollectorLabels, &cluster.Connectivity.LastCollectorContact, &cluster.Connectivity.Sources,
			&cluster.Connectivity.AvailableSources, &cluster.Connectivity.UnavailableSources,
			&cluster.Connectivity.UnknownSources, &cluster.Connectivity.SourceGapLabels,
			&cluster.Connectivity.OnDemandSourceLabels, &cluster.Freshness.FreshSources,
			&cluster.Freshness.StaleSources, &cluster.Freshness.SourcesWithoutData,
			&cluster.Freshness.LastSuccessAt); err != nil {
			return fmt.Errorf("scan dashboard connectivity: %w", err)
		}
		byID[id].Connectivity = cluster.Connectivity
		byID[id].Freshness = cluster.Freshness
		normalizeTime(&byID[id].Connectivity.LastCollectorContact)
		normalizeTime(&byID[id].Freshness.LastSuccessAt)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate dashboard connectivity: %w", err)
	}
	return nil
}

func (store *PostgresStore) loadQueue(ctx context.Context, ids []string, byID map[string]*ClusterSummary, at time.Time) error {
	rows, err := store.pool.Query(ctx, `
		WITH selected AS (SELECT unnest($1::text[]) AS cluster_id),
		collection_counts AS (
			SELECT cluster_id,
				count(*) FILTER (WHERE status='AVAILABLE') AS available,
				count(*) FILTER (WHERE status='LEASED') AS leased,
				count(*) FILTER (WHERE status IN ('AVAILABLE','LEASED') AND deadline < $2) AS overdue
			FROM collector_work_items WHERE cluster_id=ANY($1::text[]) GROUP BY cluster_id
		), diagnostic_counts AS (
			SELECT r.cluster_id,
				count(*) FILTER (WHERE w.status='AVAILABLE') AS available,
				count(*) FILTER (WHERE w.status='LEASED') AS leased,
				count(*) FILTER (WHERE w.status='BLOCKED') AS blocked,
				count(*) FILTER (WHERE w.status IN ('AVAILABLE','LEASED') AND w.deadline < $2) AS overdue
			FROM diagnostic_work_items w JOIN diagnostic_runs r USING (run_id)
			WHERE r.cluster_id=ANY($1::text[]) GROUP BY r.cluster_id
		), investigation_counts AS (
			SELECT cluster_id,
				count(*) FILTER (WHERE status='AVAILABLE') AS available,
				count(*) FILTER (WHERE status='LEASED') AS leased,
				count(*) FILTER (WHERE status='LEASED' AND lease_expires_at < $2) AS overdue
			FROM investigation_steps WHERE cluster_id=ANY($1::text[]) GROUP BY cluster_id
		)
		SELECT s.cluster_id,
			coalesce(c.available,0), coalesce(c.leased,0),
			coalesce(d.available,0), coalesce(d.leased,0), coalesce(d.blocked,0),
			coalesce(i.available,0), coalesce(i.leased,0),
			coalesce(c.overdue,0)+coalesce(d.overdue,0)+coalesce(i.overdue,0)
		FROM selected s
		LEFT JOIN collection_counts c USING (cluster_id)
		LEFT JOIN diagnostic_counts d USING (cluster_id)
		LEFT JOIN investigation_counts i USING (cluster_id)`, ids, at)
	if err != nil {
		return fmt.Errorf("load dashboard queues: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var summary QueueSummary
		if err := rows.Scan(&id, &summary.CollectionAvailable, &summary.CollectionLeased,
			&summary.DiagnosticAvailable, &summary.DiagnosticLeased, &summary.DiagnosticBlocked,
			&summary.InvestigationAvailable, &summary.InvestigationLeased, &summary.Overdue); err != nil {
			return fmt.Errorf("scan dashboard queues: %w", err)
		}
		byID[id].Queue = summary
	}
	return rows.Err()
}

func (store *PostgresStore) loadInvestigations(ctx context.Context, ids []string, byID map[string]*ClusterSummary, windowStart time.Time) error {
	rows, err := store.pool.Query(ctx, `
		WITH selected AS (SELECT unnest($1::text[]) AS cluster_id), counts AS (
			SELECT cluster_id,
				count(*) FILTER (WHERE status NOT IN ('COMPLETED','PARTIAL','BLOCKED','CANCELLED')) AS active,
				count(*) FILTER (WHERE status='AWAITING_EVIDENCE') AS awaiting_evidence,
				count(*) FILTER (WHERE status='COMPLETED' AND updated_at >= $2) AS completed,
				count(*) FILTER (WHERE status='PARTIAL' AND updated_at >= $2) AS partial,
				count(*) FILTER (WHERE status='BLOCKED' AND updated_at >= $2) AS blocked,
				count(*) FILTER (WHERE status='CANCELLED' AND updated_at >= $2) AS cancelled,
				max(updated_at) AS last_update
			FROM investigations WHERE cluster_id=ANY($1::text[]) GROUP BY cluster_id
		)
		SELECT s.cluster_id, coalesce(c.active,0), coalesce(c.awaiting_evidence,0), coalesce(c.completed,0), coalesce(c.partial,0),
			coalesce(c.blocked,0), coalesce(c.cancelled,0), c.last_update
		FROM selected s LEFT JOIN counts c USING (cluster_id)`, ids, windowStart)
	if err != nil {
		return fmt.Errorf("load dashboard investigations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var summary InvestigationSummary
		if err := rows.Scan(&id, &summary.Active, &summary.AwaitingEvidence, &summary.Completed, &summary.Partial, &summary.Blocked, &summary.Cancelled, &summary.LastUpdate); err != nil {
			return fmt.Errorf("scan dashboard investigations: %w", err)
		}
		normalizeTime(&summary.LastUpdate)
		byID[id].Investigations = summary
	}
	return rows.Err()
}

func (store *PostgresStore) loadModelUsage(ctx context.Context, ids []string, byID map[string]*ClusterSummary, windowStart time.Time) error {
	rows, err := store.pool.Query(ctx, `
		WITH selected AS (SELECT unnest($1::text[]) AS cluster_id), usage AS (
			SELECT cluster_id, count(*) AS calls,
				count(*) FILTER (WHERE outcome='SUCCEEDED') AS succeeded,
				count(*) FILTER (WHERE outcome='REJECTED') AS rejected,
				count(*) FILTER (WHERE outcome='FAILED') AS failed,
				coalesce(sum(input_tokens),0) AS input_tokens,
				coalesce(sum(output_tokens),0) AS output_tokens,
				coalesce(sum(cost_microunits),0) AS cost,
				coalesce(avg(latency_milliseconds)::bigint,0) AS average_latency,
				max(occurred_at) AS last_call
			FROM investigation_model_calls
			WHERE cluster_id=ANY($1::text[]) AND occurred_at >= $2
			GROUP BY cluster_id
		)
		SELECT s.cluster_id, coalesce(u.calls,0), coalesce(u.succeeded,0), coalesce(u.rejected,0),
			coalesce(u.failed,0), coalesce(u.input_tokens,0), coalesce(u.output_tokens,0),
			coalesce(u.cost,0), coalesce(u.average_latency,0), u.last_call
		FROM selected s LEFT JOIN usage u USING (cluster_id)`, ids, windowStart)
	if err != nil {
		return fmt.Errorf("load dashboard model usage: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var summary ModelUsageSummary
		if err := rows.Scan(&id, &summary.Calls, &summary.Succeeded, &summary.Rejected, &summary.Failed,
			&summary.InputTokens, &summary.OutputTokens, &summary.CostMicrounits,
			&summary.AverageLatencyMS, &summary.LastCallAt); err != nil {
			return fmt.Errorf("scan dashboard model usage: %w", err)
		}
		normalizeTime(&summary.LastCallAt)
		byID[id].ModelUsage = summary
	}
	return rows.Err()
}

func (store *PostgresStore) loadEvidence(ctx context.Context, ids []string, byID map[string]*ClusterSummary, windowStart, windowEnd time.Time) error {
	rows, err := store.pool.Query(ctx, `
		WITH selected AS (SELECT unnest($1::text[]) AS cluster_id), historical AS (
			SELECT cluster_id, count(*) AS total,
				count(*) FILTER (WHERE status='COMPLETE') AS complete,
				count(*) FILTER (WHERE status='PARTIAL') AS partial,
				count(*) FILTER (WHERE status='NO_DATA') AS no_data,
				count(*) FILTER (WHERE status='UNAVAILABLE') AS unavailable,
				coalesce(sum(CASE WHEN jsonb_typeof(coverage_expected)='array'
					THEN jsonb_array_length(coverage_expected) ELSE 0 END),0) AS expected_targets,
				coalesce(sum(CASE WHEN jsonb_typeof(coverage_covered)='array'
					THEN jsonb_array_length(coverage_covered) ELSE 0 END),0) AS covered_targets,
				count(*) FILTER (WHERE artifact_availability='PENDING') AS artifacts_pending,
				count(*) FILTER (WHERE artifact_availability='UNAVAILABLE') AS artifacts_unavailable,
				count(*) FILTER (WHERE artifact_availability='CORRUPT') AS artifacts_corrupt,
				max(collected_at) AS last_collected
			FROM evidence_envelopes
			WHERE cluster_id=ANY($1::text[]) AND collected_at >= $2 AND collected_at <= $3
			GROUP BY cluster_id
		), stream_base AS (
			SELECT e.*,
				CASE WHEN e.run_id IS NOT NULL
					THEN 'collection:' || coalesce(nullif(w.node_filter,''),'cluster')
					ELSE 'targets:' || e.coverage_expected::text END AS scope_key
			FROM evidence_envelopes e
			LEFT JOIN collector_work_items w ON w.run_id=e.run_id
			WHERE e.cluster_id=ANY($1::text[]) AND e.collected_at <= $3
		), ranked AS (
			SELECT stream_base.*,
				row_number() OVER (
					PARTITION BY cluster_id, source_id, operation, scope_key
					ORDER BY collected_at DESC, created_at DESC, evidence_id DESC
				) AS stream_rank
			FROM stream_base
		), current_health AS (
			SELECT cluster_id, count(*) AS total,
				count(*) FILTER (WHERE status='COMPLETE') AS complete,
				count(*) FILTER (WHERE status='PARTIAL') AS partial,
				count(*) FILTER (WHERE status='NO_DATA') AS no_data,
				count(*) FILTER (WHERE status='UNAVAILABLE') AS unavailable,
				coalesce(sum(CASE WHEN jsonb_typeof(coverage_expected)='array'
					THEN jsonb_array_length(coverage_expected) ELSE 0 END),0) AS expected_targets,
				coalesce(sum(CASE WHEN jsonb_typeof(coverage_covered)='array'
					THEN jsonb_array_length(coverage_covered) ELSE 0 END),0) AS covered_targets,
				count(*) FILTER (WHERE artifact_availability='PENDING') AS artifacts_pending,
				count(*) FILTER (WHERE artifact_availability='UNAVAILABLE') AS artifacts_unavailable,
				count(*) FILTER (WHERE artifact_availability='CORRUPT') AS artifacts_corrupt
			FROM ranked WHERE stream_rank=1 GROUP BY cluster_id
		), historical_superseded AS (
			SELECT cluster_id, count(*) AS count
			FROM ranked
			WHERE stream_rank>1 AND collected_at >= $2
			  AND status IN ('PARTIAL','NO_DATA','UNAVAILABLE')
			GROUP BY cluster_id
		)
		SELECT s.cluster_id,
			coalesce(cur.total,0), coalesce(cur.complete,0), coalesce(cur.partial,0),
			coalesce(cur.no_data,0), coalesce(cur.unavailable,0),
			coalesce(cur.expected_targets,0), coalesce(cur.covered_targets,0),
			coalesce(cur.artifacts_pending,0), coalesce(cur.artifacts_unavailable,0), coalesce(cur.artifacts_corrupt,0),
			coalesce(hs.count,0),
			coalesce(h.total,0), coalesce(h.complete,0), coalesce(h.partial,0),
			coalesce(h.no_data,0), coalesce(h.unavailable,0), coalesce(h.expected_targets,0),
			coalesce(h.covered_targets,0), coalesce(h.artifacts_pending,0),
			coalesce(h.artifacts_unavailable,0), coalesce(h.artifacts_corrupt,0), h.last_collected
		FROM selected s
		LEFT JOIN current_health cur USING (cluster_id)
		LEFT JOIN historical h USING (cluster_id)
		LEFT JOIN historical_superseded hs USING (cluster_id)`, ids, windowStart, windowEnd)
	if err != nil {
		return fmt.Errorf("load dashboard evidence coverage: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var summary EvidenceCoverageSummary
		if err := rows.Scan(&id, &summary.CurrentTotal, &summary.CurrentComplete, &summary.CurrentPartial,
			&summary.CurrentNoData, &summary.CurrentUnavailable, &summary.CurrentExpectedTargets,
			&summary.CurrentCoveredTargets, &summary.CurrentArtifactsPending,
			&summary.CurrentArtifactsUnavailable, &summary.CurrentArtifactsCorrupt,
			&summary.HistoricalSuperseded,
			&summary.Total, &summary.Complete, &summary.Partial, &summary.NoData,
			&summary.Unavailable, &summary.ExpectedTargets, &summary.CoveredTargets,
			&summary.ArtifactsPending, &summary.ArtifactsUnavailable,
			&summary.ArtifactsCorrupt, &summary.LastCollectedAt); err != nil {
			return fmt.Errorf("scan dashboard evidence coverage: %w", err)
		}
		normalizeTime(&summary.LastCollectedAt)
		byID[id].Evidence = summary
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	detailRows, err := store.pool.Query(ctx, `
		WITH stream_base AS (
			SELECT e.*,
				CASE WHEN e.run_id IS NOT NULL
					THEN 'collection:' || coalesce(nullif(w.node_filter,''),'cluster')
					ELSE 'targets:' || e.coverage_expected::text END AS scope_key
			FROM evidence_envelopes e
			LEFT JOIN collector_work_items w ON w.run_id=e.run_id
			WHERE e.cluster_id=ANY($1::text[]) AND e.collected_at <= $2
		), ranked AS (
			SELECT stream_base.*,
				row_number() OVER (
					PARTITION BY cluster_id, source_id, operation, scope_key
					ORDER BY collected_at DESC, created_at DESC, evidence_id DESC
				) AS stream_rank
			FROM stream_base
		)
		SELECT r.cluster_id, r.source_id, r.operation, r.scope_key, r.status,
			coalesce(r.run_id,''), r.collected_at, r.coverage_expected, r.coverage_covered,
			cr.series_expected, cr.series_returned, coalesce(f.code,df.error_code,''), coalesce(f.safe_message,''),
			r.artifact_availability
		FROM ranked r
		LEFT JOIN collection_runs cr ON cr.run_id=r.run_id
		LEFT JOIN LATERAL (
			SELECT code, safe_message FROM collection_failures
			WHERE run_id=r.run_id ORDER BY failure_id LIMIT 1
		) f ON true
		LEFT JOIN LATERAL (
            SELECT t.error_code FROM diagnostic_target_results t
            JOIN diagnostic_work_items dw ON dw.work_id=t.work_id
            WHERE dw.run_id=r.diagnostic_run_id AND t.error_code<>''
            ORDER BY t.attempt DESC,t.target LIMIT 1
        ) df ON true
        WHERE r.stream_rank=1
		ORDER BY r.cluster_id, r.source_id, r.operation, r.scope_key`, ids, windowEnd)
	if err != nil {
		return fmt.Errorf("load current evidence streams: %w", err)
	}
	defer detailRows.Close()
	for detailRows.Next() {
		var id, expectedJSON, coveredJSON, artifactAvailability string
		var stream EvidenceStreamHealth
		if err := detailRows.Scan(&id, &stream.SourceID, &stream.Operation, &stream.Scope,
			&stream.Status, &stream.RunID, &stream.LatestAttempt, &expectedJSON, &coveredJSON,
			&stream.SeriesExpected, &stream.SeriesReturned, &stream.FailureCode,
			&stream.SafeFailureReason, &artifactAvailability); err != nil {
			return fmt.Errorf("scan current evidence stream: %w", err)
		}
		if stream.RunID == "" && stream.FailureCode != "" {
			stream.FailureCode = domain.SafeDiagnosticFailureCode(stream.FailureCode)
			stream.SafeFailureReason = domain.DiagnosticFailureReason(stream.FailureCode)
		}
		stream.LatestAttempt = stream.LatestAttempt.UTC()
		stream.ExpectedTargets, err = decodeEvidenceTargetLabels([]byte(expectedJSON))
		if err != nil {
			return fmt.Errorf("decode current expected evidence targets: %w", err)
		}
		stream.CoveredTargets, err = decodeEvidenceTargetLabels([]byte(coveredJSON))
		if err != nil {
			return fmt.Errorf("decode current covered evidence targets: %w", err)
		}
		stream.MissingTargets = missingEvidenceTargets(stream.ExpectedTargets, stream.CoveredTargets)
		if strings.HasPrefix(stream.Scope, "targets:") {
			stream.Scope = "targets: " + strings.Join(stream.ExpectedTargets, ", ")
		}
		classifyEvidenceStream(&stream, artifactAvailability)
		byID[id].Evidence.CurrentStreams = append(byID[id].Evidence.CurrentStreams, stream)
	}
	return detailRows.Err()
}

type evidenceTargetJSON struct {
	Kind string
	ID   string
}

func decodeEvidenceTargetLabels(encoded []byte) ([]string, error) {
	if string(encoded) == "null" {
		return []string{}, nil
	}
	var targets []evidenceTargetJSON
	if err := json.Unmarshal(encoded, &targets); err != nil {
		return nil, err
	}
	labels := make([]string, 0, len(targets))
	for _, target := range targets {
		// CLUSTER was historically fabricated as a coverage target even though it
		// has no independent observation. Keep the envelope, but do not present
		// that legacy bookkeeping target as an operator-repairable gap.
		if target.Kind == "CLUSTER" {
			continue
		}
		labels = append(labels, target.Kind+":"+target.ID)
	}
	slices.Sort(labels)
	return labels, nil
}

func missingEvidenceTargets(expected, covered []string) []string {
	coveredSet := make(map[string]struct{}, len(covered))
	for _, target := range covered {
		coveredSet[target] = struct{}{}
	}
	missing := make([]string, 0)
	for _, target := range expected {
		if _, ok := coveredSet[target]; !ok {
			missing = append(missing, target)
		}
	}
	return missing
}

func classifyEvidenceStream(stream *EvidenceStreamHealth, artifactAvailability string) {
	if artifactAvailability == "PENDING" {
		stream.Condition = "evidence artifact reconciliation is pending"
		stream.RecommendedAction = "Verify the artifact reconciliation worker is running; if the state does not advance, repair its application or storage configuration."
		return
	}
	if artifactAvailability == "UNAVAILABLE" || artifactAvailability == "CORRUPT" {
		stream.Condition = "evidence artifact is " + artifactAvailability
		stream.RecommendedAction = "Repair the artifact store or reconciliation configuration, then run the operation again. An application or configuration change is required."
		return
	}
	if stream.RunID == "" && (stream.Status == "UNAVAILABLE" || (stream.Status == "PARTIAL" && stream.FailureCode != "")) {
		stream.Condition = "diagnostic execution failed"
		if stream.FailureCode == "" {
			stream.Condition = "diagnostic evidence is unavailable and no safe failure reason was recorded"
			stream.SafeFailureReason = "No safe failure reason was recorded for this evidence envelope."
		}
		stream.RecommendedAction = "Review the diagnostic runner and tool configuration, then rerun the diagnostic. An application or configuration change is required; waiting alone cannot repair this stream."
		return
	}
	switch stream.Status {
	case "COMPLETE":
		stream.Condition = "complete target and series coverage is proven"
		stream.RecommendedAction = "No evidence repair action is required for this stream."
	case "UNAVAILABLE":
		stream.Condition = "collector or source connectivity failure"
		stream.RecommendedAction = "Restore collector heartbeat and source connectivity, then run this operation again."
	case "NO_DATA":
		stream.Condition = "the source was reachable but returned no data"
		stream.RecommendedAction = "Confirm that this scope should currently emit data; if it should, repair the source/exporter configuration and run the operation again."
	case "PARTIAL":
		switch {
		case len(stream.MissingTargets) > 0:
			stream.Condition = "incomplete target coverage"
			stream.RecommendedAction = "Restore exporter coverage for the listed targets, then run this operation again."
		case stream.SeriesExpected == nil:
			stream.Condition = "authoritative expected-inventory information is missing"
			stream.RecommendedAction = "Register or collect authoritative node/GPU target inventory before rerunning. An application or configuration change is required; waiting alone cannot make this complete."
		case stream.SeriesReturned != nil && *stream.SeriesReturned < *stream.SeriesExpected:
			stream.Condition = "incomplete expected-series coverage"
			stream.RecommendedAction = "Restore the missing DCGM series or exporter metric configuration, then run this operation again."
		default:
			stream.Condition = "the source returned a partial response"
			stream.RecommendedAction = "Inspect the safe failure reason, repair the source response, and run this operation again."
		}
	default:
		stream.Condition = "unknown evidence state"
		stream.RecommendedAction = "An application change is required before this state can be considered complete."
	}
}

func (store *PostgresStore) loadAudit(ctx context.Context, ids []string, byID map[string]*ClusterSummary, windowStart time.Time) error {
	rows, err := store.pool.Query(ctx, `
		WITH selected AS (SELECT unnest($1::text[]) AS cluster_id), audit AS (
			SELECT cluster_id, count(*) AS events,
				count(*) FILTER (WHERE outcome IN ('ALLOWED','APPROVED','CLAIMED','RECORDED')) AS allowed,
				count(*) FILTER (WHERE outcome IN ('DENIED','ERROR','FAILED','REJECTED')) AS denied_or_failed,
				max(occurred_at) AS last_event
			FROM diagnostic_audit_events
			WHERE cluster_id=ANY($1::text[]) AND occurred_at >= $2
			GROUP BY cluster_id
		)
		SELECT s.cluster_id, coalesce(a.events,0), coalesce(a.allowed,0),
			coalesce(a.denied_or_failed,0), a.last_event
		FROM selected s LEFT JOIN audit a USING (cluster_id)`, ids, windowStart)
	if err != nil {
		return fmt.Errorf("load dashboard audit summary: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var summary AuditSummary
		if err := rows.Scan(&id, &summary.Events, &summary.Allowed, &summary.DeniedOrFailed, &summary.LastEventAt); err != nil {
			return fmt.Errorf("scan dashboard audit summary: %w", err)
		}
		normalizeTime(&summary.LastEventAt)
		byID[id].Audit = summary
	}
	return rows.Err()
}

func normalizeTime(value **time.Time) {
	if *value == nil {
		return
	}
	utc := (*value).UTC()
	*value = &utc
}

func (store *PostgresStore) loadNetworkMonitoring(ctx context.Context, ids []string, byID map[string]*ClusterSummary, at time.Time) error {
	rows, err := store.pool.Query(ctx, `SELECT cluster_id,enabled,summary,last_received_at FROM gp09_network_monitors WHERE cluster_id=ANY($1::text[])`, ids)
	if err != nil {
		return fmt.Errorf("load network monitoring: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var enabled bool
		var doc []byte
		var received *time.Time
		if err := rows.Scan(&id, &enabled, &doc, &received); err != nil {
			return err
		}
		c := byID[id]
		if err := json.Unmarshal(doc, &c.Network); err != nil {
			return err
		}
		c.Network.Enrolled = enabled
		if c.Network.InfiniBandState == "" {
			c.Network.InfiniBandState = c.Network.State
		}
		// Projection independently expires the source if the evaluator itself stops.
		if enabled && (received == nil || at.Sub(*received) > 3*time.Minute) {
			c.Network.State = "UNKNOWN"
			c.Network.InfiniBandState = "UNKNOWN"
			c.Network.HealthyPorts = 0
			c.Network.DownPorts = 0
			c.Network.DegradedPorts = 0
			c.Network.UnknownPorts = c.Network.ExpectedPorts
			if c.Network.Management.Enrolled {
				c.Network.Management.State = "UNKNOWN"
				c.Network.Management.HealthyLinks = 0
				c.Network.Management.DownLinks = 0
				c.Network.Management.PendingLinks = 0
				c.Network.Management.UnknownLinks = c.Network.Management.ExpectedBonds + c.Network.Management.ExpectedMembers
				for i := range c.Network.Management.Details {
					c.Network.Management.Details[i].Condition = "UNKNOWN"
					c.Network.Management.Details[i].Reason = "SOURCE_STALE"
				}
			}
			for i := range c.Network.Details {
				c.Network.Details[i].Condition = "UNKNOWN"
				c.Network.Details[i].Reason = "SOURCE_STALE"
			}
		}
	}
	return rows.Err()
}
