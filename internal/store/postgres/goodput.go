package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type GoodputStore struct{ pool *pgxpool.Pool }

func NewGoodputStore(pool *pgxpool.Pool) (*GoodputStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &GoodputStore{pool: pool}, nil
}

func (store *GoodputStore) RecordExpectedInventoryRevision(ctx context.Context, revision domain.InventoryRevision) (bool, error) {
	return store.recordInventoryRevision(ctx, application.InventoryExpected, revision)
}

// RecordExpectedInventoryRevisionIfCurrentBefore makes the preview freshness
// precondition and canonical revision write one source-scoped operation. The
// fact-stream advisory lock is the same lock used by every inventory writer,
// so two approvals cannot both validate against the same previous current
// revision and then commit in the opposite order.
func (store *GoodputStore) RecordExpectedInventoryRevisionIfCurrentBefore(ctx context.Context, revision domain.InventoryRevision, previewGeneratedAt time.Time) (bool, bool, error) {
	validated, err := domain.CreateInventoryRevision(revision)
	if err != nil {
		return false, false, err
	}
	if previewGeneratedAt.IsZero() {
		return false, false, fmt.Errorf("preview generation time is required")
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, false, fmt.Errorf("begin expected inventory revision: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockGoodputFactStream(ctx, tx, "inventory", validated.ClusterID, validated.SourceID, string(application.InventoryExpected)); err != nil {
		return false, false, err
	}

	// A concurrent retry of this exact preview may have committed while the
	// caller was waiting for the stream lock. Let the canonical writer prove
	// immutable equality before applying the supersede gate.
	var identicalRevisionExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM goodput_inventory_revisions WHERE revision_id=$1)`, validated.ID).Scan(&identicalRevisionExists); err != nil {
		return false, false, fmt.Errorf("check expected inventory revision: %w", err)
	}
	if !identicalRevisionExists {
		var currentEffectiveAt time.Time
		err := tx.QueryRow(ctx, `SELECT effective_at FROM goodput_current_inventory
			WHERE cluster_id=$1 AND source_id=$2 AND inventory_class=$3`,
			validated.ClusterID, validated.SourceID, application.InventoryExpected).Scan(&currentEffectiveAt)
		if err != nil && err != pgx.ErrNoRows {
			return false, false, fmt.Errorf("load current expected inventory revision: %w", err)
		}
		if err == nil && !currentEffectiveAt.UTC().Before(previewGeneratedAt.UTC()) {
			return false, false, nil
		}
	}

	inserted, err := recordInventoryRevisionTx(ctx, tx, application.InventoryExpected, validated)
	if err != nil {
		return false, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, false, fmt.Errorf("commit expected inventory revision: %w", err)
	}
	return inserted, true, nil
}

func (store *GoodputStore) RecordObservedInventoryRevision(ctx context.Context, revision domain.InventoryRevision) (bool, error) {
	return store.recordInventoryRevision(ctx, application.InventoryObserved, revision)
}

func (store *GoodputStore) recordInventoryRevision(ctx context.Context, class application.InventoryClass, revision domain.InventoryRevision) (bool, error) {
	if err := class.Validate(); err != nil {
		return false, err
	}
	validated, err := domain.CreateInventoryRevision(revision)
	if err != nil {
		return false, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin inventory revision: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	inserted, err := recordInventoryRevisionTx(ctx, tx, class, validated)
	if err != nil || !inserted {
		return inserted, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit inventory revision: %w", err)
	}
	return true, nil
}

// The caller validates the fact and owns the transaction, including projections.
func recordInventoryRevisionTx(ctx context.Context, tx pgx.Tx, class application.InventoryClass, validated domain.InventoryRevision) (bool, error) {
	if err := lockGoodputFactStream(ctx, tx, "inventory", validated.ClusterID, validated.SourceID, string(class)); err != nil {
		return false, err
	}
	digest := inventoryRevisionDigest(validated)
	command, err := tx.Exec(ctx, `INSERT INTO goodput_inventory_revisions
		(revision_id, cluster_id, source_id, inventory_class, schema_version, content_digest, source_at, effective_at, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (revision_id) DO NOTHING`,
		validated.ID, validated.ClusterID, validated.SourceID, class, validated.SchemaVersion,
		digest[:], validated.SourceAt, validated.EffectiveAt, validated.ObservedAt)
	if err != nil {
		return false, fmt.Errorf("insert inventory revision: %w", err)
	}
	if command.RowsAffected() == 0 {
		var storedCluster domain.ClusterID
		var storedClass application.InventoryClass
		var storedDigest []byte
		if err := tx.QueryRow(ctx, `SELECT cluster_id, inventory_class, content_digest FROM goodput_inventory_revisions WHERE revision_id=$1`, validated.ID).Scan(&storedCluster, &storedClass, &storedDigest); err != nil {
			return false, fmt.Errorf("load conflicting inventory revision: %w", err)
		}
		if storedCluster != validated.ClusterID || storedClass != class || subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
			return false, fmt.Errorf("inventory revision identifier conflicts with an immutable revision")
		}
		return false, nil
	}
	for _, entity := range validated.Entities {
		if _, err := tx.Exec(ctx, `INSERT INTO goodput_inventory_revision_entities
			(cluster_id, revision_id, entity_kind, stable_node_id, physical_gpu_uuid, mig_identity)
			VALUES ($1,$2,$3,$4,$5,$6)`, validated.ClusterID, validated.ID, entity.Kind, entity.NodeID, entity.PhysicalGPUUUID, entity.MIGIdentity); err != nil {
			return false, fmt.Errorf("insert inventory entity: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goodput_inventory_revision_validity (cluster_id, revision_id, valid_from)
		VALUES ($1,$2,$3)`, validated.ClusterID, validated.ID, validated.EffectiveAt); err != nil {
		return false, fmt.Errorf("insert inventory validity: %w", err)
	}
	if err := rebuildInventoryValidity(ctx, tx, validated.ClusterID, validated.SourceID, class); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goodput_current_inventory
		(cluster_id, source_id, inventory_class, revision_id, effective_at, source_at, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (cluster_id, source_id, inventory_class) DO UPDATE SET
			revision_id=EXCLUDED.revision_id, effective_at=EXCLUDED.effective_at,
			source_at=EXCLUDED.source_at, observed_at=EXCLUDED.observed_at
		WHERE (goodput_current_inventory.effective_at, goodput_current_inventory.observed_at,
			goodput_current_inventory.source_at, goodput_current_inventory.revision_id)
		< (EXCLUDED.effective_at, EXCLUDED.observed_at, EXCLUDED.source_at, EXCLUDED.revision_id)`,
		validated.ClusterID, validated.SourceID, class, validated.ID,
		validated.EffectiveAt, validated.SourceAt, validated.ObservedAt); err != nil {
		return false, fmt.Errorf("update current inventory projection: %w", err)
	}
	return true, nil
}

func rebuildInventoryValidity(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, sourceID domain.SourceID, class application.InventoryClass) error {
	_, err := tx.Exec(ctx, `WITH ordered AS (
		SELECT r.cluster_id, r.revision_id, r.effective_at,
			LEAD(r.effective_at) OVER (ORDER BY r.effective_at, r.observed_at, r.source_at, r.revision_id) AS valid_to
		FROM goodput_inventory_revisions r
		WHERE r.cluster_id=$1 AND r.source_id=$2 AND r.inventory_class=$3
	)
	UPDATE goodput_inventory_revision_validity v
	SET valid_from=ordered.effective_at, valid_to=ordered.valid_to
	FROM ordered
	WHERE v.cluster_id=ordered.cluster_id AND v.revision_id=ordered.revision_id`, clusterID, sourceID, class)
	if err != nil {
		return fmt.Errorf("rebuild inventory validity: %w", err)
	}
	return nil
}

func (store *GoodputStore) RecordAllocationSnapshot(ctx context.Context, snapshot domain.AllocationSnapshot) (bool, error) {
	validated, err := domain.CreateAllocationSnapshot(snapshot)
	if err != nil {
		return false, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin allocation snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	inserted, err := recordAllocationSnapshotTx(ctx, tx, validated)
	if err != nil || !inserted {
		return inserted, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit allocation snapshot: %w", err)
	}
	return true, nil
}

func recordAllocationSnapshotTx(ctx context.Context, tx pgx.Tx, validated domain.AllocationSnapshot) (bool, error) {
	if err := lockGoodputFactStream(ctx, tx, "allocation", validated.ClusterID, validated.SourceID, ""); err != nil {
		return false, err
	}
	key := allocationSnapshotKey(validated)
	command, err := tx.Exec(ctx, `INSERT INTO goodput_allocation_snapshots
		(snapshot_key, cluster_id, source_id, schema_version, scheduler_namespace, scheduler_job_id, submit_at, attempt, allocation_state, source_at, effective_at, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (snapshot_key) DO NOTHING`,
		key, validated.ClusterID, validated.SourceID, validated.SchemaVersion, validated.Job.SchedulerNamespace,
		validated.Job.JobID, validated.Job.SubmitAt, validated.Job.Attempt, validated.State,
		validated.SourceAt, validated.EffectiveAt, validated.ObservedAt)
	if err != nil {
		return false, fmt.Errorf("insert allocation snapshot: %w", err)
	}
	if command.RowsAffected() == 0 {
		var storedCluster domain.ClusterID
		if err := tx.QueryRow(ctx, `SELECT cluster_id FROM goodput_allocation_snapshots WHERE snapshot_key=$1`, key).Scan(&storedCluster); err != nil {
			return false, fmt.Errorf("load conflicting allocation snapshot: %w", err)
		}
		if storedCluster != validated.ClusterID {
			return false, fmt.Errorf("allocation snapshot key conflicts with another cluster")
		}
		return false, nil
	}
	for _, entity := range validated.Entities {
		if _, err := tx.Exec(ctx, `INSERT INTO goodput_allocation_snapshot_entities
			(cluster_id, snapshot_key, entity_kind, stable_node_id, physical_gpu_uuid, mig_identity)
			VALUES ($1,$2,$3,$4,$5,$6)`, validated.ClusterID, key, entity.Kind, entity.NodeID, entity.PhysicalGPUUUID, entity.MIGIdentity); err != nil {
			return false, fmt.Errorf("insert allocation entity: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goodput_allocation_snapshot_validity (cluster_id, snapshot_key, valid_from)
		VALUES ($1,$2,$3)`, validated.ClusterID, key, validated.EffectiveAt); err != nil {
		return false, fmt.Errorf("insert allocation validity: %w", err)
	}
	if err := rebuildAllocationValidity(ctx, tx, validated); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goodput_current_allocations
		(cluster_id, source_id, scheduler_namespace, scheduler_job_id, submit_at, attempt, snapshot_key, effective_at, source_at, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (cluster_id, source_id, scheduler_namespace, scheduler_job_id, submit_at, attempt) DO UPDATE SET
			snapshot_key=EXCLUDED.snapshot_key, effective_at=EXCLUDED.effective_at,
			source_at=EXCLUDED.source_at, observed_at=EXCLUDED.observed_at
		WHERE (goodput_current_allocations.effective_at, goodput_current_allocations.observed_at,
			goodput_current_allocations.source_at, goodput_current_allocations.snapshot_key)
		< (EXCLUDED.effective_at, EXCLUDED.observed_at, EXCLUDED.source_at, EXCLUDED.snapshot_key)`,
		validated.ClusterID, validated.SourceID, validated.Job.SchedulerNamespace, validated.Job.JobID,
		validated.Job.SubmitAt, validated.Job.Attempt, key, validated.EffectiveAt, validated.SourceAt, validated.ObservedAt); err != nil {
		return false, fmt.Errorf("update current allocation projection: %w", err)
	}
	return true, nil
}

// Serialize before inserting facts so validity rebuilds see the preceding
// writer's committed history. Different sources and inventory classes remain
// independent. Allocations share a source lock so multi-job results cannot
// deadlock by acquiring job locks in differing payload orders.
func lockGoodputFactStream(ctx context.Context, tx pgx.Tx, kind string, clusterID domain.ClusterID, sourceID domain.SourceID, class string) error {
	key, err := json.Marshal([]string{"goodput-facts", kind, string(clusterID), string(sourceID), class})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key)); err != nil {
		return fmt.Errorf("lock goodput %s fact stream: %w", kind, err)
	}
	return nil
}

func rebuildAllocationValidity(ctx context.Context, tx pgx.Tx, snapshot domain.AllocationSnapshot) error {
	_, err := tx.Exec(ctx, `WITH ordered AS (
		SELECT s.cluster_id, s.snapshot_key, s.effective_at,
			LEAD(s.effective_at) OVER (ORDER BY s.effective_at, s.observed_at, s.source_at, s.snapshot_key) AS valid_to
		FROM goodput_allocation_snapshots s
		WHERE s.cluster_id=$1 AND s.source_id=$2 AND s.scheduler_namespace=$3 AND s.scheduler_job_id=$4
			AND s.submit_at=$5 AND s.attempt=$6
	)
	UPDATE goodput_allocation_snapshot_validity v
	SET valid_from=ordered.effective_at, valid_to=ordered.valid_to
	FROM ordered
	WHERE v.cluster_id=ordered.cluster_id AND v.snapshot_key=ordered.snapshot_key`, snapshot.ClusterID, snapshot.SourceID,
		snapshot.Job.SchedulerNamespace, snapshot.Job.JobID, snapshot.Job.SubmitAt, snapshot.Job.Attempt)
	if err != nil {
		return fmt.Errorf("rebuild allocation validity: %w", err)
	}
	return nil
}

func (store *GoodputStore) GetInventoryRevision(ctx context.Context, clusterID domain.ClusterID, revisionID domain.InventoryRevisionID) (application.InventoryRevisionProjection, bool, error) {
	if clusterID == "" || revisionID == "" {
		return application.InventoryRevisionProjection{}, false, fmt.Errorf("cluster and inventory revision identifiers are required")
	}
	return store.loadInventoryRevision(ctx, `WHERE r.cluster_id=$1 AND r.revision_id=$2`, clusterID, revisionID)
}

func (store *GoodputStore) GetCurrentInventoryRevision(ctx context.Context, clusterID domain.ClusterID, sourceID domain.SourceID, class application.InventoryClass) (application.InventoryRevisionProjection, bool, error) {
	if clusterID == "" || sourceID == "" {
		return application.InventoryRevisionProjection{}, false, fmt.Errorf("cluster and source identifiers are required")
	}
	if err := class.Validate(); err != nil {
		return application.InventoryRevisionProjection{}, false, err
	}
	return store.loadInventoryRevision(ctx, `JOIN goodput_current_inventory c ON c.cluster_id=r.cluster_id AND c.revision_id=r.revision_id
		WHERE c.cluster_id=$1 AND c.source_id=$2 AND c.inventory_class=$3`, clusterID, sourceID, class)
}

func (store *GoodputStore) loadInventoryRevision(ctx context.Context, predicate string, arguments ...any) (application.InventoryRevisionProjection, bool, error) {
	var projection application.InventoryRevisionProjection
	err := store.pool.QueryRow(ctx, `SELECT r.inventory_class, r.revision_id, r.cluster_id, r.source_id, r.schema_version,
		r.source_at, r.effective_at, r.observed_at FROM goodput_inventory_revisions r `+predicate, arguments...).Scan(
		&projection.Class, &projection.Revision.ID, &projection.Revision.ClusterID, &projection.Revision.SourceID,
		&projection.Revision.SchemaVersion, &projection.Revision.SourceAt, &projection.Revision.EffectiveAt, &projection.Revision.ObservedAt)
	if err == pgx.ErrNoRows {
		return application.InventoryRevisionProjection{}, false, nil
	}
	if err != nil {
		return application.InventoryRevisionProjection{}, false, fmt.Errorf("load inventory revision: %w", err)
	}
	rows, err := store.pool.Query(ctx, `SELECT entity_kind, stable_node_id, physical_gpu_uuid, mig_identity
		FROM goodput_inventory_revision_entities WHERE cluster_id=$1 AND revision_id=$2
		ORDER BY entity_kind, stable_node_id, physical_gpu_uuid, mig_identity`, projection.Revision.ClusterID, projection.Revision.ID)
	if err != nil {
		return application.InventoryRevisionProjection{}, false, fmt.Errorf("load inventory revision entities: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var entity domain.EntityIdentity
		if err := rows.Scan(&entity.Kind, &entity.NodeID, &entity.PhysicalGPUUUID, &entity.MIGIdentity); err != nil {
			return application.InventoryRevisionProjection{}, false, fmt.Errorf("scan inventory revision entity: %w", err)
		}
		entity.ClusterID = projection.Revision.ClusterID
		projection.Revision.Entities = append(projection.Revision.Entities, entity)
	}
	if err := rows.Err(); err != nil {
		return application.InventoryRevisionProjection{}, false, fmt.Errorf("load inventory revision entities: %w", err)
	}
	return projection, true, nil
}

func (store *GoodputStore) ListCurrentAllocationSnapshots(ctx context.Context, clusterID domain.ClusterID, limit int) ([]domain.AllocationSnapshot, bool, error) {
	if clusterID == "" {
		return nil, false, fmt.Errorf("cluster identifier is required")
	}
	if err := application.ValidateGoodputLimit(limit); err != nil {
		return nil, false, err
	}
	rows, err := store.pool.Query(ctx, `SELECT s.snapshot_key, s.cluster_id, s.source_id, s.schema_version,
		s.scheduler_namespace, s.scheduler_job_id, s.submit_at, s.attempt, s.allocation_state,
		s.source_at, s.effective_at, s.observed_at
		FROM goodput_current_allocations c
		JOIN goodput_allocation_snapshots s ON s.cluster_id=c.cluster_id AND s.snapshot_key=c.snapshot_key
		WHERE c.cluster_id=$1
		ORDER BY s.effective_at DESC, s.observed_at DESC, s.source_at DESC, s.snapshot_key DESC
		LIMIT $2`, clusterID, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list current allocation snapshots: %w", err)
	}
	defer rows.Close()
	type storedSnapshot struct {
		key   string
		value domain.AllocationSnapshot
	}
	stored := make([]storedSnapshot, 0, limit+1)
	for rows.Next() {
		var item storedSnapshot
		if err := rows.Scan(&item.key, &item.value.ClusterID, &item.value.SourceID, &item.value.SchemaVersion,
			&item.value.Job.SchedulerNamespace, &item.value.Job.JobID, &item.value.Job.SubmitAt,
			&item.value.Job.Attempt, &item.value.State, &item.value.SourceAt, &item.value.EffectiveAt, &item.value.ObservedAt); err != nil {
			return nil, false, fmt.Errorf("scan current allocation snapshot: %w", err)
		}
		stored = append(stored, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list current allocation snapshots: %w", err)
	}
	more := len(stored) > limit
	if more {
		stored = stored[:limit]
	}
	values := make([]domain.AllocationSnapshot, 0, len(stored))
	for _, item := range stored {
		entityRows, err := store.pool.Query(ctx, `SELECT entity_kind, stable_node_id, physical_gpu_uuid, mig_identity
			FROM goodput_allocation_snapshot_entities WHERE cluster_id=$1 AND snapshot_key=$2
			ORDER BY entity_kind, stable_node_id, physical_gpu_uuid, mig_identity`, item.value.ClusterID, item.key)
		if err != nil {
			return nil, false, fmt.Errorf("load allocation snapshot entities: %w", err)
		}
		for entityRows.Next() {
			var entity domain.EntityIdentity
			if err := entityRows.Scan(&entity.Kind, &entity.NodeID, &entity.PhysicalGPUUUID, &entity.MIGIdentity); err != nil {
				entityRows.Close()
				return nil, false, fmt.Errorf("scan allocation snapshot entity: %w", err)
			}
			entity.ClusterID = item.value.ClusterID
			item.value.Entities = append(item.value.Entities, entity)
		}
		if err := entityRows.Err(); err != nil {
			entityRows.Close()
			return nil, false, fmt.Errorf("load allocation snapshot entities: %w", err)
		}
		entityRows.Close()
		values = append(values, item.value)
	}
	return values, more, nil
}

func allocationSnapshotKey(snapshot domain.AllocationSnapshot) string {
	digest := allocationSnapshotDigest(snapshot)
	return hex.EncodeToString(digest[:])
}

func inventoryRevisionDigest(revision domain.InventoryRevision) [sha256.Size]byte {
	entities := make([]string, 0, len(revision.Entities))
	for _, entity := range revision.Entities {
		entities = append(entities, entity.Key())
	}
	sort.Strings(entities)
	parts := []string{
		string(revision.ID), string(revision.ClusterID), string(revision.SourceID), fmt.Sprint(revision.SchemaVersion),
		revision.SourceAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		revision.EffectiveAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		revision.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		strings.Join(entities, "\x1f"),
	}
	return sha256.Sum256([]byte(strings.Join(parts, "\x1e")))
}

func allocationSnapshotDigest(snapshot domain.AllocationSnapshot) [sha256.Size]byte {
	entities := make([]string, 0, len(snapshot.Entities))
	for _, entity := range snapshot.Entities {
		entities = append(entities, entity.Key())
	}
	sort.Strings(entities)
	parts := []string{
		string(snapshot.ClusterID), string(snapshot.SourceID), fmt.Sprint(snapshot.SchemaVersion),
		string(snapshot.Job.SchedulerNamespace), string(snapshot.Job.JobID), snapshot.Job.SubmitAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		fmt.Sprint(snapshot.Job.Attempt), string(snapshot.State), snapshot.SourceAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		snapshot.EffectiveAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), snapshot.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		strings.Join(entities, "\x1f"),
	}
	return sha256.Sum256([]byte(strings.Join(parts, "\x1e")))
}
