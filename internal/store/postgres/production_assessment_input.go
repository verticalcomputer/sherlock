package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// The profile identity and inventory stay pinned; a compatible, registered V3
// revision may replace it without changing occurrence or original deadline.
func loadProductionUploadProfile(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, b a.Binding, query domain.QueryKind, at time.Time) (p domain.CoolingUploadProfile, err error) {
	field, ok := domain.CoolingUploadField(query)
	if !ok || field.Name != b.Metric {
		return p, ErrMonitoringAuthority
	}
	stage, started := "production.input.profile_family_lock", time.Now()
	defer func() { err = assessmentTransactionError(stage, started, err, "not_attempted") }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, "prometheus-cooling-profile-family:"+b.UploadProfileID); err != nil {
		return p, err
	}
	stage, started = "production.input.profile", time.Now()
	var body []byte
	err = tx.QueryRow(ctx, `SELECT p.profile FROM prometheus_cooling_upload_profiles p JOIN sources s USING(cluster_id,source_id) JOIN clusters k USING(cluster_id)
 WHERE p.profile_id=$1 AND p.revision>=$2 AND p.collector_id=$3 AND p.cluster_id=$4 AND p.source_id=$5 AND p.inventory_revision=$6
 AND p.protocol_version=3 AND p.collection_state='ENABLED' AND p.revoked_at IS NULL AND p.registered_at<=$7 AND p.starts_at<=$7
 AND s.kind='prometheus' AND k.removed_at IS NULL ORDER BY p.revision DESC LIMIT 1`, b.UploadProfileID, b.ScheduleRevision, b.UploadCollectorID, c.ClusterID, c.SourceID, c.InventoryRevision, at).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrMonitoringAuthority
	}
	if err != nil {
		return p, err
	}
	if a.DecodeStrict(body, &p, 64<<10) != nil || p.Validate() != nil || !productionProfileScope(p, c, asset, b) {
		return p, ErrMonitoringAuthority
	}
	stage, started = "production.input.profile_revision_lock", time.Now()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, fmt.Sprintf("prometheus-cooling-profile:%s:%d", p.ProfileID, p.Revision)); err != nil {
		return p, err
	}
	stage, started = "production.input.profile_active", time.Now()
	var active bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM prometheus_cooling_upload_profiles WHERE profile_id=$1 AND revision=$2 AND revoked_at IS NULL AND collection_state='ENABLED')`, p.ProfileID, p.Revision).Scan(&active); err != nil {
		return p, err
	}
	if !active {
		return p, ErrMonitoringAuthority
	}
	stage, started = "production.input.inventory", time.Now()
	var inventory string
	err = tx.QueryRow(ctx, `SELECT revision_id FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED' AND effective_at<=$3 AND observed_at<=$3 AND source_at<=$3 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1`, c.ClusterID, c.SourceID, at).Scan(&inventory)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && inventory != c.InventoryRevision {
		return p, ErrMonitoringAuthority
	}
	if err != nil {
		return p, err
	}
	stage, started = "production.input.inventory_assets", time.Now()
	err = requireCoolingUploadAssets(ctx, tx, p)
	if errors.Is(err, collectorcontrol.ErrCoolingUploadRejected) {
		return p, ErrMonitoringAuthority
	}
	return p, err
}
func productionProfileScope(p domain.CoolingUploadProfile, c a.Config, asset a.Asset, b a.Binding) bool {
	if p.Version != 3 || p.ProfileID != b.UploadProfileID || p.Revision < b.ScheduleRevision || string(p.CollectorID) != b.UploadCollectorID || string(p.ClusterID) != c.ClusterID || string(p.SourceID) != c.SourceID || p.InventoryRevision != c.InventoryRevision {
		return false
	}
	nodes := []string{}
	for _, x := range p.Assets {
		nodes = append(nodes, string(x.NodeID))
	}
	slices.Sort(nodes)
	return slices.Equal(slices.Compact(nodes), b.ScopeNodes) && slices.Contains(p.Assets, domain.CoolingUploadAsset{NodeID: domain.StableNodeID(asset.NodeID), GPUUUID: domain.PhysicalGPUUUID(asset.GPUUUID)})
}

var errReceiptLookupIncomplete = errors.New("receipt observation lookup incomplete")

// Look up each receipt's run by its unique ID before applying scope predicates.
// The lateral boundary prevents a low-cardinality source-time estimate from
// rescanning the source's run history for every receipt.
// The bounded selection transmits each consecutive equal metric-field document and each
// profile revision once. Adjacency uses exact JSONB equality; parsing
// still validates the whole document, including conflicting duplicate fields.
// No cache survives this call or replaces each receipt's temporal validation.
// Receipt admission already serialized against revocation. Retain that proof
// when a compatible revision is replaced; do not reject historical good samples
// merely because their old profile has since been revoked.
func loadProductionUploadAttempts(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, b a.Binding, query domain.QueryKind, from, at time.Time) (map[string]assessmentAttempt, []string, bool, error) {
	rows, err := tx.Query(ctx, `WITH selected AS MATERIALIZED (
 SELECT r.run_id,r.scheduled_for,r.completed_at,u.received_at,r.status,r.coverage_complete,u.observation_lookup_complete,
 CASE WHEN octet_length(r.metric_fields::text)<=65536 THEN r.metric_fields ELSE NULL END AS metric_fields,
 p.profile_id,p.profile_hash,p.revision,i.revision_id,i.source_at
 FROM prometheus_cooling_upload_receipts u JOIN prometheus_cooling_upload_profiles p ON p.profile_id=u.profile_id AND p.revision=u.profile_revision AND p.profile_hash=u.profile_hash AND p.collector_id=u.collector_id
 JOIN LATERAL (SELECT * FROM collection_runs WHERE run_id=u.run_id OFFSET 0) r
 ON r.cluster_id=p.cluster_id AND r.source_id=p.source_id
 LEFT JOIN LATERAL (SELECT revision_id,source_at FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED' AND effective_at<=r.scheduled_for AND observed_at<=r.completed_at ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1)i ON true
 WHERE p.cluster_id=$1 AND p.source_id=$2 AND r.query_kind=$3 AND r.range_start IS NULL AND r.job_id IS NULL
 AND r.idempotency_key='prometheus-cooling-report-v2-'||u.payload_hash
 AND u.received_at BETWEEN $4 AND $5 AND r.completed_at<=$5 AND p.profile_id=$6 AND p.revision>=$7 AND p.collector_id=$8 AND p.inventory_revision=$9
 AND p.protocol_version=3 AND p.collection_state='ENABLED' AND p.registered_at<r.scheduled_for AND r.scheduled_for>=p.starts_at
 AND (p.revoked_at IS NULL OR u.received_at<=p.revoked_at)
 ORDER BY u.received_at DESC,r.run_id DESC LIMIT 257
), grouped AS (
 SELECT *,lag(metric_fields) OVER(ORDER BY received_at DESC,run_id DESC) AS previous_fields,
 row_number() OVER(ORDER BY received_at DESC,run_id DESC) AS receipt_ordinal,
 row_number() OVER(PARTITION BY profile_hash,revision ORDER BY received_at DESC,run_id DESC) AS profile_ordinal
 FROM selected
)
SELECT run_id,scheduled_for,completed_at,received_at,status,coverage_complete,observation_lookup_complete,
 CASE WHEN receipt_ordinal=1 OR metric_fields IS DISTINCT FROM previous_fields THEN metric_fields END,
 receipt_ordinal=1 OR metric_fields IS DISTINCT FROM previous_fields AS fields_changed,
 CASE WHEN profile_ordinal=1 THEN
  (SELECT p.profile FROM prometheus_cooling_upload_profiles p
   WHERE p.profile_id=grouped.profile_id AND p.revision=grouped.revision AND p.profile_hash=grouped.profile_hash)
 END,profile_hash,revision,revision_id,source_at
 FROM grouped ORDER BY received_at DESC,run_id DESC`, c.ClusterID, c.SourceID, query, from, at, b.UploadProfileID, b.ScheduleRevision, b.UploadCollectorID, c.InventoryRevision)
	if err != nil {
		return nil, nil, false, err
	}
	defer rows.Close()
	attempts := map[string]assessmentAttempt{}
	cache := productionProfileCache{}
	supported := false
	ids := []string{}
	identity := domain.GPUObservationIdentity{EntityKey: asset.EntityKey, NodeID: domain.StableNodeID(asset.NodeID), PhysicalGPUUUID: domain.PhysicalGPUUUID(asset.GPUUUID), Canonical: true}
	for rows.Next() {
		if len(ids) >= 256 {
			return attempts, ids, true, nil
		}
		var id, hash string
		var revision int64
		var fieldsChanged bool
		var slot, completed, received time.Time
		var status domain.ResultStatus
		var complete, lookupComplete bool
		var fieldsBody, profileBody []byte
		var inventory *string
		var inventoryAt *time.Time
		if err := rows.Scan(&id, &slot, &completed, &received, &status, &complete, &lookupComplete, &fieldsBody, &fieldsChanged, &profileBody, &hash, &revision, &inventory, &inventoryAt); err != nil {
			return nil, nil, false, err
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, false, err
		}
		if fieldsChanged {
			var fields []domain.DCGMFieldEvidence
			supported = len(fieldsBody) <= 64<<10 && json.Unmarshal(fieldsBody, &fields) == nil && monitoringFieldState(fields, identity, b.Metric) == "SUPPORTED"
		}
		var profile domain.CoolingUploadProfile
		if len(profileBody) > 0 {
			profile, err = cache.decode(profileBody, hash, revision)
		} else {
			cached, found := cache[productionProfileKey{hash, revision}]
			if !found {
				continue
			}
			profile, err = cached.profile, nil
		}
		if err != nil || !productionProfileScope(profile, c, asset, b) {
			continue
		}
		task := profile.Task(query, slot)
		if string(task.RunID) != id || !slot.Equal(slot.Truncate(domain.CoolingUploadInterval)) || completed.Before(slot) || completed.After(task.Deadline) || received.After(at) {
			continue
		}
		// Historical receipts have no complete observation directory. Abort the
		// acquisition transaction so an unproven absence cannot advance state.
		// The independent due lane can still evaluate retained facts on time.
		if !lookupComplete {
			return nil, nil, false, errReceiptLookupIncomplete
		}
		p := a.Provenance{Mode: "upload", CollectionRunID: id, Operation: b.Operation, ScheduleRevision: profile.Revision, InventoryRevision: profile.InventoryRevision, CollectorID: string(profile.CollectorID), UploadProfileID: profile.ProfileID, UploadProfileHash: hash}
		ids = append(ids, id)
		attempts[id] = assessmentAttempt{completed: completed.UTC(), scheduled: slot.UTC(), provenance: p, usable: status == domain.ResultSucceeded && complete && supported && inventory != nil && *inventory == c.InventoryRevision && inventoryAt != nil && !inventoryAt.After(completed)}
	}
	return attempts, ids, false, rows.Err()
}

func validateProductionBaseline(ctx context.Context, tx pgx.Tx, c a.Config, asset a.Asset, b a.Binding) error {
	var body []byte
	err := tx.QueryRow(ctx, `SELECT profile FROM prometheus_cooling_upload_profiles WHERE profile_id=$1 AND revision=$2 AND profile_hash=$3 AND collector_id=$4 AND cluster_id=$5 AND source_id=$6 AND inventory_revision=$7 AND protocol_version=3 AND collection_state='ENABLED'`, b.UploadProfileID, b.ScheduleRevision, b.UploadProfileHash, b.UploadCollectorID, c.ClusterID, c.SourceID, c.InventoryRevision).Scan(&body)
	if err != nil {
		return fmt.Errorf("production baseline authority: %w", err)
	}
	var p domain.CoolingUploadProfile
	if a.DecodeStrict(body, &p, 64<<10) != nil || p.Validate() != nil || !productionProfileScope(p, c, asset, b) {
		return ErrMonitoringAuthority
	}
	return nil
}

// One bounded receipt selection owns this cache. It never survives a refresh or
// replaces per-receipt time, task, field, inventory or scope validation.
type productionProfileKey struct {
	hash     string
	revision int64
}
type productionCachedProfile struct {
	profile domain.CoolingUploadProfile
	body    []byte
}
type productionProfileCache map[productionProfileKey]productionCachedProfile

func (cache productionProfileCache) decode(body []byte, hash string, revision int64) (domain.CoolingUploadProfile, error) {
	var profile domain.CoolingUploadProfile
	if len(body) == 0 || len(body) > 64<<10 || !a.ValidHash(hash) || revision < 1 {
		return profile, a.ErrInvalid
	}
	key := productionProfileKey{hash, revision}
	if cached, ok := cache[key]; ok {
		if !bytes.Equal(cached.body, body) {
			return profile, a.ErrInvalid
		}
		profile = cached.profile
		profile.Assets = slices.Clone(profile.Assets)
		return profile, nil
	}
	if len(cache) >= 256 {
		return profile, ErrAssessmentCapacity
	}
	if a.DecodeStrict(body, &profile, 64<<10) != nil || profile.Validate() != nil || profile.Revision != revision {
		return profile, a.ErrInvalid
	}
	stored := profile
	stored.Assets = slices.Clone(profile.Assets)
	cache[key] = productionCachedProfile{stored, bytes.Clone(body)}
	return profile, nil
}
