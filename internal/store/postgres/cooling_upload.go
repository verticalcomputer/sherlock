package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// RegisterCoolingUploadProfile binds one operator-supplied profile file to its
// approved inventory and records the earliest time it could confer authority.
func (s *CollectionStore) RegisterCoolingUploadProfile(ctx context.Context, profile domain.CoolingUploadProfile, hash string) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if digest, err := domain.ParseSHA256(hash); err != nil || digest.String() != hash {
		return fmt.Errorf("invalid cooling upload profile hash")
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockCoolingUploadProfile(ctx, tx, profile.ProfileID, profile.Revision); err != nil {
		return err
	}
	// Promotion is irreversible for a profile family. Check before the
	// idempotent-startup path too: a previously registered V2 file must not
	// undo a later V3 disable when a disconnected old process restarts.
	if profile.Version == domain.CoolingUploadVersion {
		var promoted bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
            SELECT 1 FROM public.prometheus_cooling_upload_profiles
            WHERE profile_id=$1 AND protocol_version=3)`, profile.ProfileID).Scan(&promoted); err != nil {
			return err
		}
		if promoted {
			return fmt.Errorf("cooling upload profile family has advanced to continuous authority")
		}
	}
	var identical bool
	err = tx.QueryRow(ctx, `SELECT profile_hash=$3 AND profile=$4::jsonb
 FROM public.prometheus_cooling_upload_profiles WHERE profile_id=$1 AND revision=$2`,
		profile.ProfileID, profile.Revision, hash, encoded).Scan(&identical)
	if err == nil {
		if !identical {
			return fmt.Errorf("cooling upload profile revision already binds different content")
		}
		if profile.Version == domain.CoolingUploadProductionVersion {
			var current bool
			if err := tx.QueryRow(ctx, `SELECT revoked_at IS NULL AND NOT EXISTS (
              SELECT 1 FROM public.prometheus_cooling_upload_profiles newer WHERE newer.profile_id=p.profile_id AND newer.revision>p.revision)
              FROM public.prometheus_cooling_upload_profiles p WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision).Scan(&current); err != nil {
				return err
			}
			if !current {
				return fmt.Errorf("cooling upload profile revision is superseded")
			}
		}
		return nil
	}
	if err != pgx.ErrNoRows {
		return err
	}
	if err := lockGoodputFactStream(ctx, tx, "inventory", profile.ClusterID, profile.SourceID, "EXPECTED"); err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if profile.Version == domain.CoolingUploadVersion && !now.Before(profile.EndsAt.Add(-domain.CoolingUploadInterval)) {
		return fmt.Errorf("cooling upload profile has no future usable slot")
	}
	if err := requireCoolingUploadOwner(ctx, tx, profile); err != nil {
		return err
	}
	if profile.State != "DISABLED" {
		if err := requireCoolingUploadInventory(ctx, tx, profile, now); err != nil {
			return err
		}
	}
	if profile.Version == domain.CoolingUploadProductionVersion {
		return registerContinuousCoolingProfile(ctx, tx, profile, hash, encoded, now)
	}
	var overlapping bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM public.prometheus_cooling_upload_profiles
 WHERE cluster_id=$1 AND source_id=$2 AND collector_id=$3 AND revoked_at IS NULL
 AND (ends_at IS NULL OR ends_at>$4) AND (ends_at IS NULL OR ends_at>$6) AND starts_at<$5 AND collection_state<>'DISABLED')`, profile.ClusterID, profile.SourceID, profile.CollectorID,
		profile.StartsAt, profile.EndsAt, now).Scan(&overlapping); err != nil {
		return err
	}
	if overlapping {
		return fmt.Errorf("cooling upload profile overlaps an active enrollment for this collector and source")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.prometheus_cooling_upload_profiles
 (profile_id,revision,profile_hash,cluster_id,source_id,collector_id,inventory_revision,profile,starts_at,ends_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, profile.ProfileID, profile.Revision, hash,
		profile.ClusterID, profile.SourceID, profile.CollectorID, profile.InventoryRevision, encoded,
		profile.StartsAt.UTC(), profile.EndsAt.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecordCoolingUpload proves receipt from the authenticated collector against
// persisted profile authority. The run, samples and receipt commit together.
func (s *CollectionStore) RecordCoolingUpload(ctx context.Context, collector domain.CollectorID, cluster domain.ClusterID,
	report domain.CoolingUploadReport) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockCoolingUploadProfile(ctx, tx, report.ProfileID, report.ProfileRevision); err != nil {
		return false, err
	}
	var encodedProfile []byte
	var profileHash string
	var registeredAt, now time.Time
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT profile,profile_hash,registered_at,revoked_at,clock_timestamp()
 FROM public.prometheus_cooling_upload_profiles
 WHERE profile_id=$1 AND revision=$2 AND collector_id=$3 AND cluster_id=$4`,
		report.ProfileID, report.ProfileRevision, collector, cluster).
		Scan(&encodedProfile, &profileHash, &registeredAt, &revokedAt, &now)
	if err == pgx.ErrNoRows {
		return false, collectorcontrol.ErrCoolingUploadRejected
	}
	if err != nil {
		return false, err
	}
	var profile domain.CoolingUploadProfile
	if err := json.Unmarshal(encodedProfile, &profile); err != nil {
		return false, fmt.Errorf("decode stored cooling upload profile: %w", err)
	}
	slot := report.Result.Task.ScheduledFor
	if revokedAt != nil || profile.CollectorID != collector || profile.ClusterID != cluster ||
		!registeredAt.Before(slot) || (profile.Version == domain.CoolingUploadVersion && now.After(profile.EndsAt.Add(domain.CoolingUploadRetention))) {
		return false, collectorcontrol.ErrCoolingUploadRejected
	}
	if err := report.Validate(profile, profileHash, now); err != nil {
		return false, fmt.Errorf("%w: %v", collectorcontrol.ErrCoolingUploadRejected, err)
	}
	if err := lockGoodputFactStream(ctx, tx, "inventory", profile.ClusterID, profile.SourceID, "EXPECTED"); err != nil {
		return false, err
	}
	if err := requireCoolingUploadOwner(ctx, tx, profile); err != nil {
		return false, err
	}
	if err := requireCoolingUploadInventory(ctx, tx, profile, slot); err != nil {
		return false, err
	}
	encodedReport, err := json.Marshal(report)
	if err != nil {
		return false, err
	}
	if len(encodedReport) > domain.CoolingUploadMaxBytes {
		return false, collectorcontrol.ErrCoolingUploadRejected
	}
	payloadHash := domain.ChecksumSHA256(encodedReport).String()
	result := report.Result
	result.Task.IdempotencyKey = "prometheus-cooling-report-v2-" + payloadHash
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, result.Task.RunID); err != nil {
		return false, err
	}
	var prior bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM public.prometheus_cooling_upload_receipts
 WHERE run_id=$1 AND profile_id=$2 AND profile_revision=$3 AND profile_hash=$4 AND collector_id=$5 AND payload_hash=$6)
 FROM public.collection_runs WHERE run_id=$1`, result.Task.RunID, profile.ProfileID, profile.Revision, profileHash,
		collector, payloadHash).Scan(&prior)
	if err == nil {
		return prior, nil
	}
	if err != pgx.ErrNoRows {
		return false, err
	}
	prepareCoolingUploadResult(&result, profile)
	inserted, err := persistCollectionResultRowsTx(ctx, tx, result, nil, false)
	if err != nil || !inserted {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.prometheus_cooling_upload_receipts
 (run_id,profile_id,profile_revision,profile_hash,collector_id,payload_hash) VALUES ($1,$2,$3,$4,$5,$6)`,
		result.Task.RunID, profile.ProfileID, profile.Revision, profileHash, collector, payloadHash); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func lockCoolingUploadProfile(ctx context.Context, tx pgx.Tx, id string, revision int64) error {
	// Serialize revisions of the same continuous authority before the original
	// per-revision lock used by the SQL revocation guard.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "prometheus-cooling-profile-family:"+id); err != nil {
		return err
	}
	key := fmt.Sprintf("prometheus-cooling-profile:%s:%d", id, revision)
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key)
	return err
}

func requireCoolingUploadOwner(ctx context.Context, tx pgx.Tx, profile domain.CoolingUploadProfile) error {
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM public.collectors c JOIN public.clusters k USING(cluster_id)
 JOIN public.sources s USING(cluster_id)
 WHERE c.collector_id=$1 AND c.cluster_id=$2 AND c.status='ACTIVE'
 AND k.removed_at IS NULL AND s.source_id=$3 AND s.kind='prometheus')`,
		profile.CollectorID, profile.ClusterID, profile.SourceID).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return collectorcontrol.ErrCoolingUploadRejected
	}
	return nil
}

func requireCoolingUploadInventory(ctx context.Context, tx pgx.Tx, profile domain.CoolingUploadProfile, at time.Time) error {
	var revision string
	var effectiveAt, observedAt time.Time
	err := tx.QueryRow(ctx, `SELECT revision_id,effective_at,observed_at
 FROM public.goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED'
 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1`, profile.ClusterID,
		profile.SourceID).Scan(&revision, &effectiveAt, &observedAt)
	if err == pgx.ErrNoRows || err == nil && (revision != profile.InventoryRevision || effectiveAt.After(at) || observedAt.After(at)) {
		return fmt.Errorf("%w: cooling profile inventory revision does not govern the slot", collectorcontrol.ErrCoolingUploadRejected)
	}
	if err != nil {
		return err
	}
	return requireCoolingUploadAssets(ctx, tx, profile)
}

// requireCoolingUploadAssets checks that each enrolled GPU maps to exactly one
// physical inventory entity and an expected node in the named revision.
func requireCoolingUploadAssets(ctx context.Context, tx pgx.Tx, profile domain.CoolingUploadProfile) error {
	nodes := make([]string, 0, len(profile.Assets))
	gpus := make([]string, 0, len(profile.Assets))
	for _, asset := range profile.Assets {
		nodes = append(nodes, string(asset.NodeID))
		gpus = append(gpus, string(asset.GPUUUID))
	}
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT count(*)=$5 AND coalesce(bool_and(
 EXISTS (SELECT 1 FROM public.goodput_inventory_revision_entities n
  WHERE n.cluster_id=$1 AND n.revision_id=$2 AND n.entity_kind='NODE' AND n.stable_node_id=a.node)
 AND (SELECT count(*)=1 AND bool_and(g.entity_kind='GPU' AND g.stable_node_id=a.node)
  FROM public.goodput_inventory_revision_entities g
  WHERE g.cluster_id=$1 AND g.revision_id=$2 AND g.physical_gpu_uuid=a.gpu)
 ),false) FROM unnest($3::text[],$4::text[]) AS a(node,gpu)`,
		profile.ClusterID, profile.InventoryRevision, nodes, gpus, len(profile.Assets)).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("%w: cooling upload asset has no unambiguous physical inventory entry", collectorcontrol.ErrCoolingUploadRejected)
	}
	return nil
}

func prepareCoolingUploadResult(result *domain.CollectionResult, profile domain.CoolingUploadProfile) {
	field, _ := domain.CoolingUploadField(result.Task.Query)
	result.Observations = slices.Clone(result.Observations)
	seen := make(map[domain.PhysicalGPUUUID]bool, len(result.Observations))
	for i := range result.Observations {
		observation := &result.Observations[i]
		gpu := domain.PhysicalGPUUUID(observation.Labels[1].Value)
		seen[gpu] = true
		observation.ID = domain.ObservationID("prom-cooling-sample-" + domain.ChecksumSHA256(
			[]byte(string(result.Task.RunID)+"\x00"+string(gpu))).String())
		observation.Semantics = &domain.MetricSemantics{Kind: field.Kind, Reset: field.Reset}
	}
	expected := len(profile.Assets)
	result.Coverage.SeriesExpected = &expected
	result.Coverage.Complete = result.Status == domain.ResultSucceeded && len(seen) == len(profile.Assets)
	for _, asset := range profile.Assets {
		evidence := domain.DCGMFieldEvidence{NodeID: asset.NodeID, GPU: asset.GPUUUID, Metric: field.Name,
			State: "UNKNOWN", Reason: "missing_or_unavailable"}
		if seen[asset.GPUUUID] {
			evidence.State, evidence.Reason = "SUPPORTED", "fresh_sample"
		}
		result.Coverage.MetricFields = append(result.Coverage.MetricFields, evidence)
	}
}
