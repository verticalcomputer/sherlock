package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// The caller owns the profile-family and source inventory locks. Supersession
// revokes receipt admission immediately; already committed evidence retains its
// original profile/receipt. Old spooled reports are never relabeled or drained
// under new authority. This deliberately records a gap at a revision handoff.
func registerContinuousCoolingProfile(ctx context.Context, tx pgx.Tx, p domain.CoolingUploadProfile, hash string, encoded []byte, now time.Time) error {
	var revision int64
	var cluster, source, collector string
	err := tx.QueryRow(ctx, `SELECT revision,cluster_id,source_id,collector_id
 FROM public.prometheus_cooling_upload_profiles WHERE profile_id=$1 ORDER BY revision DESC LIMIT 1`, p.ProfileID).
		Scan(&revision, &cluster, &source, &collector)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == nil && (p.Revision <= revision || cluster != string(p.ClusterID) || source != string(p.SourceID) || collector != string(p.CollectorID)) {
		return fmt.Errorf("continuous cooling revision regresses or changes authority identity")
	}
	if err == pgx.ErrNoRows && p.State == "DISABLED" {
		return fmt.Errorf("cannot disable an unknown cooling authority")
	}
	var overlapping bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.prometheus_cooling_upload_profiles
 WHERE cluster_id=$1 AND source_id=$2 AND collector_id=$3 AND profile_id<>$4 AND revoked_at IS NULL
 AND collection_state<>'DISABLED' AND (ends_at IS NULL OR ends_at>$5))`, p.ClusterID, p.SourceID, p.CollectorID, p.ProfileID, now).Scan(&overlapping); err != nil {
		return err
	}
	if overlapping {
		return fmt.Errorf("continuous cooling scope overlaps another active profile")
	}
	if _, err := tx.Exec(ctx, `UPDATE public.prometheus_cooling_upload_profiles SET revoked_at=clock_timestamp()
 WHERE profile_id=$1 AND revoked_at IS NULL`, p.ProfileID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.prometheus_cooling_upload_profiles
 (profile_id,revision,profile_hash,cluster_id,source_id,collector_id,inventory_revision,profile,starts_at,ends_at,protocol_version,collection_state)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,3,$10)`, p.ProfileID, p.Revision, hash, p.ClusterID, p.SourceID, p.CollectorID, p.InventoryRevision, encoded, p.StartsAt.UTC(), p.State); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
