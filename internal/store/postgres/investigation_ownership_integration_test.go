//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigator"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"time"
)

// Exercise the general worker between deterministic supervisor transitions.
// Also inject legacy AVAILABLE claims, as left by pre-fix production workers.
func m15AssertGeneralWorkerExcludesSchedule(ctx context.Context, p *pgxpool.Pool, cluster domain.ClusterID) error {
	store, err := storepg.NewInvestigationLeaseStore(p)
	if err != nil {
		return err
	}
	for pass := 0; pass < 4; pass++ {
		if pass == 1 {
			_, err = p.Exec(ctx, `INSERT INTO investigation_claims(investigation_id,cluster_id,available_at)
    SELECT i.investigation_id,i.cluster_id,clock_timestamp() FROM investigations i JOIN schedule_repair_detections d USING(investigation_id,cluster_id)
    WHERE i.cluster_id=$1 ON CONFLICT DO NOTHING`, cluster)
			if err != nil {
				return err
			}
		}

		if pass >= 2 {
			// An old expired or still-live claim must not be re-adopted or renewed.
			duration := -time.Minute
			if pass == 3 {
				duration = time.Minute
			}
			rows, e := p.Query(ctx, `UPDATE investigation_claims c SET status='LEASED',lease_owner='old-worker',lease_epoch=1,
                lease_token_hash=decode(repeat('00',32),'hex'),lease_expires_at=$2
                FROM schedule_repair_detections d WHERE d.cluster_id=$1 AND d.investigation_id=c.investigation_id
                RETURNING c.investigation_id`, cluster, time.Now().Add(duration))
			if e != nil {
				return e
			}
			var ids []domain.InvestigationID
			for rows.Next() {
				var id domain.InvestigationID
				if e = rows.Scan(&id); e != nil {
					rows.Close()
					return e
				}
				ids = append(ids, id)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			for _, id := range ids {
				if e = store.Heartbeat(ctx, investigator.Lease{InvestigationID: id, Owner: "old-worker", Epoch: 1}, time.Now(), time.Minute); e == nil {
					return fmt.Errorf("renewed a deterministic investigation")
				}
			}
		}
		lease, found, err := store.Claim(ctx, "general-ownership-regression", time.Now(), time.Minute, 1, 1)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		var owned bool
		err = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schedule_repair_detections WHERE investigation_id=$1)`, lease.InvestigationID).Scan(&owned)
		releasedAt := time.Now()
		releaseErr := store.Release(ctx, lease, releasedAt, releasedAt)
		if err != nil {
			return err
		}
		if releaseErr != nil {
			return releaseErr
		}
		if owned {
			return fmt.Errorf("general worker claimed deterministic investigation on pass %d", pass)
		}
	}
	return nil
}
