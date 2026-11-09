package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// RegisterPrometheusRenewal is used by the offline issuer, never by intake.
// The row lock and expected serial/fingerprint prevent a stale or concurrent
// renewal. The previous leaf remains usable only within its existing validity.
func (s *CollectorControlStore) RegisterPrometheusRenewal(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, expected string, fingerprint [32]byte, next collectorcontrol.IssuedIdentity) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'"); err != nil {
		return err
	}
	var previousExpiry time.Time
	err = tx.QueryRow(ctx, `
		SELECT i.not_after
		FROM public.collectors c JOIN public.collector_identities i
		  ON i.collector_id=c.collector_id AND i.certificate_serial=c.identity_serial
		WHERE c.collector_id=$1 AND c.cluster_id=$2 AND c.status='ACTIVE'
		  AND c.identity_serial=$3 AND i.certificate_sha256=$4
		  AND i.revoked_at IS NULL AND i.superseded_at IS NULL
		  AND i.not_before <= clock_timestamp()
		  AND i.not_after BETWEEN clock_timestamp() + interval '1 hour' AND clock_timestamp() + interval '6 hours'
		FOR UPDATE OF c, i`, collector, cluster, expected, fingerprint[:]).Scan(&previousExpiry)
	if err != nil {
		return fmt.Errorf("current identity did not match the renewal window and scope: %w", err)
	}
	if next.Serial == expected || !next.NotAfter.After(previousExpiry) {
		return fmt.Errorf("renewal must extend the current identity with a new serial")
	}
	if err := insertCollectorIdentity(ctx, tx, collector, next); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE public.collector_identities SET superseded_at=clock_timestamp()
		WHERE collector_id=$1 AND certificate_serial=$2`, collector, expected); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE public.collectors SET identity_serial=$2, identity_not_after=$3
		WHERE collector_id=$1`, collector, next.Serial, next.NotAfter.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
