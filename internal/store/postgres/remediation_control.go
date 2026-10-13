package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"time"
)

// ClaimRemediationControl leases only the named LIVE run. It never steals an
// active supervisor lease, discovers another run, or resets an uncertain effect.
func (s *RemediationStore) ClaimRemediationControl(ctx context.Context, cluster domain.ClusterID, run domain.RemediationRunID, owner string, lease time.Duration) (RemediationSupervisorClaim, error) {
	if !domain.ValidRemediationToken(string(cluster)) || !domain.ValidRemediationToken(string(run)) || !domain.ValidRemediationToken(owner) || lease < time.Second || lease > application.MaxRemediationLease {
		return RemediationSupervisorClaim{}, application.ErrRemediationLeaseInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return RemediationSupervisorClaim{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = LockRepairAuthority(ctx, tx, cluster); err != nil {
		return RemediationSupervisorClaim{}, err
	}
	var claim RemediationSupervisorClaim
	err = tx.QueryRow(ctx, `UPDATE remediation_runs SET supervisor_owner=$3, supervisor_until=clock_timestamp()+($4*interval '1 millisecond'), supervisor_generation=supervisor_generation+1 WHERE cluster_id=$1 AND run_id=$2 AND assurance='LIVE' AND (supervisor_until IS NULL OR supervisor_until<=clock_timestamp()) RETURNING run_id,supervisor_owner,supervisor_generation,supervisor_until`, cluster, run, owner, lease.Milliseconds()).Scan(&claim.RunID, &claim.Owner, &claim.Generation, &claim.ExpiresAt)
	if err == pgx.ErrNoRows {
		return RemediationSupervisorClaim{}, application.ErrRemediationLeaseInvalid
	}
	if err != nil {
		return RemediationSupervisorClaim{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return RemediationSupervisorClaim{}, err
	}
	return claim, nil
}
