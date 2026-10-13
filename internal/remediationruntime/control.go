package remediationruntime

import (
	"context"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/store/postgres"
	"time"
)

// Control performs one explicitly named operator action through the same
// authority and generation fences as the supervisor. No discovery or forward
// dispatch runs in this path. Possession of the scoped DB identity is required.
func (r *Runtime) Control(ctx context.Context, operation string, runID domain.RemediationRunID) error {
	if !r.cfg.Live || !domain.ValidRemediationToken(string(runID)) || (operation != "cancel" && operation != "rollback" && operation != "reconcile") {
		return application.ErrRemediationForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Lease)
	defer cancel()
	claim, err := r.store.ClaimRemediationControl(ctx, r.cfg.ClusterID, runID, r.cfg.Owner, r.cfg.Lease)
	if err != nil {
		return err
	}
	defer func() {
		releaseCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = r.store.ReleaseRemediation(releaseCtx, r.cfg.ClusterID, claim, r.cfg.PollInterval)
	}()
	ctx = postgres.ContextWithRemediationSupervisorClaim(ctx, claim)
	switch operation {
	case "cancel":
		_, err = r.service.CancelRemediation(ctx, r.cfg.ClusterID, runID, "sherlock-remediator")
	case "rollback":
		_, err = r.service.RollbackRemediation(ctx, r.cfg.ClusterID, runID, "sherlock-remediator", r.cfg.Owner)
	case "reconcile":
		loaded, found, loadErr := r.store.LoadRemediationRun(ctx, r.cfg.ClusterID, runID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return application.ErrRemediationNotFound
		}
		if loaded.LatestAttemptID == "" {
			return nil
		}
		if !loaded.LatestReceipt && !loaded.Run.State().Terminal() {
			if _, _, err = r.store.RecoverCommittedLiveEffect(ctx, r.cfg.ClusterID, runID, loaded.LatestAttemptID); err != nil {
				return err
			}
		}
		err = r.store.ReconcileCollectionRequest(ctx, r.cfg.ClusterID, runID, loaded.LatestAttemptID)
		if err != nil {
			return err
		}
		loaded, found, err = r.store.LoadRemediationRun(ctx, r.cfg.ClusterID, runID)
		if err != nil {
			return err
		}
		if !found {
			return application.ErrRemediationNotFound
		}
		if loaded.Run.State() == domain.RemediationVerifying && loaded.LatestReceipt {
			_, err = r.service.VerifyRemediation(ctx, r.cfg.ClusterID, runID, "sherlock-remediator")
		} else if loaded.Run.State() == domain.RemediationRollingBack && loaded.LatestStage == domain.RemediationStageRollback && loaded.LatestReceipt {
			_, err = r.service.VerifyRemediationRollback(ctx, r.cfg.ClusterID, runID, "sherlock-remediator")
		}
	}
	return err
}
