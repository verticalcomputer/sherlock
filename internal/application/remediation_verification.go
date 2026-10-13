package application

import (
	"context"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"time"
)

func verificationTargets(loaded LoadedRemediationRun) []domain.RemediationTarget {
	if loaded.LatestAttemptID != "" {
		return loaded.LatestTargets
	}
	return loaded.ExecutedTargets // legacy in-memory fixtures; PostgreSQL always supplies an attempt.
}

func (service *RemediationService) VerifyRemediationRollback(ctx context.Context, cluster domain.ClusterID, id domain.RemediationRunID, actor string) (domain.RemediationRun, error) {
	loaded, plan, _, rollback, facts, err := service.stage(ctx, cluster, id)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	if loaded.Run.State() != domain.RemediationRollingBack || loaded.LatestStage != domain.RemediationStageRollback || !loaded.LatestReceipt || rollback == nil {
		return domain.RemediationRun{}, ErrRemediationConflict
	}
	observations, err := service.facts.ReadRemediationObservations(ctx, RemediationObservationQuery{ClusterID: cluster, RunID: id, AttemptID: loaded.LatestAttemptID, Targets: loaded.LatestTargets, Window: rollback.ObservationWindow, Conditions: conditionIDs(rollback.Postconditions)})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	results := remediation.EvaluateConditions(rollback.Postconditions, waveTargets(plan, loaded.LatestTargets), observations, remediationObservationTime(facts.Now, observations))
	restored := len(results) > 0
	for _, r := range results {
		if r.Result != domain.ConditionSatisfied {
			restored = false
		}
	}
	if !restored && facts.Now.Before(loaded.DeadlineAt) {
		return loaded.Run, nil
	}
	advanced, err := loaded.Run.RecordRollback(domain.RemediationVerification{Postconditions: results}, facts.Now)
	if err != nil {
		return domain.RemediationRun{}, err
	}
	audit, err := service.newAudit(RemediationAuditEvent{Kind: RemediationAuditVerification, ClusterID: cluster, RunID: id, AttemptID: loaded.LatestAttemptID, ActorID: actor, Outcome: string(advanced.State()), RecipeDigest: plan.Rollback.Digest, TargetSetDigest: plan.TargetSetDigest})
	if err != nil {
		return domain.RemediationRun{}, err
	}
	err = service.runs.RecordRemediationTransition(ctx, RemediationTransition{ClusterID: cluster, Run: advanced, ExpectedVersion: loaded.Run.Version(), Phase: RemediationPhaseRollbackVerify, Observations: observations, DeadlineAt: loaded.DeadlineAt, AttentionRequired: !restored}, audit)
	return advanced, err
}

// The observation adapter supplies its database read instant, which can be later
// than the policy snapshot. Source timestamps are validated independently.
func remediationObservationTime(now time.Time, observations []domain.ConditionObservation) time.Time {
	for _, o := range observations {
		if o.ReadAt.After(now) {
			now = o.ReadAt
		}
	}
	return now
}
