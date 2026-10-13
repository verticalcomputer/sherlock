//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestM15SupervisorClaimGenerationFencesStaleRelease(t *testing.T) {
	fixture := newRemediationFixture(t)
	plan := fixture.plan(t, domain.RemediationRunID("supervisor-fence-"+fixture.suffix), fixture.targets[:1])
	if _, created := fixture.create(t, plan, "supervisor-fence"); !created {
		t.Fatal("expected remediation run to be created")
	}

	ctx := context.Background()
	first, err := fixture.store.ClaimRemediation(ctx, fixture.clusterID, "shared-supervisor", time.Minute)
	if err != nil || first.RunID != plan.RunID || first.Generation < 1 {
		t.Fatalf("first claim = %+v, err = %v", first, err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_runs SET supervisor_until=clock_timestamp()-interval '1 second' WHERE cluster_id=$1 AND run_id=$2`, fixture.clusterID, plan.RunID); err != nil {
		t.Fatal(err)
	}
	second, err := fixture.store.ClaimRemediation(ctx, fixture.clusterID, "shared-supervisor", time.Minute)
	if err != nil || second.RunID != plan.RunID || second.Generation != first.Generation+1 {
		t.Fatalf("takeover claim = %+v, err = %v", second, err)
	}
	if current, err := fixture.store.RemediationClaimCurrent(ctx, fixture.clusterID, first); err != nil || current {
		t.Fatalf("stale claim current = %v, err = %v", current, err)
	}
	if current, err := fixture.store.RemediationClaimCurrent(ctx, fixture.clusterID, second); err != nil || !current {
		t.Fatalf("successor claim current = %v, err = %v", current, err)
	}
	if err := fixture.store.ReleaseRemediation(ctx, fixture.clusterID, first, 0); !errors.Is(err, application.ErrRemediationLeaseInvalid) {
		t.Fatalf("stale release error = %v", err)
	}
	if current, err := fixture.store.RemediationClaimCurrent(ctx, fixture.clusterID, second); err != nil || !current {
		t.Fatalf("stale release disturbed successor: current = %v, err = %v", current, err)
	}
	stored, found, err := fixture.store.LoadRemediationRun(ctx, fixture.clusterID, plan.RunID)
	if err != nil || !found {
		t.Fatalf("load run for stale transition: found=%t err=%v", found, err)
	}
	checking, err := stored.Run.BeginPolicyCheck(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	staleCtx := storepg.ContextWithRemediationSupervisorClaim(ctx, first)
	if err = fixture.store.RecordRemediationTransition(staleCtx, application.RemediationTransition{
		ClusterID: fixture.clusterID, Run: checking, ExpectedVersion: stored.Run.Version(),
	}, fixture.audit(application.RemediationAuditPolicy, plan, "stale-supervisor")); !errors.Is(err, application.ErrRemediationLeaseInvalid) {
		t.Fatalf("stale supervisor transition error = %v", err)
	}
	stored, found, err = fixture.store.LoadRemediationRun(ctx, fixture.clusterID, plan.RunID)
	if err != nil || !found || stored.Run.State() != domain.RemediationProposed {
		t.Fatalf("stale supervisor changed run: found=%t state=%s err=%v", found, stored.Run.State(), err)
	}
	if err := fixture.store.ReleaseRemediation(ctx, fixture.clusterID, second, 0); err != nil {
		t.Fatalf("release current claim: %v", err)
	}
}
