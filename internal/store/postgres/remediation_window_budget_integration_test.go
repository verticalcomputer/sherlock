//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestRemediationWindowBudgetSerializesDispatch(t *testing.T) {
	f := newRemediationFixture(t)
	first, firstAudit := newRemediationDispatchSecurityInput(t, f, f.targets[:1], 3, 0)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE remediation_policies SET max_forward_attempts=1 WHERE cluster_id=$1`, f.clusterID); err != nil {
		t.Fatal(err)
	}
	plan := f.plan(t, domain.RemediationRunID("window-second-"+f.suffix), f.targets[1:2])
	plan.ActionCardID = ""
	stored, _ := f.create(t, plan, "window-second-create")
	second, secondAudit := remediationDispatchInputForPlan(t, f, stored, plan, first.Policy, f.targets[1], "window-second")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, d := range []struct {
		i application.RemediationDispatchInput
		a application.RemediationAuditEvent
	}{{first, firstAudit}, {second, secondAudit}} {
		go func(d struct {
			i application.RemediationDispatchInput
			a application.RemediationAuditEvent
		}) {
			<-start
			_, err := f.store.DispatchRemediationAttempt(ctx, d.i, d.a)
			results <- err
		}(d)
	}
	close(start)
	allowed, denied := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			allowed++
		} else if errors.Is(err, application.ErrRemediationForbidden) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if allowed != 1 || denied != 1 {
		t.Fatalf("allowed %d denied %d", allowed, denied)
	}
	facts, err := f.store.ReadRemediationFacts(ctx, application.RemediationFactQuery{ClusterID: f.clusterID, RecipeID: plan.Recipe.ID, RecipeVersion: plan.Recipe.Version})
	if err != nil || facts.ForwardAttemptsInWindow == nil || *facts.ForwardAttemptsInWindow != 1 {
		t.Fatalf("window usage %v error %v", facts.ForwardAttemptsInWindow, err)
	}
}
