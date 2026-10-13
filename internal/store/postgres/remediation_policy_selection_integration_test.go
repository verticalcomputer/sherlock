//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestRemediationPolicySelection(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled tie", true: "enabled tie"}[enabled], func(t *testing.T) {
			f := newRemediationFixture(t)
			input, audit := newRemediationDispatchSecurityInput(t, f, f.targets[:1], 2, 0)
			ctx := context.Background()
			_, err := f.pool.Exec(ctx, `INSERT INTO remediation_policies
    (cluster_id,policy_id,version,recipe_id,recipe_version,enabled,max_tier,incident_kinds,max_targets,max_concurrent_runs,cooldown_seconds,evidence_max_age_seconds,min_evidence_coverage,not_before,not_after)
    SELECT cluster_id,policy_id||'-tie',version,recipe_id,recipe_version,$2,max_tier,incident_kinds,max_targets,max_concurrent_runs,cooldown_seconds,evidence_max_age_seconds,min_evidence_coverage,not_before,not_after
    FROM remediation_policies WHERE cluster_id=$1`, f.clusterID, enabled)
			if err != nil {
				t.Fatal(err)
			}
			q := application.RemediationFactQuery{ClusterID: f.clusterID, RecipeID: input.Run.Plan().Recipe.ID, RecipeVersion: input.Run.Plan().Recipe.Version, RunID: input.Run.Plan().RunID}
			facts, err := f.store.ReadRemediationFacts(ctx, q)
			if err != nil || !facts.Policy.Ambiguous {
				t.Fatalf("tie must be explicit: facts=%+v err=%v", facts.Policy, err)
			}
			if _, err = f.store.DispatchRemediationAttempt(ctx, input, audit); !errors.Is(err, application.ErrRemediationForbidden) {
				t.Fatalf("tie must block commit-time dispatch: %v", err)
			}
			assertNoRemediationAttempt(t, f, input.Attempt.ID)
			// A unique newer disabled policy must win, never fall back to enabled.
			if _, err = f.pool.Exec(ctx, `UPDATE remediation_policies SET version=2,enabled=false WHERE cluster_id=$1 AND policy_id LIKE '%-tie'`, f.clusterID); err != nil {
				t.Fatal(err)
			}
			facts, err = f.store.ReadRemediationFacts(ctx, q)
			if err != nil || facts.Policy.Ambiguous || facts.Policy.Version != 2 || facts.EnabledCluster {
				t.Fatalf("newest disabled policy must win: %+v %v", facts, err)
			}
		})
	}
}

func TestRemediationCooldownAdmissionRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, state    string
		count          int
		durableAttempt bool
		blocked        bool
	}{
		{"admission refusal", "POLICY_BLOCKED", 0, false, false},
		{"counter records attempt", "POLICY_BLOCKED", 1, false, true},
		{"durable attempt despite zero counter", "POLICY_BLOCKED", 0, true, true},
		{"failed run", "FAILED", 0, false, true},
		{"cancelled run", "CANCELLED", 0, false, true},
		{"uncertain contained run", "CONTAINED", 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRemediationFixture(t)
			input, audit := newRemediationDispatchSecurityInput(t, f, f.targets[:1], 2, 3600)
			plan := f.plan(t, domain.RemediationRunID("cooldown-prior-"+f.suffix), f.targets[1:2])
			plan.ActionCardID = ""
			prior, _ := f.create(t, plan, "cooldown-prior")
			ctx := context.Background()
			if tc.durableAttempt {
				priorInput, priorAudit := remediationDispatchInputForPlan(t, f, prior, plan, input.Policy, f.targets[1], "prior")
				if _, err := f.store.DispatchRemediationAttempt(ctx, priorInput, priorAudit); err != nil {
					t.Fatal(err)
				}
			}
			// Simulate durable historical records, including a stale attempt counter.
			if _, err := f.pool.Exec(ctx, `UPDATE remediation_runs SET state=$3,total_attempts=$4,completed_at=clock_timestamp() WHERE cluster_id=$1 AND run_id=$2`, f.clusterID, plan.RunID, tc.state, tc.count); err != nil {
				t.Fatal(err)
			}
			facts, err := f.store.ReadRemediationFacts(ctx, application.RemediationFactQuery{ClusterID: f.clusterID, RecipeID: plan.Recipe.ID, RecipeVersion: plan.Recipe.Version, RunID: input.Run.Plan().RunID})
			if err != nil {
				t.Fatal(err)
			}
			recent := facts.LastRunEndedAt != nil && time.Since(*facts.LastRunEndedAt) < time.Minute
			if recent != tc.blocked {
				t.Fatalf("cooldown recent=%v want %v", recent, tc.blocked)
			}
			_, err = f.store.DispatchRemediationAttempt(ctx, input, audit)
			if tc.blocked {
				if !errors.Is(err, application.ErrRemediationForbidden) {
					t.Fatalf("prior attempt must block: %v", err)
				}
				assertNoRemediationAttempt(t, f, input.Attempt.ID)
			} else if err != nil {
				t.Fatalf("admission refusal must allow dispatch: %v", err)
			}
		})
	}
}
