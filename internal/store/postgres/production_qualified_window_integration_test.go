//go:build integration

package postgres

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

func TestProductionQualifiedEpisodeBetweenAcquisitions(t *testing.T) {
	f, store, c, now := productionStoreFixture(t)
	ctx := t.Context()
	asset := c.Assessment.Assets[0]
	id := "short-qualified-episode"
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	_, err = tx.Exec(ctx, `INSERT INTO gp09_monitor_enrollments(policy_id,cluster_id,source_id,entity_key,rule_id,rule_version,operation,scope_key,policy,evaluator_state) VALUES($1,$2,$3,$4,'gpu_thermal',1,'temperature',$5,'{}','{}')`, id, c.Assessment.ClusterID, c.Assessment.SourceID, asset.EntityKey, fmt.Sprintf("%064d", 1))
	if err != nil {
		t.Fatal(err)
	}
	policy := monitoring.Policy{ID: id, ClusterID: domain.ClusterID(c.Assessment.ClusterID), SourceID: domain.SourceID(c.Assessment.SourceID), EntityKey: asset.EntityKey, Rule: monitoring.RuleGPUThermal, RuleVersion: 1, Revision: 1}
	checkpoint := now.Add(-30 * time.Second)
	openAt, closeAt := checkpoint.Add(2*time.Second), checkpoint.Add(17*time.Second)
	for _, v := range []monitoring.Transition{
		{Kind: monitoring.TransitionOpen, Occurrence: 1, At: openAt, Severity: domain.HealthSeverityCritical, Reason: monitoring.ReasonThermalThreshold},
		{Kind: monitoring.TransitionRecover, Occurrence: 1, At: closeAt, Severity: domain.HealthSeverityCritical, Reason: monitoring.ReasonFreshRecovery},
	} {
		if err := publishMonitoringTransition(ctx, tx, policy, v, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	for _, tc := range []struct {
		checkpoint time.Time
		want       int
	}{{checkpoint, 2}, {time.Time{}, 0}, {now, 0}} {
		facts, err := loadAssessmentQualified(ctx, tx, c.Assessment, asset, now, tc.checkpoint)
		if err != nil || len(facts) != tc.want {
			t.Fatalf("checkpoint %s: got %d facts, want %d: %v", tc.checkpoint, len(facts), tc.want, err)
		}
		for i, f := range facts {
			var q a.Qualified
			if err := json.Unmarshal(f.Body, &q); err != nil {
				t.Fatal(err)
			}
			if q.Transition != []string{"OPEN", "RECOVER"}[i] || !f.AvailableAt.Equal([]time.Time{openAt, closeAt}[i]) {
				t.Fatalf("unexpected qualified transition %s at %s", q.Transition, f.AvailableAt)
			}
		}
		if tc.want > 0 {
			engine, err := a.NewProductionAssetEngine(ctx, c, checkpoint, store.registry, asset.EntityKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.AdvanceProductionBatch(ctx, asset.EntityKey, now, facts); err != nil {
				t.Fatal(err)
			}
			if len(engine.Decisions) == 0 || engine.Decisions[0].Action != "URGENT" || !engine.Decisions[0].LogicalAt.Equal(openAt) {
				t.Fatalf("critical OPEN lost between acquisitions: %+v", engine.Decisions)
			}
		}
	}
}
