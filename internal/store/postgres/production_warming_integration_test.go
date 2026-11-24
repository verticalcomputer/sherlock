//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

// Use the same retained facts and outbox as the evaluator. All model actions
// are injected, and no delivery worker or webhook exists in this test.
func TestProductionWarmingReviewFence(t *testing.T) {
	for _, mode := range []string{"notify", "watch", "disable during inference", "expired claim", "recover during inference", "dip during inference", "conflict during inference", "coverage during inference", "power gap between scrapes", "stale during inference", "unchanged crossing", "fallback", "missing reference"} {
		t.Run(mode, func(t *testing.T) {
			f, s, c, now := productionStoreFixture(t)
			ctx := t.Context()
			s.config.Revision++
			s.config.WarmingTriage = true
			if err := s.Start(ctx); err != nil {
				t.Fatal(err)
			}
			asset := c.Assessment.Assets[0].EntityKey
			anchor := now.Add(-61 * time.Second)
			if mode == "stale during inference" {
				anchor = now.Add(-70 * time.Second)
			}
			d := a.Decision{ID: strings.Repeat("a", 64), CandidateID: strings.Repeat("b", 64), Asset: asset, LogicalAt: now, Kind: "TERMINAL", Action: "INVESTIGATE", Outcome: "gpu_cooling/UNRESOLVED_WARMING", TerminalEndpoint: &a.FeatureRef{SourceAt: now, Value: 80}}
			if mode == "fallback" {
				d.Outcome = ""
				d.DecisionSource = "HOST_FALLBACK"
				d.HostCause = "DEADLINE_FALLBACK"
				d.TerminalEndpoint = nil
			}
			var facts []a.Fact
			for i := -1; i <= 2; i++ {
				facts = append(facts, productionStoreSamples(t, c, anchor.Add(time.Duration(i)*15*time.Second))...)
			}
			proof, _ := json.Marshal(map[string]any{"facts": facts[:4]})
			snapshot, _ := json.Marshal(map[string]any{"facts": facts[4:]})
			st := cooling.State{Schema: 1, Branches: []string{"SLOW"}, Reference: &a.FeatureRef{SourceAt: anchor.Add(-10 * time.Minute), Value: 70}, EntryEndpoint: &a.FeatureRef{SourceAt: anchor, Value: 80}}
			if mode == "missing reference" {
				st.Reference = nil
			}
			initial, err := a.NewPayload("gpu_cooling", "candidate", 1, st)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := beginProductionAssessmentTx(ctx, s.pool)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(tx)
			_, err = tx.Exec(ctx, `INSERT INTO production_assessment_decisions(event_id,enrollment_id,occurrence_id,asset,kind,logical_at,evidence,evidence_hash)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, d.ID, c.Assessment.RunID, d.CandidateID, asset, d.Kind, anchor, proof, strings.Repeat("c", 64))
			if err != nil {
				t.Fatal(err)
			}
			hold, err := queueWarming(ctx, tx, d, initial, s.config.Revision)
			if err != nil || !hold {
				t.Fatalf("queue=%t err=%v", hold, err)
			}
			if err = PublishProductionAssessment(ctx, tx, ProductionAssessmentEvent{EnrollmentID: c.Assessment.RunID, ClusterID: c.Assessment.ClusterID, SourceID: c.Assessment.SourceID, Category: c.Assessment.Category, Asset: asset, OccurrenceID: d.CandidateID, EventID: d.ID, Kind: "OPEN", Summary: "Warming", Evidence: proof, At: anchor, warmingHold: hold}); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE production_assessment_states SET snapshot=$2 WHERE enrollment_id=$1`, c.Assessment.RunID, snapshot); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			calls := 0
			infer := func(ctx context.Context, raw json.RawMessage) (string, string, error) {
				calls++
				if strings.Contains(string(raw), asset) || !strings.Contains(string(raw), `"reference_c":70`) {
					t.Fatal("unsafe or incomplete model input")
				}
				switch mode {
				case "dip during inference", "unchanged crossing":
					fresh := productionStoreSamples(t, c, anchor.Add(45*time.Second))
					if mode == "dip during inference" {
						for i, fact := range fresh {
							var sample a.Sample
							if err := json.Unmarshal(fact.Body, &sample); err != nil {
								t.Fatal(err)
							}
							if sample.Metric == cooling.Temperature {
								sample.Value = 50
								fresh[i], err = a.NewFact(c.Assessment.Category, c.Assessment.RunID, asset, "SAMPLE", fact.AvailableAt, sample)
								if err != nil {
									t.Fatal(err)
								}
							}
						}
					}
					updateWarmingTestSnapshot(t, f, c.Assessment.RunID, append(facts[4:], fresh...))
				case "conflict during inference", "coverage during inference", "power gap between scrapes":
					at := anchor.Add(30 * time.Second)
					var body any = a.Conflict{Metric: cooling.Temperature, SourceAt: at, Code: "CONFLICT"}
					kind := "CONFLICT"
					if mode == "coverage during inference" {
						body = a.Coverage{Metric: cooling.Temperature, From: at, Through: at, Code: "GAP"}
						kind = "COVERAGE"
					}
					if mode == "power gap between scrapes" {
						body = a.Coverage{Metric: cooling.Power, From: anchor.Add(7 * time.Second), Through: anchor.Add(8 * time.Second), Code: "GAP"}
						kind = "COVERAGE"
					}
					// Retained hosts consume canonical bodies. The fact ID only needs to
					// be distinct from the seeded sample IDs for this race fixture.
					raw, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					negative := a.Fact{ID: strings.Repeat("d", 64), Asset: asset, Kind: kind, Body: raw, AvailableAt: now}
					updateWarmingTestSnapshot(t, f, c.Assessment.RunID, append(facts[4:], negative))
				case "stale during inference":
					// The final source endpoint was already 40s old when claimed.
					time.Sleep(5200 * time.Millisecond)
				case "watch":
					return "WATCH", "Cooling", nil
				case "disable during inference":
					if _, err := SetProductionAssessmentNotifications(ctx, s.pool, c.Assessment.ClusterID, c.Assessment.RunID, s.config.Revision, false, "test"); err != nil {
						t.Fatal(err)
					}
				case "expired claim":
					f.exec(t, `UPDATE production_assessment_decisions SET warming_attempt=warming_attempt+1 WHERE event_id=$1`, d.ID)
				case "recover during inference":
					f.exec(t, `UPDATE production_assessment_decisions SET closed_at=clock_timestamp() WHERE event_id=$1`, d.ID)
				}
				return "NOTIFY", "Sustained increase", nil
			}
			if err = s.ProcessWarmingTriage(ctx, infer); err != nil {
				t.Fatal(err)
			}
			expectedCalls := 1
			if mode == "missing reference" {
				expectedCalls = 0
			}
			if calls != expectedCalls {
				t.Fatalf("calls %d", calls)
			}
			var status, message string
			if err = f.admin.QueryRow(ctx, `SELECT status,message FROM gp09_alert_outbox WHERE event_key=$1`, d.ID).Scan(&status, &message); err != nil {
				t.Fatal(err)
			}
			if mode == "notify" || mode == "unchanged crossing" || mode == "fallback" {
				if status != "PENDING" || !strings.Contains(message, "70 → 80") || !strings.Contains(message, "Sustained increase") {
					t.Fatalf("unexpected notification %s %q", status, message)
				}
			} else if status != "DISABLED" {
				t.Fatalf("unexpected delivery %s", status)
			}
			if err = s.ProcessWarmingTriage(ctx, infer); err != nil || calls != expectedCalls {
				t.Fatalf("duplicate call %d %v", calls, err)
			}
		})
	}
}

func updateWarmingTestSnapshot(t *testing.T, f *assessmentFixture, enrollment string, facts []a.Fact) {
	t.Helper()
	snapshot, err := json.Marshal(map[string]any{"facts": facts})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE production_assessment_states SET snapshot=$2 WHERE enrollment_id=$1`, enrollment, snapshot)
}
