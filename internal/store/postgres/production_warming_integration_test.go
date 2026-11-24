//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

// Use the same retained facts and outbox as the evaluator. All model actions
// are injected, and no delivery worker or webhook exists in this test.
func TestProductionWarmingReviewFence(t *testing.T) {
	for _, mode := range []string{"notify", "watch", "disable during inference", "expired claim", "recover during inference", "dip during inference", "conflict during inference", "coverage during inference", "power gap between scrapes", "stale during inference", "unchanged crossing", "fallback", "missing reference", "rapid", "mixed", "rebound", "urgent during inference", "legacy", "first worsening", "delayed tail", "delayed entry receipt"} {
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
			if mode == "unchanged crossing" {
				anchor = now.Add(-32 * time.Second)
			}
			if mode == "stale during inference" {
				anchor = now.Add(-70 * time.Second)
			}
			d := a.Decision{ID: strings.Repeat("a", 64), CandidateID: strings.Repeat("b", 64), Asset: asset, LogicalAt: now, Kind: "TERMINAL", Action: "INVESTIGATE", Outcome: "gpu_cooling/UNRESOLVED_WARMING", TerminalEndpoint: &a.FeatureRef{SourceAt: now, Value: 80}}
			if mode == "first worsening" {
				d.Kind, d.Outcome, d.Codes = "UPDATE", "", []string{"higher_temperature"}
				d.LogicalAt, d.TerminalEndpoint = anchor, nil
			}
			if mode == "fallback" {
				d.Outcome = ""
				d.DecisionSource = "HOST_FALLBACK"
				d.HostCause = "DEADLINE_FALLBACK"
				d.TerminalEndpoint = nil
			}
			entered := anchor
			if mode == "delayed entry receipt" {
				entered = anchor.Add(10 * time.Second)
			}
			if mode == "first worsening" {
				entered = anchor.Add(-15 * time.Minute)
			}
			var facts []a.Fact
			for i := -10; i <= 2; i++ {
				at := anchor.Add(time.Duration(i) * 15 * time.Second)
				group := productionStoreSamples(t, c, at)
				if i < -1 && mode != "rebound" && mode != "missing reference" {
					for j, fact := range group {
						var sample a.Sample
						if err := json.Unmarshal(fact.Body, &sample); err != nil {
							t.Fatal(err)
						}
						if sample.Metric != cooling.Temperature {
							continue
						}
						sample.Value = 70
						var err error
						group[j], err = a.NewFact(c.Assessment.Category, c.Assessment.RunID, asset, "SAMPLE", at, sample)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				if mode == "delayed entry receipt" && i <= 0 {
					for j, fact := range group {
						reissued, err := a.NewFact(c.Assessment.Category, c.Assessment.RunID, asset, fact.Kind, entered, fact.Body)
						if err != nil {
							t.Fatal(err)
						}
						group[j] = reissued
					}
				}
				facts = append(facts, group...)
			}
			entryThrough := len(facts) - 6 // Immutable entry history plus the warm endpoint before crossing.
			proof, _ := json.Marshal(map[string]any{"facts": facts[:entryThrough]})
			snapshot, _ := json.Marshal(map[string]any{"facts": facts[entryThrough:]})
			st := cooling.State{Schema: 1, Branches: []string{"SLOW"}, Reference: &a.FeatureRef{SourceAt: anchor.Add(-10 * time.Minute), Value: 70}, EntryEndpoint: &a.FeatureRef{SourceAt: anchor, Value: 80}}
			switch mode {
			case "first worsening":
				st.EntryEndpoint = &a.FeatureRef{SourceAt: anchor.Add(-15 * time.Minute), Value: 62}
			case "missing reference":
				st.EntryEndpoint = nil
			case "rapid", "rebound":
				st.Branches = []string{"RAPID"}
			case "mixed":
				st.Branches = []string{"RAPID", "SLOW"}
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
			hold, err := queueWarming(ctx, tx, d, initial, entered, s.config.Revision)
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
			if mode == "legacy" {
				f.exec(t, `UPDATE production_assessment_decisions SET warming_comparable=false,warming_reference_c=70,warming_reference_at=$2 WHERE event_id=$1`, d.ID, anchor.Add(-10*time.Minute))
			}
			lookups := 0
			if mode == "notify" || mode == "rebound" || mode == "delayed entry receipt" {
				s.SetWarmingProfileLookup(func(gpu string, at time.Time, c cooling.WarmingContext) *cooling.HistoricalProfile {
					lookups++
					if gpu != asset || !at.Equal(entered) || c.ComparableLoad == nil {
						t.Fatal("incorrect profile lookup")
					}
					normal, upper := 69., 72.
					return &cooling.HistoricalProfile{Status: "qualified", MedianC: &normal, P95C: &upper, CenterW: 200, Samples: 10, Days: 8, Periods: 9}
				})
			}
			calls := 0
			infer := func(ctx context.Context, raw json.RawMessage) (string, string, error) {
				calls++
				if strings.Contains(string(raw), asset) || !strings.Contains(string(raw), `"reference_c":70`) {
					t.Fatal("unsafe or incomplete model input")
				}
				if (mode == "notify" || mode == "delayed entry receipt") && !strings.Contains(string(raw), `"historical_profile":{"status":"qualified"`) {
					t.Fatal("profile unavailable in model request")
				}
				switch mode {
				case "urgent during inference":
					tx, err := beginProductionAssessmentTx(ctx, s.pool)
					if err != nil {
						t.Fatal(err)
					}
					defer rollbackMonitoringTx(tx)
					urgent := a.Decision{CandidateID: d.CandidateID, ID: strings.Repeat("f", 64), Action: "URGENT", Kind: "UPDATE"}
					if err = retireWarmingForUrgent(ctx, tx, c.Assessment.RunID, urgent); err != nil {
						t.Fatal(err)
					}
					if err = tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				case "dip during inference", "unchanged crossing", "delayed tail":
					source := anchor.Add(45 * time.Second)
					if mode == "unchanged crossing" {
						source = time.Now().UTC()
					}
					fresh := productionStoreSamples(t, c, source)
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
					updateWarmingTestSnapshot(t, f, c.Assessment.RunID, append(facts[entryThrough:], fresh...))
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
					updateWarmingTestSnapshot(t, f, c.Assessment.RunID, append(facts[entryThrough:], negative))
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
			if mode == "missing reference" || mode == "rebound" {
				expectedCalls = 0
			}
			if calls != expectedCalls {
				t.Fatalf("calls %d", calls)
			}
			var status, message string
			if err = f.admin.QueryRow(ctx, `SELECT status,message FROM gp09_alert_outbox WHERE event_key=$1`, d.ID).Scan(&status, &message); err != nil {
				t.Fatal(err)
			}
			if mode == "notify" || mode == "unchanged crossing" || mode == "fallback" || mode == "rapid" || mode == "mixed" || mode == "legacy" || mode == "first worsening" || mode == "delayed entry receipt" {
				if status != "PENDING" || !strings.Contains(message, "70 → 80") || !strings.Contains(message, "Sustained increase") {
					t.Fatalf("unexpected notification %s %q", status, message)
				}
			} else if status != "DISABLED" {
				t.Fatalf("unexpected delivery %s", status)
			}
			if mode == "notify" || mode == "watch" {
				var audit []byte
				if err := f.admin.QueryRow(ctx, `SELECT warming_calls FROM production_assessment_decisions WHERE event_id=$1`, d.ID).Scan(&audit); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(audit), `"comparable_load"`) {
					t.Fatalf("reference not audited: %s", audit)
				}
				if mode == "notify" && (!strings.Contains(message, "24-day profile near 200 W") || !strings.Contains(string(audit), `"historical_profile"`)) {
					t.Fatal("historical context missing")
				}
			}
			if mode == "rebound" {
				// Rotation of the daily profile while an occurrence is open
				// cannot replace its reference, even during a held retry.
				f.exec(t, `UPDATE production_assessment_decisions SET warming_next_at=clock_timestamp() WHERE event_id=$1`, d.ID)
				if err = s.ProcessWarmingTriage(ctx, infer); err != nil || lookups != 1 || calls != 0 {
					t.Fatalf("held retry lookups %d, inferences %d: %v", lookups, calls, err)
				}
				var stored, audited float64
				if err = f.admin.QueryRow(ctx, `SELECT (warming_profile->>'median_c')::float8,(warming_gate#>>'{historical_profile,median_c}')::float8 FROM production_assessment_decisions WHERE event_id=$1`, d.ID).Scan(&stored, &audited); err != nil || stored != 69 || audited != stored {
					t.Fatalf("pinned and audited reference %v %v: %v", stored, audited, err)
				}
				var gate string
				if err := f.admin.QueryRow(ctx, `SELECT warming_gate->>'status' FROM production_assessment_decisions WHERE event_id=$1`, d.ID).Scan(&gate); err != nil || gate != "awaiting_sustained_crossing" {
					t.Fatalf("held rebound audit %s: %v", gate, err)
				}
			}
			if err = s.ProcessWarmingTriage(ctx, infer); err != nil || calls != expectedCalls {
				t.Fatalf("duplicate call %d %v", calls, err)
			}
			if mode == "rebound" || mode == "urgent during inference" || mode == "notify" {
				// Exercise the follow-up path using the same predicate and publisher
				// as the assessment pass. A recovery must follow the original intent.
				tx, err := beginProductionAssessmentTx(ctx, s.pool)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackMonitoringTx(tx)
				held, err := warmingOpenHeld(ctx, tx, c.Assessment.RunID, d.CandidateID)
				if err != nil || held != (mode != "notify") {
					t.Fatalf("follow-up hold %t: %v", held, err)
				}
				recoveryID := strings.Repeat("9", 64)
				if err = PublishProductionAssessment(ctx, tx, ProductionAssessmentEvent{EnrollmentID: c.Assessment.RunID, ClusterID: c.Assessment.ClusterID, SourceID: c.Assessment.SourceID, Category: c.Assessment.Category, Asset: asset, OccurrenceID: d.CandidateID, EventID: recoveryID, Kind: "RECOVER", Summary: "Recovered", Evidence: proof, At: now, warmingHold: held}); err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				var recoveryStatus string
				if err = f.admin.QueryRow(ctx, `SELECT status FROM gp09_alert_outbox WHERE event_key=$1`, recoveryID).Scan(&recoveryStatus); err != nil || recoveryStatus != status {
					t.Fatalf("recovery intent %s, original %s: %v", recoveryStatus, status, err)
				}
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

func TestComparableWarmingMigrationRoundTrip(t *testing.T) {
	f := newAssessmentFixture(t)
	for _, direction := range []string{"down", "up"} {
		sql, err := os.ReadFile("../../../migrations/000093_warming_comparable_load." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.admin.Exec(t.Context(), string(sql)); err != nil {
			t.Fatal(err)
		}
	}
}
