package alertassessment_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

func TestAssessmentReportIndependentDetectionAndRequestTime(t *testing.T) {
	s, registry := fixture(t)
	s.Config.RunDurationSeconds = 300
	start := s.StartAt
	asset := s.Config.Assets[0].EntityKey
	when := func(sec int) time.Time { return start.Add(time.Duration(sec) * time.Second) }
	due := when(60)
	labels := []a.Label{
		{Asset: asset, From: when(0), Through: when(100), Classification: "ACTIONABLE", ActionDue: &due},
		{Asset: asset, From: when(100), Through: when(150), Classification: "TRANSIENT"},
		{Asset: asset, From: when(150), Through: when(200), Classification: "UNKNOWN"},
		{Asset: asset, From: when(200), Through: when(250), Classification: "ACTIONABLE"},
	}
	e, err := a.NewEngine(t.Context(), s.Config, start, registry)
	if err != nil {
		t.Fatal(err)
	}
	e.State = "CLOSED"
	seq := int64(0)
	add := func(entry int, terminalAt time.Time, outcome, action string) *a.Candidate {
		seq++
		c := &a.Candidate{ID: fmt.Sprintf("candidate-%02d", seq), Sequence: seq, Asset: asset, BudgetMS: 0, EnteredAt: when(entry), Phase: "FINAL"}
		d := a.Decision{ID: fmt.Sprintf("decision-%02d", seq), CandidateID: c.ID, Asset: asset, Sequence: seq, BudgetMS: 0, Kind: "TERMINAL", LogicalAt: terminalAt, Action: action, DecisionSource: "CATEGORY", Outcome: outcome}
		e.Candidates = append(e.Candidates, c)
		e.Decisions = append(e.Decisions, d, d)
		return c
	}
	warming := "gpu_cooling/COOLING_SUSPECTED"
	unresolved := "gpu_cooling/UNRESOLVED_WARMING"
	first := add(0, when(50), unresolved, "INVESTIGATE")
	add(65, when(68), unresolved, "INVESTIGATE")
	e.Decisions = append(e.Decisions, a.Decision{ID: "supported-update", CandidateID: first.ID, BudgetMS: 0, Asset: asset, Kind: "UPDATE", LogicalAt: when(70), Action: "URGENT", DecisionSource: "CATEGORY", Codes: []string{"urgent"}})
	add(100, when(105), warming, "INVESTIGATE")
	add(150, when(155), warming, "INVESTIGATE")
	add(270, when(275), warming, "INVESTIGATE")
	legacy := []a.Legacy{{Asset: asset, At: when(40), Triggered: true}, {Asset: asset, At: when(40), Triggered: true}, {Asset: asset, At: when(45), Triggered: true}, {Asset: asset, At: when(101), Triggered: false}}
	var rows []a.ScoreRow
	summaries, err := e.ScoreWithLegacy(labels, legacy, func(r a.ScoreRow) error {
		if r.BudgetMS == 0 {
			rows = append(rows, r)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r := rows[0]
	if r.AssociatedSequences != 2 || r.RequestSequences != 2 || r.DetectedSequences != 1 || r.AdditionalRequestSequences != 1 || r.AdditionalDetectedSequences != 0 ||
		r.RequestDeadline != "MET" || r.RequestDelayUS == nil || *r.RequestDelayUS != 50_000_000 || r.DetectionDelayUS == nil || *r.DetectionDelayUS != 70_000_000 || r.Legacy.CapturedEvaluations != 2 || r.Legacy.TriggeredEvaluations != 2 {
		t.Fatalf("incorrect independent statistics %+v", r)
	}
	if rows[1].AssociatedSequences != 1 || rows[1].Legacy.CapturedEvaluations != 1 || rows[1].Legacy.TriggeredEvaluations != 0 || rows[2].ScoringStatus != "UNKNOWN_LABEL" || rows[2].Detected != nil {
		t.Fatalf("incorrect boundary/unknown association %+v", rows)
	}
	if s := summaries[0]; s.TP != 1 || s.FP != 1 || s.UnscoredDetectedSequences != 2 || s.DetectedActionableLabels != 1 || s.DetectionMisses != 1 || s.RequestMisses != 1 || s.Recall.Value == nil || *s.Recall.Value != 0.5 {
		t.Fatalf("incorrect summary %+v", s)
	}
	if s := summaries[1]; s.Precision.Status != "UNAVAILABLE" || s.Recall.Value == nil || *s.Recall.Value != 0 || s.DetectionMisses != 2 {
		t.Fatalf("candidate-free summary %+v", s)
	}
	for _, delta := range []time.Duration{0, time.Microsecond} {
		e.Decisions[0].LogicalAt = due.Add(delta)
		e.Decisions[1].LogicalAt = e.Decisions[0].LogicalAt
		_, err = e.Score(labels, func(row a.ScoreRow) error {
			if row.BudgetMS == 0 && row.From == start {
				want := "MET"
				if delta > 0 {
					want = "LATE"
				}
				if row.RequestDeadline != want {
					t.Fatalf("deadline delta %s got %s", delta, row.RequestDeadline)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	first.Phase = "QUARANTINED"
	incomplete, err := e.Score(labels, func(row a.ScoreRow) error {
		if row.ScoringStatus != "INCOMPLETE" || row.Detected != nil || row.Requested != nil {
			t.Fatalf("incomplete row %+v", row)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(incomplete)
	if err != nil || bytes.Contains(b, []byte("precision")) || !bytes.Contains(b, []byte(first.ID)) {
		t.Fatalf("incomplete report %s %v", b, err)
	}
}

func TestAssessmentReportRejectsOverlapAndConflictingCapture(t *testing.T) {
	s, _ := fixture(t)
	base := s.Labels[0]
	s.Labels = append(s.Labels, a.Label{Asset: base.Asset, From: base.From.Add(time.Second), Through: base.Through, Classification: "UNKNOWN"})
	if a.ValidateLabels(s) == nil {
		t.Fatal("overlapping label accepted")
	}
	s.Labels = s.Labels[:1]
	s.Legacy = append(s.Legacy, a.Legacy{Asset: s.Legacy[0].Asset, At: s.Legacy[0].At, Triggered: !s.Legacy[0].Triggered})
	if a.ValidateLabels(s) == nil {
		t.Fatal("conflicting legacy capture accepted")
	}
}

func TestAssessmentMarkdownEscapesAndBoundsPreview(t *testing.T) {
	r := a.Report{RunID: "[fake](https://example.com)", Decisions: []a.Decision{{Action: "INVESTIGATE", Asset: "asset\n## injected", Summary: "[x](javascript:evil) <img>\n" + strings.Repeat("猫*_", 1000)}}}
	text := a.MarkdownReport(r)
	if strings.Contains(text, "## injected") || strings.Contains(text, "[x](javascript:evil)") || strings.Contains(text, "<img>") || !strings.Contains(text, "[Evidence](evidence.ndjson)") || !strings.Contains(text, "SHADOW — NOT SENT") {
		t.Fatalf("unsafe preview %q", text[:min(500, len(text))])
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "- ") && (len(line) > 3000 || !strings.Contains(line, "[truncated]")) {
			t.Fatalf("unexpected preview limit %d", len(line))
		}
	}
}
