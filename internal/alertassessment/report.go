package alertassessment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Ratio struct {
	Status      string   `json:"status"`
	Numerator   int64    `json:"numerator"`
	Denominator int64    `json:"denominator"`
	Value       *float64 `json:"value,omitempty"`
}

func ratio(n, d int64) Ratio {
	r := Ratio{Status: "UNAVAILABLE", Numerator: n, Denominator: d}
	if d > 0 {
		v := float64(n) / float64(d)
		r.Status = "AVAILABLE"
		r.Value = &v
	}
	return r
}

type ScoreRow struct {
	Asset                       string       `json:"asset"`
	From                        time.Time    `json:"from"`
	Through                     time.Time    `json:"through"`
	Classification              string       `json:"classification"`
	BudgetMS                    int64        `json:"budget_ms"`
	AssociatedSequences         int64        `json:"associated_sequences"`
	DetectedSequences           int64        `json:"detected_sequences"`
	RequestSequences            int64        `json:"request_sequences"`
	AdditionalDetectedSequences int64        `json:"additional_detected_sequences"`
	AdditionalRequestSequences  int64        `json:"additional_request_sequences"`
	Detected                    *bool        `json:"detected,omitempty"`
	Requested                   *bool        `json:"requested,omitempty"`
	FirstDetectionID            string       `json:"first_detection_id,omitempty"`
	FirstRequestID              string       `json:"first_request_id,omitempty"`
	DetectionDelayUS            *int64       `json:"detection_delay_us,omitempty"`
	RequestDelayUS              *int64       `json:"request_delay_us,omitempty"`
	RequestDeadline             string       `json:"request_deadline"`
	ScoringStatus               string       `json:"scoring_status"`
	ActionDue                   *time.Time   `json:"action_due,omitempty"`
	Legacy                      *LegacyScore `json:"legacy,omitempty"`
}
type ScoreSummary struct {
	BudgetMS                  int64    `json:"budget_ms"`
	ScoringStatus             string   `json:"scoring_status"`
	IncompleteCandidateIDs    []string `json:"incomplete_candidate_ids"`
	UnmatchedSequences        int64    `json:"unmatched_sequences"`
	TransientRequestSequences int64    `json:"transient_request_sequences"`
	TP                        int64    `json:"tp"`
	FP                        int64    `json:"fp"`
	UnscoredDetectedSequences int64    `json:"unscored_detected_sequences"`
	ActionableLabels          int64    `json:"actionable_labels"`
	DetectedActionableLabels  int64    `json:"detected_actionable_labels"`
	DetectionMisses           int64    `json:"detection_misses"`
	RequestMisses             int64    `json:"request_misses"`
	Precision                 Ratio    `json:"precision"`
	Recall                    Ratio    `json:"recall"`
}

func (s ScoreSummary) MarshalJSON() ([]byte, error) {
	if s.ScoringStatus == "INCOMPLETE" {
		return json.Marshal(struct {
			BudgetMS               int64    `json:"budget_ms"`
			ScoringStatus          string   `json:"scoring_status"`
			IncompleteCandidateIDs []string `json:"incomplete_candidate_ids"`
			UnmatchedSequences     int64    `json:"unmatched_sequences"`
		}{s.BudgetMS, s.ScoringStatus, s.IncompleteCandidateIDs, s.UnmatchedSequences})
	}
	type summary ScoreSummary
	return json.Marshal(summary(s))
}

type LegacyScore struct {
	Status               string     `json:"status"`
	CapturedEvaluations  int64      `json:"captured_evaluations"`
	TriggeredEvaluations int64      `json:"triggered_evaluations"`
	CapturedLabelHit     *bool      `json:"captured_label_hit,omitempty"`
	FirstTriggerAt       *time.Time `json:"first_trigger_at,omitempty"`
}

type ArmReport struct {
	BudgetMS                 int64 `json:"budget_ms"`
	PhysicalCandidates       int64 `json:"physical_candidates"`
	IndependentUrgentEntries int64 `json:"independent_urgent_entries"`
	TerminalDispositions     int64 `json:"terminal_dispositions"`
	TerminalPreviews         int64 `json:"terminal_previews"`
	SupportedConcerns        int64 `json:"supported_concerns"`
	SupportedTransients      int64 `json:"supported_transients"`
	Unresolved               int64 `json:"unresolved"`
	Updates                  int64 `json:"updates"`
	OverdueCommitments       int64 `json:"overdue_commitments"`
	AssessmentFailures       int64 `json:"assessment_failures"`
	Pending                  int64 `json:"pending"`
	Quarantined              int64 `json:"quarantined"`
}

type DecisionExecution struct {
	ID          string    `json:"id"`
	ExecutedAt  time.Time `json:"executed_at"`
	CommittedAt time.Time `json:"committed_at"`
	LatenessUS  int64     `json:"lateness_us"`
}

type ExecutionReport struct {
	ClosedAt          *time.Time          `json:"closed_at,omitempty"`
	ClosureLatenessUS int64               `json:"closure_lateness_us"`
	Decisions         []DecisionExecution `json:"decisions"`
	BuildStatus       string              `json:"build_status,omitempty"`
}

type previewChange struct {
	value    float64
	sourceAt time.Time
}

type Report struct {
	Schema                      int64             `json:"schema"`
	RunID                       string            `json:"run_id"`
	ConfigHash                  string            `json:"config_hash"`
	DescriptorHash              string            `json:"descriptor_hash"`
	Provenance                  string            `json:"provenance"`
	State                       string            `json:"state"`
	Coverage                    string            `json:"coverage"`
	Timing                      string            `json:"timing"`
	Decisions                   []Decision        `json:"decisions"`
	Failures                    []Failure         `json:"failures"`
	Scores                      []ScoreSummary    `json:"scores"`
	LegacyNotificationCounts    string            `json:"legacy_notification_counts"`
	FollowupTruncated           bool              `json:"followup_truncated"`
	StartAt                     time.Time         `json:"start_at"`
	AdmissionEndAt              time.Time         `json:"admission_end_at"`
	StopReason                  string            `json:"stop_reason,omitempty"`
	ScoringProfile              string            `json:"scoring_profile"`
	LegacyComparison            string            `json:"legacy_comparison"`
	LegacyDetectionRecall       string            `json:"legacy_detection_recall"`
	LegacyDetectionMisses       string            `json:"legacy_detection_misses"`
	LegacyNotificationPrecision string            `json:"legacy_notification_precision"`
	Arms                        []ArmReport       `json:"arms"`
	FailureOverflow             int64             `json:"failure_overflow"`
	MonitoringQualification     string            `json:"monitoring_qualification"`
	MonitoringPreviews          int64             `json:"monitoring_previews"`
	MonitoringAnnotations       int64             `json:"monitoring_annotations"`
	Telemetry                   []TelemetryRecord `json:"telemetry"`
	Execution                   ExecutionReport   `json:"execution"`
	HigherTemperatureCoverage   map[string]string `json:"higher_temperature_coverage"`
	Comparison                  string            `json:"comparison"`
	ExecutionNotReproduced      []string          `json:"execution_not_reproduced"`
	RecordedBuildHash           string            `json:"recorded_build_hash,omitempty"`
	BuildStatus                 string            `json:"build_status,omitempty"`
	DetectionQuality            string            `json:"detection_quality"`
	decisionElapsedMS           map[string]int64
	previewChanges              map[string]previewChange
	UnknownFrom                 *time.Time         `json:"unknown_from,omitempty"`
	UnknownThrough              *time.Time         `json:"unknown_through,omitempty"`
	CoverageIntervals           []CoverageInterval `json:"coverage_intervals,omitempty"`
}

func ValidateLabels(s Suite) error {
	assets := map[string]bool{}
	for _, a := range s.Config.Assets {
		assets[a.EntityKey] = true
	}
	end := s.StartAt.Add(time.Duration(s.Config.RunDurationSeconds) * time.Second)
	labels := append([]Label{}, s.Labels...)
	sort.Slice(labels, func(i, j int) bool {
		if labels[i].Asset != labels[j].Asset {
			return labels[i].Asset < labels[j].Asset
		}
		return labels[i].From.Before(labels[j].From)
	})
	for i, l := range labels {
		if !assets[l.Asset] || !l.From.Before(l.Through) || l.From.Before(s.StartAt) || l.Through.After(end) || !slices.Contains([]string{"ACTIONABLE", "TRANSIENT", "UNKNOWN"}, l.Classification) {
			return ErrInvalid
		}
		if i > 0 && labels[i-1].Asset == l.Asset && l.From.Before(labels[i-1].Through) {
			return ErrInvalid
		}
		if l.ActionDue != nil && (l.Classification != "ACTIONABLE" || l.ActionDue.Before(l.From) || l.ActionDue.After(l.Through.Add(120*time.Second))) {
			return ErrInvalid
		}
	}
	captures := map[string]bool{}
	for _, l := range s.Legacy {
		if !assets[l.Asset] {
			return ErrInvalid
		}
		k := l.Asset + "/" + l.At.UTC().Format(time.RFC3339Nano)
		if old, ok := captures[k]; ok && old != l.Triggered {
			return ErrInvalid
		}
		captures[k] = l.Triggered
	}
	return nil
}
func (e *Engine) evidenceClass(d Decision) string {
	if d.DecisionSource == "HOST_FALLBACK" {
		return "UNRESOLVED"
	}
	if d.DecisionSource != "CATEGORY" {
		return ""
	}
	if d.Kind == "TERMINAL" {
		for _, o := range e.descriptor.Outcomes {
			if o.Code == d.Outcome && o.Phase == "FINAL" {
				return o.EvidenceClass
			}
		}
	}
	if d.Kind == "UPDATE" {
		class := ""
		for _, u := range e.descriptor.Updates {
			if slices.Contains(d.Codes, u.Code) {
				if u.EvidenceClass == "SUPPORTED_CONCERN" {
					return u.EvidenceClass
				}
				class = u.EvidenceClass
			}
		}
		return class
	}
	return ""
}

func decisionOrder(a, b Decision) int {
	if n := a.LogicalAt.Compare(b.LogicalAt); n != 0 {
		return n
	}
	return strings.Compare(a.ID, b.ID)
}

func sortedLabels(labels []Label) []Label {
	out := append([]Label{}, labels...)
	slices.SortFunc(out, func(a, b Label) int {
		if a.Asset != b.Asset {
			return strings.Compare(a.Asset, b.Asset)
		}
		if n := a.From.Compare(b.From); n != 0 {
			return n
		}
		return a.Through.Compare(b.Through)
	})
	return out
}

func containingLabel(ordered []Label, asset string, at time.Time) int {
	i := sort.Search(len(ordered), func(i int) bool {
		return ordered[i].Asset > asset || ordered[i].Asset == asset && ordered[i].Through.After(at)
	})
	if i == len(ordered) || ordered[i].Asset != asset || at.Before(ordered[i].From) {
		return -1
	}
	return i
}

func legacyScores(labels []Label, legacy []Legacy) map[int]LegacyScore {
	out := map[int]LegacyScore{}
	ordered := append([]Legacy{}, legacy...)
	slices.SortFunc(ordered, func(a, b Legacy) int {
		if a.Asset != b.Asset {
			return strings.Compare(a.Asset, b.Asset)
		}
		return a.At.Compare(b.At)
	})
	for i, row := range ordered {
		if i > 0 && row.Asset == ordered[i-1].Asset && row.At.Equal(ordered[i-1].At) {
			continue
		}
		li := containingLabel(labels, row.Asset, row.At)
		if li < 0 {
			continue
		}
		s := out[li]
		s.Status = "AVAILABLE"
		s.CapturedEvaluations++
		if row.Triggered {
			s.TriggeredEvaluations++
			if s.FirstTriggerAt == nil {
				t := row.At
				s.FirstTriggerAt = &t
			}
		}
		hit := s.TriggeredEvaluations > 0
		s.CapturedLabelHit = &hit
		out[li] = s
	}
	return out
}

func (e *Engine) Score(labels []Label, emit func(ScoreRow) error) ([]ScoreSummary, error) {
	return e.ScoreWithLegacy(labels, nil, emit)
}

// ScoreWithLegacy emits one row at a time. The index contains only the bounded
// candidate ledger, regardless of the number of labeled intervals.
func (e *Engine) ScoreWithLegacy(labels []Label, legacy []Legacy, emit func(ScoreRow) error) ([]ScoreSummary, error) {
	if err := ValidateLabels(Suite{Config: e.Config, StartAt: e.StartAt, Labels: labels, Legacy: legacy}); err != nil {
		return nil, err
	}
	ordered := sortedLabels(labels)
	captured := legacyScores(ordered, legacy)
	decisions := append([]Decision{}, e.Decisions...)
	slices.SortFunc(decisions, decisionOrder)
	firstDetected, firstRequest := map[string]Decision{}, map[string]Decision{}
	seen := map[string]bool{}
	terminal := map[string]bool{}
	for _, d := range decisions {
		if seen[d.ID] {
			continue
		}
		seen[d.ID] = true
		if d.Kind == "TERMINAL" {
			terminal[d.CandidateID] = true
		}
		if e.evidenceClass(d) == "SUPPORTED_CONCERN" {
			if _, ok := firstDetected[d.CandidateID]; !ok {
				firstDetected[d.CandidateID] = d
			}
		}
		if d.Action == "INVESTIGATE" || d.Action == "URGENT" {
			if _, ok := firstRequest[d.CandidateID]; !ok {
				firstRequest[d.CandidateID] = d
			}
		}
	}
	summaries := make([]ScoreSummary, len(e.Config.BudgetsMS))
	summaryIndex := map[int64]int{}
	for i, b := range e.Config.BudgetsMS {
		summaryIndex[b] = i
		summaries[i] = ScoreSummary{BudgetMS: b, ScoringStatus: "COMPLETE", IncompleteCandidateIDs: []string{}}
		if e.State != "CLOSED" {
			summaries[i].ScoringStatus = "INCOMPLETE"
		}
	}
	matched := map[int][]*Candidate{}
	incompleteIDs := []string{}
	for _, c := range e.Candidates {
		bi, ok := summaryIndex[c.BudgetMS]
		if !ok {
			continue
		}
		summary := &summaries[bi]
		if c.Phase != "FINAL" || !terminal[c.ID] {
			incompleteIDs = append(incompleteIDs, c.ID)
		}
		li := containingLabel(ordered, c.Asset, c.EnteredAt)
		if li < 0 {
			summary.UnmatchedSequences++
			if _, ok := firstDetected[c.ID]; ok {
				summary.UnscoredDetectedSequences++
			}
			continue
		}
		matched[li] = append(matched[li], c)
	}
	if len(incompleteIDs) > 0 {
		for i := range summaries {
			summaries[i].ScoringStatus = "INCOMPLETE"
			summaries[i].IncompleteCandidateIDs = SortedUnique(incompleteIDs)
		}
	}
	for li, l := range ordered {
		for bi, budget := range e.Config.BudgetsMS {
			sum := &summaries[bi]
			row := ScoreRow{Asset: l.Asset, From: l.From, Through: l.Through, Classification: l.Classification, BudgetMS: budget, ActionDue: l.ActionDue, RequestDeadline: "UNKNOWN", ScoringStatus: sum.ScoringStatus}
			capture, ok := captured[li]
			if !ok {
				capture.Status = "UNAVAILABLE"
			}
			row.Legacy = &capture
			var detection, request *Decision
			for _, c := range matched[li] {
				if c.BudgetMS != budget {
					continue
				}
				row.AssociatedSequences++
				if d, ok := firstDetected[c.ID]; ok {
					row.DetectedSequences++
					if detection == nil || decisionOrder(d, *detection) < 0 {
						chosen := d
						detection = &chosen
					}
					switch l.Classification {
					case "ACTIONABLE":
						sum.TP++
					case "TRANSIENT":
						sum.FP++
					default:
						sum.UnscoredDetectedSequences++
					}
				}
				if d, ok := firstRequest[c.ID]; ok {
					row.RequestSequences++
					if request == nil || decisionOrder(d, *request) < 0 {
						chosen := d
						request = &chosen
					}
					if l.Classification == "TRANSIENT" {
						sum.TransientRequestSequences++
					}
				}
			}
			row.AdditionalDetectedSequences = max(int64(0), row.DetectedSequences-1)
			row.AdditionalRequestSequences = max(int64(0), row.RequestSequences-1)
			if detection != nil {
				row.FirstDetectionID = detection.ID
				delay := detection.LogicalAt.Sub(l.From).Microseconds()
				row.DetectionDelayUS = &delay
			}
			if request != nil {
				row.FirstRequestID = request.ID
				delay := request.LogicalAt.Sub(l.From).Microseconds()
				row.RequestDelayUS = &delay
			}
			if row.ScoringStatus == "COMPLETE" {
				if l.Classification == "UNKNOWN" {
					row.ScoringStatus = "UNKNOWN_LABEL"
				} else {
					det, req := detection != nil, request != nil
					row.Detected, row.Requested = &det, &req
					if l.Classification == "ACTIONABLE" {
						sum.ActionableLabels++
						if det {
							sum.DetectedActionableLabels++
						} else {
							sum.DetectionMisses++
						}
						if !req {
							sum.RequestMisses++
						}
						if l.ActionDue != nil {
							switch {
							case !req:
								row.RequestDeadline = "MISSED"
							case request.LogicalAt.After(*l.ActionDue):
								row.RequestDeadline = "LATE"
							default:
								row.RequestDeadline = "MET"
							}
						}
					}
				}
			}
			if emit != nil {
				if err := emit(row); err != nil {
					return nil, err
				}
			}
		}
	}
	for i := range summaries {
		s := &summaries[i]
		s.Precision, s.Recall = ratio(s.TP, s.TP+s.FP), ratio(s.DetectedActionableLabels, s.ActionableLabels)
	}
	return summaries, nil
}

func (e *Engine) Report(provenance string, labels []Label) (Report, error) {
	return e.ReportWithLegacy(provenance, labels, nil)
}

func (e *Engine) ReportWithLegacy(provenance string, labels []Label, legacy []Legacy) (Report, error) {
	scores, err := e.ScoreWithLegacy(labels, legacy, nil)
	if err != nil {
		return Report{}, err
	}
	r := Report{Schema: 1, RunID: e.Config.RunID, ConfigHash: e.configHash, DescriptorHash: e.descriptorHash, Provenance: provenance, State: e.State, Timing: "LOGICAL_POLICY", Coverage: "UNKNOWN", Decisions: append([]Decision{}, e.Decisions...), Failures: append([]Failure{}, e.Failures...), Scores: scores, LegacyNotificationCounts: "UNAVAILABLE", LegacyDetectionRecall: "UNAVAILABLE", LegacyDetectionMisses: "UNAVAILABLE", LegacyNotificationPrecision: "UNAVAILABLE", LegacyComparison: "UNAVAILABLE", FollowupTruncated: e.FollowupTruncated, StartAt: e.StartAt, AdmissionEndAt: e.AdmissionEndAt, StopReason: e.StopReason, ScoringProfile: "interval-entry-v1", FailureOverflow: e.FailureOverflow, MonitoringQualification: "UNAVAILABLE", Telemetry: []TelemetryRecord{}, Execution: ExecutionReport{Decisions: []DecisionExecution{}}, HigherTemperatureCoverage: map[string]string{}, Comparison: "INLINE_REPLAY", ExecutionNotReproduced: []string{}}
	r.UnknownFrom, r.UnknownThrough = e.UnknownFrom, e.UnknownThrough
	r.CoverageIntervals = e.CoverageIntervals
	r.DetectionQuality = "DETECTION_QUALITY_UNQUALIFIED"
	r.decisionElapsedMS = map[string]int64{}
	if e.RecordedBuildHash != "" {
		buildID := "unknown"
		if info, ok := debug.ReadBuildInfo(); ok {
			buildID = info.String()
		}
		r.RecordedBuildHash = e.RecordedBuildHash
		r.BuildStatus = "MISMATCH"
		if fmt.Sprintf("%x", sha256.Sum256([]byte(buildID))) == e.RecordedBuildHash {
			r.BuildStatus = "MATCH"
		}
	}

	r.Execution.BuildStatus = r.BuildStatus
	r.previewChanges = map[string]previewChange{}
	if len(legacy) > 0 {
		r.LegacyComparison = "CAPTURED_EVALUATIONS"
	}
	if e.Shadow {
		r.Comparison = "OBSERVED_SHADOW"
	}
	if len(e.Failures) > 0 || e.FailureOverflow > 0 || e.UnknownFrom != nil {
		r.Coverage = "PARTIAL"
	}
	slices.SortFunc(r.Decisions, decisionOrder)
	slices.SortFunc(r.Failures, func(a, b Failure) int { return strings.Compare(a.ID, b.ID) })
	for _, rec := range e.Telemetry {
		r.Telemetry = append(r.Telemetry, *rec)
		r.MonitoringQualification = "QUALIFIED_OCCURRENCES_CAPTURED"
		if rec.Disposition == "PREVIEW" {
			r.MonitoringPreviews++
		} else {
			r.MonitoringAnnotations++
		}
	}
	if e.FailureOverflow > 0 {
		r.MonitoringQualification = "UNKNOWN_OVERFLOW"
	}
	slices.SortFunc(r.Telemetry, func(a, b TelemetryRecord) int { return strings.Compare(a.ID, b.ID) })
	if !e.ClosedAt.IsZero() {
		closed := e.ClosedAt
		r.Execution.ClosedAt = &closed
		lastDue := e.AdmissionEndAt
		for _, c := range e.Candidates {
			if c.Terminal != nil && c.Terminal.LogicalAt.Equal(c.DueAt) && c.DueAt.After(lastDue) {
				lastDue = c.DueAt
			}
		}
		r.Execution.ClosureLatenessUS = max(int64(0), closed.Sub(lastDue).Microseconds())
	}
	arms := map[int64]*ArmReport{}
	for _, budget := range e.Config.BudgetsMS {
		arms[budget] = &ArmReport{BudgetMS: budget}
	}
	byID := map[string]*Candidate{}
	for _, c := range e.Candidates {
		byID[c.ID] = c
		a := arms[c.BudgetMS]
		if a == nil {
			continue
		}
		a.PhysicalCandidates++
		if c.Entry.Basis == "INDEPENDENT_URGENT" {
			a.IndependentUrgentEntries++
		}
		switch c.Phase {
		case "QUARANTINED":
			a.Quarantined++
		case "OBSERVING":
			a.Pending++
		}
		if c.Terminal != nil {
			availability, ok := e.endpointAvailability[c.ID]
			if !ok {
				availability = e.temperatureCoverage(context.Background(), c)
			}
			r.HigherTemperatureCoverage[c.ID] = availability
		}
	}
	for _, d := range r.Decisions {
		a := arms[d.BudgetMS]
		if a == nil {
			continue
		}
		if c := byID[d.CandidateID]; c != nil {
			r.decisionElapsedMS[d.ID] = d.LogicalAt.Sub(c.EnteredAt).Milliseconds()
		}
		change, ok := e.previewComparisons[d.ID]
		if !ok {
			change, ok = e.previewChange(context.Background(), d)
		}
		if ok {
			r.previewChanges[d.ID] = change
		}
		r.Execution.Decisions = append(r.Execution.Decisions, DecisionExecution{d.ID, d.ExecutedAt, d.CommittedAt, d.LatenessUS})
		if d.Kind == "UPDATE" {
			a.Updates++
			continue
		}
		a.TerminalDispositions++
		if d.Action != "NONE" {
			a.TerminalPreviews++
		}
		if d.LatenessUS > 0 {
			a.OverdueCommitments++
		}
		switch e.evidenceClass(d) {
		case "SUPPORTED_CONCERN":
			a.SupportedConcerns++
		case "BENIGN":
			a.SupportedTransients++
		case "UNRESOLVED":
			a.Unresolved++
		}
	}
	for _, f := range r.Failures {
		if c := byID[f.CandidateID]; c != nil {
			arms[c.BudgetMS].AssessmentFailures += f.Count
		}
	}
	for _, b := range e.Config.BudgetsMS {
		r.Arms = append(r.Arms, *arms[b])
	}
	return r, nil
}

func (e *Engine) previewChange(ctx context.Context, d Decision) (previewChange, bool) {
	if d.TerminalEndpoint == nil {
		return previewChange{}, false
	}
	var prior *Feature
	for _, id := range d.Support {
		f, ok := e.fact(ctx, id)
		var feature Feature
		if !ok || f.Kind != "FEATURE" || json.Unmarshal(f.Body, &feature) != nil || feature.FeatureKind != "temperature_endpoint" || feature.Unit != "celsius" || !feature.SourceAt.Before(d.TerminalEndpoint.SourceAt) {
			continue
		}
		if prior == nil || feature.SourceAt.Before(prior.SourceAt) {
			prior = &feature
		}
	}
	if prior == nil {
		return previewChange{}, false
	}
	return previewChange{value: d.TerminalEndpoint.Value - prior.Value, sourceAt: prior.SourceAt}, true
}

func (e *Engine) endpointConflicts(ctx context.Context, asset, id string) ([][32]byte, bool) {
	f, ok := e.fact(ctx, id)
	if !ok {
		return nil, false
	}
	var out [][32]byte
	for _, sid := range factRefs(f) {
		measured, ok := e.fact(ctx, sid)
		var sample Sample
		if !ok || measured.Kind != "SAMPLE" || json.Unmarshal(measured.Body, &sample) != nil {
			continue
		}
		conflictID, _ := Identity("conflict", e.Config.Category, map[string]any{"run": e.Config.RunID, "asset": asset, "metric": sample.Metric, "source_at": sample.SourceAt})
		raw, _ := hex.DecodeString(conflictID)
		var key [32]byte
		copy(key[:], raw)
		out = append(out, key)
	}
	return out, len(out) > 0
}

func (e *Engine) temperatureCoverage(ctx context.Context, c *Candidate) string {
	if c.Terminal.Endpoint == nil {
		return "UNAVAILABLE"
	}
	refs, ok := e.endpointConflictIDs[c.ID]
	if !ok {
		refs, ok = e.endpointConflicts(ctx, c.Asset, c.Terminal.Endpoint.ID)
	}
	if !ok {
		return "UNAVAILABLE"
	}
	for _, id := range refs {
		if f, ok := e.fact(ctx, hex.EncodeToString(id[:])); ok && (e.ClosedAt.IsZero() || !f.AvailableAt.After(e.ClosedAt)) {
			return "UNAVAILABLE"
		}
	}
	return "AVAILABLE"
}

func SemanticReport(r Report) ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	delete(doc, "execution")
	delete(doc, "build_status")
	var decisions []map[string]json.RawMessage
	if err = json.Unmarshal(doc["decisions"], &decisions); err != nil {
		return nil, err
	}
	for _, d := range decisions {
		delete(d, "executed_at")
		delete(d, "committed_at")
		delete(d, "lateness_us")
	}
	if doc["decisions"], err = json.Marshal(decisions); err != nil {
		return nil, err
	}
	var arms []map[string]json.RawMessage
	if err = json.Unmarshal(doc["arms"], &arms); err != nil {
		return nil, err
	}
	for _, a := range arms {
		delete(a, "overdue_commitments")
	}
	if doc["arms"], err = json.Marshal(arms); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

func escapeMarkdown(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			r = ' '
		}
		if r == 96 || strings.ContainsRune("\\*_{}[]()#+-.!|<>~&", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func boundedPreview(s string) string {
	const marker = " … [truncated]\n"
	if len(s) <= 3000 {
		return s
	}
	end := 3000 - len(marker)
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	// Leave the evidence link intact when truncation is necessary.
	return s[:end] + marker
}

func WriteMarkdownReport(w io.Writer, r Report) error {
	if _, err := fmt.Fprintf(w, "# Alert assessment replay\n\nRun %s\n\nProvenance %s. Timing %s.\n\nCoverage %s. Legacy notification counts %s.\n\n", escapeMarkdown(r.RunID), escapeMarkdown(r.Provenance), escapeMarkdown(r.Timing), escapeMarkdown(r.Coverage), escapeMarkdown(r.LegacyNotificationCounts)); err != nil {
		return err
	}
	for _, d := range r.Decisions {
		temperature := "unavailable"
		if d.TerminalEndpoint != nil {
			temperature = strconv.FormatFloat(d.TerminalEndpoint.Value, 'f', -1, 64) + " °C"
		}
		stage := d.Outcome
		if stage == "" {
			stage = d.HostCause
		}
		if stage == "" {
			stage = strings.Join(d.Codes, ", ")
		}
		signed := "unavailable"
		if change, ok := r.previewChanges[d.ID]; ok {
			signed = fmt.Sprintf("%+.3g °C from the cited %s endpoint", change.value, change.sourceAt.UTC().Format(time.RFC3339Nano))
		}
		preview := fmt.Sprintf("- **SHADOW — NOT SENT** %s for %s. Temperature %s. Signed change %s. Budget %d ms, elapsed %d ms. Decision %s. [Evidence](evidence.ndjson) bundle %s. %s\n",
			escapeMarkdown(d.Action), escapeMarkdown(d.Asset), temperature, signed, d.BudgetMS, r.decisionElapsedMS[d.ID], escapeMarkdown(stage), escapeMarkdown(d.BundleID), escapeMarkdown(d.Summary))
		if _, err := io.WriteString(w, boundedPreview(preview)); err != nil {
			return err
		}
	}
	for _, t := range r.Telemetry {
		if t.Disposition != "PREVIEW" {
			continue
		}
		text := fmt.Sprintf("- **SHADOW — NOT SENT** Monitoring investigation for %s. Temperature and signed change unavailable. [Evidence](evidence.ndjson) %s\n", escapeMarkdown(t.Asset), escapeMarkdown(t.Summary))
		if _, err := io.WriteString(w, boundedPreview(text)); err != nil {
			return err
		}
	}
	return nil
}

func MarkdownReport(r Report) string {
	var b strings.Builder
	_ = WriteMarkdownReport(&b, r)
	return b.String()
}

func CheckExpected(e *Engine, expected []Expected) error {
	actual := []Expected{}
	for _, d := range e.Decisions {
		if d.Kind != "TERMINAL" {
			continue
		}
		actual = append(actual, Expected{Asset: d.Asset, Sequence: d.Sequence, BudgetMS: d.BudgetMS, LogicalAt: d.LogicalAt, Action: d.Action, Outcome: d.Outcome, DecisionSource: d.DecisionSource})
	}
	key := func(x Expected) string { return fmt.Sprintf("%s/%020d/%020d", x.Asset, x.Sequence, x.BudgetMS) }
	sort.Slice(actual, func(i, j int) bool { return key(actual[i]) < key(actual[j]) })
	want := append([]Expected{}, expected...)
	sort.Slice(want, func(i, j int) bool { return key(want[i]) < key(want[j]) })
	a, err := Canonical(actual)
	if err != nil {
		return err
	}
	b, err := Canonical(want)
	if err != nil {
		return err
	}
	if string(a) != string(b) {
		return fmt.Errorf("EXPECTED_MISMATCH")
	}
	return nil
}
