package alertassessment_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

func fixture(t testing.TB) (a.Suite, *a.Registry) {
	t.Helper()
	r, err := a.NewRegistry(cooling.Category{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../test/assessment/v1/suite.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.ParseSuite(b, r)
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

func TestAssessmentReplayExactEventsAndTelemetry(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckExpected(e, s.Expected); err != nil {
		t.Fatal(err)
	}
	entered := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	var entryBundle string
	for _, c := range e.Candidates {
		if !c.EnteredAt.Equal(entered) || !c.DueAt.Equal(entered.Add(time.Duration(c.BudgetMS)*time.Millisecond)) {
			t.Fatalf("wrong clocks %+v", c)
		}
		if entryBundle != "" && entryBundle != c.Entry.BundleID {
			t.Fatal("arms do not share entry evidence")
		}
		entryBundle = c.Entry.BundleID
		if c.BudgetMS == 0 && c.Terminal.Endpoint != nil {
			t.Fatal("fallback projected a temperature")
		}
	}
	report, err := e.ReportWithLegacy(s.Provenance, s.Labels, s.Legacy)
	if err != nil {
		t.Fatal(err)
	}
	if report.MonitoringPreviews != 1 || report.MonitoringAnnotations != 1 || !report.FollowupTruncated {
		t.Fatalf("wrong routing %+v", report.Telemetry)
	}
	if len(report.Failures) != 2 || !slices.ContainsFunc(report.Failures, func(f a.Failure) bool { return f.Code == "CONFLICT" && f.Count == 1 }) {
		t.Fatalf("wrong failure ledger %+v", report.Failures)
	}
	for _, d := range e.Decisions {
		if d.Kind == "UPDATE" && (d.Outcome != "" || !slices.Equal(d.Codes, []string{"urgent"})) {
			t.Fatalf("incorrect update %+v", d)
		}
	}
	dup, contradiction := 0, 0
	for _, f := range e.Facts {
		switch f.Kind {
		case "PROVENANCE":
			dup++
		case "CONFLICT":
			contradiction++
		}
	}
	if dup != 1 || contradiction != 1 {
		t.Fatalf("deduplication got %d provenance and %d conflicts", dup, contradiction)
	}
	expected, err := a.SemanticReport(report)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(s.Facts)
	slices.Reverse(s.Legacy)
	reordered, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := reordered.ReportWithLegacy(s.Provenance, s.Labels, s.Legacy)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := a.SemanticReport(again)
	if err != nil || !bytes.Equal(expected, actual) {
		t.Fatalf("non-deterministic semantic report %v", err)
	}
}

func TestAssessmentReplayDelayedWakeDueAndDrain(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	samples := []a.Fact{}
	for _, f := range s.Facts {
		if f.Kind == "SAMPLE" && f.AvailableAt.Before(s.StartAt.Add(30*time.Second)) {
			samples = append(samples, f)
		}
	}
	early := s.StartAt.Add(29 * time.Second)
	if err = e.Advance(t.Context(), early, early, early, samples, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Candidates) != 0 {
		t.Fatal("future source was eligible")
	}
	late := s.StartAt.Add(40 * time.Second)
	// Simulate restart with the retained facts and enrollment, before the
	// first wake after the future sample's source time.
	resumed, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	resumed.Facts, resumed.Bundles, resumed.Enrollments = e.Facts, e.Bundles, e.Enrollments
	if err = resumed.Advance(t.Context(), late, late, late, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(resumed.Candidates) != 5 {
		t.Fatalf("received %d candidates", len(resumed.Candidates))
	}
	if d := resumed.Decisions[0]; d.LogicalAt != s.StartAt.Add(30*time.Second+125*time.Microsecond) || d.LatenessUS != 9_999_875 {
		t.Fatalf("bad delayed zero arm %+v", d)
	}
	if err = resumed.Advance(t.Context(), resumed.AdmissionEndAt, resumed.AdmissionEndAt, resumed.AdmissionEndAt, nil, nil); err != nil {
		t.Fatal(err)
	}
	if resumed.State != "DRAINING" {
		t.Fatalf("state %s", resumed.State)
	}
	due := resumed.Candidates[4].DueAt
	commit := due.Add(250 * time.Millisecond)
	if err = resumed.Advance(t.Context(), commit, commit, commit, nil, nil); err != nil {
		t.Fatal(err)
	}
	if resumed.State != "CLOSED" || resumed.ClosedAt != commit || !resumed.FollowupTruncated {
		t.Fatalf("bad closure %s %s", resumed.State, resumed.ClosedAt)
	}
	d := resumed.Decisions[len(resumed.Decisions)-1]
	if d.LatenessUS != 250_000 || d.LogicalAt != due {
		t.Fatalf("bad drain terminal %+v", d)
	}
	r, err := resumed.Report(s.Provenance, nil)
	if err != nil || r.Execution.ClosureLatenessUS != 250_000 {
		t.Fatalf("bad execution report %+v %v", r.Execution, err)
	}
}

func TestAssessmentReplayAggregateTimeoutLeavesFutureArmsObserving(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	batch := []a.Fact{}
	for _, f := range s.Facts {
		if f.Kind == "SAMPLE" && f.AvailableAt.Before(entry) {
			batch = append(batch, f)
		}
	}
	budget := int64(15000)
	faults := []a.Fault{{At: entry, Asset: s.Config.Assets[0].EntityKey, Purpose: "ASSESS", BudgetMS: &budget, Code: "TIME_BUDGET"}}
	var observed []string
	e.ObserveGPU = func(asset string, _ time.Duration) { observed = append(observed, asset) }
	if err = e.Advance(t.Context(), entry, entry, entry, batch, faults); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(observed, []string{s.Config.Assets[0].EntityKey}) {
		t.Fatalf("assessment arms sharing a budget produced observations %v", observed)
	}
	if len(e.Candidates) != 5 || len(e.Decisions) != 1 || e.Decisions[0].DecisionSource != "CATEGORY" || len(e.Failures) != 4 {
		t.Fatalf("bad partial pass candidates=%d decisions=%+v failures=%+v", len(e.Candidates), e.Decisions, e.Failures)
	}
	for _, c := range e.Candidates[1:] {
		if c.Phase != "OBSERVING" || c.State.Hash != c.InitialState.Hash || c.EnteredAt != entry {
			t.Fatalf("failed arm changed state: %+v", c)
		}
	}
	if err = e.Advance(t.Context(), entry, entry, entry, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Candidates) != 5 || len(e.Decisions) != 1 {
		t.Fatal("retry duplicated committed entry")
	}
}

func TestAssessmentObserveGPUPreInvocationWork(t *testing.T) {
	for _, tc := range []struct {
		name string
		code string
	}{
		{name: "preparation timeout", code: "TIME_BUDGET"},
		{name: "due host fallback", code: "COVERAGE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, reg := fixture(t)
			e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
			if err != nil {
				t.Fatal(err)
			}
			entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
			var facts []a.Fact
			for _, f := range s.Facts {
				if f.Kind == "SAMPLE" && !f.AvailableAt.After(entry) {
					facts = append(facts, f)
				}
			}
			asset := s.Config.Assets[0].EntityKey
			var observed []string
			e.ObserveGPU = func(asset string, elapsed time.Duration) {
				if elapsed < 0 {
					t.Errorf("negative GPU elapsed time %s", elapsed)
				}
				observed = append(observed, asset)
			}
			if err := e.Advance(t.Context(), entry, entry, entry, facts, nil); err != nil {
				t.Fatal(err)
			}
			if len(e.Candidates) != 5 || !slices.Equal(observed, []string{asset}) {
				t.Fatalf("entry produced %d arms and observations %v", len(e.Candidates), observed)
			}
			observed = nil
			if err := e.AdvanceAssets(t.Context(), entry, entry, entry, nil, nil, []string{}); err != nil {
				t.Fatal(err)
			}
			if err := e.Advance(t.Context(), entry, entry, entry, nil, nil); err != nil {
				t.Fatal(err)
			}
			if len(observed) != 0 {
				t.Fatalf("idle advances produced observations %v", observed)
			}
			arm := e.Candidates[1]
			if arm.BudgetMS != 15000 || arm.Phase != "OBSERVING" {
				t.Fatalf("expected a pending 15s arm: %+v", arm)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.code == "TIME_BUDGET" {
				bundle := e.Bundles[arm.Entry.BundleID]
				delete(e.Bundles, bundle.ID)
				lookups := 0
				e.LookupBundle = func(ctx context.Context, id string) (a.Bundle, bool) {
					if id != bundle.ID {
						return a.Bundle{}, false
					}
					lookups++
					// The first lookup proves the retained entry. The request
					// then reloads the bundle before resolving its fact IDs.
					if lookups == 2 {
						cancel()
					}
					return bundle, true
				}
			} else {
				e.SuppressAsset(asset, tc.code)
			}
			due := arm.DueAt
			if err := e.AdvanceAssets(ctx, due, due, due, nil, nil, []string{}); err != nil {
				t.Fatal(err)
			}
			last := e.Decisions[len(e.Decisions)-1]
			if last.CandidateID != arm.ID || last.DecisionSource != "HOST_FALLBACK" || last.FailureCode != tc.code {
				t.Fatalf("unexpected due decision %+v", last)
			}
			if !slices.Equal(observed, []string{asset}) {
				t.Fatalf("due GPU work produced observations %v", observed)
			}
		})
	}
}

func TestAssessmentArchiveLargeChunkRoundTrip(t *testing.T) {
	s, r := fixture(t)
	// The archive exceeds the inline limit while each chunk stays bounded.
	// Preserve actual row payload counts and immutable fact identity.
	s.Config.RunDurationSeconds = 3601
	s.Config.Limits.PayloadBytes = 64 << 20
	asset := s.Config.Assets[0]
	ch, _ := s.Config.Hash()
	_, d, dh, _ := r.LookupVersion(s.Config.Category, s.Config.Implementation)
	configBytes := archiveValue(t, s.Config)
	descriptorBytes := archiveValue(t, d)
	end := s.StartAt.Add(time.Duration(s.Config.RunDurationSeconds) * time.Second)
	run := map[string]any{"run_id": s.Config.RunID, "config": configBytes, "config_hash": ch, "descriptor": descriptorBytes, "descriptor_hash": dh, "build_hash": dh,
		"mode": "replay", "state": "CLOSED", "start_at": s.StartAt, "admission_end_at": end, "closed_at": end, "stopped_at": end, "stop_reason": "DURATION",
		"payload_bytes": int64(0), "fact_count": int64(0), "physical_count": int64(0), "record_count": int64(0), "overflow_count": int64(0), "coverage": "W10=",
		"incomplete_count": int64(0), "followup_truncated": false}
	source := &fixtureArchive{meta: a.ArchiveMetadata{RunID: s.Config.RunID, ConfigHash: ch, Provenance: "SYNTHETIC"}}
	source.rows = append(source.rows, archiveRow(t, "run", s.Config.RunID, run))
	source.rows = append(source.rows, archiveRow(t, "enrollments", asset.EntityKey, map[string]any{"run_id": s.Config.RunID, "category": s.Config.Category, "asset": asset.EntityKey, "node_id": asset.NodeID, "gpu_uuid": asset.GPUUUID,
		"inventory_revision": s.Config.InventoryRevision, "bindings": archiveValue(t, s.Config.Bindings), "discovery_floor": s.StartAt, "next_due_at": end, "sequence": int64(0), "revision": int64(1), "rearm_eligible": true}))
	n := int64(0)
	for n = 1; n <= 1500; n++ {
		at := s.StartAt.Add(time.Duration((n-1)/550) * 901 * time.Second)
		snapshot := make([]a.SnapshotEntry, 32)
		for i := range snapshot {
			snapshot[i] = a.SnapshotEntry{Metric: strings.Repeat("m", 128), Unit: strings.Repeat("u", 128), SourceAt: at, Support: "UNKNOWN"}
		}
		f, err := a.NewFact(s.Config.Category, s.Config.RunID, asset.EntityKey, "QUALIFIED", at, a.Qualified{PolicyID: "test-inert-warning", Occurrence: n, Transition: "OPEN", Rule: "gpu_thermal", RuleVersion: 1, EnrollmentRevision: 1, Severity: "WARNING", QualifiedAt: at, Snapshot: snapshot})
		if err != nil {
			t.Fatal(err)
		}
		source.rows = append(source.rows, archiveRow(t, "facts", f.ID, map[string]any{"run_id": f.Run, "id": f.ID, "asset": f.Asset, "kind": f.Kind, "available_at": f.AvailableAt, "body": archiveValue(t, f)}))
	}
	for first := 2; first < len(source.rows); first += 550 {
		last := min(first+550, len(source.rows))
		slices.SortFunc(source.rows[first:last], func(a, b a.ArchiveRow) int { return strings.Compare(a.Key, b.Key) })
	}

	run["fact_count"] = n - 1
	run["record_count"] = int64(len(source.rows))
	source.rows[0] = archiveRow(t, "run", s.Config.RunID, run)
	for _, row := range source.rows {
		size, err := a.ArchiveRowPayloadBytes(row)
		if err != nil {
			t.Fatal(err)
		}
		source.meta.SourcePayloadBytes += size
	}
	run["payload_bytes"] = source.meta.SourcePayloadBytes
	source.rows[0] = archiveRow(t, "run", s.Config.RunID, run)
	source.meta.RecordCount = int64(len(source.rows))
	if source.meta.SourcePayloadBytes <= 16<<20 {
		t.Fatal("fixture does not exceed the inline input limit")
	}
	dir := filepath.Join(t.TempDir(), "archive")
	manifest, err := a.WriteArchive(t.Context(), dir, source)
	if err != nil {
		t.Fatal(err)
	}
	source.rows = nil
	if len(manifest.Chunks) < 3 {
		t.Fatal("archive did not split chunks")
	}
	for _, chunk := range manifest.Chunks {
		if chunk.Bytes > 8<<20 {
			t.Fatalf("oversized chunk %+v", chunk)
		}
	}
	// The shuffled hash order from the fixture is validated through the packed
	// fact index; no full in-memory archive is passed to replay.
	replayed, err := a.ReplayArchive(t.Context(), dir, r)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Ideal.State != "CLOSED" || len(replayed.Mismatched) != 0 || len(replayed.Observed.Candidates) != 0 {
		t.Fatalf("unexpected reproduction %+v", replayed.Mismatched)
	}
	path := filepath.Join(dir, manifest.Chunks[0].File)
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = a.ReplayArchive(t.Context(), dir, r); !errors.Is(err, a.ErrInvalid) {
		t.Fatalf("corrupted chunk returned %v", err)
	}
}

type fixtureArchive struct {
	meta  a.ArchiveMetadata
	rows  []a.ArchiveRow
	index int
}

func (s *fixtureArchive) Metadata() a.ArchiveMetadata { return s.meta }
func (s *fixtureArchive) Next(context.Context) (a.ArchiveRow, error) {
	if s.index == len(s.rows) {
		return a.ArchiveRow{}, io.EOF
	}
	i := s.index
	s.index++
	return s.rows[i], nil
}
func (*fixtureArchive) Close(context.Context) error { return nil }

func archiveValue(t testing.TB, v any) string {
	t.Helper()
	b, err := a.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func archiveRow(t testing.TB, table, key string, body any) a.ArchiveRow {
	t.Helper()
	b, err := a.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	return a.ArchiveRow{Table: table, Key: key, Body: json.RawMessage(b)}
}

func TestAssessmentReplayArchiveRejectsTraversal(t *testing.T) {
	_, registry := fixture(t)
	dir := t.TempDir()
	manifest := fmt.Sprintf("{%q:1,%q:%q,%q:%q,%q:%q,%q:1,%q:1,%q:[{%q:%q,%q:1,%q:%q,%q:1,%q:%q}],%q:true}",
		"schema", "run_id", "fixture", "config_hash", strings.Repeat("a", 64), "provenance", "SYNTHETIC", "source_payload_bytes", "record_count", "chunks", "file", "../outside", "bytes", "sha256", strings.Repeat("a", 64), "records", "section", "run", "complete")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReplayArchive(t.Context(), dir, registry); !errors.Is(err, a.ErrInvalid) {
		t.Fatalf("traversal got %v", err)
	}
}

type reassessmentContextFixture struct{ cooling.Category }

func (reassessmentContextFixture) ValidateResult(context.Context, a.Request, a.Result) error {
	return nil
}

func (fixture reassessmentContextFixture) Evaluate(ctx context.Context, r a.Request) (a.Result, error) {
	x := a.Result{Kind: "UNCHANGED", UpdateCodes: []string{}, Support: []string{}, Reasons: []string{}, ProposedFeatures: []a.Feature{}}
	if r.Purpose == "DISCOVER" {
		return fixture.Category.Evaluate(ctx, r)
	}
	if r.Scope == "TRACKER" {
		p, err := a.NewPayload(r.Category, "tracker", 1, map[string]any{"at": r.LogicalAt})
		if err != nil {
			return x, err
		}
		x.State = &p
		for _, f := range r.Facts {
			if f.Kind != "SAMPLE" || !f.AvailableAt.Equal(r.LogicalAt) {
				continue
			}
			feature := a.Feature{FeatureKind: "rebound", SourceAt: r.LogicalAt, Value: 5, Unit: "celsius", Support: []string{f.ID}}
			id, err := a.FeatureID(r, feature)
			if err != nil {
				return x, err
			}
			x.ProposedFeatures = append(x.ProposedFeatures, feature)
			x.Support = append(x.Support, id)
		}
		return x, nil
	}
	if r.Purpose != "ASSESS" {
		return x, nil
	}
	x.Kind, x.Phase, x.Action, x.Outcome = "ASSESSMENT", "OBSERVING", "NONE", "gpu_cooling/OBSERVING"
	if r.LogicalAt.Before(r.Entry.Fallback.DueAt) {
		return x, nil
	}
	x.Phase, x.Action, x.Outcome = "FINAL", "INVESTIGATE", "gpu_cooling/UNRESOLVED_WARMING"
	if r.SharedContext != nil {
		for _, f := range r.Facts {
			if f.Kind != "TRACKER_CONTEXT" || !f.AvailableAt.Equal(r.SharedContext.AvailableAt) {
				continue
			}
			x.Support = append(x.Support, f.ID)
		}
	}
	return x, nil
}

func TestAssessmentTrackerContextFrozenAcrossRestartAndDueCutoff(t *testing.T) {
	s, _ := fixture(t)
	reg, err := a.NewRegistry(reassessmentContextFixture{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	first := []a.Fact{}
	for _, f := range s.Facts {
		if f.Kind == "SAMPLE" && f.AvailableAt.Before(entry) {
			first = append(first, f)
		}
	}
	if err = e.Advance(t.Context(), entry, entry, entry, first, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Candidates) != 5 {
		t.Fatalf("discovery produced %d arms, failures=%+v", len(e.Candidates), e.Failures)
	}
	old := *e.Candidates[1]
	extra := func(at time.Time) a.Fact {
		t.Helper()
		asset := s.Config.Assets[0].EntityKey
		body := a.Sample{Metric: cooling.Temperature, Unit: "celsius", SourceAt: at, CollectedAt: at, CompletedAt: at,
			Value: 76, SourceRecord: "synthetic-tracker",
			Provenance: a.Provenance{Mode: "fixture", CollectionRunID: "synthetic-tracker", Operation: "prometheus.gpu_temperature.v1", ScheduleRevision: 1, InventoryRevision: s.Config.InventoryRevision, SourceRecord: "synthetic-tracker"}}
		f, err := a.NewFact(s.Config.Category, s.Config.RunID, asset, "SAMPLE", at, body)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	t35, t50 := s.StartAt.Add(35*time.Second), s.StartAt.Add(50*time.Second)
	for _, at := range []time.Time{t35, t50} {
		if err = e.Advance(t.Context(), at, at, at, []a.Fact{extra(at)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	contextID := map[time.Time]string{}
	for _, f := range e.Facts {
		if f.Kind != "TRACKER_CONTEXT" {
			continue
		}
		contextID[f.AvailableAt] = f.ID
		var tracker a.TrackerContext
		if err = json.Unmarshal(f.Body, &tracker); err != nil {
			t.Fatal(err)
		}
		bundle, ok := e.Bundles[tracker.BundleID]
		if !ok || len(bundle.Features) == 0 || slices.Contains(bundle.Facts, f.ID) {
			t.Fatalf("invalid tracker DAG %+v", bundle)
		}
	}
	if len(contextID) != 3 || contextID[entry] == "" {
		t.Fatalf("tracker history missing %+v failures=%+v", contextID, e.Failures)
	}
	resumed, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	resumed.Facts, resumed.Bundles, resumed.Enrollments, resumed.Candidates = e.Facts, e.Bundles, e.Enrollments, e.Candidates
	resumed.Candidates[1] = &old
	late := s.StartAt.Add(65 * time.Second)
	if err = resumed.Advance(t.Context(), late, late, late, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		i   int
		ctx time.Time
	}{{1, t35}, {2, t50}} {
		c := resumed.Candidates[want.i]
		for _, d := range resumed.Decisions {
			if d.CandidateID != c.ID {
				continue
			}
			if d.Kind != "TERMINAL" || !slices.Equal(d.Support, []string{contextID[want.ctx]}) || d.LogicalAt != c.DueAt {
				t.Fatalf("arm %d consumed wrong cutoff context %+v", c.BudgetMS, d)
			}
		}
		if c.Terminal == nil {
			t.Fatalf("arm %d never finalized", c.BudgetMS)
		}
	}
}

func TestAssessmentDueUsesRetainedFreshProjectionDespiteExecutionDelay(t *testing.T) {
	s, reg := fixture(t)
	s.Config.RunDurationSeconds = 1800
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	var input []a.Fact
	for _, f := range s.Facts {
		if f.Kind == "SAMPLE" && f.AvailableAt.Before(entry) {
			input = append(input, f)
		}
	}
	if err = e.Advance(t.Context(), entry, entry, entry, input, nil); err != nil {
		t.Fatal(err)
	}
	due := e.Candidates[1].DueAt
	t35 := due.Add(-10 * time.Second)
	var sample a.Sample
	if err = json.Unmarshal(input[0].Body, &sample); err != nil {
		t.Fatal(err)
	}
	sample.SourceAt, sample.CollectedAt, sample.CompletedAt = t35, t35, t35
	f, err := a.NewFact(s.Config.Category, s.Config.RunID, input[0].Asset, "SAMPLE", t35, sample)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Advance(t.Context(), t35, t35, t35, []a.Fact{f}, nil); err != nil {
		t.Fatal(err)
	}
	if e.Candidates[1].Terminal != nil {
		t.Fatal("arm finalized prematurely")
	}
	late := due.Add(10 * time.Minute)
	q, err := a.NewFact(s.Config.Category, s.Config.RunID, input[0].Asset, "QUALIFIED", late, a.Qualified{PolicyID: "late-open", Occurrence: 1,
		Transition: "OPEN", Rule: "gpu_thermal", RuleVersion: 1, EnrollmentRevision: 1, Severity: "CRITICAL", QualifiedAt: due, Snapshot: []a.SnapshotEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Advance(t.Context(), late, late, late, []a.Fact{q}, nil); err != nil {
		t.Fatal(err)
	}
	c := e.Candidates[1]
	for _, d := range e.Decisions {
		if d.CandidateID != c.ID || d.Kind != "TERMINAL" {
			continue
		}
		if d.LatenessUS != 600_000_000 || d.LogicalAt != due || d.Outcome != "gpu_cooling/UNRESOLVED_WARMING" || d.TerminalEndpoint == nil || d.TerminalEndpoint.SourceAt != t35 {
			t.Fatalf("due used wrong time or post-cutoff fact %+v", d)
		}
		if slices.Contains(e.Bundles[d.BundleID].Facts, q.ID) {
			t.Fatal("late fact entered due bundle")
		}
		return
	}
	t.Fatal("due terminal missing")
}

func TestAssessmentReplayRejectsNoncanonicalArchiveConfig(t *testing.T) {
	s, reg := fixture(t)
	cfg := s.Config
	cfg.Policy = bytes.Replace(cfg.Policy, []byte("\"stable_watts\":10"), []byte("\"stable_watts\":1e1"), 1)
	h, _ := cfg.Hash()
	normalizedHash, _ := s.Config.Hash()
	if h == normalizedHash {
		t.Fatal("test fixture did not change the pinned hash")
	}
	_, d, dh, err := reg.LookupVersion(cfg.Category, cfg.Implementation)
	if err != nil {
		t.Fatal(err)
	}
	end := s.StartAt.Add(time.Duration(cfg.RunDurationSeconds) * time.Second)
	row := map[string]any{"run_id": cfg.RunID, "config": archiveValue(t, cfg), "config_hash": h, "descriptor": archiveValue(t, d),
		"descriptor_hash": dh, "build_hash": dh, "mode": "replay", "state": "CLOSED", "start_at": s.StartAt, "admission_end_at": end,
		"closed_at": end, "stopped_at": end, "stop_reason": "DURATION", "payload_bytes": int64(0), "fact_count": int64(0), "physical_count": int64(0),
		"record_count": int64(1), "overflow_count": int64(0), "incomplete_count": int64(0), "coverage": "W10=", "followup_truncated": false}
	size, err := a.ArchiveRowPayloadBytes(archiveRow(t, "run", cfg.RunID, row))
	if err != nil {
		t.Fatal(err)
	}
	row["payload_bytes"] = size
	source := &fixtureArchive{meta: a.ArchiveMetadata{RunID: cfg.RunID, ConfigHash: h, Provenance: "OBSERVED_AVAILABILITY", SourcePayloadBytes: size, RecordCount: 1},
		rows: []a.ArchiveRow{archiveRow(t, "run", cfg.RunID, row)}}
	dir := filepath.Join(t.TempDir(), "archive")
	if _, err = a.WriteArchive(t.Context(), dir, source); err != nil {
		t.Fatal(err)
	}
	if _, err = a.ReplayArchive(t.Context(), dir, reg); !errors.Is(err, a.ErrInvalid) {
		t.Fatalf("noncanonical config returned %v", err)
	}
}

func TestAssessmentArchivePreservesObservedFailureAndIdealReproduction(t *testing.T) {
	s, reg := fixture(t)
	observed, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	source := archiveEngineFixture(t, observed, reg)
	dir := filepath.Join(t.TempDir(), "archive")
	if _, err = a.WriteArchive(t.Context(), dir, source); err != nil {
		t.Fatal(err)
	}
	replayed, err := a.ReplayArchive(t.Context(), dir, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed.Mismatched) != 0 || len(replayed.ExecutionNotReproduced) != 1 || replayed.ExecutionNotReproduced[0] != observed.Candidates[0].ID {
		t.Fatalf("unexpected reproduction mismatches=%v failure exclusions=%v", replayed.Mismatched, replayed.ExecutionNotReproduced)
	}
	if replayed.Observed.Candidates[0] == nil || len(replayed.Observed.Decisions) != len(observed.Decisions) {
		t.Fatal("observed ledger is incomplete")
	}
	containsFallback := func(e *a.Engine) bool {
		return slices.ContainsFunc(e.Decisions, func(d a.Decision) bool { return d.DecisionSource == "HOST_FALLBACK" })
	}
	if !containsFallback(replayed.Observed) || containsFallback(replayed.Ideal) {
		t.Fatal("observed failure was not preserved independently of ideal replay")
	}
}

func archiveEngineFixture(t testing.TB, e *a.Engine, reg *a.Registry) *fixtureArchive {
	t.Helper()
	cfg := e.Config
	ch, _ := cfg.Hash()
	_, d, dh, err := reg.LookupVersion(cfg.Category, cfg.Implementation)
	if err != nil {
		t.Fatal(err)
	}
	source := &fixtureArchive{meta: a.ArchiveMetadata{RunID: cfg.RunID, ConfigHash: ch, Provenance: "OBSERVED_AVAILABILITY"}}
	appendRow := func(table, key string, body map[string]any) {
		source.rows = append(source.rows, archiveRow(t, table, key, body))
	}
	run := map[string]any{"run_id": cfg.RunID, "config": archiveValue(t, cfg), "config_hash": ch, "descriptor": archiveValue(t, d),
		"descriptor_hash": dh, "build_hash": dh, "mode": "shadow", "state": "CLOSED", "start_at": e.StartAt, "admission_end_at": e.AdmissionEndAt,
		"closed_at": e.ClosedAt, "stopped_at": e.AdmissionEndAt, "stop_reason": e.StopReason, "payload_bytes": int64(0), "fact_count": int64(len(e.Facts)),
		"physical_count": int64(len(e.Candidates) / 5), "record_count": int64(0), "overflow_count": e.FailureOverflow, "coverage": "W10=", "incomplete_count": int64(0), "followup_truncated": e.FollowupTruncated}
	appendRow("run", cfg.RunID, run)
	for _, asset := range cfg.Assets {
		en := e.Enrollments[asset.EntityKey]
		body := map[string]any{"run_id": cfg.RunID, "category": cfg.Category, "asset": asset.EntityKey, "node_id": asset.NodeID, "gpu_uuid": asset.GPUUUID,
			"inventory_revision": cfg.InventoryRevision, "bindings": archiveValue(t, cfg.Bindings), "discovery_floor": en.DiscoveryFloor, "next_due_at": e.ClosedAt,
			"sequence": en.Sequence, "revision": en.Revision, "rearm_eligible": !en.Active}
		if en.Tracker != nil {
			body["tracker"] = base64.StdEncoding.EncodeToString(en.Tracker.Body)
			body["tracker_hash"] = en.Tracker.Hash
		}
		appendRow("enrollments", asset.EntityKey, body)
	}
	facts := make([]a.Fact, 0, len(e.Facts))
	for _, f := range e.Facts {
		facts = append(facts, f)
	}
	slices.SortFunc(facts, func(a, b a.Fact) int {
		if t := a.AvailableAt.Compare(b.AvailableAt); t != 0 {
			return t
		}
		return strings.Compare(a.ID, b.ID)
	})
	for _, f := range facts {
		appendRow("facts", f.ID, map[string]any{"run_id": f.Run, "asset": f.Asset, "id": f.ID, "kind": f.Kind, "available_at": f.AvailableAt, "body": archiveValue(t, f)})
	}
	sortSince := func(start int) {
		slices.SortFunc(source.rows[start:], func(a, b a.ArchiveRow) int { return strings.Compare(a.Key, b.Key) })
	}
	i := len(source.rows)
	for _, b := range e.Bundles {
		appendRow("bundles", b.ID, map[string]any{"run_id": b.Run, "id": b.ID, "asset": b.Asset, "logical_at": b.LogicalAt, "availability_cutoff": b.AvailabilityCutoff, "body": archiveValue(t, b)})
	}
	sortSince(i)
	i = len(source.rows)
	for _, c := range e.Candidates {
		appendRow("candidates", c.ID, map[string]any{"run_id": cfg.RunID, "id": c.ID, "category": cfg.Category, "asset": c.Asset, "sequence": c.Sequence, "budget_ms": c.BudgetMS,
			"revision": c.Revision, "phase": c.Phase, "entered_at": c.EnteredAt, "due_at": c.DueAt, "entry_bundle": c.Entry.BundleID, "entry": archiveValue(t, c.Entry),
			"initial_state": base64.StdEncoding.EncodeToString(c.InitialState.Body), "initial_hash": c.InitialState.Hash, "state": base64.StdEncoding.EncodeToString(c.State.Body), "state_hash": c.State.Hash,
			"terminal_id": c.Terminal.DecisionID, "terminal": archiveValue(t, c.Terminal), "reserved_codes": c.ReservedCodes})
	}
	sortSince(i)
	i = len(source.rows)
	for _, d := range e.Decisions {
		route := "hardware_investigation"
		if d.Action == "NONE" {
			route = "none"
		}
		meta := map[string]any{"schema": int64(1), "route": route, "urgent_occurrences": d.UrgentOccurrences}
		if d.TerminalEndpoint != nil {
			meta["terminal_endpoint"] = d.TerminalEndpoint
		}
		row := map[string]any{"run_id": cfg.RunID, "id": d.ID, "candidate_id": d.CandidateID, "kind": d.Kind, "logical_at": d.LogicalAt, "executed_at": d.ExecutedAt,
			"committed_at": d.CommittedAt, "lateness_us": d.LatenessUS, "action": d.Action, "decision_source": d.DecisionSource, "bundle_id": d.BundleID,
			"codes": d.Codes, "reasons": d.Reasons, "support": d.Support, "summary": d.Summary, "metadata": archiveValue(t, meta)}
		for key, value := range map[string]string{"outcome": d.Outcome, "host_cause": d.HostCause, "failure_code": d.FailureCode} {
			if value != "" {
				row[key] = value
			}
		}
		if d.Details != nil {
			row["details"] = base64.StdEncoding.EncodeToString(d.Details.Body)
			row["details_hash"] = d.Details.Hash
		}
		appendRow("decisions", d.ID, row)
	}
	sortSince(i)
	i = len(source.rows)
	for _, f := range e.Failures {
		from, through := f.FirstAt, f.At
		if f.LogicalFrom != nil {
			from = *f.LogicalFrom
		}
		if f.LogicalThrough != nil {
			through = *f.LogicalThrough
		}
		body := map[string]any{"schema": int64(1), "fact_ids": f.FactIDs, "message": f.Code, "from": from, "through": through}
		if f.BundleID != "" {
			body["bundle_id"] = f.BundleID
		}
		appendRow("failures", f.ID, map[string]any{"run_id": cfg.RunID, "id": f.ID, "category": cfg.Category, "asset": f.Asset, "kind": f.Kind, "code": f.Code,
			"scope_key": f.ScopeKey, "first_at": f.FirstAt, "last_at": f.At, "count": f.Count, "body": archiveValue(t, body)})
	}
	for _, f := range e.Telemetry {
		body := map[string]any{"schema": int64(1), "disposition": f.Disposition, "policy_id": f.PolicyID, "occurrence": f.Occurrence, "open_fact": f.OpenFact, "bundle_id": f.BundleID, "summary": f.Summary}
		if f.RecoverFact != "" {
			body["recover_fact"] = f.RecoverFact
		}
		if f.PreviewID != "" {
			body["preview_id"] = f.PreviewID
		}
		if f.PhysicalSequence > 0 {
			body["physical_sequence"] = f.PhysicalSequence
		}
		appendRow("failures", f.ID, map[string]any{"run_id": cfg.RunID, "id": f.ID, "category": cfg.Category, "asset": f.Asset, "kind": "QUALIFIED_TELEMETRY", "code": "QUALIFIED_TELEMETRY",
			"scope_key": f.ID, "first_at": f.FirstAt, "last_at": f.LastAt, "count": f.Count, "body": archiveValue(t, body)})
	}
	sortSince(i)
	run["record_count"] = int64(len(source.rows))
	source.rows[0] = archiveRow(t, "run", cfg.RunID, run)
	for _, row := range source.rows {
		n, err := a.ArchiveRowPayloadBytes(row)
		if err != nil {
			t.Fatal(err)
		}
		source.meta.SourcePayloadBytes += n
	}
	run["payload_bytes"] = source.meta.SourcePayloadBytes
	source.rows[0] = archiveRow(t, "run", cfg.RunID, run)
	source.meta.RecordCount = int64(len(source.rows))
	return source
}

func assessmentWarmFacts(s a.Suite, before time.Time) []a.Fact {
	return slices.DeleteFunc(slices.Clone(s.Facts), func(f a.Fact) bool {
		return f.Kind != "SAMPLE" || !f.AvailableAt.Before(before)
	})
}

func assessmentQualification(t testing.TB, s a.Suite, policy, rule, transition string, occ int64, available, qualified time.Time) a.Fact {
	t.Helper()
	f, err := a.NewFact(s.Config.Category, s.Config.RunID, s.Config.Assets[0].EntityKey, "QUALIFIED", available,
		a.Qualified{PolicyID: policy, Occurrence: occ, Transition: transition, Rule: rule, RuleVersion: 1, EnrollmentRevision: 1,
			Severity: "CRITICAL", QualifiedAt: qualified, Snapshot: []a.SnapshotEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAssessmentCrossedDeadlineSamplesRetryClock(t *testing.T) {
	s, _ := fixture(t)
	reg, err := a.NewRegistry(reassessmentContextFixture{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	if err = e.Advance(t.Context(), entry, entry, entry, assessmentWarmFacts(s, entry), nil); err != nil {
		t.Fatal(err)
	}
	c := e.Candidates[1]
	before, after := c.DueAt.Add(-time.Millisecond), c.DueAt.Add(time.Microsecond)
	f, err := a.NewFact(s.Config.Category, s.Config.RunID, c.Asset, "COVERAGE", before,
		a.Coverage{Metric: cooling.Power, From: before, Through: before, Code: "sparse", SourceRecord: "trigger-retry"})
	if err != nil {
		t.Fatal(err)
	}
	e.CommitClock = func() time.Time { return after }
	if err = e.Advance(t.Context(), before, before, before, []a.Fact{f}, nil); err != nil {
		t.Fatal(err)
	}
	for _, d := range e.Decisions {
		if d.CandidateID != c.ID {
			continue
		}
		if d.DecisionSource != "CATEGORY" || d.LogicalAt != c.DueAt || d.ExecutedAt != after || d.CommittedAt != after || d.LatenessUS != 1 {
			t.Fatalf("invalid retry clocks %+v", d)
		}
		return
	}
	t.Fatal("due result missing")
}

func TestAssessmentDelayedDiscoveryProcessesIntermediateUrgentTransition(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	openAt, recoverAt, wake := s.StartAt.Add(33*time.Second), s.StartAt.Add(35*time.Second), s.StartAt.Add(40*time.Second)
	input := assessmentWarmFacts(s, entry)
	input = append(input, assessmentQualification(t, s, "intermediate-thermal", "gpu_thermal", "OPEN", 1, openAt, openAt),
		assessmentQualification(t, s, "intermediate-thermal", "gpu_thermal", "RECOVER", 1, recoverAt, recoverAt))
	if err = e.Advance(t.Context(), wake, wake, wake, input, nil); err != nil {
		t.Fatal(err)
	}
	urgent := 0
	for _, d := range e.Decisions {
		if d.Action != "URGENT" {
			continue
		}
		urgent++
		if d.LogicalAt != openAt || d.ExecutedAt != wake {
			t.Fatalf("intermediate action clocks changed %+v", d)
		}
	}
	if urgent != 5 {
		t.Fatalf("missed intermediate urgent events: %d, %+v", urgent, e.Decisions)
	}
}

func TestAssessmentCorruptEntryIsQuarantinedWithoutFallback(t *testing.T) {
	for name, mutate := range map[string]func(*a.Candidate){
		"basis":                func(c *a.Candidate) { c.Entry.Basis = "INVALID" },
		"summary":              func(c *a.Candidate) { c.Entry.Fallback.Summary = string([]byte{0xff}) },
		"support-not-in-entry": func(c *a.Candidate) { c.Entry.Support = []string{strings.Repeat("a", 64)} },
	} {
		t.Run(name, func(t *testing.T) {
			s, reg := fixture(t)
			e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
			if err != nil {
				t.Fatal(err)
			}
			entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
			if err = e.Advance(t.Context(), entry, entry, entry, assessmentWarmFacts(s, entry), nil); err != nil {
				t.Fatal(err)
			}
			c := e.Candidates[1]
			mutate(c)
			if err = e.Advance(t.Context(), c.DueAt, c.DueAt, c.DueAt, nil, nil); err != nil {
				t.Fatal(err)
			}
			if c.Phase != "QUARANTINED" || c.Terminal != nil || !slices.ContainsFunc(e.Failures, func(f a.Failure) bool { return f.CandidateID == c.ID && f.Code == "HOST_STATE" }) {
				t.Fatalf("untrusted entry received a disposition %+v", c)
			}
		})
	}
}

func TestAssessmentTelemetryWaitsForQualificationAndSuppressesFirstSeenClosed(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	first := s.StartAt.Add(time.Second)
	qualified := first.Add(3 * time.Second)
	open := assessmentQualification(t, s, "future-monitor", "telemetry_loss", "OPEN", 1, first, qualified)
	staleOpen := assessmentQualification(t, s, "closed-monitor", "telemetry_loss", "OPEN", 1, first, s.StartAt)
	staleRecover := assessmentQualification(t, s, "closed-monitor", "telemetry_loss", "RECOVER", 1, first, first)
	if err = e.Advance(t.Context(), first, first, first, []a.Fact{open, staleOpen, staleRecover}, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Telemetry) != 0 {
		t.Fatalf("early or retrospective telemetry route %+v", e.Telemetry)
	}
	if err = e.Advance(t.Context(), qualified, qualified, qualified, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Telemetry) != 1 {
		t.Fatalf("missing qualified occurrence %+v", e.Telemetry)
	}
	for _, r := range e.Telemetry {
		if r.FirstAt != qualified || r.PolicyID != "future-monitor" || r.OpenFact != open.ID {
			t.Fatalf("invalid preview %+v", r)
		}
	}
	recoverAt := qualified.Add(time.Second)
	recover := assessmentQualification(t, s, "future-monitor", "telemetry_loss", "RECOVER", 1, recoverAt, recoverAt)
	if err = e.Advance(t.Context(), recoverAt, recoverAt, recoverAt, []a.Fact{recover}, nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.Telemetry {
		if r.RecoverFact != recover.ID || r.LastAt != recoverAt || r.FirstAt != qualified {
			t.Fatalf("matching recovery did not preserve preview %+v", r)
		}
	}
}

func longQualification(t testing.TB, s a.Suite, seq int64, at time.Time) a.Fact {
	t.Helper()
	snapshot := make([]a.SnapshotEntry, 32)
	for i := range snapshot {
		snapshot[i] = a.SnapshotEntry{Metric: strings.Repeat("m", 128), Unit: strings.Repeat("u", 128), SourceAt: at, Support: "UNKNOWN"}
	}
	f, err := a.NewFact(s.Config.Category, s.Config.RunID, s.Config.Assets[0].EntityKey, "QUALIFIED", at,
		a.Qualified{PolicyID: "test-inert-warning", Occurrence: seq, Transition: "OPEN", Rule: "gpu_thermal", RuleVersion: 1, EnrollmentRevision: 1,
			Severity: "WARNING", QualifiedAt: at, Snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAssessmentInlineAcquisitionStopsAtPayloadReserve(t *testing.T) {
	s, reg := fixture(t)
	s.Facts = []a.Fact{}
	s.Expected = []a.Expected{}
	s.Faults = []a.Fault{}
	s.Config.Limits.PayloadBytes = 8 << 20
	for i := int64(1); i <= 400; i++ {
		s.Facts = append(s.Facts, longQualification(t, s, i, s.StartAt))
	}
	raw, err := a.Canonical(s)
	if err != nil || len(raw) > 16<<20 {
		t.Fatalf("fixture must fit inline limit, %d %v", len(raw), err)
	}
	parsed, err := a.ParseSuite(raw, reg)
	if err != nil {
		t.Fatal(err)
	}
	e, err := a.Replay(t.Context(), parsed, reg)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "CLOSED" || e.StopReason != "CAPACITY" || len(e.Facts) != 0 ||
		!slices.ContainsFunc(e.Failures, func(f a.Failure) bool { return f.Code == "CAPACITY" && f.ScopeKey == "payload_reserve" }) {
		t.Fatalf("acquisition exceeded reserve: state %s reason %s facts %d failures %+v", e.State, e.StopReason, len(e.Facts), e.Failures)
	}
}

func TestAssessmentArchiveMarksIdealOnlyMissedDiscovery(t *testing.T) {
	s, reg := fixture(t)
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	s.Facts = assessmentWarmFacts(s, entry)
	until := s.StartAt.Add(time.Duration(s.Config.RunDurationSeconds) * time.Second)
	s.Faults = []a.Fault{{At: entry, Asset: s.Config.Assets[0].EntityKey, Purpose: "DISCOVER", Code: "STORE_UNAVAILABLE", Until: &until}}
	s.Expected = []a.Expected{}
	observed, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Candidates) != 0 {
		t.Fatal("store outage admitted a candidate")
	}
	asset := s.Config.Assets[0].EntityKey
	code, scope := "CAPACITY", "DISCOVER/0"
	id, err := a.Identity("failure", s.Config.Category, map[string]any{"run": s.Config.RunID, "asset": asset, "code": code, "scope_key": scope})
	if err != nil {
		t.Fatal(err)
	}
	first, last := entry.Add(-time.Second), entry.Add(time.Second)
	coalesced := a.Failure{ID: id, Asset: asset, Kind: "COVERAGE", Code: code, ScopeKey: scope, FirstAt: first, At: last,
		Count: 2, FactIDs: []string{}, LogicalFrom: &s.StartAt, LogicalThrough: &first}
	for _, tc := range []struct {
		name     string
		failures []a.Failure
		gaps     []a.CoverageInterval
	}{
		{name: "store unavailable", failures: observed.Failures},
		{name: "coalesced discovery capacity", failures: []a.Failure{coalesced}},
		{name: "deadline capacity interval", gaps: []a.CoverageInterval{
			{From: s.StartAt, Through: first, Code: "COVERAGE", Count: 1},
			{From: entry, Through: last, Code: "DEADLINE_CAPACITY", Count: 1},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed.Failures = tc.failures
			source := archiveEngineFixture(t, observed, reg)
			if len(tc.gaps) > 0 {
				sealFixtureArchive(t, source, func(run map[string]any) {
					run["coverage"] = archiveValue(t, tc.gaps)
					run["unknown_from"], run["unknown_through"] = s.StartAt, last
				})
			}
			dir := filepath.Join(t.TempDir(), "archive")
			if _, err := a.WriteArchive(t.Context(), dir, source); err != nil {
				t.Fatal(err)
			}
			got, err := a.ReplayArchive(t.Context(), dir, reg)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Ideal.Candidates) != 5 || len(got.ExecutionNotReproduced) != 5 || len(got.Mismatched) != 0 {
				t.Fatalf("ideal-only execution exclusions missing: ideal %d affected %v mismatches %v", len(got.Ideal.Candidates), got.ExecutionNotReproduced, got.Mismatched)
			}
		})
	}
}

func TestAssessmentArchivePreservesOpaqueQuarantine(t *testing.T) {
	s, reg := fixture(t)
	observed, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	source := archiveEngineFixture(t, observed, reg)
	id := observed.Candidates[0].ID
	asset := observed.Candidates[0].Asset
	when := observed.Candidates[0].DueAt
	source.rows = slices.DeleteFunc(source.rows, func(row a.ArchiveRow) bool {
		p := readArchiveFixtureRow(t, row)
		return row.Table == "decisions" && p["candidate_id"] == id || row.Table == "failures" && p["scope_key"] == id
	})
	for i, row := range source.rows {
		if row.Table != "candidates" || row.Key != id {
			continue
		}
		p := readArchiveFixtureRow(t, row)
		p["phase"] = "QUARANTINED"
		p["entry"] = base64.StdEncoding.EncodeToString([]byte("{"))
		delete(p, "terminal")
		delete(p, "terminal_id")
		p["reserved_codes"] = []string{}
		source.rows[i] = archiveRow(t, row.Table, row.Key, p)
	}
	failureID, _ := a.Identity("failure", s.Config.Category, map[string]any{"run": s.Config.RunID, "asset": asset, "scope_key": id, "code": "HOST_STATE"})
	body := archiveValue(t, map[string]any{"schema": int64(1), "fact_ids": []string{}, "message": "HOST_STATE", "from": when, "through": when})
	q := archiveRow(t, "failures", failureID, map[string]any{"run_id": s.Config.RunID, "id": failureID, "category": s.Config.Category, "asset": asset,
		"kind": "COMPONENT", "code": "HOST_STATE", "scope_key": id, "first_at": when, "last_at": when, "count": int64(1), "body": body})
	source.rows = append(source.rows, q)
	slices.SortStableFunc(source.rows, func(x, y a.ArchiveRow) int {
		if x.Table == "failures" && y.Table == "failures" {
			return strings.Compare(x.Key, y.Key)
		}
		return 0
	})
	sealFixtureArchive(t, source, func(run map[string]any) { run["incomplete_count"] = int64(1) })
	dir := filepath.Join(t.TempDir(), "archive")
	if _, err = a.WriteArchive(t.Context(), dir, source); err != nil {
		t.Fatal(err)
	}
	replayed, err := a.ReplayArchive(t.Context(), dir, reg)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := replayed.Observed.Report(s.Provenance, s.Labels)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Scores[0].ScoringStatus != "INCOMPLETE" || !slices.Contains(replayed.ExecutionNotReproduced, id) || len(replayed.Mismatched) != 0 {
		t.Fatalf("quarantine ledger was lost %+v / %+v", rep.Scores, replayed.Mismatched)
	}
}

func TestAssessmentArchiveDoesNotExemptUnrelatedSequence(t *testing.T) {
	s, reg := fixture(t)
	s.Faults = []a.Fault{}
	observed, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	source := archiveEngineFixture(t, observed, reg)
	id := observed.Decisions[0].ID
	for i, row := range source.rows {
		if row.Table != "decisions" || row.Key != id {
			continue
		}
		p := readArchiveFixtureRow(t, row)
		p["summary"] = "Deliberate semantic mismatch for the first sequence."
		source.rows[i] = archiveRow(t, row.Table, row.Key, p)
	}
	asset := observed.Candidates[0].Asset
	when := s.StartAt.Add(90 * time.Second)
	failureScope := "DISCOVER/1"
	failureID, _ := a.Identity("failure", s.Config.Category, map[string]any{"run": s.Config.RunID, "asset": asset, "scope_key": failureScope, "code": "PANIC"})
	body := archiveValue(t, map[string]any{"schema": int64(1), "fact_ids": []string{}, "message": "PANIC", "from": when, "through": when})
	source.rows = append(source.rows, archiveRow(t, "failures", failureID, map[string]any{"run_id": s.Config.RunID, "id": failureID, "category": s.Config.Category, "asset": asset,
		"kind": "COMPONENT", "code": "PANIC", "scope_key": failureScope, "first_at": when, "last_at": when, "count": int64(1), "body": body}))
	slices.SortStableFunc(source.rows, func(x, y a.ArchiveRow) int {
		if x.Table == "failures" && y.Table == "failures" {
			return strings.Compare(x.Key, y.Key)
		}
		return 0
	})
	sealFixtureArchive(t, source, func(map[string]any) {})
	dir := filepath.Join(t.TempDir(), "archive")
	if _, err = a.WriteArchive(t.Context(), dir, source); err != nil {
		t.Fatal(err)
	}
	replayed, err := a.ReplayArchive(t.Context(), dir, reg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(replayed.Mismatched, []string{id}) || len(replayed.ExecutionNotReproduced) != 0 {
		t.Fatalf("an unrelated failure hid comparison: mismatch=%v affected=%v", replayed.Mismatched, replayed.ExecutionNotReproduced)
	}
}

func readArchiveFixtureRow(t testing.TB, row a.ArchiveRow) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(row.Body))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
func sealFixtureArchive(t testing.TB, source *fixtureArchive, change func(map[string]any)) {
	t.Helper()
	run := readArchiveFixtureRow(t, source.rows[0])
	change(run)
	run["record_count"] = int64(len(source.rows))
	source.rows[0] = archiveRow(t, "run", source.meta.RunID, run)
	source.meta.RecordCount = int64(len(source.rows))
	source.meta.SourcePayloadBytes = 0
	for _, row := range source.rows {
		n, err := a.ArchiveRowPayloadBytes(row)
		if err != nil {
			t.Fatal(err)
		}
		source.meta.SourcePayloadBytes += n
	}
	run["payload_bytes"] = source.meta.SourcePayloadBytes
	source.rows[0] = archiveRow(t, "run", source.meta.RunID, run)
}

// This explicit load gate is separate from the ordinary correctness suite.
func TestAssessmentArchiveLongActiveWorkingSet(t *testing.T) {
	if os.Getenv("SHERLOCK_ASSESSMENT_ARCHIVE_STRESS") != "1" {
		t.Skip("set SHERLOCK_ASSESSMENT_ARCHIVE_STRESS=1 for the archive load gate")
	}
	s, reg := fixture(t)
	s.Config.RunDurationSeconds = 60000
	s.Config.Limits.PayloadBytes = 128 << 20
	s.Faults = []a.Fault{}
	recoveryAt := s.StartAt.Add(42000 * time.Second)
	s.Facts = append(s.Facts, assessmentQualification(t, s, "synthetic-thermal", "gpu_thermal", "RECOVER", 1, recoveryAt, recoveryAt))
	for sec := int64(5); sec <= 365; sec += 15 {
		s.Facts = append(s.Facts, assessmentSampleAt(t, s, recoveryAt.Add(time.Duration(sec)*time.Second), 65))
	}
	observed, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	en := observed.Enrollments[s.Config.Assets[0].EntityKey]
	if en.Active || en.DiscoveryFloor.Before(recoveryAt) || len(observed.Candidates) != 5 {
		t.Fatalf("control case did not rearm after recovery %+v", en)
	}
	source := archiveEngineFixture(t, observed, reg)
	firstBundle := slices.IndexFunc(source.rows, func(row a.ArchiveRow) bool { return row.Table == "bundles" })
	tail := slices.Clone(source.rows[firstBundle:])
	source.rows = source.rows[:firstBundle]
	metric := strings.Repeat("\\", 65) + strings.Repeat("m", 63)
	unit := strings.Repeat("\\", 65) + strings.Repeat("u", 63)
	for i := int64(0); i < 4600; i++ {
		at := s.StartAt.Add((100 + time.Duration(i/100)*901) * time.Second)
		snapshot := make([]a.SnapshotEntry, 32)
		for k := range snapshot {
			snapshot[k] = a.SnapshotEntry{Metric: metric, Unit: unit, SourceAt: at, Support: "UNKNOWN"}
		}
		f, err := a.NewFact(s.Config.Category, s.Config.RunID, s.Config.Assets[0].EntityKey, "QUALIFIED", at,
			a.Qualified{PolicyID: "inert-warning-for-memory-gate", Occurrence: i/2 + 1, Transition: []string{"OPEN", "RECOVER"}[i%2], Rule: "gpu_thermal",
				RuleVersion: 1, EnrollmentRevision: 1, Severity: "WARNING", QualifiedAt: at, Snapshot: snapshot})
		if err != nil {
			t.Fatal(err)
		}
		source.rows = append(source.rows, archiveRow(t, "facts", f.ID, map[string]any{"run_id": f.Run, "asset": f.Asset, "id": f.ID, "kind": f.Kind, "available_at": f.AvailableAt, "body": archiveValue(t, f)}))
	}
	stressFactCount := len(source.rows) - 2
	factTimes := map[string]string{}
	for _, row := range source.rows[2:] {
		p := readArchiveFixtureRow(t, row)
		factTimes[row.Key] = p["available_at"].(string)
	}
	slices.SortFunc(source.rows[2:], func(a, b a.ArchiveRow) int {
		if d := strings.Compare(factTimes[a.Key], factTimes[b.Key]); d != 0 {
			return d
		}
		return strings.Compare(a.Key, b.Key)
	})
	source.rows = append(source.rows, tail...)
	sealFixtureArchive(t, source, func(run map[string]any) { run["fact_count"] = int64(stressFactCount) })
	if source.meta.SourcePayloadBytes <= 64<<20 {
		t.Fatalf("fixture payload %d is too small", source.meta.SourcePayloadBytes)
	}
	dir := filepath.Join(t.TempDir(), "archive")
	manifest, err := a.WriteArchive(t.Context(), dir, source)
	if err != nil {
		t.Fatal(err)
	}
	source.rows = nil
	tail = nil
	factTimes = nil
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTicker(500 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
				runtime.GC()
				var current runtime.MemStats
				runtime.ReadMemStats(&current)
				b := current.HeapAlloc
				for p := peak.Load(); b > p; p = peak.Load() {
					if peak.CompareAndSwap(p, b) {
						break
					}
				}
			}
		}
	}()
	replayed, err := a.ReplayArchiveWithEvidence(t.Context(), dir, reg, io.Discard)
	close(stop)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	extra := uint64(0)
	if p := peak.Load(); p > baseline.HeapAlloc {
		extra = p - baseline.HeapAlloc
	}
	t.Logf("archive payload %d bytes, retained warning volume %d facts, peak sampled after-GC extra heap %d bytes", manifest.SourcePayloadBytes, stressFactCount, extra)
	idealEnrollment := replayed.Ideal.Enrollments[s.Config.Assets[0].EntityKey]
	if idealEnrollment.Active || idealEnrollment.DiscoveryFloor.Before(recoveryAt) || len(replayed.Mismatched) != 0 {
		t.Fatalf("long warning history prevented later rearm: active=%v floor=%s mismatches=%v failures=%+v", idealEnrollment.Active, idealEnrollment.DiscoveryFloor, replayed.Mismatched, replayed.Ideal.Failures)
	}
	if peak.Load() == 0 || extra > 64<<20 || len(replayed.Ideal.Facts) > 1024 || len(replayed.Ideal.Bundles) > 16 || len(replayed.Ideal.Candidates) != 5 {
		t.Fatalf("working set did not remain bounded: facts %d bundles %d candidates %d extra %d", len(replayed.Ideal.Facts), len(replayed.Ideal.Bundles), len(replayed.Ideal.Candidates), extra)
	}
}

func assessmentSampleAt(t testing.TB, s a.Suite, at time.Time, value float64) a.Fact {
	t.Helper()
	const record = "synthetic-settling-sample"
	f, err := a.NewFact(s.Config.Category, s.Config.RunID, s.Config.Assets[0].EntityKey, "SAMPLE", at, a.Sample{
		Metric: cooling.Temperature, Unit: "celsius", SourceAt: at, CollectedAt: at, CompletedAt: at, Value: value, SourceRecord: record,
		Provenance: a.Provenance{Mode: "fixture", CollectionRunID: record, Operation: "prometheus.gpu_temperature.v1", ScheduleRevision: 1, InventoryRevision: s.Config.InventoryRevision, SourceRecord: record},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAssessmentDelayedHistoryContinuesDiscoveryAfterRearm(t *testing.T) {
	s, reg := fixture(t)
	s.Config.RunDurationSeconds = 900
	at := func(sec int) time.Time { return s.StartAt.Add(time.Duration(sec) * time.Second) }
	first := assessmentQualification(t, s, "first-thermal", "gpu_thermal", "OPEN", 1, at(1), at(1))
	firstRecovered := assessmentQualification(t, s, "first-thermal", "gpu_thermal", "RECOVER", 1, at(2), at(2))
	second := assessmentQualification(t, s, "second-thermal", "gpu_thermal", "OPEN", 1, at(380), at(380))
	secondRecovered := assessmentQualification(t, s, "second-thermal", "gpu_thermal", "RECOVER", 1, at(385), at(385))
	facts := []a.Fact{first, firstRecovered, second, secondRecovered}
	for sec := 5; sec <= 365; sec += 15 {
		facts = append(facts, assessmentSampleAt(t, s, at(sec), 65))
	}
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Advance(t.Context(), at(400), at(400), at(400), facts, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Candidates) != 10 {
		t.Fatalf("retained rearm did not admit the next physical sequence; got %d candidates, failures %+v", len(e.Candidates), e.Failures)
	}
	for _, c := range e.Candidates {
		wanted := at(1)
		if c.Sequence == 2 {
			wanted = at(380)
		}
		if c.EnteredAt != wanted || c.Terminal == nil || c.Terminal.Action != "URGENT" {
			t.Fatalf("incorrect historical sequence %+v", c)
		}
	}
}

func TestAssessmentInlineAcquisitionRollsBackSamePassDerivedFootprint(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	batch := []a.Fact{assessmentQualification(t, s, "entry-under-reserve", "gpu_thermal", "OPEN", 1, s.StartAt, s.StartAt)}
	rowSize := func(f a.Fact) int64 {
		row := archiveRow(t, "facts", f.ID, map[string]any{"run_id": f.Run, "id": f.ID, "asset": f.Asset, "kind": f.Kind, "available_at": f.AvailableAt, "body": archiveValue(t, f)})
		size, err := a.ArchiveRowPayloadBytes(row)
		if err != nil {
			t.Fatal(err)
		}
		return size
	}
	size := rowSize(batch[0])
	for i := int64(1); ; i++ {
		f := longQualification(t, s, i, s.StartAt)
		n := rowSize(f)
		if size+n > (4<<20)-(9<<10) {
			break
		}
		size += n
		batch = append(batch, f)
	}
	invocations := 0
	e.ObserveGPU = func(string, time.Duration) { invocations++ }
	if err = e.Advance(t.Context(), s.StartAt, s.StartAt, s.StartAt, batch, nil); err != nil {
		t.Fatal(err)
	}
	if invocations != 1 || e.State != "CLOSED" || e.StopReason != "CAPACITY" || len(e.Facts)+len(e.Bundles)+len(e.Candidates)+len(e.Decisions) != 0 {
		t.Fatalf("whole acquisition was not rolled back: attempted %d state %s reason %s facts %d bundles %d candidates %d", invocations, e.State, e.StopReason, len(e.Facts), len(e.Bundles), len(e.Candidates))
	}
	for _, en := range e.Enrollments {
		if en.Active || en.Sequence != 0 || en.Revision != 1 || en.Tracker != nil {
			t.Fatalf("tentative tracker was retained %+v", en)
		}
	}
}

func TestAssessmentArchiveOverflowAfterDueExcludesRelevantFollowup(t *testing.T) {
	s, reg := fixture(t)
	s.Config.RunDurationSeconds = 240
	s.Faults = []a.Fault{}
	e, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	source := archiveEngineFixture(t, e, reg)
	start, exactThrough, uncoveredThrough := s.StartAt.Add(10*time.Second), s.StartAt.Add(20*time.Second), s.StartAt.Add(180*time.Second)
	exactGap := a.CoverageInterval{From: start, Through: exactThrough, Code: "COVERAGE", Count: 1}
	sealFixtureArchive(t, source, func(run map[string]any) {
		run["coverage"] = archiveValue(t, []a.CoverageInterval{exactGap})
		run["unknown_from"], run["unknown_through"] = start, uncoveredThrough
		run["overflow_count"] = int64(1)
	})
	dir := filepath.Join(t.TempDir(), "archive")
	if _, err = a.WriteArchive(t.Context(), dir, source); err != nil {
		t.Fatal(err)
	}
	result, err := a.ReplayArchive(t.Context(), dir, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ExecutionNotReproduced) != 5 || !slices.Contains(result.ExecutionNotReproduced, e.Candidates[0].ID) || len(result.Mismatched) != 0 {
		t.Fatalf("omitted gap did not cover retained follow-up %+v", result.ExecutionNotReproduced)
	}
}

func TestAssessmentArchiveGapAfterKnownRearmDoesNotExclude(t *testing.T) {
	s, reg := fixture(t)
	s.Config.RunDurationSeconds = 900
	s.Faults = []a.Fault{}
	at := func(sec int) time.Time { return s.StartAt.Add(time.Duration(sec) * time.Second) }
	s.Facts = []a.Fact{assessmentQualification(t, s, "early-thermal", "gpu_thermal", "OPEN", 1, at(1), at(1)),
		assessmentQualification(t, s, "early-thermal", "gpu_thermal", "RECOVER", 1, at(2), at(2))}
	for sec := 5; sec <= 365; sec += 15 {
		s.Facts = append(s.Facts, assessmentSampleAt(t, s, at(sec), 65))
	}
	observed, err := a.Replay(t.Context(), s, reg)
	if err != nil {
		t.Fatal(err)
	}
	en := observed.Enrollments[s.Config.Assets[0].EntityKey]
	if en.Active || en.DiscoveryFloor.After(at(365)) || en.Sequence != 1 {
		t.Fatalf("fixture lacks a committed early rearm %+v", en)
	}
	source := archiveEngineFixture(t, observed, reg)
	gap := a.CoverageInterval{From: at(600), Through: at(660), Code: "COVERAGE", Count: 1}
	sealFixtureArchive(t, source, func(run map[string]any) {
		run["coverage"] = archiveValue(t, []a.CoverageInterval{gap})
		run["unknown_from"], run["unknown_through"] = gap.From, gap.Through
	})
	dir := filepath.Join(t.TempDir(), "archive")
	if _, err = a.WriteArchive(t.Context(), dir, source); err != nil {
		t.Fatal(err)
	}
	result, err := a.ReplayArchive(t.Context(), dir, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ExecutionNotReproduced) != 0 || len(result.Mismatched) != 0 {
		t.Fatalf("post-rearm gap excluded prior dispositions: unreproduced=%v mismatched=%v", result.ExecutionNotReproduced, result.Mismatched)
	}
}

func TestAssessmentDeferredTelemetryAdmissionHonorsReserve(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	qualification := s.StartAt.Add(time.Second)
	batch := []a.Fact{}
	rowSize := func(f a.Fact) int64 {
		row := archiveRow(t, "facts", f.ID, map[string]any{"run_id": f.Run, "id": f.ID, "asset": f.Asset, "kind": f.Kind, "available_at": f.AvailableAt, "body": archiveValue(t, f)})
		n, err := a.ArchiveRowPayloadBytes(row)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	var size int64
	for occ := int64(1); occ <= 64; occ++ {
		f := assessmentQualification(t, s, "reserve-monitor", "telemetry_loss", "OPEN", occ, s.StartAt, qualification)
		batch = append(batch, f)
		size += rowSize(f)
	}
	for n := int64(1); ; n++ {
		f := longQualification(t, s, n, s.StartAt)
		v := rowSize(f)
		if size+v > (4<<20)-(40<<10) {
			break
		}
		size += v
		batch = append(batch, f)
	}
	if err = e.Advance(t.Context(), s.StartAt, s.StartAt, s.StartAt, batch, nil); err != nil {
		t.Fatal(err)
	}
	if e.State != "ACTIVE" || len(e.Facts) != len(batch) || len(e.Telemetry) != 0 {
		t.Fatalf("first nonqualifying pass should commit facts: state=%s facts=%d telemetry=%d", e.State, len(e.Facts), len(e.Telemetry))
	}
	bundles := len(e.Bundles)
	if err = e.Advance(t.Context(), qualification, qualification, qualification, nil, nil); err != nil {
		t.Fatal(err)
	}
	if e.State != "CLOSED" || e.StopReason != "CAPACITY" || len(e.Facts) != len(batch) || len(e.Bundles) != bundles || len(e.Telemetry) != 0 || len(e.Candidates) != 0 {
		t.Fatalf("deferred admission crossed reserve: state=%s reason=%s facts=%d bundles=%d telemetry=%d", e.State, e.StopReason, len(e.Facts), len(e.Bundles), len(e.Telemetry))
	}
}

func TestAssessmentRecoveryPinsOpaqueVersionAndUsesTrustedFallback(t *testing.T) {
	s, reg := fixture(t)
	warm, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entered := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	if err = warm.Advance(t.Context(), entered, entered, entered, assessmentWarmFacts(s, entered), nil); err != nil {
		t.Fatal(err)
	}
	_, d, _, err := reg.LookupVersion(s.Config.Category, s.Config.Implementation)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Config
	c.Implementation = 9
	d.Implementation = 9
	c.Policy = json.RawMessage("{\"opaque_for_recovery\":true}")
	ch, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	dh, err := a.Identity("descriptor", d.Category, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.NewEngine(t.Context(), c, s.StartAt, reg); err == nil {
		t.Fatal("normal admission accepted an unavailable category")
	}
	raw, err := a.Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	recoveredConfig, err := a.ParseRecoveryConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.ParseRecoveryConfig([]byte("{")); !errors.Is(err, a.ErrInvalid) {
		t.Fatal("malformed recovery config accepted")
	}
	if _, err = a.NewRecoveryEngine(t.Context(), recoveredConfig, s.StartAt, d, strings.Repeat("a", 64), dh); err == nil {
		t.Fatal("mismatched immutable config accepted")
	}
	if _, err = a.NewRecoveryEngine(t.Context(), recoveredConfig, s.StartAt, d, ch, strings.Repeat("a", 64)); err == nil {
		t.Fatal("mismatched pinned descriptor accepted")
	}
	e, err := a.NewRecoveryEngine(t.Context(), recoveredConfig, s.StartAt, d, ch, dh)
	if err != nil {
		t.Fatal(err)
	}
	e.Facts, e.Bundles, e.Enrollments, e.Candidates = warm.Facts, warm.Bundles, warm.Enrollments, warm.Candidates
	countedFacts, countedBundles := len(e.Facts), len(e.Bundles)
	first := e.Candidates[1]
	before := first.DueAt.Add(-time.Microsecond)
	if err = e.Advance(t.Context(), before, before, before, nil, nil); err != nil {
		t.Fatal(err)
	}
	if first.Phase != "OBSERVING" || len(e.Decisions) != 0 {
		t.Fatal("recovery changed a future arm")
	}
	// A corrupt or unavailable category state is irrelevant to the already
	// trusted fallback envelope.
	first.State.Body = json.RawMessage("{")
	late := first.DueAt.Add(time.Microsecond)
	if err = e.Advance(t.Context(), late, late, late, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Decisions) != 1 {
		t.Fatalf("expected one durable disposition, got %d", len(e.Decisions))
	}
	x := e.Decisions[0]
	if x.CandidateID != first.ID || x.DecisionSource != "HOST_FALLBACK" || x.FailureCode != "UNSUPPORTED_VERSION" ||
		x.BundleID != first.Entry.BundleID || x.Action != "INVESTIGATE" || x.LogicalAt != first.DueAt || x.LatenessUS != 1 ||
		!slices.Equal(x.Support, first.Entry.Support) || len(e.Facts) != countedFacts || len(e.Bundles) != countedBundles {
		t.Fatalf("wrong host-only expiry %+v", x)
	}
	second := e.Candidates[2]
	second.Entry.Basis = "INVALID"
	if err = e.Advance(t.Context(), second.DueAt, second.DueAt, second.DueAt, nil, nil); err != nil {
		t.Fatal(err)
	}
	if second.Phase != "QUARANTINED" || len(e.Decisions) != 1 {
		t.Fatalf("untrusted host core was not quarantined %+v", second)
	}
}

func TestAssessmentSuppressedAssetUsesCapacityFallbackWithoutCategory(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	if err = e.Advance(t.Context(), entry, entry, entry, assessmentWarmFacts(s, entry), nil); err != nil {
		t.Fatal(err)
	}
	c := e.Candidates[1]
	e.SuppressAsset(c.Asset, "CAPACITY")
	e.Registry = nil // A category call in the recovery path would panic.
	before := c.DueAt.Add(-time.Microsecond)
	extra := assessmentSampleAt(t, s, before, 100)
	n := len(e.Facts)
	if err = e.Advance(t.Context(), before, before, before, []a.Fact{extra}, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Facts) != n || c.Phase != "OBSERVING" {
		t.Fatal("suppressed asset accepted input or changed a future arm")
	}
	if err = e.Advance(t.Context(), c.DueAt, c.DueAt, c.DueAt, nil, nil); err != nil {
		t.Fatal(err)
	}
	last := e.Decisions[len(e.Decisions)-1]
	if last.CandidateID != c.ID || last.FailureCode != "CAPACITY" || last.DecisionSource != "HOST_FALLBACK" || last.BundleID != c.Entry.BundleID {
		t.Fatalf("missing scoped host fallback %+v", last)
	}
	if !slices.ContainsFunc(e.Failures, func(f a.Failure) bool {
		return f.Asset == c.Asset && f.ScopeKey == "FOLLOW_UP/1" && f.Code == "CAPACITY" && f.Count == 2 &&
			f.LogicalFrom != nil && f.LogicalFrom.Equal(entry) && f.LogicalThrough != nil && f.LogicalThrough.Equal(c.DueAt)
	}) {
		t.Fatalf("suppressed active asset lost its follow-up coverage: %+v", e.Failures)
	}
}

func TestAssessmentDiscoverySkipsUnusedTrackerContextLookup(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	asset := s.Config.Assets[0].EntityKey
	activeLookups, inactiveLookups := 0, 0
	var retained a.Fact
	e.LookupContext = func(ctx context.Context, key string, cutoff, floor time.Time) (a.Fact, bool) {
		if e.Enrollments[asset].Active {
			activeLookups++
		} else {
			inactiveLookups++
		}
		return retained, retained.Asset == key && !retained.AvailableAt.After(cutoff) && !retained.AvailableAt.Before(floor)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	if err = e.Advance(t.Context(), entry, entry, entry, assessmentWarmFacts(s, entry), nil); err != nil {
		t.Fatal(err)
	}
	if !e.Enrollments[asset].Active || inactiveLookups != 0 {
		t.Fatalf("discovery active %v, unused context lookups %d", e.Enrollments[asset].Active, inactiveLookups)
	}
	for id, f := range e.Facts {
		if f.Kind == "TRACKER_CONTEXT" {
			retained = f
			delete(e.Facts, id)
		}
	}
	if retained.ID == "" {
		t.Fatal("fixture did not retain entry tracker context")
	}
	e.LookupFact = func(ctx context.Context, id string) (a.Fact, bool) { return retained, id == retained.ID }
	wake := entry.Add(time.Second)
	if err = e.Advance(t.Context(), wake, wake, wake, []a.Fact{assessmentSampleAt(t, s, wake, 75)}, nil); err != nil {
		t.Fatal(err)
	}
	if activeLookups == 0 || len(e.Failures) != 0 {
		t.Fatalf("active work made %d retained context lookups, failures %+v", activeLookups, e.Failures)
	}
}

func TestAssessmentSuppressedDiscoveryCoalescesWithoutBlockingOtherAsset(t *testing.T) {
	s, reg := fixture(t)
	blocked := s.Config.Assets[0]
	healthy := blocked
	healthy.GPUUUID = "GPU-00000000-0000-0000-0000-000000000002"
	healthy.EntityKey = strings.Replace(blocked.EntityKey, blocked.GPUUUID, healthy.GPUUUID, 1)
	s.Config.Assets = append(s.Config.Assets, healthy)
	s.Config.Limits.GPUCount = 2
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	floor := s.StartAt.Add(5 * time.Second)
	if err = e.AdvanceAssets(t.Context(), floor, floor, floor, nil, nil, []string{blocked.EntityKey}); err != nil {
		t.Fatal(err)
	}
	en := e.Enrollments[blocked.EntityKey]
	if !en.DiscoveryFloor.Equal(floor) {
		t.Fatalf("fixture did not advance discovery floor: %+v", en)
	}
	revision, processed := en.Revision, en.ProcessedAt
	e.SuppressAsset(blocked.EntityKey, "CAPACITY")
	deferred := s.StartAt.Add(6 * time.Second)
	if err = e.AdvanceAssets(t.Context(), deferred, deferred, deferred, nil, nil, []string{}); err != nil {
		t.Fatal(err)
	}
	if len(e.Failures) != 0 {
		t.Fatalf("unselected asset generated failures: %+v", e.Failures)
	}
	first := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	facts := []a.Fact{assessmentSampleAt(t, s, first, 100)}
	for _, f := range assessmentWarmFacts(s, first) {
		f, err := a.NewFact(s.Config.Category, f.Run, healthy.EntityKey, f.Kind, f.AvailableAt, f.Body)
		if err != nil {
			t.Fatal(err)
		}
		facts = append(facts, f)
	}
	firstExec := first.Add(2 * time.Millisecond)
	if err = e.AdvanceAssets(t.Context(), first, firstExec, firstExec, facts, nil, []string{blocked.EntityKey, healthy.EntityKey}); err != nil {
		t.Fatal(err)
	}
	last := first.Add(time.Second)
	lastExec := last.Add(3 * time.Millisecond)
	if err = e.AdvanceAssets(t.Context(), last, lastExec, lastExec, nil, nil, []string{blocked.EntityKey}); err != nil {
		t.Fatal(err)
	}
	if len(e.Candidates) != 5 || slices.ContainsFunc(e.Candidates, func(c *a.Candidate) bool { return c.Asset != healthy.EntityKey }) ||
		len(e.Decisions) != 1 || e.Decisions[0].CandidateID != e.Candidates[0].ID || e.Decisions[0].DecisionSource != "CATEGORY" {
		t.Fatalf("wrong disposition for healthy asset: %d candidates, decisions %+v", len(e.Candidates), e.Decisions)
	}
	if _, admitted := e.Facts[facts[0].ID]; admitted || en.Revision != revision || !en.ProcessedAt.Equal(processed) || !en.DiscoveryFloor.Equal(floor) || en.Active {
		t.Fatalf("suppressed asset consumed work: admitted %v enrollment %+v", admitted, en)
	}
	if len(e.Failures) != 1 {
		t.Fatalf("expected one coalesced failure, got %+v", e.Failures)
	}
	failure := e.Failures[0]
	if failure.Asset != blocked.EntityKey || failure.Kind != "COVERAGE" || failure.Code != "CAPACITY" || failure.ScopeKey != "DISCOVER/0" ||
		failure.Count != 2 || !failure.FirstAt.Equal(firstExec) || !failure.At.Equal(lastExec) ||
		failure.LogicalFrom == nil || !failure.LogicalFrom.Equal(floor) || failure.LogicalThrough == nil || !failure.LogicalThrough.Equal(last) {
		t.Fatalf("wrong discovery coverage: %+v", failure)
	}
}

func TestAssessmentSuppressedDiscoveryPreservesOverflowWindow(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	e.Shadow = true
	e.Failures = make([]a.Failure, 1023)
	e.Telemetry["existing"] = &a.TelemetryRecord{}
	from, through := s.StartAt.Add(5*time.Second), s.StartAt.Add(9*time.Second)
	e.UnknownFrom, e.UnknownThrough = &from, &through
	for i := range 1023 {
		at := from.Add(time.Duration(i) * time.Microsecond)
		e.CoverageIntervals = append(e.CoverageIntervals, a.CoverageInterval{Code: "COVERAGE", From: at, Through: at, Count: 1})
	}
	marker := a.CoverageInterval{Code: "DEADLINE_CAPACITY", From: through, Through: through, Count: 1}
	e.CoverageIntervals = append(e.CoverageIntervals, marker)
	asset := s.Config.Assets[0].EntityKey
	e.SuppressAsset(asset, "CAPACITY")
	first, last := s.StartAt.Add(10*time.Second), s.StartAt.Add(20*time.Second)
	for _, at := range []time.Time{first, last} {
		executed := at.Add(time.Millisecond)
		if err = e.AdvanceAssets(t.Context(), at, executed, executed, nil, nil, []string{asset}); err != nil {
			t.Fatal(err)
		}
	}
	if e.FailureOverflow != 2 || len(e.Failures)+len(e.Telemetry) != 1024 || len(e.Candidates)+len(e.Decisions) != 0 ||
		e.UnknownFrom == nil || !e.UnknownFrom.Equal(s.StartAt) || e.UnknownThrough == nil || !e.UnknownThrough.Equal(last) {
		t.Fatalf("wrong overflow summary: count %d, unknown %v through %v", e.FailureOverflow, e.UnknownFrom, e.UnknownThrough)
	}
	if len(e.CoverageIntervals) != 1024 || !slices.Contains(e.CoverageIntervals, marker) ||
		!slices.Contains(e.CoverageIntervals, a.CoverageInterval{Code: "CAPACITY", From: s.StartAt, Through: last, Count: 2}) {
		t.Fatalf("bounded coverage ledger of %d intervals lost a capacity window", len(e.CoverageIntervals))
	}
	acquisitionFrom, acquisitionThrough := last.Add(time.Second), last.Add(2*time.Second)
	e.RecordCoverageGap(acquisitionFrom, acquisitionThrough)
	if len(e.CoverageIntervals) != 1024 || !slices.Contains(e.CoverageIntervals, marker) ||
		!slices.ContainsFunc(e.CoverageIntervals, func(gap a.CoverageInterval) bool {
			return gap.Code == "COVERAGE" && !gap.From.After(acquisitionFrom) && gap.Through.Equal(acquisitionThrough)
		}) {
		t.Fatal("bounded coverage ledger lost an acquisition gap")
	}
}

func TestAssessmentArchiveAdmissionInputWitness(t *testing.T) {
	for _, tc := range []struct {
		name, witness  string
		present, valid bool
	}{
		{"absent", "", false, true}, {"present", strings.Repeat("a", 64), true, true},
		{"empty", "", true, false}, {"invalid", "invalid", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, reg := fixture(t)
			e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
			if err != nil {
				t.Fatal(err)
			}
			end := e.AdmissionEndAt
			if err = e.Advance(t.Context(), end, end, end, nil, nil); err != nil {
				t.Fatal(err)
			}
			source := archiveEngineFixture(t, e, reg)
			before := source.meta.SourcePayloadBytes
			if tc.present {
				run := readArchiveFixtureRow(t, source.rows[0])
				run["input_config_hash"] = tc.witness
				source.rows[0] = archiveRow(t, "run", source.meta.RunID, run)
				if !tc.valid {
					if _, err := a.ArchiveRowPayloadBytes(source.rows[0]); !errors.Is(err, a.ErrInvalid) {
						t.Fatalf("invalid witness accepted: %v", err)
					}
					return
				}
				sealFixtureArchive(t, source, func(map[string]any) {})
			}
			if source.meta.SourcePayloadBytes != before+int64(len(tc.witness)) {
				t.Fatal("witness physical byte accounting mismatch")
			}
			dir := filepath.Join(t.TempDir(), "archive")
			if _, err = a.WriteArchive(t.Context(), dir, source); err != nil {
				t.Fatal(err)
			}
			result, err := a.ReplayArchive(t.Context(), dir, reg)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Mismatched) != 0 || result.Observed.Config.RunID != s.Config.RunID {
				t.Fatal("witness changed replay semantics")
			}
		})
	}
}

func TestAssessmentRequestResolverUsesGPUDeadline(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	if err := e.Advance(t.Context(), entry, entry, entry, assessmentWarmFacts(s, entry), nil); err != nil {
		t.Fatal(err)
	}
	if len(e.Candidates) != 5 {
		t.Fatal("fixture requires active cohort")
	}
	e.Shadow = true
	e.Bundles = map[string]a.Bundle{}
	calls := 0
	e.LookupBundle = func(ctx context.Context, _ string) (a.Bundle, bool) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > a.ShadowGPUBudget {
			t.Fatal("request lookup did not receive the GPU deadline")
		}
		<-ctx.Done()
		return a.Bundle{}, false
	}
	wake := entry.Add(time.Second)
	parent, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := e.Advance(parent, wake, wake, wake, []a.Fact{assessmentSampleAt(t, s, wake, 75)}, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || parent.Err() != nil {
		t.Fatalf("lookup calls=%d parent=%v", calls, parent.Err())
	}
	if !slices.ContainsFunc(e.Failures, func(f a.Failure) bool { return f.Code == "TIME_BUDGET" && f.ScopeKey == "FOLLOW_UP/1" }) {
		t.Fatalf("missing TIME_BUDGET: %+v", e.Failures)
	}
	for _, c := range e.Candidates {
		if c.Phase == "QUARANTINED" {
			t.Fatal("request timeout quarantined an admitted arm")
		}
	}
}

func TestAssessmentRequestResolverAllowsExtendedGPUWork(t *testing.T) {
	s, reg := fixture(t)
	e, err := a.NewEngine(t.Context(), s.Config, s.StartAt, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry := s.StartAt.Add(30*time.Second + 125*time.Microsecond)
	if err := e.Advance(t.Context(), entry, entry, entry, assessmentWarmFacts(s, entry), nil); err != nil {
		t.Fatal(err)
	}
	bundles := e.Bundles
	e.Bundles = map[string]a.Bundle{}
	e.Shadow = true
	calls := 0
	e.LookupBundle = func(ctx context.Context, id string) (a.Bundle, bool) {
		calls++
		if calls == 1 {
			// A resolver that needs more than the previous 50 ms allowance must
			// finish under the revised budget, without losing its frozen input.
			timer := time.NewTimer(75 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal("resolver canceled before completing extended work")
			}
		}
		b, ok := bundles[id]
		return b, ok
	}
	wake := entry.Add(time.Second)
	if err := e.Advance(t.Context(), wake, wake, wake, []a.Fact{assessmentSampleAt(t, s, wake, 75)}, nil); err != nil {
		t.Fatal(err)
	}
	if calls == 0 || len(e.Failures) != 0 {
		t.Fatalf("lookup calls=%d failures=%+v", calls, e.Failures)
	}
}
