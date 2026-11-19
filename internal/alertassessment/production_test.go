package alertassessment_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func productionFixture(t *testing.T) (a.ProductionConfig, *a.Registry, time.Time) {
	t.Helper()
	suite, _ := fixture(t)
	r, err := a.NewRegistry(cooling.Category{}, cooling.ProductionCategory{})
	if err != nil {
		t.Fatal(err)
	}
	c := suite.Config
	c.Implementation = 2
	c.RunDurationSeconds = 0
	c.BudgetsMS = []int64{120000}
	for i := range c.Bindings {
		b := &c.Bindings[i]
		b.ScopeNodes = []string{c.Assets[0].NodeID}
		b.UploadCollectorID = "collector"
		b.UploadProfileID = "production"
		b.UploadProfileHash = strings.Repeat("a", 64)
	}
	cfg, err := a.NormalizeProductionConfig(t.Context(), a.ProductionConfig{Schema: 1, Revision: 1, EvidenceBaseURL: "https://sherlock.example", Assessment: c}, r)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, r, suite.StartAt
}
func productionSamples(t *testing.T, c a.ProductionConfig, at time.Time, temperature float64) []a.Fact {
	t.Helper()
	facts := []a.Fact{}
	for _, b := range c.Assessment.Bindings {
		v, u := temperature, "celsius"
		if b.Metric == cooling.Power {
			v, u = 200, "watts"
		}
		id := fmt.Sprintf("sample-%s-%d", b.Metric, at.Unix())
		digest := domain.ChecksumSHA256([]byte(id)).String()
		sample := a.Sample{Metric: b.Metric, Unit: u, SourceAt: at, CollectedAt: at, CompletedAt: at, Value: v, SourceRecord: id, Provenance: a.Provenance{Mode: "upload", CollectionRunID: domain.CoolingUploadRunPrefix + digest, Operation: b.Operation, ScheduleRevision: b.ScheduleRevision, InventoryRevision: c.Assessment.InventoryRevision, SourceRecord: id, CollectorID: b.UploadCollectorID, UploadProfileID: b.UploadProfileID, UploadProfileHash: b.UploadProfileHash}}
		f, err := a.NewFact(c.Assessment.Category, c.Assessment.RunID, c.Assessment.Assets[0].EntityKey, "SAMPLE", at, sample)
		if err != nil {
			t.Fatal(err)
		}
		facts = append(facts, f)
	}
	return facts
}
func TestProductionConfigCannotEnterShadow(t *testing.T) {
	c, r, start := productionFixture(t)
	raw, err := json.Marshal(c.Assessment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.ParseConfig(t.Context(), raw, r); err == nil {
		t.Fatal("production config admitted as shadow")
	}
	c.Assessment.Implementation = 1
	if _, err = a.NewProductionEngine(t.Context(), c, start, r); err == nil {
		t.Fatal("old implementation granted production capability")
	}
}
func TestProductionContinuousRestartAndRecovery(t *testing.T) {
	c, r, start := productionFixture(t)
	start = start.Add(48 * time.Hour)
	e, err := a.NewProductionEngine(t.Context(), c, start.Add(-48*time.Hour), r)
	if err != nil {
		t.Fatal(err)
	}
	asset := c.Assessment.Assets[0].EntityKey
	if err = e.RestoreProduction(asset, nil); err != nil {
		t.Fatal(err)
	}
	seenTerminal, seenRecovery := false, false
	var originalID string
	var originalDue time.Time
	for sec := 0; sec <= 900; sec += 15 {
		at := start.Add(time.Duration(sec) * time.Second)
		temperature := 80.0
		if sec > 150 {
			temperature = 55
		}
		if err = e.Advance(t.Context(), at, at, at, productionSamples(t, c, at, temperature), nil); err != nil {
			t.Fatal(err)
		}
		if e.State != "ACTIVE" {
			t.Fatalf("continuous lifecycle closed after24h: %s %s", e.State, e.StopReason)
		}
		for _, d := range e.Decisions {
			if d.Kind == "TERMINAL" {
				seenTerminal = true
			}
			if d.Kind == "RECOVER" {
				seenRecovery = true
			}
			if _, err = e.ProductionEvidence(d); err != nil {
				t.Fatalf("missing retainedproof %s: %v", d.Kind, err)
			}
		}
		if sec == 30 {
			if len(e.Candidates) != 1 {
				t.Fatalf("want one production arm, got%d failures%+v", len(e.Candidates), e.Failures)
			}
			originalID, originalDue = e.Candidates[0].ID, e.Candidates[0].DueAt
		}
		snapshot, err := e.SnapshotProduction(asset, at)
		if err != nil {
			t.Fatalf("snapshot at%d: %v", sec, err)
		}
		e, err = a.NewProductionEngine(t.Context(), c, start.Add(-48*time.Hour), r)
		if err != nil {
			t.Fatal(err)
		}
		if err = e.RestoreProduction(asset, snapshot); err != nil {
			t.Fatal(err)
		}
		if sec == 45 && (len(e.Candidates) != 1 || e.Candidates[0].ID != originalID || !e.Candidates[0].DueAt.Equal(originalDue)) {
			t.Fatal("restart changed occurrence or deadline")
		}
	}
	if !seenTerminal || !seenRecovery {
		t.Fatalf("terminal=%v recovery=%v failures=%+v", seenTerminal, seenRecovery, e.Failures)
	}
}

func TestProductionEvidenceRouteScope(t *testing.T) {
	cfg, r, _ := productionFixture(t)
	for _, id := range []string{"space name", "a/b", "a%2fb", "café", ".", ".."} {
		c := cfg
		c.Assessment.RunID = id
		if _, err := a.NormalizeProductionConfig(t.Context(), c, r); err == nil {
			t.Fatalf("invalid route enrollment accepted %q", id)
		}
		c = cfg
		c.Assessment.ClusterID = id
		if _, err := a.NormalizeProductionConfig(t.Context(), c, r); err == nil {
			t.Fatalf("invalid route cluster accepted %q", id)
		}
	}
	for _, origin := range []string{" ", "\t", "/admin/history", "http://sherlock.example", "https://user:secret@sherlock.example", "https://sherlock.example/path", "https://sherlock.example/%2f", "https://sherlock.example/?x=1", "https://sherlock.example?", "https://sherlock.example#"} {
		c := cfg
		c.EvidenceBaseURL = origin
		if _, err := a.NormalizeProductionConfig(t.Context(), c, r); err == nil {
			t.Fatalf("nonorigin evidence URL accepted %q", origin)
		}
	}
	cfg.Assessment.RunID = "production:cld1_rc.6-2026"
	cfg.EvidenceBaseURL = "https://sherlock.example/"
	if _, err := a.NormalizeProductionConfig(t.Context(), cfg, r); err != nil {
		t.Fatal("valid route rejected", err)
	}
}

func TestProductionConfigWithoutEvidenceOrigin(t *testing.T) {
	cfg, r, _ := productionFixture(t)
	cfg.EvidenceBaseURL = ""
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, omit := range []bool{false, true} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if omit {
			delete(fields, "evidence_base_url")
		} else {
			fields["evidence_base_url"] = json.RawMessage(`""`)
		}
		input, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := a.ParseProductionConfig(t.Context(), input, r)
		if err != nil || parsed.EvidenceBaseURL != "" || parsed.NotificationsEnabled != cfg.NotificationsEnabled {
			t.Fatalf("no-origin configuration omitted=%v: config=%+v err=%v", omit, parsed, err)
		}
	}
}

func TestProductionSnapshotCancellationAndOpaqueBytes(t *testing.T) {
	c, r, start := productionFixture(t)
	e, err := a.NewProductionEngine(t.Context(), c, start, r)
	if err != nil {
		t.Fatal(err)
	}
	asset := c.Assessment.Assets[0].EntityKey
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = e.SnapshotProductionContext(ctx, asset, start); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled snapshot: %v", err)
	}
	if _, err = e.ProductionEvidenceContext(ctx, a.Decision{BundleID: "missing"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled evidence: %v", err)
	}
	// JSON snapshot encoding must not HTML-escape opaque category payloads and
	// thereby change their immutable content hash during persistence.
	p, err := a.NewPayload(c.Assessment.Category, "tracker", 1, struct {
		Value string `json:"value"`
	}{"a<b&c"})
	if err != nil {
		t.Fatal(err)
	}
	e.Enrollments[asset].Tracker = &p
	raw, err := e.SnapshotProductionContext(t.Context(), asset, start)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := a.NewProductionEngine(t.Context(), c, start, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = copy.RestoreProduction(asset, raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copy.Enrollments[asset].Tracker.Body, p.Body) {
		t.Fatal("snapshot changed opaque bytes")
	}
}

// Cancellation can arrive after entry, while recent evidence is traversed.
// This deterministic context avoids timing-dependent sleeps in the regression.
type productionCancelDuringTraversal struct {
	context.Context
	remaining int
}

func (c *productionCancelDuringTraversal) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}
func TestProductionSnapshotStopsDuringTraversal(t *testing.T) {
	c, r, start := productionFixture(t)
	e, err := a.NewProductionEngine(t.Context(), c, start, r)
	if err != nil {
		t.Fatal(err)
	}
	asset := c.Assessment.Assets[0].EntityKey
	for n := range 3 {
		id := fmt.Sprintf("unused-%d", n)
		e.Facts[id] = a.Fact{ID: id, Kind: "SAMPLE", Asset: asset, Body: json.RawMessage(`{}`)}
	}
	ctx := &productionCancelDuringTraversal{Context: t.Context(), remaining: 3}
	if _, err = e.SnapshotProductionContext(ctx, asset, start); !errors.Is(err, context.Canceled) {
		t.Fatalf("traversal ignored cancellation: %v", err)
	}
}

func TestProductionFleetLimitsPreserveShadowBounds(t *testing.T) {
	c, r, _ := productionFixture(t)
	c.Assessment.Assets = nil
	nodes := []string{}
	for i := 0; i < 128; i++ {
		node := fmt.Sprintf("node-%02d", i/8)
		gpu := fmt.Sprintf("GPU-%012d", i)
		if i%8 == 0 {
			nodes = append(nodes, node)
		}
		c.Assessment.Assets = append(c.Assessment.Assets, a.Asset{EntityKey: fmt.Sprintf("%s/GPU/%s/%s/", c.Assessment.ClusterID, node, gpu), NodeID: node, GPUUUID: gpu})
	}
	c.Assessment.Limits.GPUCount = 128
	c.Assessment.Limits.NodeCount = 16
	for i := range c.Assessment.Bindings {
		c.Assessment.Bindings[i].ScopeNodes = nodes
	}
	if _, err := a.NormalizeProductionConfig(t.Context(), c, r); err != nil {
		t.Fatalf("full production fleet rejected: %v", err)
	}
	for _, counts := range [][2]int64{{129, 16}, {128, 17}} {
		bad := c
		bad.Assessment.Limits.GPUCount = counts[0]
		bad.Assessment.Limits.NodeCount = counts[1]
		if _, err := a.NormalizeProductionConfig(t.Context(), bad, r); err == nil {
			t.Fatal("unbounded production accepted")
		}
	}
	shadow := c.Assessment
	shadow.Implementation = 1
	shadow.RunDurationSeconds = 60
	shadow.BudgetsMS = []int64{0, 15000, 30000, 60000, 120000}
	raw, err := json.Marshal(shadow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.ParseConfig(t.Context(), raw, r); err == nil {
		t.Fatal("fleet production limits leaked into shadow")
	}
}

func TestProductionAssetEngineRetainsEnrollmentHash(t *testing.T) {
	c, r, start := productionFixture(t)
	second := c.Assessment.Assets[0]
	second.GPUUUID = "GPU-00000000-0000-0000-0000-000000000002"
	second.EntityKey = fmt.Sprintf("%s/GPU/%s/%s/", c.Assessment.ClusterID, second.NodeID, second.GPUUUID)
	c.Assessment.Assets = append(c.Assessment.Assets, second)
	c.Assessment.Limits.GPUCount = 2
	c, err := a.NormalizeProductionConfig(t.Context(), c, r)
	if err != nil {
		t.Fatal(err)
	}
	full, err := a.NewProductionEngine(t.Context(), c, start, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = full.RestoreProduction(second.EntityKey, nil); err != nil {
		t.Fatal(err)
	}
	selected, err := a.NewProductionAssetEngine(t.Context(), c, start, r, second.EntityKey)
	if err != nil {
		t.Fatal(err)
	}
	fullReport, err := full.Report("SYNTHETIC", nil)
	if err != nil {
		t.Fatal(err)
	}
	selectedReport, err := selected.Report("SYNTHETIC", nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := c.Assessment.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if fullReport.ConfigHash != want || selectedReport.ConfigHash != want || len(selected.Enrollments) != 1 || len(selected.Config.Assets) != 1 {
		t.Fatal("asset engine lost immutable full-enrollment identity")
	}
	if len(c.Assessment.Assets) != 2 {
		t.Fatal("asset engine mutated source enrollment")
	}
	if _, err = a.NewProductionAssetEngine(t.Context(), c, start, r, "unadmitted"); err == nil {
		t.Fatal("asset engine expanded admission")
	}
}
