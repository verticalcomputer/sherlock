package adminui

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestStackedBarLaysSegmentsEndToEndAgainstSharedScale(t *testing.T) {
	bar := newStackedBar([]barPart{{Class: "healthy", Count: 3}, {Class: "degraded"}, {Class: "unavailable", Count: 1}}, 8)
	if bar.Total != 4 || bar.Segments[0].X != "0.000%" || bar.Segments[0].Width != "37.500%" || bar.Segments[1].Width != "0%" || bar.Segments[2].X != "37.500%" || bar.Segments[2].Width != "12.500%" {
		t.Fatalf("bar = %+v", bar)
	}
	if own := newStackedBar([]barPart{{Count: 1}, {Count: 3}}, 0); own.Segments[1].X != "25.000%" || own.Segments[1].Width != "75.000%" {
		t.Fatalf("self-scaled bar = %+v", own)
	}
}

func TestActivityWindowBucketsRunsByUTCDayAndOutcome(t *testing.T) {
	now := time.Date(2026, 9, 11, 16, 0, 0, 0, time.UTC)
	window := buildActivityWindow([]Investigation{
		{Status: "COMPLETED", UpdatedAt: now.Add(-time.Hour), AuditedCostMicrounits: 400_000, AuditedTokens: 1_000},
		{Status: "PARTIAL", UpdatedAt: now.Add(-2 * time.Hour), AuditedCostMicrounits: 100_000},
		{Status: "FAILED", UpdatedAt: time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)},
		{Status: "COMPLETED", UpdatedAt: time.Date(2026, 8, 28, 23, 59, 0, 0, time.UTC)},
	}, now)
	if window.RunCount != 3 || window.Cost != 500_000 || window.Tokens != 1_000 || len(window.Runs.Columns) != activityDays {
		t.Fatalf("window totals = %+v", window)
	}
	first, today := window.Runs.Columns[0], window.Runs.Columns[activityDays-1]
	if first.Label != "29" || len(first.Segments) != 1 || first.Segments[0].Class != "unavailable" || today.Label != "11" || today.Narrow {
		t.Fatalf("window edges = %+v / %+v", first, today)
	}
	if window.Runs.MaxLabel != "2" || today.Segments[0] != (columnSegment{Class: "healthy", Y: "76.00", Height: "60.00"}) || today.Segments[1] != (columnSegment{Class: "degraded", Y: "16.00", Height: "60.00"}) {
		t.Fatalf("today's stacked column = %+v (max %s)", today.Segments, window.Runs.MaxLabel)
	}
	if window.Spend.MaxLabel != "$0.60" || window.Spend.Columns[activityDays-1].Title != "11 Sep · $0.50 · 1,000 tokens" {
		t.Fatalf("spend chart = %s %q", window.Spend.MaxLabel, window.Spend.Columns[activityDays-1].Title)
	}
	if empty := buildActivityWindow(nil, now); !empty.Runs.Empty || !empty.Spend.Empty {
		t.Fatal("an empty window must say so rather than draw zero-height columns")
	}
}

func TestNiceCeilingKeepsWholeMidpoints(t *testing.T) {
	for input, want := range map[int64]int64{0: 2, 1: 2, 3: 4, 10: 10, 11: 20, 431_510: 600_000} {
		if got := niceCeiling(input); got != want {
			t.Errorf("niceCeiling(%d) = %d, want %d", input, got, want)
		}
	}
}

func TestOverviewChartsEveryClusterFromCurrentSummariesAndRuns(t *testing.T) {
	provider := sampleProvider()
	provider.clusters = append(provider.clusters, ClusterRecord{ID: "cluster-2", DisplayName: "Pune A100", State: StateNoData})
	provider.summary.EvidenceStreams = []EvidenceStreamHealth{{State: StateHealthy}, {State: StateUnavailable}}
	provider.operations.Repairs = RepairOverview{Available: true, Succeeded: 3, Contained: 1}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/operations", nil).Body.String()
	for _, value := range []string{
		"Cluster health", `href="/admin/clusters/cluster-1"`, "Mumbai H100", "Pune A100",
		`<span class="badge degraded">DEGRADED</span>`, "1 / 2 streams complete", "Summary unavailable", "62.5% · 80 GPUs observed",
		`<figure class="column-chart">`, "20 Aug · 1 run", "20 Aug · $0.43 · 59,537 tokens",
		"Live incidents by cluster", "1 critical or high severity", "Repair outcomes", "Verified recoveries",
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("overview missing %q: %s", value, body)
		}
	}
	if strings.Contains(body, "GPU fault") || strings.Contains(body, `style="`) {
		t.Fatalf("overview repeats incident detail or relies on inline styles: %s", body)
	}
}

func TestClusterListUsesCurrentSummaryAndMovesDeletionToEdit(t *testing.T) {
	provider := sampleProvider()
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	list := doRequest(server, cookie, http.MethodGet, "/admin/clusters?updated=cluster-1", nil).Body.String()
	for _, value := range []string{"1 managed cluster", `<span class="badge degraded">DEGRADED</span>`, "Saved changes to", `href="/admin/clusters/cluster-1/edit"`, "62.5%"} {
		if !strings.Contains(list, value) {
			t.Fatalf("cluster list missing %q: %s", value, list)
		}
	}
	if strings.Contains(list, `<span class="badge healthy">HEALTHY</span>`) || strings.Contains(list, "/delete") {
		t.Fatalf("cluster list shows the stale registered state or a destructive form: %s", list)
	}
	edit := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/edit", nil).Body.String()
	if !strings.Contains(edit, `action="/admin/clusters/cluster-1/delete"`) || !strings.Contains(edit, `name="confirmation"`) {
		t.Fatalf("edit page is missing the confirmed decommission form: %s", edit)
	}
}

func TestSelfHostedFontIsAllowedAndCornersStaySquare(t *testing.T) {
	server, _, _, _ := newTestServer(t, sampleProvider(), 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	page := doRequest(server, cookie, http.MethodGet, "/admin/operations", nil)
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "font-src 'self'") {
		t.Fatalf("CSP blocks the self-hosted font: %s", page.Header().Get("Content-Security-Policy"))
	}
	font := doRequest(server, cookie, http.MethodGet, "/admin/assets/GeistMono-Variable.woff2", nil)
	if font.Code != http.StatusOK || font.Header().Get("Content-Type") != "font/woff2" || font.Body.Len() < 1024 {
		t.Fatalf("font asset = %d %q %d bytes", font.Code, font.Header().Get("Content-Type"), font.Body.Len())
	}
	css := doRequest(server, cookie, http.MethodGet, "/admin/assets/dashboard.css", nil).Body.String()
	if !strings.Contains(css, `url("/admin/assets/GeistMono-Variable.woff2")`) {
		t.Fatal("stylesheet does not load the self-hosted font")
	}
	for _, match := range regexp.MustCompile(`border-radius:\s*([^;}]+)`).FindAllStringSubmatch(css, -1) {
		if value := strings.TrimSpace(match[1]); value != "0" && value != "50%" {
			t.Fatalf("rounded box corner %q; boxes stay square and only status dots are round", value)
		}
	}
}
