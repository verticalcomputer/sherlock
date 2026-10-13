package adminui

import (
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestEvidenceBlockersGroupRepeatedScopesIntoOneRow(t *testing.T) {
	streams := make([]EvidenceStreamHealth, 0, 7)
	for index, node := range []string{"comp001", "comp002", "comp003", "comp001", "comp004", "comp005"} {
		stream := evidenceRepairTestStream()
		stream.Operation = "gpu_ecc_counters"
		stream.Scope = "node:" + node + ":" + string(rune('a'+index))
		stream.MissingTargets = []string{"NODE:" + node}
		stream.SafeFailureReason = "reason varies by scope " + node
		stream.RecommendedAction = "Raise the diagnostic runner timeout, then rerun gpu_ecc_counters."
		streams = append(streams, stream)
	}
	utilization := evidenceRepairTestStream()
	utilization.State = StateUnavailable
	utilization.Status = "UNAVAILABLE"
	complete := evidenceRepairTestStream()
	complete.Status, complete.Condition = "COMPLETE", "complete coverage"
	streams = append(streams, utilization, complete)

	groups := groupEvidenceBlockers(streams)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2: %+v", len(groups), groups)
	}
	if groups[0].Operation != "dcgm_gpu_utilization" || groups[0].State != StateUnavailable {
		t.Fatalf("worst group was not ordered first: %+v", groups[0])
	}
	if len(groups[1].Streams) != 6 || strings.Join(groups[1].Targets, ",") != "NODE:comp001,NODE:comp002,NODE:comp003,NODE:comp004,NODE:comp005" {
		t.Fatalf("repeated scopes were not folded with deduplicated targets: %+v", groups[1])
	}

	provider := sampleProvider()
	provider.summary.EvidenceStreams = streams
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/gates", nil).Body.String()
	if strings.Count(body, `<article class="blocker `) != 2 || strings.Count(body, "Restore exporter coverage") != 2 {
		t.Fatalf("each repair should render once in the gate and once in the dialog: %s", body)
	}
	for _, value := range []string{"6 scopes", "5 missing targets", "reason varies by scope comp004", "Resolve 7 warnings together", "7 evidence streams block completeness"} {
		if !strings.Contains(body, value) {
			t.Fatalf("grouped blocker missing %q: %s", value, body)
		}
	}
}

func TestNextActionLeadsWithTheStepThatUnblocksTheCluster(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	issue := &Ticket{ID: "ticket-1"}
	blockers := []evidenceBlockerGroup{{Operation: "gpu_ecc_counters", Streams: make([]EvidenceStreamHealth, 3)}}
	rerun := investigationForm{Available: true, MaxModelTokens: 120000, MaxCostUSD: "2.00", DeadlineMinutes: 30}
	repairRun := Investigation{ID: "repair-run", IncidentID: "ticket-1", Question: evidenceRepairQuestionPrefix + " groups", Status: "COLLECTING", UpdatedAt: now.Add(-time.Minute)}
	partial := &Investigation{ID: "inv-partial", IncidentID: "ticket-1", Status: "PARTIAL"}
	completed := &Investigation{ID: "inv-done", IncidentID: "ticket-1", Status: "COMPLETED"}
	running := &Investigation{ID: "inv-running", IncidentID: "ticket-1", Status: "PLANNING"}

	cases := []struct {
		name           string
		glance         clusterGlance
		blockers       []evidenceBlockerGroup
		investigations []Investigation
		kind, id       string
	}{
		{name: "evidence blockers need a repair plan", glance: clusterGlance{PrimaryIssue: issue, LatestInvestigation: partial}, blockers: blockers, kind: "repair-plan"},
		{name: "a running repair plan is followed, not restarted", glance: clusterGlance{PrimaryIssue: issue}, blockers: blockers, investigations: []Investigation{repairRun}, kind: "open-investigation", id: "repair-run"},
		{name: "a running investigation is followed", glance: clusterGlance{PrimaryIssue: issue, LatestInvestigation: running}, kind: "open-investigation", id: "inv-running"},
		{name: "a completed report is reviewed", glance: clusterGlance{PrimaryIssue: issue, LatestInvestigation: completed}, kind: "open-investigation", id: "inv-done"},
		{name: "an unfinished run is rerun", glance: clusterGlance{PrimaryIssue: issue, LatestInvestigation: partial}, kind: "rerun"},
		{name: "a healthy cluster needs nothing", glance: clusterGlance{State: StateHealthy}, kind: "none"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			action := buildNextAction(test.glance, test.blockers, rerun, test.investigations, now)
			if action.Kind != test.kind || action.InvestigationID != test.id || action.Title == "" {
				t.Fatalf("next action = %+v, want %s %q", action, test.kind, test.id)
			}
		})
	}
}

func TestClusterSummarySeparatesCoverageFromIdleWorkflows(t *testing.T) {
	provider := sampleProvider()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for index := range provider.summary.Dimensions {
		metric := &provider.summary.Dimensions[index]
		switch metric.Label {
		case "Evidence":
			metric.Value, metric.Detail, metric.State = "5 / 8 current", "3 partial · 0 no data · 0 unavailable", StateDegraded
		case "Investigations":
			metric.Value, metric.State = "0 active", StateNoData
		case "Model usage":
			metric.Value, metric.State = "0 calls", StateNoData
		case "Diagnostic audit":
			metric.Value, metric.State = "0 events", StateNoData
		}
	}
	provider.summary.EvidenceStreams = []EvidenceStreamHealth{{
		SourceID: "fixture2-zone5", Operation: "dcgm_gpu_ecc", Status: "PARTIAL", State: StateDegraded,
		Condition: "missing fields", RecommendedAction: "Review exporter field support.", LatestAttempt: now,
	}}
	provider.summary.SlurmOperations = []SlurmOperationStatus{{
		SourceID: "fixture2-zone6", Operation: "slurm.snapshot.v1", Status: "PARTIAL", Fresh: true, LastCompletedAt: &now,
	}}
	provider.operations.Tickets = []Ticket{
		{ID: "old-xid-1", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Status: "OPEN", LastSignalAt: now.Add(-48 * time.Hour)},
		{ID: "old-xid-2", ClusterID: "cluster-1", RuleID: "dcgm.xid.nonzero.v1", Status: "OPEN", LastSignalAt: now.Add(-72 * time.Hour)},
	}
	provider.operations.Investigations[0].Status = "BLOCKED"
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)

	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1", nil)
	body := response.Body.String()
	for _, value := range []string{
		"Monitoring is current, but evidence coverage is incomplete.",
		"1 of 2 applicable gates met", "1 requiring attention", "0 current · 2 older XID records still open",
		"Continuous rail monitoring not enrolled", "slurm.snapshot.v1", "PARTIAL", "Workflow activity",
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("cluster summary missing %q: %s", value, body)
		}
	}
	if strings.Count(body, "NOT APPLICABLE") != 2 {
		t.Fatalf("incident-only gates were counted or marked as current: %s", body)
	}
	gateList := regexp.MustCompile(`(?s)<ol class="gate-steps">(.*?)</ol>`).FindStringSubmatch(body)
	if len(gateList) != 2 || strings.Contains(gateList[1], "BLOCKED") {
		t.Fatalf("old blocked investigation leaked into current gates: %s", body)
	}

	health := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/health", nil).Body.String()
	if !strings.Contains(health, "1 of 4 requiring attention") || !strings.Contains(health, "Workflow activity") {
		t.Fatalf("idle workflow was counted as monitoring failure: %s", health)
	}
}

func TestIncidentGatesRemainActionableForCurrentIssueOrQueueBacklog(t *testing.T) {
	base := clusterGlance{Queue: Metric{Value: "0 overdue", State: StateHealthy}, Evidence: Metric{State: StateHealthy}}
	steps := buildRecoveryPlan(base, nil, nil, nil, nil, nil, nil, EvidenceHistory{})
	if met, applicable := openFirstUnmetGate(steps); met != 1 || applicable != 2 || !steps[2].NotApplicable || !steps[3].NotApplicable {
		t.Fatalf("idle cluster gates = %d/%d %+v", met, applicable, steps)
	}
	base.Queue = Metric{Value: "1 overdue", State: StateDegraded}
	steps = buildRecoveryPlan(base, nil, nil, nil, nil, nil, nil, EvidenceHistory{})
	if _, applicable := openFirstUnmetGate(steps); applicable != 3 || steps[3].NotApplicable || steps[3].Title != "Drain overdue or blocked work" {
		t.Fatalf("queue backlog was hidden by no current incident: %+v", steps)
	}
	base.IssueCount = 1
	base.PrimaryIssue = &Ticket{ID: "current"}
	base.LatestInvestigation = &Investigation{ID: "old", IncidentID: "other", Status: "COMPLETED"}
	steps = buildRecoveryPlan(base, nil, nil, nil, nil, nil, nil, EvidenceHistory{})
	if _, applicable := openFirstUnmetGate(steps); applicable != 4 || steps[2].State == StateHealthy || steps[3].State == StateHealthy || strings.Contains(steps[2].Current, "COMPLETED") {
		t.Fatalf("unrelated completed run satisfied current incident gates: %+v", steps)
	}
}

func TestOneClickRerunSubmitsTheRenderedDefaults(t *testing.T) {
	provider := sampleProvider()
	provider.operations.Investigations[0].Status = "PARTIAL"
	provider.operations.Investigations[0].EntityIDs = []string{"d1-bom-comp007"}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1", nil).Body.String()

	form := regexp.MustCompile(`(?s)<div class="next-action-buttons">\s*<form method="post" action="/admin/clusters/cluster-1/investigations">(.*?)</form>`).FindStringSubmatch(body)
	if form == nil {
		t.Fatalf("one-click rerun form missing: %s", body)
	}
	values := url.Values{}
	for _, field := range regexp.MustCompile(`name="([a-z_]+)" value="([^"]*)"`).FindAllStringSubmatch(form[1], -1) {
		values.Set(field[1], html.UnescapeString(field[2]))
	}
	if strings.Count(values.Get("success_criteria"), "\n") != 2 {
		t.Fatalf("multi-line success criteria did not survive a hidden field: %q", values.Get("success_criteria"))
	}
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/investigations", values)
	if response.Code != http.StatusSeeOther || provider.started.Question != "Why did the GPU fail?" || len(provider.started.SuccessCriteria) != 3 || len(provider.started.EntityIDs) != 1 || provider.started.EntityIDs[0] != "d1-bom-comp007" {
		t.Fatalf("one-click rerun = %d %q, started=%+v", response.Code, response.Body.String(), provider.started)
	}
}

func TestRerunDoesNotReuseGeneratedRepairQuestion(t *testing.T) {
	glance := clusterGlance{PrimaryIssue: &Ticket{ID: "ticket-1"}, LatestInvestigation: &Investigation{IncidentID: "ticket-1", Question: evidenceRepairQuestionPrefix + " groups", EntityKind: "node", EntityIDs: []string{"comp001"}}}
	form := buildInvestigationForm(glance, "admin-key")
	if strings.HasPrefix(form.Question, evidenceRepairQuestionPrefix) || form.EntityIDs != "comp001" || !form.Available {
		t.Fatalf("rerun form = %+v", form)
	}
	glance.LatestInvestigation.EntityIDs = []string{"node/comp007/gpu/3"}
	if unsubmittable := buildInvestigationForm(glance, "admin-key"); unsubmittable.Available {
		t.Fatalf("rerun offered for a scope the start handler rejects: %+v", unsubmittable)
	}
}

func TestClusterShowsEnrolledContinuousMonitoringAndSourceGaps(t *testing.T) {
	provider := sampleProvider()
	provider.summary.Network = networkmonitor.Summary{Enrolled: true, Revision: "fixture2-zone3-20260930-v1", State: "UNKNOWN", IntervalSeconds: 60, ExpectedNodes: 14, ExpectedPorts: 112, HealthyPorts: 104, UnknownPorts: 8, OpenEpisodes: 1, PendingAlerts: 1, Details: []application.NetworkPortAssessment{{Key: application.NetworkPortKey{Node: "fixture2-zone1-comp001", Device: "mlx5_0", Port: 1}, Condition: "UNKNOWN", Reason: "AUTH_UNAVAILABLE", ReadError: "SSH_AUTH_DENIED"}}}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1", nil).Body.String()
	for _, text := range []string{"Continuous InfiniBand monitoring", "104 / 112", "14 approved nodes", "SSH_AUTH_DENIED", "AUTH_UNAVAILABLE", "Short outages between polls may be missed", "1 open network episodes"} {
		if !strings.Contains(body, text) {
			t.Fatalf("missing %q: %s", text, body)
		}
	}
	if strings.Contains(body, "Continuous rail monitoring not enrolled") {
		t.Fatal("enrolled source rendered as absent")
	}
}

func TestClusterShowsManagementMemberLossSeparatelyFromHealthyIB(t *testing.T) {
	provider := sampleProvider()
	zero := uint64(0)
	provider.summary.Network = networkmonitor.Summary{Enrolled: true, State: "DEGRADED", InfiniBandState: "HEALTHY", IntervalSeconds: 60, ExpectedNodes: 14, ExpectedPorts: 112, HealthyPorts: 112, Management: networkmonitor.ManagementSummary{Enrolled: true, Revision: "fixture2-zone4-20260930-v1", State: "DEGRADED", ExpectedBonds: 14, ExpectedMembers: 28, ExpectedLinks: 42, HealthyLinks: 41, DownLinks: 1, Details: []networkmonitor.ManagementAssessment{{Node: "fixture2-zone1-comp001", Interface: "enp55s0f0np0", Bond: "bond0", Condition: "DOWN", Reason: "CARRIER_OR_OPERSTATE_DOWN", Carrier: "0", OperState: "down", ObservedAt: time.Now().UTC(), RXErrors: &zero}}}}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1", nil).Body.String()
	for _, text := range []string{"Continuous management-network monitoring", "41 / 42 healthy links", "14 approved bonds and 28 members", "enp55s0f0np0", "CARRIER_OR_OPERSTATE_DOWN", "HEALTHY · 112 / 112", "1 down · 0 unknown", "Retained errors RX / TX", "0 / UNKNOWN", "Local interface health does not prove switch reachability"} {
		if !strings.Contains(body, text) {
			t.Fatalf("missing %q in %s", text, body)
		}
	}
	health := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/health", nil).Body.String()
	if !strings.Contains(health, "Management links") || !strings.Contains(health, "41 / 42 healthy") {
		t.Fatalf("missing management signal: %s", health)
	}
}
