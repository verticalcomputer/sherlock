package adminui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type failingStartProvider struct{ *fakeProvider }

func (provider failingStartProvider) StartInvestigation(_ context.Context, _ string, input InvestigationStart, mutation MutationContext) (InvestigationStartResult, error) {
	provider.started, provider.mutation = input, mutation
	return InvestigationStartResult{}, errors.New("response lost after durable start")
}

func evidenceRepairTestStream() EvidenceStreamHealth {
	expected, returned := 80, 79
	return EvidenceStreamHealth{
		SourceID: "prometheus-pilot", Operation: "dcgm_gpu_utilization", Scope: "collection:cluster",
		Status: "PARTIAL", State: StatePartial, RunID: "run-latest",
		LatestAttempt:  time.Date(2026, 8, 20, 11, 59, 0, 0, time.UTC),
		MissingTargets: []string{"GPU:GPU-missing"}, SeriesExpected: &expected, SeriesReturned: &returned,
		Condition: "incomplete target coverage", FailureCode: "PARTIAL_DATA",
		SafeFailureReason: "one registered GPU returned no series",
		RecommendedAction: "Restore exporter coverage for the listed targets, then run this operation again.",
	}
}

func evidenceRepairTestStreams() []EvidenceStreamHealth {
	first := evidenceRepairTestStream()
	second := evidenceRepairTestStream()
	second.Operation = "gpu.ecc_counters"
	second.RunID = "diagnostic-latest"
	second.MissingTargets = []string{"GPU:GPU-second"}
	second.Condition = "diagnostic evidence is unavailable"
	second.RecommendedAction = "Repair the diagnostic runner configuration, then rerun the diagnostic."
	return []EvidenceStreamHealth{first, second}
}

func TestEvidenceWarningsStartOneHeavyConsolidatedProposalInvestigation(t *testing.T) {
	provider := sampleProvider()
	streams := evidenceRepairTestStreams()
	provider.summary.EvidenceStreams = streams
	server, clock, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/evidence-repair-proposals", url.Values{
		"csrf_token": {server.csrfToken(cookie.Value)},
	})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/clusters/cluster-1?repair_proposal_started=investigation-new" {
		t.Fatalf("proposal response = %d %q: %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	started := provider.started
	if started.IncidentID != "ticket-1" || started.Purpose != "EVIDENCE_REPAIR_PLAN" || started.EntityKind != "cluster" || len(started.EntityIDs) != 1 || started.EntityIDs[0] != "cluster-1" {
		t.Fatalf("proposal scope = %+v", started)
	}
	if started.MaxDecisions != 48 || started.MaxToolCalls != 80 || started.MaxDiagnosticCalls != 0 || started.MaxFanOut != 1 || started.MaxModelTokens != 600_000 || started.MaxCostMicrounits != 15_000_000 {
		t.Fatalf("proposal budget = %+v", started)
	}
	if !started.WindowStart.Equal(clock.now.Add(-24*time.Hour)) || !started.WindowEnd.Equal(clock.now) || !started.Deadline.Equal(clock.now.Add(90*time.Minute)) {
		t.Fatalf("proposal times = %s..%s deadline %s", started.WindowStart, started.WindowEnd, started.Deadline)
	}
	if !strings.HasPrefix(started.IdempotencyKey, "admin-ai-repair-v3-") {
		t.Fatalf("proposal idempotency key = %q", started.IdempotencyKey)
	}
	for _, required := range []string{"one operator-ready", "all current evidence warnings together", "dcgm_gpu_utilization", "gpu.ecc_counters", "GPU:GPU-missing", "GPU:GPU-second", "shared root causes", "deduplicate repeated work", "rollback", "Do not execute"} {
		if !strings.Contains(started.Question, required) {
			t.Fatalf("proposal question missing %q: %s", required, started.Question)
		}
	}
	if len(started.Question) > 4096 {
		t.Fatalf("proposal question exceeds private API limit: %d", len(started.Question))
	}
	if len(provider.mutation.SessionFingerprint) != 32 {
		t.Fatalf("proposal mutation attribution length = %d", len(provider.mutation.SessionFingerprint))
	}
	reordered := []EvidenceStreamHealth{streams[1], streams[0]}
	if evidenceRepairBatchKey("cluster-1", streams) != evidenceRepairBatchKey("cluster-1", reordered) {
		t.Fatal("batch key changed when only display order changed")
	}
	refreshed := append([]EvidenceStreamHealth(nil), streams...)
	refreshed[0].RunID = "new-periodic-run"
	refreshed[0].LatestAttempt = refreshed[0].LatestAttempt.Add(time.Minute)
	refreshed[0].SafeFailureReason = "refreshed safe reason"
	if evidenceRepairBatchKey("cluster-1", streams) != evidenceRepairBatchKey("cluster-1", refreshed) {
		t.Fatal("periodic attempt metadata changed an equivalent repair key")
	}
}

func TestEvidenceRepairProposalReloadsLatestWarningsAtSubmission(t *testing.T) {
	provider := sampleProvider()
	streams := evidenceRepairTestStreams()
	streams[0].MissingTargets = []string{"GPU:GPU-current"}
	streams[0].LatestAttempt = streams[0].LatestAttempt.Add(time.Minute)
	provider.summary.EvidenceStreams = streams
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/evidence-repair-proposals", url.Values{
		"csrf_token": {server.csrfToken(cookie.Value)}, "proposal_key": {strings.Repeat("a", 32)},
	})
	if response.Code != http.StatusSeeOther || !strings.Contains(provider.started.Question, "GPU:GPU-current") {
		t.Fatalf("refreshed proposal = %d, started=%+v, body=%s", response.Code, provider.started, response.Body.String())
	}
}

func TestEvidenceRepairScopeUsesActualMissingNodesInsteadOfExpectedGPUInventory(t *testing.T) {
	nodeWarning := evidenceRepairTestStream()
	nodeWarning.MissingTargets = []string{"NODE:comp002", "NODE:comp001"}
	gpuInventoryOnly := evidenceRepairTestStream()
	gpuInventoryOnly.MissingTargets = nil
	gpuInventoryOnly.ExpectedTargets = []string{"GPU:GPU-1", "GPU:GPU-2", "GPU:GPU-3"}

	kind, ids := evidenceRepairScope("cluster-1", []EvidenceStreamHealth{gpuInventoryOnly, nodeWarning})
	if kind != "node" || strings.Join(ids, ",") != "comp002,comp001" {
		t.Fatalf("repair scope = %s %v, want only actual missing nodes", kind, ids)
	}
}

func TestEvidenceRepairQuestionGroupsRepeatedWarningsAndKeepsRepairDetails(t *testing.T) {
	streams := make([]EvidenceStreamHealth, 0, 40)
	for index := 0; index < 40; index++ {
		stream := evidenceRepairTestStream()
		stream.Operation = "gpu.ecc_counters"
		stream.SourceID = "diagnostic-runner"
		stream.MissingTargets = []string{"NODE:comp" + string(rune('a'+index%26))}
		stream.RecommendedAction = "Restore the diagnostic runner dependency, then rerun all affected diagnostics."
		streams = append(streams, stream)
	}

	question := evidenceRepairQuestion(streams)
	if strings.Count(question, "gpu.ecc_counters") != 1 {
		t.Fatalf("repeated warnings were not grouped: %s", question)
	}
	for _, required := range []string{"NODE:compa", "and 2 more", "Restore the diagnostic runner dependency", "shared root causes"} {
		if !strings.Contains(question, required) {
			t.Fatalf("grouped question missing %q: %s", required, question)
		}
	}
	if len(question) > 4096 {
		t.Fatalf("grouped question exceeds private API limit: %d", len(question))
	}
}

func TestEvidenceRepairProposalRecoversDurableRunAfterStartResponseFailure(t *testing.T) {
	provider := sampleProvider()
	provider.summary.EvidenceStreams = evidenceRepairTestStreams()
	provider.operations.Investigations = append(provider.operations.Investigations, Investigation{
		ID: "investigation-existing", ClusterID: "cluster-1", IncidentID: "ticket-1",
		Question: evidenceRepairQuestionPrefix + " Current blocker groups: existing", Status: "PLANNING",
		UpdatedAt: time.Date(2026, 8, 20, 11, 59, 0, 0, time.UTC),
	})
	clock := &fakeClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	server, err := New(Options{Provider: failingStartProvider{provider}, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: clock})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/evidence-repair-proposals", url.Values{
		"csrf_token": {server.csrfToken(cookie.Value)},
	})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/clusters/cluster-1?repair_proposal_started=investigation-existing" {
		t.Fatalf("recovered response = %d %q: %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
}

func TestEvidenceRepairFailureBannerLinksRecentDurableRun(t *testing.T) {
	provider := sampleProvider()
	provider.summary.EvidenceStreams = evidenceRepairTestStreams()
	provider.operations.Investigations = append(provider.operations.Investigations, Investigation{
		ID: "investigation-existing", ClusterID: "cluster-1", IncidentID: "ticket-1",
		Question: evidenceRepairQuestionPrefix + " Current blocker groups: existing", Status: "BLOCKED",
		UpdatedAt: time.Date(2026, 8, 20, 11, 59, 0, 0, time.UTC),
	})
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1?repair_proposal_failed=1", nil)
	body := response.Body.String()
	if !strings.Contains(body, "latest start response could not be confirmed") || !strings.Contains(body, "/admin/investigations/investigation-existing") || strings.Contains(body, "could not be started. Reload") {
		t.Fatalf("failure recovery banner = %s", body)
	}
}

func evidenceRepairTestInvestigation(id, status string, updatedAt time.Time) Investigation {
	return Investigation{
		ID: id, ClusterID: "cluster-1", IncidentID: "ticket-1",
		Question: evidenceRepairQuestionPrefix + " Current blocker groups: existing", Status: status, UpdatedAt: updatedAt,
	}
}

// A finished run keeps its idempotency key. With an unchanged warning set the
// next submission reused that key, conflicted with the stored request, and
// created nothing, while the recovery redirect presented the old run as started.
func TestEvidenceRepairKeyStartsNewGenerationOnlyAfterFinishedRun(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	streams := evidenceRepairTestStreams()
	first := buildEvidenceRepairInvestigation("cluster-1", "ticket-1", streams, now, "")
	if first.IdempotencyKey != "admin-ai-repair-v3-"+evidenceRepairBatchKey("cluster-1", streams) {
		t.Fatalf("first generation key = %q", first.IdempotencyKey)
	}

	running := []Investigation{evidenceRepairTestInvestigation("investigation-running", "SYNTHESIZING", now)}
	if previous := latestFinishedEvidenceRepairInvestigation(running, "ticket-1"); previous != nil {
		t.Fatalf("running investigation started a new generation: %+v", previous)
	}

	history := []Investigation{
		evidenceRepairTestInvestigation("investigation-old", "PARTIAL", now.Add(-48*time.Hour)),
		evidenceRepairTestInvestigation("investigation-cancelled", "CANCELLED", now.Add(-10*time.Minute)),
		evidenceRepairTestInvestigation("investigation-running", "SYNTHESIZING", now),
		{ID: "investigation-other-incident", IncidentID: "ticket-2", Question: evidenceRepairQuestionPrefix, Status: "COMPLETED", UpdatedAt: now},
		{ID: "investigation-not-repair", IncidentID: "ticket-1", Question: "Why is comp007 unhealthy?", Status: "COMPLETED", UpdatedAt: now},
	}
	previous := latestFinishedEvidenceRepairInvestigation(history, "ticket-1")
	if previous == nil || previous.ID != "investigation-cancelled" {
		t.Fatalf("latest finished repair = %+v", previous)
	}
	next := buildEvidenceRepairInvestigation("cluster-1", "ticket-1", streams, now.Add(time.Minute), previous.ID)
	if next.IdempotencyKey == first.IdempotencyKey || !strings.HasPrefix(next.IdempotencyKey, first.IdempotencyKey+"-") || len(next.IdempotencyKey) > 128 {
		t.Fatalf("next generation key = %q, first = %q", next.IdempotencyKey, first.IdempotencyKey)
	}
	if again := buildEvidenceRepairInvestigation("cluster-1", "ticket-1", streams, now.Add(2*time.Minute), previous.ID); again.IdempotencyKey != next.IdempotencyKey {
		t.Fatalf("repeated click in the same generation changed key: %q != %q", again.IdempotencyKey, next.IdempotencyKey)
	}
}

func TestEvidenceRepairProposalAfterCancelledRunUsesNewKey(t *testing.T) {
	provider := sampleProvider()
	streams := evidenceRepairTestStreams()
	provider.summary.EvidenceStreams = streams
	server, clock, _, _ := newTestServer(t, provider, 2)
	provider.operations.Investigations = append(provider.operations.Investigations, evidenceRepairTestInvestigation("investigation-cancelled", "CANCELLED", clock.now.Add(-5*time.Minute)))
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/evidence-repair-proposals", url.Values{
		"csrf_token": {server.csrfToken(cookie.Value)},
	})
	want := buildEvidenceRepairInvestigation("cluster-1", "ticket-1", streams, clock.now, "investigation-cancelled").IdempotencyKey
	if response.Code != http.StatusSeeOther || provider.started.IdempotencyKey != want {
		t.Fatalf("response = %d, key = %q, want %q", response.Code, provider.started.IdempotencyKey, want)
	}
}

func TestEvidenceRepairStartFailureDoesNotPresentFinishedRunAsStarted(t *testing.T) {
	provider := sampleProvider()
	provider.summary.EvidenceStreams = evidenceRepairTestStreams()
	clock := &fakeClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	provider.operations.Investigations = append(provider.operations.Investigations, evidenceRepairTestInvestigation("investigation-cancelled", "CANCELLED", clock.now.Add(-time.Minute)))
	server, err := New(Options{Provider: failingStartProvider{provider}, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: clock})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/evidence-repair-proposals", url.Values{
		"csrf_token": {server.csrfToken(cookie.Value)},
	})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/clusters/cluster-1?repair_proposal_failed=1" {
		t.Fatalf("finished run presented as started: %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestEvidenceRepairProposalRequiresDeterministicIncident(t *testing.T) {
	provider := sampleProvider()
	streams := evidenceRepairTestStreams()
	provider.summary.EvidenceStreams = streams
	provider.operations.Tickets = nil
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/evidence-repair-proposals", url.Values{
		"csrf_token": {server.csrfToken(cookie.Value)},
	})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/clusters/cluster-1?repair_proposal_no_incident=1" || provider.started.Question != "" {
		t.Fatalf("incident-free proposal = %d, started=%+v, body=%s", response.Code, provider.started, response.Body.String())
	}
}

func TestEvidenceRepairProposalRedirectsCleanlyWhenGateRecovered(t *testing.T) {
	provider := sampleProvider()
	provider.summary.EvidenceStreams = nil
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/evidence-repair-proposals", url.Values{
		"csrf_token": {server.csrfToken(cookie.Value)},
	})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/clusters/cluster-1?repair_proposal_cleared=1" || provider.started.Question != "" {
		t.Fatalf("recovered proposal = %d %q, started=%+v", response.Code, response.Header().Get("Location"), provider.started)
	}
}

func TestEvidenceRepairProposalRendersOneCombinedModalAction(t *testing.T) {
	provider := sampleProvider()
	streams := evidenceRepairTestStreams()
	provider.summary.EvidenceStreams = streams
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1", nil)
	body := response.Body.String()
	for _, required := range []string{
		"Review repair plan", "Resolve 2 warnings together", "Suggested repair scope",
		"Generate one AI repair plan", "evidence-repair-proposals", "latest blockers are reloaded when you submit",
		"dcgm_gpu_utilization", "gpu.ecc_counters", "Repair the diagnostic runner configuration",
		"proposal only", "up to 600k model tokens", "no automatic or privileged changes",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("rendered AI proposal action missing %q: %s", required, body)
		}
	}
	if strings.Contains(body, cookie.Value) {
		t.Fatal("Access assertion leaked into rendered proposal form")
	}
	if strings.Count(body, "Generate one AI repair plan") != 1 || strings.Contains(body, "Generate AI repair proposal") {
		t.Fatalf("expected one consolidated generation action: %s", body)
	}
	if !strings.Contains(body, `<dialog class="repair-modal" id="evidence-repair-modal"`) || !strings.Contains(body, `data-dialog-open="evidence-repair-modal"`) {
		t.Fatalf("combined repair modal wiring is missing: %s", body)
	}
	if strings.Contains(body, "proposal_key") {
		t.Fatalf("rendered form retained a mutable evidence fingerprint: %s", body)
	}
}

func TestEvidenceRepairProposalRequiresCSRF(t *testing.T) {
	provider := sampleProvider()
	streams := evidenceRepairTestStreams()
	provider.summary.EvidenceStreams = streams
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/cluster-1/evidence-repair-proposals", url.Values{
		"csrf_token": {"bad"},
	})
	if response.Code != http.StatusForbidden || provider.started.Question != "" {
		t.Fatalf("CSRF rejection = %d, started=%+v", response.Code, provider.started)
	}
}

func TestRepairProposalIncludesOlderCurrentWarningInItsScope(t *testing.T) {
	now := time.Date(2026, 9, 11, 17, 0, 0, 0, time.UTC)
	stream := evidenceRepairTestStream()
	stream.LatestAttempt = now.Add(-7 * 24 * time.Hour)
	input := buildEvidenceRepairInvestigation("cluster-1", "incident-1", []EvidenceStreamHealth{stream}, now, "")
	if input.WindowStart.After(stream.LatestAttempt) || input.MaxDiagnosticCalls != 0 {
		t.Fatalf("old current warning excluded: %+v", input)
	}
}
