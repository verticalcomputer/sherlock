package adminui

import (
	"net/http"
	"strings"
	"testing"
)

func TestReportLeadsWithConclusionsAndCollapsesTheAuditTrail(t *testing.T) {
	server, _, _, _ := newTestServer(t, sampleProvider(), 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/investigations/inv-1", nil).Body.String()

	for _, value := range []string{
		`href="/admin/clusters/cluster-1"`, "No recommended action was recorded", "Findings",
		"Report integrity", "No synthesis statement was omitted", "No proposed action was refused",
		"Not recorded by this run", "what remains unknown", `<details class="audit-trail" id="audit-trail">`,
		"1 evidence entry · 0 context manifests · 1 AI call",
		`href="#evidence-evidence-1"`, `id="evidence-evidence-1"`,
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("report missing %q: %s", value, body)
		}
	}
	for _, absent := range []string{`id="timeline-title"`, `id="unknowns-title"`, `id="coverage-title"`, `model-call" open`, "Show full question"} {
		if strings.Contains(body, absent) {
			t.Fatalf("report should not render %q when empty or short: %s", absent, body)
		}
	}
	summary := strings.Index(body, `class="report-facts"`)
	findings := strings.Index(body, `id="findings-title"`)
	audit := strings.Index(body, `class="audit-trail"`)
	if summary < 0 || !(summary < findings && findings < audit) {
		t.Fatalf("report order is summary %d, findings %d, audit %d", summary, findings, audit)
	}
}

func TestReportShowsActionCardRecordedSectionsAndShortRepairTitle(t *testing.T) {
	provider := sampleProvider()
	provider.report.Question = evidenceRepairQuestionPrefix + " Current blocker groups: 1. gpu_ecc_counters"
	provider.report.PrimaryAction = &ReportActionCard{ID: "action-1", Owner: "platform", Urgency: "NOW", Action: "Raise the diagnostic runner timeout", Rationale: "Every timeout hit the 20s ceiling.", Targets: []string{"NODE:comp001"}, EscalationCondition: "Timeouts persist at 60s.", EvidenceIDs: []string{"evidence-1"}}
	provider.report.ReportSections = []ReportSection{{ID: "u-1", Kind: "UNKNOWN", Statement: "Whether GPU 3 recovered after reset."}}
	provider.report.ReportOmissions = []ReportOmission{{Kind: "FINDING", Reason: "CITATION_NOT_IN_LEDGER", Count: 2}}
	server, _, _, _ := newTestServer(t, provider, 2)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	body := doRequest(server, cookie, http.MethodGet, "/admin/investigations/inv-1", nil).Body.String()

	for _, value := range []string{
		"<h1>Combined evidence repair plan</h1>", "Show full question", "gpu_ecc_counters",
		"Recommended action", "Raise the diagnostic runner timeout", "Escalate if", "NODE:comp001",
		`id="unknowns-title"`, "Whether GPU 3 recovered after reset.",
		"2 synthesis statements were omitted", "cited evidence the ledger does not hold",
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("report missing %q: %s", value, body)
		}
	}
	if strings.Contains(body, "No recommended action was recorded") || strings.Contains(body, "<span>what remains unknown</span>") {
		t.Fatalf("recorded content was reported as missing: %s", body)
	}
}
