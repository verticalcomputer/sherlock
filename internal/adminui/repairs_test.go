package adminui

import (
	"net/http"
	"strings"
	"testing"
)

func TestRepairOverviewIsReadOnlyAndUnavailableIsExplicit(t *testing.T) {
	for _, available := range []bool{false, true} {
		p := sampleProvider()
		p.operations.Repairs = RepairOverview{Available: available, ActiveRequests: 3, Decisions: []RepairDecision{{Code: "<script>injected</script>", Count: 2}}}
		server, _, _, _ := newTestServer(t, p, 2)
		_, cookie := authenticateWithAccess(t, server, testAssertion)
		body := doRequest(server, cookie, http.MethodGet, "/admin/repairs", nil).Body.String()
		if !strings.Contains(body, "Collection repair") {
			t.Fatal("repair section missing")
		}
		if strings.Contains(body, "<script>injected</script>") || strings.Contains(body, "<form") {
			t.Fatal("unescaped data or mutation form in operations")
		}
		if available && (!strings.Contains(body, "Global repair gate: disabled") || !strings.Contains(body, "Other assessment")) {
			t.Fatal("missing escaped snapshot")
		}
		if !available && !strings.Contains(body, "Collection repair data is unavailable") {
			t.Fatal("missing explicit unavailable state")
		}
	}
}
