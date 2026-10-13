//go:build integration

package adminui

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
)

// ExerciseRepairFormForIntegration exposes only the existing test fixture to
// external tests, avoiding the production postgres -> adminui import cycle.
func ExerciseRepairFormForIntegration(t *testing.T, now time.Time, cluster, investigation string, wrap func(DataProvider, application.Clock) DataProvider) {
	t.Helper()
	fake := sampleProvider()
	fake.summary.ID = cluster
	for index := range fake.operations.Tickets {
		fake.operations.Tickets[index].ClusterID = cluster
	}
	stream := evidenceRepairTestStream()
	stream.LatestAttempt = now.Add(-time.Hour)
	fake.summary.EvidenceStreams = []EvidenceStreamHealth{stream}
	server, clock, _, _ := newTestServer(t, fake, 2)
	clock.now = now
	server.provider = wrap(fake, clock)
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	response := doRequest(server, cookie, http.MethodPost, "/admin/clusters/"+cluster+"/evidence-repair-proposals", url.Values{"csrf_token": {server.csrfToken(cookie.Value)}})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/clusters/"+cluster+"?repair_proposal_started="+investigation {
		t.Fatalf("UI failed: status=%d location=%s", response.Code, response.Header().Get("Location"))
	}
}
