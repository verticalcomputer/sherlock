package adminui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkspacePagesSeparateDetailsAndRetainAccessControl(t *testing.T) {
	p := sampleProvider()
	p.operations.Repairs = RepairOverview{Available: true, Succeeded: 1}
	s, _, audit, _ := newTestServer(t, p, 2)
	_, cookie := authenticateWithAccess(t, s, testAssertion)
	for _, tc := range []struct{ path, present, absent string }{
		{"/admin/operations", "Cluster health", "GPU fault"},
		{"/admin/incidents", "GPU fault", "Why did the GPU fail?"},
		{"/admin/investigations", "Why did the GPU fail?", "GPU fault"},
		{"/admin/repairs", "Verified recoveries", "GPU fault"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			unauth := httptest.NewRecorder()
			s.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if unauth.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated response = %d", unauth.Code)
			}
			response := doRequest(s, cookie, http.MethodGet, tc.path, nil)
			body := response.Body.String()
			if response.Code != 200 || !strings.Contains(body, tc.present) || strings.Contains(body, tc.absent) {
				t.Fatalf("wrong page content: %d %s", response.Code, body)
			}
			if !strings.Contains(body, `aria-current="page"`) || !strings.Contains(body, `href="#workspace"`) {
				t.Fatal("missing accessible navigation")
			}
		})
	}
	if len(audit.events) == 0 {
		t.Fatal("no audit events recorded")
	}
	p.err = errors.New("unavailable")
	body := doRequest(s, cookie, http.MethodGet, "/admin/operations", nil).Body.String()
	if !strings.Contains(body, "Repair authority unavailable") || strings.Contains(body, "Global repair gate disabled") || strings.Contains(body, `class="kpi-grid"`) {
		t.Fatal("missing data presented as known")
	}
}
