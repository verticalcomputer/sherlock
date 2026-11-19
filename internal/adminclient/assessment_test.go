package adminclient

import (
	"context"
	"encoding/json"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAssessmentClientScopeAndCursors(t *testing.T) {
	foreign := false
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/internal/admin/v1/clusters/cluster-1/assessment/enrollment/occurrence" || r.URL.Query().Get("after") != "12" || r.URL.Query().Get("after_audit") != "3" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("wrong bound request")
		}
		c := "cluster-1"
		if foreign {
			c = "other"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(alertdelivery.ProductionNotificationHistory{Occurrence: alertdelivery.ProductionOccurrence{ClusterID: c, EnrollmentID: "enrollment", ID: "occurrence"}, NextAfter: 13, More: true})
	}))
	defer api.Close()
	httpClient := api.Client()
	httpClient.Timeout = 5 * time.Second
	client, e := New(api.URL, []byte(testToken), httpClient)
	if e != nil {
		t.Fatal(e)
	}
	h, e := client.GetAssessmentHistory(context.Background(), "cluster-1", "enrollment", "occurrence", 12, 3)
	if e != nil || h.NextAfter != 13 || !h.More {
		t.Fatal(h, e)
	}
	foreign = true
	if _, e = client.GetAssessmentHistory(context.Background(), "cluster-1", "enrollment", "occurrence", 12, 3); e == nil {
		t.Fatal("foreign response accepted")
	}
	if _, e = client.GetAssessmentHistory(context.Background(), "cluster-1", "../other", "occurrence", 12, 3); e == nil {
		t.Fatal("unsafe scope")
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

func TestAssessmentEvidenceUIBindsHumanAndPagination(t *testing.T) {
	sawHistory := false
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("missing service auth")
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/internal/admin/v1/audit" {
			w.WriteHeader(204)
			return
		}
		session, err := auth.VerifyHumanSession([]byte(testToken), r.Header.Get(auth.HumanSessionHeader), r.Method, r.URL.RequestURI(), time.Now().UTC())
		if err != nil || session.Principal.Subject != "subject-1" {
			t.Error("missing request-bound human proof", err)
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/internal/admin/v1/human-access":
			_, _ = w.Write([]byte(`{"clusters":[{"cluster_id":"cluster-1","role":"CLUSTER_VIEWER"}]}`))
		case "/internal/admin/v1/clusters/cluster-1/assessment/enrollment/occurrence":
			sawHistory = true
			if r.URL.Query().Get("after") != "12" || r.URL.Query().Get("after_audit") != "3" {
				t.Error("pagination not included in signed request")
			}
			_ = json.NewEncoder(w).Encode(alertdelivery.ProductionNotificationHistory{Occurrence: alertdelivery.ProductionOccurrence{ID: "occurrence", EnrollmentID: "enrollment", ClusterID: "cluster-1", Asset: "<script>bad</script>"}, NextAfter: 13, More: true})
		default:
			w.WriteHeader(404)
		}
	}))
	defer api.Close()
	client, err := New(api.URL, []byte(testToken), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ui, err := adminui.New(adminui.Options{Provider: client, Auditor: client, ErrorReporter: humanSessionErrorReporter{}, AccessVerifier: humanSessionAccessVerifier{}, RequireHumanAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters/cluster-1/assessment/enrollment/occurrence?after=12&after_audit=3", nil)
	request.Header.Set("Cf-Access-Jwt-Assertion", "signed-test-assertion")
	response := httptest.NewRecorder()
	ui.ServeHTTP(response, request)
	if response.Code != 200 || !sawHistory || strings.Contains(response.Body.String(), "<script>") || !strings.Contains(response.Body.String(), "Next events") {
		t.Fatalf("status=%d history=%v body=%s", response.Code, sawHistory, response.Body.String())
	}
	sawHistory = false
	request = httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters/other/assessment/enrollment/occurrence", nil)
	request.Header.Set("Cf-Access-Jwt-Assertion", "signed-test-assertion")
	response = httptest.NewRecorder()
	ui.ServeHTTP(response, request)
	if response.Code != 404 || sawHistory {
		t.Fatal("foreign cluster reached history provider", response.Code)
	}
}
