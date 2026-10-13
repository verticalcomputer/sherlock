package adminclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSharedReportClientRejectsRawOrMismatchedContract(t *testing.T) {
	for _, test := range []struct {
		name   string
		report investigationReportResponse
	}{
		{"not shared", investigationReportResponse{}},
		{"raw scope", investigationReportResponse{Shared: true, Evidence: []reportEvidenceResponse{{ExactScope: "raw"}}}},
		{"model IO", investigationReportResponse{Shared: true, ModelCalls: []modelCallResponse{{}}}},
		{"context", investigationReportResponse{Shared: true, ContextManifests: []contextManifestResponse{{}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/admin/v1/investigations/inv-1/shared" {
					t.Errorf("wrong path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(test.report)
			}))
			defer api.Close()
			if _, err := newTestClient(t, api.URL).LoadInvestigationReport(context.Background(), "inv-1"); err == nil {
				t.Fatal("unsafe shared report accepted")
			}
		})
	}
}

func TestHumanAccessClientFailsClosedOnInvalidProjection(t *testing.T) {
	for _, payload := range []string{
		`{"clusters":[]}`,
		`{"clusters":[{"cluster_id":"cluster-1","role":"CLUSTER_VIEWER","can_investigate":true}]}`,
		`{"clusters":[{"cluster_id":"cluster-1","role":"CLUSTER_ADMIN","can_manage_policy":true}]}`,
		`{"clusters":[{"cluster_id":"cluster-1","role":"CLUSTER_VIEWER"},{"cluster_id":"cluster-1","role":"CLUSTER_VIEWER"}]}`,
		`{"clusters":[{"cluster_id":"cluster-1","role":"OWNER"}]}`,
	} {
		t.Run(payload, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(payload))
			}))
			defer api.Close()
			if _, err := newTestClient(t, api.URL).LoadHumanAccess(context.Background()); err == nil {
				t.Fatal("invalid human projection accepted")
			}
		})
	}
}
