package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type scopedHumanProvider struct{}

func (scopedHumanProvider) Snapshot(_ context.Context, query adminview.Query) (adminview.Dashboard, error) {
	result := adminview.Dashboard{GeneratedAt: query.At}
	for _, id := range []string{"cluster-1", "cluster-2"} {
		if query.ClusterID == "" || query.ClusterID == id {
			result.Clusters = append(result.Clusters, adminview.ClusterSummary{ClusterID: id, DisplayName: id})
		}
	}
	return result, nil
}

type fakeHumanGrants struct {
	role       auth.HumanRole
	revoked    bool
	credential bool
	policy     bool
	raw        bool
	platform   bool
}

func (grants *fakeHumanGrants) ListHumanMemberships(_ context.Context, principal auth.HumanPrincipal) ([]auth.HumanMembership, error) {
	if principal.Subject != "user-1" || grants.role == "" || grants.revoked {
		return nil, nil
	}
	return []auth.HumanMembership{{Issuer: principal.Issuer, Subject: principal.Subject, ClusterID: "cluster-1", Role: grants.role, Revision: 1}}, nil
}

func (grants *fakeHumanGrants) HumanMembership(_ context.Context, principal auth.HumanPrincipal, clusterID domain.ClusterID) (auth.HumanMembership, error) {
	if principal.Subject != "user-1" || clusterID != "cluster-1" || grants.role == "" || grants.revoked {
		return auth.HumanMembership{}, adminmanage.ErrNotFound
	}
	return auth.HumanMembership{Issuer: principal.Issuer, Subject: principal.Subject, ClusterID: clusterID, Role: grants.role, Revision: 1}, nil
}

func (grants *fakeHumanGrants) HumanPrivilege(_ context.Context, principal auth.HumanPrincipal, clusterID domain.ClusterID, privilege auth.HumanPrivilege) (auth.HumanPrivilegeGrant, error) {
	allowed := privilege == auth.PrivilegeCredentialManage && grants.credential ||
		privilege == auth.PrivilegePolicyManage && grants.policy ||
		privilege == auth.PrivilegeRawEvidence && grants.raw
	if !allowed {
		return auth.HumanPrivilegeGrant{}, adminmanage.ErrNotFound
	}
	return auth.HumanPrivilegeGrant{Issuer: principal.Issuer, Subject: principal.Subject, ClusterID: clusterID, Privilege: privilege, Revision: 1}, nil
}

func (grants *fakeHumanGrants) HumanPlatformAdmin(_ context.Context, principal auth.HumanPrincipal) (auth.HumanPlatformGrant, error) {
	if !grants.platform {
		return auth.HumanPlatformGrant{}, adminmanage.ErrNotFound
	}
	return auth.HumanPlatformGrant{Issuer: principal.Issuer, Subject: principal.Subject, Revision: 1}, nil
}

func humanAuthorizationServer(t *testing.T, grants *fakeHumanGrants) (*Server, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 29, 12, 30, 0, 0, time.UTC)
	management := &fakeManagement{
		clusters: []adminmanage.Cluster{{ID: "cluster-1"}, {ID: "cluster-2"}},
		operations: adminmanage.Operations{Tickets: []adminmanage.Ticket{
			{ID: "allowed-ticket", ClusterID: "cluster-1"}, {ID: "foreign-ticket", ClusterID: "cluster-2"},
		}},
		report: adminmanage.InvestigationReport{ID: "report-1", ClusterID: "cluster-1"},
	}
	server, err := New(Options{Provider: scopedHumanProvider{}, Management: management, Auditor: &fakeAuditor{},
		ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: now},
		RequireHumanSession: true, RequireHumanAuthorization: true, HumanAuthorization: grants})
	if err != nil {
		t.Fatal(err)
	}
	return server, now
}

func serveHuman(t *testing.T, server *Server, at time.Time, subject, method, path, actor string) *httptest.ResponseRecorder {
	t.Helper()
	principal := auth.HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: subject}
	proof, err := auth.SealHumanSession([]byte(testServiceToken), auth.HumanSession{Principal: principal}, method, path, at)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Authorization", "Bearer "+testServiceToken)
	request.Header.Set(auth.HumanSessionHeader, proof)
	if actor != "" {
		request.Header.Set("X-Sherlock-Access-Subject", actor)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func TestHumanRouteMatrixDeniesViewerMutationsAndForeignCluster(t *testing.T) {
	grants := &fakeHumanGrants{role: auth.RoleClusterViewer}
	server, now := humanAuthorizationServer(t, grants)
	for _, test := range []struct {
		name, method, path, actor string
		want                      int
	}{
		{"own summary", "GET", "/internal/admin/v1/clusters/cluster-1/summary", "", http.StatusOK},
		{"foreign summary", "GET", "/internal/admin/v1/clusters/cluster-2/summary", "", http.StatusNotFound},
		{"own edit", "PATCH", "/internal/admin/v1/clusters/cluster-1", "", http.StatusForbidden},
		{"own delete", "DELETE", "/internal/admin/v1/clusters/cluster-1", "", http.StatusForbidden},
		{"investigation run", "POST", "/internal/admin/v1/clusters/cluster-1/investigations", "", http.StatusForbidden},
		{"investigation cancel", "POST", "/internal/admin/v1/investigations/report-1/cancel", "", http.StatusForbidden},
		{"credential metadata", "GET", "/internal/admin/v1/clusters/cluster-1/credentials", "user-1", http.StatusForbidden},
		{"credential write", "POST", "/internal/admin/v1/clusters/cluster-1/credentials", "user-1", http.StatusForbidden},
		{"credential revoke", "DELETE", "/internal/admin/v1/clusters/cluster-1/credentials/cred_1", "user-1", http.StatusForbidden},
		{"credential access test", "POST", "/internal/admin/v1/clusters/cluster-1/credentials/cred_1/access-tests", "user-1", http.StatusForbidden},
		{"credential inventory", "POST", "/internal/admin/v1/clusters/cluster-1/credentials/cred_1/inventory-discoveries", "user-1", http.StatusForbidden},
		{"credential access cancel", "POST", "/internal/admin/v1/clusters/cluster-1/credential-access-tests/test-1/cancel", "user-1", http.StatusForbidden},
		{"policy preview", "POST", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", "", http.StatusForbidden},
		{"policy import", "POST", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews/preview-1/import", "", http.StatusForbidden},
		{"forged actor", "GET", "/internal/admin/v1/clusters/cluster-1/summary", "user-2", http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := serveHuman(t, server, now, "user-1", test.method, test.path, test.actor)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
	for _, test := range []struct{ path, forbidden string }{
		{"/internal/admin/v1/clusters", "cluster-2"},
		{"/internal/admin/v1/dashboard", "cluster-2"},
		{"/internal/admin/v1/operations", "foreign-ticket"},
	} {
		response := serveHuman(t, server, now, "user-1", "GET", test.path, "")
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), test.forbidden) {
			t.Fatalf("foreign scope leaked on %s: status=%d body=%s", test.path, response.Code, response.Body.String())
		}
	}
	grants.revoked = true
	if response := serveHuman(t, server, now, "user-1", "GET", "/internal/admin/v1/clusters/cluster-1/summary", ""); response.Code != http.StatusNotFound {
		t.Fatalf("revoked cluster status=%d", response.Code)
	}
	if response := serveHuman(t, server, now, "user-1", "GET", "/internal/admin/v1/clusters", ""); response.Code != http.StatusForbidden {
		t.Fatalf("revoked list status=%d", response.Code)
	}
}

func TestHumanSensitivePrivilegesStaySeparate(t *testing.T) {
	grants := &fakeHumanGrants{role: auth.RoleClusterAdmin}
	server, now := humanAuthorizationServer(t, grants)
	principal := auth.HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "user-1"}
	request := httptest.NewRequest(http.MethodGet, "/internal/admin/v1/clusters/cluster-1/credentials", nil)
	for _, test := range []struct {
		name, cluster string
		grant         humanRouteGrant
		change        func()
		want          bool
	}{
		{"credential absent", "cluster-1", humanRouteGrant{capability: auth.CapabilityConfigurationRead, privilege: auth.PrivilegeCredentialManage}, func() {}, false},
		{"credential granted", "cluster-1", humanRouteGrant{capability: auth.CapabilityConfigurationRead, privilege: auth.PrivilegeCredentialManage}, func() { grants.credential = true }, true},
		{"policy still absent", "cluster-1", humanRouteGrant{capability: auth.CapabilityConfigurationWrite, privilege: auth.PrivilegePolicyManage}, func() {}, false},
		{"policy granted", "cluster-1", humanRouteGrant{capability: auth.CapabilityConfigurationWrite, privilege: auth.PrivilegePolicyManage}, func() { grants.policy = true }, true},
		{"platform still absent", "cluster-1", humanRouteGrant{capability: auth.CapabilityConfigurationWrite, platform: true}, func() {}, false},
		{"platform granted", "cluster-1", humanRouteGrant{capability: auth.CapabilityConfigurationWrite, platform: true}, func() { grants.platform = true }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.change()
			response := httptest.NewRecorder()
			got := server.authorizeHumanCluster(response, request, principal, test.cluster, test.grant)
			if got != test.want {
				t.Fatalf("authorized=%v want=%v status=%d", got, test.want, response.Code)
			}
		})
	}
	if response := serveHuman(t, server, now, "user-1", http.MethodGet, "/internal/admin/v1/investigations/report-1", ""); response.Code != http.StatusForbidden {
		t.Fatalf("raw report without privilege status=%d", response.Code)
	}
	grants.raw = true
	response := serveHuman(t, server, now, "user-1", http.MethodGet, "/internal/admin/v1/investigations/report-1", "")
	if response.Code != http.StatusOK {
		t.Fatalf("raw report with privilege status=%d body=%s", response.Code, response.Body.String())
	}
	var report map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil || report["cluster_id"] != "cluster-1" {
		t.Fatalf("raw report=%v err=%v", report, err)
	}
	grants.role = auth.RoleClusterViewer
	if response := serveHuman(t, server, now, "user-1", http.MethodGet, "/internal/admin/v1/investigations/report-1", ""); response.Code != http.StatusOK {
		t.Fatalf("viewer with separate raw grant status=%d", response.Code)
	}
}

func TestHumanRouteInventoryCoversEveryPrivateRoute(t *testing.T) {
	for _, test := range []struct{ method, suffix string }{
		{"GET", "summary"}, {"GET", "operations"}, {"GET", "gpu-metrics"}, {"GET", "progress"},
		{"POST", "investigations"}, {"PATCH", ""}, {"DELETE", ""}, {"GET", "credentials"},
		{"POST", "credentials"}, {"DELETE", "credentials/credential-1"},
		{"POST", "credentials/credential-1/access-tests"}, {"POST", "credentials/credential-1/inventory-discoveries"},
		{"GET", "credential-access-tests"}, {"POST", "credential-access-tests/test-1/cancel"},
		{"GET", "inventory-discovery/latest"}, {"GET", "expected-inventory"},
		{"POST", "expected-inventory/previews"}, {"POST", "expected-inventory/previews/preview-1/import"},
	} {
		var rest []string
		if test.suffix != "" {
			rest = strings.Split(test.suffix, "/")
		}
		if _, ok := reviewedHumanRoute(test.method, rest); !ok {
			t.Fatalf("unreviewed private route %s %s", test.method, test.suffix)
		}
	}
	for _, rest := range [][]string{{"unknown"}, {"credentials", "credential-1", "secret"}, {"expected-inventory", "previews", "x", "delete"}} {
		if _, ok := reviewedHumanRoute(http.MethodGet, rest); ok {
			t.Fatalf("unreviewed route accepted: %v", rest)
		}
	}
}
