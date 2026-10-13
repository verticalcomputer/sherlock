package adminui

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type browserFixtureProvider struct{ *fakeProvider }

func (p browserFixtureProvider) LoadHumanAccess(ctx context.Context) ([]ClusterAccess, error) {
	session, ok := HumanSessionFromContext(ctx)
	if !ok {
		return nil, ErrHumanAccessDenied
	}
	if session.Principal.Subject == "revoked" {
		return nil, ErrHumanAccessDenied
	}
	admin := session.Principal.Subject == "admin"
	role := string(auth.RoleClusterViewer)
	if admin {
		role = string(auth.RoleClusterAdmin)
	}
	return []ClusterAccess{{ClusterID: "cluster-1", Role: role, CanConfigure: admin, CanInvestigate: admin}}, nil
}

type browserFixtureVerifier struct{}

func (browserFixtureVerifier) Verify(_ context.Context, assertion string) (AccessIdentity, error) {
	if assertion != "viewer" && assertion != "admin" && assertion != "revoked" {
		return AccessIdentity{}, ErrCloudflareAccessDenied
	}
	return AccessIdentity{Issuer: "https://fixture.cloudflareaccess.com", Subject: assertion}, nil
}

type browserFixtureAuditor struct{}

func (browserFixtureAuditor) RecordAdminEvent(context.Context, AuditEvent) error { return nil }

// Explicit opt-in starts a loopback-only deterministic browser fixture. These
// synthetic sessions never authenticate with Access or reach a cluster/API.
// Run: SHERLOCK_GP11_BROWSER_FIXTURE_DIR=/tmp/gp11-browser go test
// ./internal/adminui -run '^TestGP11BrowserFixture$' -timeout 13m -v
func TestGP11BrowserFixture(t *testing.T) {
	directory := os.Getenv("SHERLOCK_GP11_BROWSER_FIXTURE_DIR")
	if directory == "" {
		t.Skip("explicit browser fixture opt-in required")
	}
	provider := sampleProvider()
	provider.clusters[0].DisplayName = "GP-11 browser fixture (synthetic)"
	now := time.Date(2026, 9, 30, 14, 0, 0, 0, time.UTC)
	nodes, gpus := int64(14), int64(112)
	provider.summary.Health = application.ClusterHealthView{SchemaVersion: 1, ClusterID: "cluster-1", GeneratedAt: now, WindowStart: now.Add(-5 * time.Minute), WindowEnd: now,
		Capacity:   application.ClusterCapacityView{Condition: application.ConditionUnknown, ExpectedNodes: &nodes, ExpectedGPUs: &gpus},
		Monitoring: application.ClusterMonitoringView{CollectorCondition: application.ConditionHealthy, FreshnessCondition: application.ConditionHealthy, CoverageCondition: application.ConditionDegraded, SupportCondition: application.ConditionUnknown, ExpectedCollectors: 1, FreshCollectors: 1, CompleteStreams: 5, PartialStreams: 3},
		Workload:   application.ConditionUnknown, Progress: domain.ProgressUnmeasured, Attention: []string{"METRIC_COVERAGE_GAP"}}
	provider.summary.EvidenceStreams = []EvidenceStreamHealth{evidenceRepairTestStream()}
	provider.report.Shared, provider.report.Version, provider.report.Status = true, 3, "PLANNING"
	provider.report.Evidence[0].ExactScope = ""
	provider.report.ModelCalls = nil
	provider.report.ContextManifests = nil
	ui, err := New(Options{Provider: browserFixtureProvider{provider}, AccessVerifier: browserFixtureVerifier{}, Auditor: browserFixtureAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: &fakeClock{now: now}, RequireHumanAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fixture/session" {
			role := r.URL.Query().Get("role")
			http.SetCookie(w, &http.Cookie{Name: "fixture-session", Value: role, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/admin/clusters/cluster-1", http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie("fixture-session")
		if err == nil {
			r.Header.Set(accessAssertionHeader, cookie.Value)
		}
		ui.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	go func() { _ = server.Serve(listener) }()
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(map[string]string{"url": "http://" + listener.Addr().String(), "sessions": "viewer,admin,revoked,expired", "scope": "synthetic loopback fixture; no production access"})
	if err := os.WriteFile(filepath.Join(directory, "fixture.json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log(string(metadata))
	select {
	case <-time.After(12 * time.Minute):
	case <-t.Context().Done():
	}
}
