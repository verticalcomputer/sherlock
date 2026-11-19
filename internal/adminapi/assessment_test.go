package adminapi

import (
	"context"
	"errors"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"net/http"
	"strings"
	"testing"
)

type fakeAssessmentHistory struct {
	calls   int
	err     error
	foreign bool
}

func (f *fakeAssessmentHistory) HistoryPageWithAudit(_ context.Context, c, e, o string, _, _ int64) (alertdelivery.ProductionNotificationHistory, error) {
	f.calls++
	if f.foreign {
		c = "cluster-2"
	}
	return alertdelivery.ProductionNotificationHistory{Occurrence: alertdelivery.ProductionOccurrence{ID: o, ClusterID: c, EnrollmentID: e}}, f.err
}
func TestAssessmentHistoryRequiresLiveMembershipAndExactScope(t *testing.T) {
	grants := &fakeHumanGrants{role: auth.RoleClusterViewer}
	s, now := humanAuthorizationServer(t, grants)
	p := &fakeAssessmentHistory{}
	s.assessmentHistoryProvider = p
	path := "/internal/admin/v1/clusters/cluster-1/assessment/enrollment/occurrence?after=0&after_audit=0"
	if w := serveHuman(t, s, now, "user-1", http.MethodGet, path, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := serveWithoutToken(s, path); w.Code != 401 {
		t.Fatal("missing service auth", w.Code)
	}
	if w := serveHuman(t, s, now, "user-1", http.MethodGet, strings.Replace(path, "cluster-1", "cluster-2", 1), ""); w.Code != 404 {
		t.Fatal("foreign cluster", w.Code)
	}
	grants.revoked = true
	if w := serveHuman(t, s, now, "user-1", http.MethodGet, path, ""); w.Code != 404 {
		t.Fatal("revoked membership", w.Code)
	}
	grants.revoked = false
	if w := serveHuman(t, s, now, "user-1", http.MethodGet, path+"&after=2", ""); w.Code != 400 {
		t.Fatal("duplicate cursor", w.Code)
	}
	if p.calls != 1 {
		t.Fatal("unauthorized/invalid call reached store", p.calls)
	}
	p.foreign = true
	if w := serveHuman(t, s, now, "user-1", http.MethodGet, path, ""); w.Code != 404 {
		t.Fatal("scope mismatch", w.Code)
	}
	p.foreign = false
	p.err = errors.New("private database password")
	if w := serveHuman(t, s, now, "user-1", http.MethodGet, path, ""); w.Code != 503 || strings.Contains(w.Body.String(), "password") {
		t.Fatal("backend leaked", w.Body.String())
	}
	s.requireHumanAuthorization = false
	if w := serve(s, http.MethodGet, path, nil, ""); w.Code == 200 {
		t.Fatal("compatibility mode exposed evidence")
	}
}
