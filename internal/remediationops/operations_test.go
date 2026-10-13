package remediationops

import (
	"context"
	clientprom "github.com/prometheus/client_golang/prometheus"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type readerFunc func(context.Context, string, int) (Snapshot, error)

func (f readerFunc) RemediationOperations(c context.Context, s string, n int) (Snapshot, error) {
	return f(c, s, n)
}
func TestObserverRedactsAndBoundsLabels(t *testing.T) {
	r := clientprom.NewRegistry()
	o, err := New(readerFunc(func(context.Context, string, int) (Snapshot, error) {
		return Snapshot{RunStates: []Bucket{{"VERIFYING", 2}}, RequestStates: []Bucket{{"CLAIMED", 1}}, DecisionCodes: []Bucket{{"SOURCE_UNAVAILABLE", 3}}}, nil
	}), "cluster-private", r)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	o.RecordFailure("run-secret-123")
	o.RecordIteration(time.Millisecond, "ok")
	recorder := httptest.NewRecorder()
	o.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, want := range []string{"sherlock_remediation_runs", "state=\"VERIFYING\"", "class=\"iteration_error\"", "sherlock_remediation_iterations_total", "outcome=\"ok\""} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"cluster-private", "run-secret-123", "target", "evidence"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("leaked %q", forbidden)
		}
	}
}
func TestObserverReadyDoesNotExposeReaderError(t *testing.T) {
	r := clientprom.NewRegistry()
	o, _ := New(readerFunc(func(context.Context, string, int) (Snapshot, error) { return Snapshot{}, context.DeadlineExceeded }), "c", r)
	w := httptest.NewRecorder()
	o.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "deadline") {
		t.Fatalf("status/body %d %q", w.Code, w.Body.String())
	}
	_ = time.Second
}

func TestRefreshContentionRefusesWithoutQueuing(t *testing.T) {
	o, err := New(readerFunc(func(context.Context, string, int) (Snapshot, error) {
		t.Fatal("busy refresh queried database")
		return Snapshot{}, nil
	}), "cluster", clientprom.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	start := time.Now()
	if err = o.Refresh(context.Background()); err == nil {
		t.Fatal("concurrent refresh admitted")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("refresh queued behind another request")
	}
}
func TestEveryScheduleDecisionRetainsItsCategory(t *testing.T) {
	for _, code := range []string{"SCHEDULE_DISPATCH_GAP", "SCHEDULE_FACTS_UNKNOWN", "STREAM_DISABLED", "COLLECTION_ACTIVE", "SOURCE_UNAVAILABLE", "COLLECTOR_UNAVAILABLE", "INVENTORY_MISSING", "COVERAGE_INCOMPLETE", "COLLECTION_FAILED", "STREAM_FRESH", "NORMAL_SCHEDULER_DUE"} {
		if decisionClass(code) != code {
			t.Fatalf("lost category %s", code)
		}
	}
}
