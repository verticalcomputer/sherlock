package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type snapshotReaderFake struct {
	mu          sync.Mutex
	calls       int
	inFlight    int32
	maxInFlight int32
	keysSeen    [][]domain.ScheduleKey
	deadlines   []time.Time
	hasDeadline []bool
	snapshot    domain.DurableSchedulerSnapshot
	err         error
	release     chan struct{}
	mutateKeys  bool
	// expireFirst makes the read wait for its context to expire before
	// responding. With expireSucceed it then returns the configured snapshot
	// with nil error despite the expiry; otherwise it returns the context
	// error. The observed context error is recorded for assertions.
	expireFirst   bool
	expireSucceed bool
	observedErr   error
}

func (f *snapshotReaderFake) ReadDurableScheduleSnapshot(ctx context.Context, keys []domain.ScheduleKey) (domain.DurableSchedulerSnapshot, error) {
	current := atomic.AddInt32(&f.inFlight, 1)
	for {
		maximum := atomic.LoadInt32(&f.maxInFlight)
		if current <= maximum || atomic.CompareAndSwapInt32(&f.maxInFlight, maximum, current) {
			break
		}
	}
	defer atomic.AddInt32(&f.inFlight, -1)
	if f.expireFirst {
		<-ctx.Done()
		observed := ctx.Err()
		f.mu.Lock()
		f.calls++
		f.observedErr = observed
		f.mu.Unlock()
		if f.expireSucceed {
			return f.snapshot, nil
		}
		return domain.DurableSchedulerSnapshot{}, observed
	}
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return domain.DurableSchedulerSnapshot{}, ctx.Err()
		}
	}
	deadline, ok := ctx.Deadline()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.keysSeen = append(f.keysSeen, append([]domain.ScheduleKey(nil), keys...))
	if f.mutateKeys {
		for i := range keys {
			keys[i] = domain.ScheduleKey{}
		}
	}
	f.deadlines = append(f.deadlines, deadline)
	f.hasDeadline = append(f.hasDeadline, ok)
	return f.snapshot, f.err
}

func (f *snapshotReaderFake) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func snapshotTestKey() domain.ScheduleKey {
	return domain.ScheduleKey{ClusterID: "cluster", SourceID: "source", Operation: domain.OperationPrometheusGPUUtilization}
}

func snapshotTestReading(observed time.Time, coalesced int64) domain.DurableSchedulerSnapshot {
	return domain.DurableSchedulerSnapshot{ObservedAt: observed, Rows: []domain.DurableSchedulerSnapshotRow{
		{Key: snapshotTestKey(), NextDue: observed.Add(-30 * time.Second), CoalescedIntervals: coalesced},
	}}
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting: %s", message)
}

func gatherValue(t *testing.T, reg *prom.Registry, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			match := true
			for _, label := range metric.Label {
				if want, ok := labels[label.GetName()]; ok && want != label.GetValue() {
					match = false
				}
			}
			if match && len(labels) > 0 {
				switch {
				case metric.Gauge != nil:
					return metric.Gauge.GetValue(), true
				case metric.Counter != nil:
					return metric.Counter.GetValue(), true
				}
			}
			if len(labels) == 0 {
				if metric.Gauge != nil {
					return metric.Gauge.GetValue(), true
				}
				if metric.Counter != nil {
					return metric.Counter.GetValue(), true
				}
			}
		}
	}
	return 0, false
}

func TestDurableMetricsPublishingEnabled(t *testing.T) {
	if durableMetricsPublishingEnabled(nil) || durableMetricsPublishingEnabled([]domain.ScheduleKey{}) {
		t.Fatal("empty enrollment must not publish")
	}
	if !durableMetricsPublishingEnabled([]domain.ScheduleKey{snapshotTestKey()}) {
		t.Fatal("nonempty enrollment must publish")
	}
}

func TestDurableSchedulerPublisherFactoryValidation(t *testing.T) {
	keys := []domain.ScheduleKey{snapshotTestKey()}
	if _, err := newDurableSchedulerPublisher(prom.NewRegistry(), nil, keys, time.Second, time.Second, discardLogger()); err == nil {
		t.Fatal("nil reader accepted")
	}
	fake := &snapshotReaderFake{}
	if _, err := newDurableSchedulerPublisher(prom.NewRegistry(), fake, keys, time.Second, time.Second, nil); err == nil {
		t.Fatal("nil logger accepted")
	}
	if _, err := newDurableSchedulerPublisher(prom.NewRegistry(), fake, keys, 0, time.Second, discardLogger()); err == nil {
		t.Fatal("non-positive interval accepted")
	}
	if _, err := newDurableSchedulerPublisher(prom.NewRegistry(), fake, keys, time.Second, 0, discardLogger()); err == nil {
		t.Fatal("non-positive timeout accepted")
	}
	duplicates := []domain.ScheduleKey{snapshotTestKey(), snapshotTestKey()}
	if _, err := newDurableSchedulerPublisher(prom.NewRegistry(), fake, duplicates, time.Second, time.Second, discardLogger()); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	unknown := []domain.ScheduleKey{{ClusterID: "c", SourceID: "s", Operation: "example.unreviewed.v9"}}
	if _, err := newDurableSchedulerPublisher(prom.NewRegistry(), fake, unknown, time.Second, time.Second, discardLogger()); err == nil {
		t.Fatal("unreviewed operation accepted")
	}
	reg := prom.NewRegistry()
	if _, err := newDurableSchedulerPublisher(reg, fake, keys, time.Second, time.Second, discardLogger()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.CollectAndCount(reg); got != 1 {
		t.Fatalf("expected only the refresh gauge before the first snapshot, got %d metrics", got)
	}
	if value, found := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); !found || value != 0 {
		t.Fatalf("initial refresh success=%v found=%t, want 0", value, found)
	}
}

func TestDurableSchedulerPublisherImmediatePublication(t *testing.T) {
	reg := prom.NewRegistry()
	observed := time.Unix(9_000_000, 0).UTC()
	fake := &snapshotReaderFake{snapshot: snapshotTestReading(observed, 7)}
	publisher, err := newDurableSchedulerPublisher(reg, fake, []domain.ScheduleKey{snapshotTestKey()}, time.Hour, time.Second, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); publisher.run(ctx) }()
	waitForCondition(t, 5*time.Second, func() bool { return fake.callCount() >= 1 }, "immediate refresh")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not exit")
	}
	labels := map[string]string{"cluster": "cluster", "source": "source", "operation": "prometheus.gpu_utilization.v1"}
	if value, found := gatherValue(t, reg, "sherlock_durable_scheduler_due_age_seconds", labels); !found || value != 30 {
		t.Fatalf("due age=%v found=%t, want 30", value, found)
	}
	if value, found := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); !found || value != 7 {
		t.Fatalf("coalesced=%v found=%t, want 7", value, found)
	}
	if value, found := gatherValue(t, reg, "sherlock_durable_scheduler_snapshot_timestamp_seconds", nil); !found || value != 9e+06 {
		t.Fatalf("snapshot timestamp=%v found=%t", value, found)
	}
	if value, found := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); !found || value != 1 {
		t.Fatalf("refresh success=%v found=%t, want 1", value, found)
	}
}

func TestDurableSchedulerPublisherHTTPHandler(t *testing.T) {
	reg := prom.NewRegistry()
	fake := &snapshotReaderFake{snapshot: snapshotTestReading(time.Unix(9_000_001, 0).UTC(), 2)}
	publisher, err := newDurableSchedulerPublisher(reg, fake, []domain.ScheduleKey{snapshotTestKey()}, time.Hour, time.Second, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	publisher.refresh(context.Background())
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	body := recorder.Body.String()
	for _, name := range []string{
		"sherlock_durable_scheduler_due_age_seconds",
		"sherlock_durable_scheduler_coalesced_intervals_total",
		"sherlock_durable_scheduler_dropped_intervals",
		"sherlock_durable_scheduler_snapshot_timestamp_seconds",
		"sherlock_durable_scheduler_refresh_success 1",
	} {
		if !strings.Contains(body, name) {
			t.Fatalf("handler body misses %q:\n%s", name, body)
		}
	}
}

func TestDurableSchedulerPublisherFailurePreservesAndRecovers(t *testing.T) {
	reg := prom.NewRegistry()
	first := time.Unix(9_000_010, 0).UTC()
	reading := snapshotTestReading(first, 3)
	reading.Rows[0].DroppedIntervals = 2
	fake := &snapshotReaderFake{snapshot: reading}
	publisher, err := newDurableSchedulerPublisher(reg, fake, []domain.ScheduleKey{snapshotTestKey()}, time.Hour, time.Second, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	publisher.refresh(ctx)
	labels := map[string]string{"cluster": "cluster", "source": "source", "operation": "prometheus.gpu_utilization.v1"}
	fake.err = errors.New("database unavailable")
	publisher.refresh(ctx)
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); value != 3 {
		t.Fatalf("failed refresh changed coalesced to %v", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_dropped_intervals", labels); value != 2 {
		t.Fatalf("failed refresh changed dropped to %v", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_snapshot_timestamp_seconds", nil); value != 9000010 {
		t.Fatalf("failed refresh changed snapshot timestamp to %v", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 0 {
		t.Fatalf("failed refresh success=%v, want 0", value)
	}
	second := first.Add(time.Minute)
	fake.err = nil
	fake.mu.Lock()
	fake.snapshot = snapshotTestReading(second, 9)
	fake.mu.Unlock()
	publisher.refresh(ctx)
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); value != 9 {
		t.Fatalf("recovery coalesced=%v, want 9", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_dropped_intervals", labels); value != 0 {
		t.Fatalf("recovery dropped=%v, want 0", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 1 {
		t.Fatalf("recovery success=%v, want 1", value)
	}
	fake.mu.Lock()
	fake.snapshot = domain.DurableSchedulerSnapshot{ObservedAt: second.Add(time.Minute)}
	fake.mu.Unlock()
	publisher.refresh(ctx)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if strings.HasPrefix(family.GetName(), "sherlock_durable_scheduler_") &&
			family.GetName() != "sherlock_durable_scheduler_snapshot_timestamp_seconds" &&
			family.GetName() != "sherlock_durable_scheduler_refresh_success" &&
			len(family.Metric) != 0 {
			t.Fatalf("empty snapshot left series in %s", family.GetName())
		}
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 1 {
		t.Fatalf("empty snapshot success=%v, want 1", value)
	}
}

func TestDurableSchedulerPublisherSlowReadsDoNotOverlap(t *testing.T) {
	reg := prom.NewRegistry()
	fake := &snapshotReaderFake{
		release:  make(chan struct{}),
		snapshot: domain.DurableSchedulerSnapshot{ObservedAt: time.Unix(9_000_020, 0).UTC()},
	}
	publisher, err := newDurableSchedulerPublisher(reg, fake, []domain.ScheduleKey{snapshotTestKey()}, 20*time.Millisecond, 5*time.Second, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); publisher.run(ctx) }()
	waitForCondition(t, 5*time.Second, func() bool { return atomic.LoadInt32(&fake.inFlight) == 1 }, "first read entry")
	time.Sleep(100 * time.Millisecond)
	if calls := fake.callCount(); calls != 0 {
		t.Fatalf("overlapping refresh completed while the first read was blocked: calls=%d", calls)
	}
	if maximum := atomic.LoadInt32(&fake.maxInFlight); maximum != 1 {
		t.Fatalf("concurrent reads=%d, want exactly 1", maximum)
	}
	close(fake.release)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not exit")
	}
	if maximum := atomic.LoadInt32(&fake.maxInFlight); maximum != 1 {
		t.Fatalf("concurrent reads=%d after release, want exactly 1", maximum)
	}
}

func TestDurableSchedulerPublisherDeadlineAndCancellation(t *testing.T) {
	reg := prom.NewRegistry()
	fake := &snapshotReaderFake{snapshot: domain.DurableSchedulerSnapshot{ObservedAt: time.Unix(9_000_030, 0).UTC()}}
	publisher, err := newDurableSchedulerPublisher(reg, fake, []domain.ScheduleKey{snapshotTestKey()}, time.Hour, 100*time.Millisecond, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	publisher.refresh(context.Background())
	fake.mu.Lock()
	if len(fake.hasDeadline) != 1 || !fake.hasDeadline[0] {
		fake.mu.Unlock()
		t.Fatal("read context carried no deadline")
	}
	deadline := fake.deadlines[0]
	fake.mu.Unlock()
	if !deadline.After(started) || deadline.After(started.Add(2*time.Second)) {
		t.Fatalf("read deadline %v outside the configured timeout", deadline)
	}

	blockedReg := prom.NewRegistry()
	blocked := &snapshotReaderFake{
		release:  make(chan struct{}),
		snapshot: domain.DurableSchedulerSnapshot{ObservedAt: time.Unix(9_000_031, 0).UTC()},
	}
	running, err := newDurableSchedulerPublisher(blockedReg, blocked, []domain.ScheduleKey{snapshotTestKey()}, time.Hour, 5*time.Second, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); running.run(ctx) }()
	waitForCondition(t, 5*time.Second, func() bool { return atomic.LoadInt32(&blocked.inFlight) == 1 }, "blocked read entry")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher leaked after cancellation")
	}
	if value, found := gatherValue(t, blockedReg, "sherlock_durable_scheduler_refresh_success", nil); !found || value != 0 {
		t.Fatalf("cancelled refresh success=%v found=%t, want 0", value, found)
	}
}

func TestDurableSchedulerPublisherCopiesKeys(t *testing.T) {
	reg := prom.NewRegistry()
	keys := []domain.ScheduleKey{snapshotTestKey()}
	fake := &snapshotReaderFake{mutateKeys: true, snapshot: domain.DurableSchedulerSnapshot{ObservedAt: time.Unix(9_000_040, 0).UTC()}}
	publisher, err := newDurableSchedulerPublisher(reg, fake, keys, time.Hour, time.Second, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	keys[0] = domain.ScheduleKey{ClusterID: "mutated", SourceID: "mutated", Operation: domain.OperationPrometheusGPUXID}
	publisher.refresh(context.Background())
	publisher.refresh(context.Background())
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.keysSeen) != 2 {
		t.Fatalf("reads=%d, want 2", len(fake.keysSeen))
	}
	for i, seen := range fake.keysSeen {
		if len(seen) != 1 || seen[0] != snapshotTestKey() {
			t.Fatalf("read %d used mutated keys: %+v", i, seen)
		}
	}
}

func refreshReturns(t *testing.T, publisher *durableSchedulerPublisher) {
	t.Helper()
	refreshed := make(chan struct{})
	go func() { defer close(refreshed); publisher.refresh(context.Background()) }()
	select {
	case <-refreshed:
	case <-time.After(10 * time.Second):
		t.Fatal("refresh did not return after the read finished")
	}
}

func TestDurableSchedulerPublisherTimeoutPreservesAndRecovers(t *testing.T) {
	reg := prom.NewRegistry()
	first := time.Unix(9_100_000, 0).UTC()
	fake := &snapshotReaderFake{snapshot: snapshotTestReading(first, 3)}
	publisher, err := newDurableSchedulerPublisher(reg, fake, []domain.ScheduleKey{snapshotTestKey()}, time.Hour, 300*time.Millisecond, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	publisher.refresh(context.Background())
	labels := map[string]string{"cluster": "cluster", "source": "source", "operation": "prometheus.gpu_utilization.v1"}
	fake.mu.Lock()
	fake.expireFirst = true
	fake.mu.Unlock()
	refreshReturns(t, publisher)
	fake.mu.Lock()
	observed := fake.observedErr
	fake.mu.Unlock()
	if observed != context.DeadlineExceeded {
		t.Fatalf("blocked read observed %v, want context.DeadlineExceeded", observed)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); value != 3 {
		t.Fatalf("timed-out refresh changed coalesced to %v", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_snapshot_timestamp_seconds", nil); value != 9.1e+06 {
		t.Fatalf("timed-out refresh changed snapshot timestamp to %v", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 0 {
		t.Fatalf("timed-out refresh success=%v, want 0", value)
	}
	second := first.Add(time.Minute)
	fake.mu.Lock()
	fake.expireFirst = false
	fake.snapshot = snapshotTestReading(second, 11)
	fake.mu.Unlock()
	publisher.refresh(context.Background())
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); value != 11 {
		t.Fatalf("recovery coalesced=%v, want 11", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 1 {
		t.Fatalf("recovery success=%v, want 1", value)
	}
}

func TestDurableSchedulerPublisherExpiredSuccessTreatedAsFailed(t *testing.T) {
	reg := prom.NewRegistry()
	first := time.Unix(9_100_100, 0).UTC()
	fake := &snapshotReaderFake{snapshot: snapshotTestReading(first, 5)}
	publisher, err := newDurableSchedulerPublisher(reg, fake, []domain.ScheduleKey{snapshotTestKey()}, time.Hour, 300*time.Millisecond, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	publisher.refresh(context.Background())
	labels := map[string]string{"cluster": "cluster", "source": "source", "operation": "prometheus.gpu_utilization.v1"}
	second := first.Add(time.Minute)
	fake.mu.Lock()
	fake.expireFirst = true
	fake.expireSucceed = true
	fake.snapshot = snapshotTestReading(second, 8)
	fake.mu.Unlock()
	refreshReturns(t, publisher)
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); value != 5 {
		t.Fatalf("expired refresh published coalesced=%v, want prior 5", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_due_age_seconds", labels); value != 30 {
		t.Fatalf("expired refresh published due age=%v, want prior 30", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_snapshot_timestamp_seconds", nil); value != 9.1001e+06 {
		t.Fatalf("expired refresh changed snapshot timestamp to %v", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 0 {
		t.Fatalf("expired refresh success=%v, want 0", value)
	}
	fake.mu.Lock()
	fake.expireFirst = false
	fake.expireSucceed = false
	fake.mu.Unlock()
	publisher.refresh(context.Background())
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); value != 8 {
		t.Fatalf("recovery coalesced=%v, want 8", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 1 {
		t.Fatalf("recovery success=%v, want 1", value)
	}
}

func TestDurableSchedulerPublisherInvalidSnapshotPreservesAndLogsSafely(t *testing.T) {
	reg := prom.NewRegistry()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	first := time.Unix(9_100_200, 0).UTC()
	fake := &snapshotReaderFake{snapshot: snapshotTestReading(first, 4)}
	publisher, err := newDurableSchedulerPublisher(reg, fake, []domain.ScheduleKey{snapshotTestKey()}, time.Hour, time.Second, logger)
	if err != nil {
		t.Fatal(err)
	}
	publisher.refresh(context.Background())
	labels := map[string]string{"cluster": "cluster", "source": "source", "operation": "prometheus.gpu_utilization.v1"}
	const marker = "marker-intruder-zz9"
	fake.mu.Lock()
	fake.snapshot = domain.DurableSchedulerSnapshot{ObservedAt: first.Add(time.Minute), Rows: []domain.DurableSchedulerSnapshotRow{
		{Key: domain.ScheduleKey{ClusterID: marker, SourceID: "source", Operation: domain.OperationPrometheusGPUUtilization}, NextDue: first, CoalescedIntervals: 99},
	}}
	fake.mu.Unlock()
	publisher.refresh(context.Background())
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "sherlock_durable_scheduler_due_age_seconds" && family.GetName() != "sherlock_durable_scheduler_coalesced_intervals_total" {
			continue
		}
		if len(family.Metric) != 1 {
			t.Fatalf("%s has %d series after invalid snapshot, want exactly the prior one", family.GetName(), len(family.Metric))
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetValue() == marker {
					t.Fatalf("invalid snapshot leaked series into %s", family.GetName())
				}
			}
		}
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); value != 4 {
		t.Fatalf("invalid snapshot changed coalesced to %v", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_snapshot_timestamp_seconds", nil); value != 9.1002e+06 {
		t.Fatalf("invalid snapshot changed snapshot timestamp to %v", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 0 {
		t.Fatalf("invalid snapshot success=%v, want 0", value)
	}
	recorded := logs.String()
	if !strings.Contains(recorded, "scheduler.snapshot_failed") || !strings.Contains(recorded, "DURABLE_SNAPSHOT_FAILED") {
		t.Fatalf("failure log misses the fixed event/code: %q", recorded)
	}
	if strings.Contains(recorded, marker) {
		t.Fatalf("failure log leaked schedule identity: %q", recorded)
	}
	fake.mu.Lock()
	fake.snapshot = snapshotTestReading(first.Add(2*time.Minute), 6)
	fake.mu.Unlock()
	publisher.refresh(context.Background())
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_coalesced_intervals_total", labels); value != 6 {
		t.Fatalf("recovery coalesced=%v, want 6", value)
	}
	if value, _ := gatherValue(t, reg, "sherlock_durable_scheduler_refresh_success", nil); value != 1 {
		t.Fatalf("recovery success=%v, want 1", value)
	}
}
