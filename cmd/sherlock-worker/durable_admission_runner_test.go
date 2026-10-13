package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type admissionFunc func(context.Context, domain.DurableAdmissionPolicy) (domain.ScheduleAdmission, bool, error)

func (f admissionFunc) AdmitDueSchedule(ctx context.Context, p domain.DurableAdmissionPolicy) (domain.ScheduleAdmission, bool, error) {
	return f(ctx, p)
}

func TestDurableRejectionsBoundedAndAttemptBased(t *testing.T) {
	r := prom.NewRegistry()
	key := domain.ScheduleKey{ClusterID: "c", SourceID: "s", Operation: domain.OperationPrometheusGPUUtilization}
	m, err := newDurableRejectionMetrics(r, []domain.ScheduleKey{key})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		m.observe(domain.ScheduleAdmission{ScheduleKey: key, QuotaRejection: "source"})
	}
	m.observe(domain.ScheduleAdmission{ScheduleKey: key, QuotaRejection: "arbitrary-error"})
	m.observe(domain.ScheduleAdmission{QuotaRejection: "source"})
	m.observe(domain.ScheduleAdmission{ScheduleKey: key})
	for i := 0; i < 5; i++ {
		families, err := r.Gather()
		if err != nil || len(families) != 1 || len(families[0].Metric) != 3 {
			t.Fatalf("bounded metrics: %v %v", families, err)
		}
		if got := testutil.ToFloat64(m.counters[key]["source"]); got != 3 {
			t.Fatalf("scrape inflation: %v", got)
		}
	}
}

func TestDurableAdmissionLoopDeadlineRecoveryAndJoin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls, active, maxActive atomic.Int32
	entered := make(chan struct{}, 1)
	store := admissionFunc(func(ctx context.Context, _ domain.DurableAdmissionPolicy) (domain.ScheduleAdmission, bool, error) {
		n := active.Add(1)
		defer active.Add(-1)
		if n > maxActive.Load() {
			maxActive.Store(n)
		}
		if calls.Add(1) == 1 {
			<-ctx.Done()
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Error(ctx.Err())
			}
			return domain.ScheduleAdmission{}, false, ctx.Err()
		}
		entered <- struct{}{}
		<-ctx.Done()
		return domain.ScheduleAdmission{}, false, ctx.Err()
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runDurableAdmission(ctx, store, domain.DurableAdmissionPolicy{GlobalLimit: 1, ClusterLimit: 1}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Millisecond, 100*time.Millisecond)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no recovery after deadline")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("no cancel/join")
	}
	if maxActive.Load() != 1 || active.Load() != 0 {
		t.Fatalf("overlap/leak %d %d", maxActive.Load(), active.Load())
	}
}
