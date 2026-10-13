package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type monitoringRefreshFunc func(context.Context) error

func (f monitoringRefreshFunc) Refresh(ctx context.Context) error { return f(ctx) }

func TestMonitoringRefreshRetriesWithoutSamplesAndRedactsErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	calls := 0
	err := runMonitoringRefresh(ctx, monitoringRefreshFunc(func(context.Context) error {
		calls++
		if calls == 3 {
			cancel()
			return nil
		}
		return errors.New("private database payload must not appear")
	}), logger, time.Millisecond, time.Millisecond)
	if !errors.Is(err, context.Canceled) || calls != 3 {
		t.Fatalf("refresh stopped prematurely: calls=%d err=%v", calls, err)
	}
	if strings.Contains(output.String(), "private database") || strings.Count(output.String(), "control.monitoring_refresh_failed") != 2 {
		t.Fatalf("unexpected monitoring log: %s", output.String())
	}
}

func TestMonitoringRefreshBoundsPassAndJoinsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	exited := make(chan struct{})
	done := make(chan error, 1)
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	go func() {
		done <- runMonitoringRefresh(ctx, monitoringRefreshFunc(func(pass context.Context) error {
			if _, ok := pass.Deadline(); !ok {
				return errors.New("missing pass deadline")
			}
			close(started)
			<-pass.Done()
			close(exited)
			return pass.Err()
		}), logger, time.Hour, time.Minute)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("initial pass did not start independently of samples")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("loop cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh did not join cancelled pass")
	}
	select {
	case <-exited:
	default:
		t.Fatal("loop returned before its pass exited")
	}
}

func TestMonitoringRefreshRejectsInvalidBounds(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	store := monitoringRefreshFunc(func(context.Context) error { t.Fatal("invalid configuration ran a pass"); return nil })
	for _, bounds := range [][2]time.Duration{{0, time.Second}, {time.Second, 0}, {-time.Second, time.Second}, {time.Second, -time.Second}} {
		if err := runMonitoringRefresh(context.Background(), store, logger, bounds[0], bounds[1]); err == nil {
			t.Fatal("invalid bounds accepted")
		}
	}
}

func TestMonitoringRefreshLongPassDoesNotOverlapTicks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	active, calls := 0, 0
	err := runMonitoringRefresh(ctx, monitoringRefreshFunc(func(pass context.Context) error {
		active++
		defer func() { active-- }()
		if active != 1 {
			t.Fatal("monitoring passes overlapped")
		}
		calls++
		if calls == 2 {
			cancel()
			return nil
		}
		<-pass.Done()
		return pass.Err()
	}), logger, time.Millisecond, 3*time.Millisecond)
	if calls != 2 || active != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("serial deadline handling: calls=%d active=%d err=%v", calls, active, err)
	}
}

func TestMonitoringRefreshTimeoutDoesNotStopNextPass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	calls := 0
	err := runMonitoringRefresh(ctx, monitoringRefreshFunc(func(pass context.Context) error {
		calls++
		if calls == 2 {
			cancel()
			return nil
		}
		<-pass.Done()
		if !errors.Is(pass.Err(), context.DeadlineExceeded) {
			t.Fatalf("pass did not expire: %v", pass.Err())
		}
		return pass.Err()
	}), logger, 2*time.Millisecond, time.Millisecond)
	if calls != 2 || !errors.Is(err, context.Canceled) {
		t.Fatalf("deadline prevented subsequent evaluation: calls=%d err=%v", calls, err)
	}
}
