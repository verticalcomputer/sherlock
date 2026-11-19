package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

type productionLoopStub struct {
	refreshCalled, cleanupCalled, refreshFinished chan struct{}
	timeout                                       bool
}

func (s *productionLoopStub) Refresh(ctx context.Context) error {
	defer func() {
		select {
		case s.refreshFinished <- struct{}{}:
		default:
		}
	}()
	select {
	case s.refreshCalled <- struct{}{}:
	default:
	}
	if s.timeout {
		<-ctx.Done()
		return ctx.Err()
	}
	return errors.New("AUTHORITY_LOST")
}
func (s *productionLoopStub) Cleanup(ctx context.Context) (int, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	s.cleanupCalled <- struct{}{}
	return 1, nil
}
func TestProductionCleanupSurvivesRefreshFailureAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "authority_lost", true: "budget_exhausted"}[timeout], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s := &productionLoopStub{make(chan struct{}, 4), make(chan struct{}, 4), make(chan struct{}, 4), timeout}
			refreshTick := make(chan time.Time, 2)
			cleanupTick := make(chan time.Time, 2)
			done := make(chan struct{})
			go func() {
				defer close(done)
				runProductionAssessmentLoops(ctx, s, slog.New(slog.NewTextHandler(io.Discard, nil)), refreshTick, cleanupTick, 10*time.Millisecond, 20*time.Millisecond)
			}()
			for _, ch := range []chan struct{}{s.refreshCalled, s.cleanupCalled} {
				select {
				case <-ch:
				case <-time.After(time.Second):
					t.Fatal("startup loop did not run")
				}
			}
			select {
			case <-s.refreshFinished:
			case <-time.After(time.Second):
				t.Fatal("refresh did not reach failure or deadline")
			}
			cleanupTick <- time.Now()
			select {
			case <-s.cleanupCalled:
			case <-time.After(time.Second):
				t.Fatal("cleanup starved by refresh")
			}
			refreshTick <- time.Now()
			select {
			case <-s.refreshCalled:
			case <-time.After(time.Second):
				t.Fatal("refresh stopped")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("shutdown did not join both loops")
			}
		})
	}
}

func TestProductionAssessmentDiagnosticWarnings(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stub := assessmentDiagnosticLoopStub{refreshErr: assessmentPrivateDatabaseError(), cleanupErr: assessmentPrivateDatabaseError()}
	records := make(chan []byte, 4)
	logger := slog.New(slog.NewJSONHandler(assessmentDiagnosticLogWriter{records}, nil))
	done := make(chan struct{})
	go func() {
		defer close(done)
		runProductionAssessmentLoops(ctx, stub, logger, make(chan time.Time), make(chan time.Time), time.Second, time.Second)
	}()
	seen := make(map[string]bool)
	for range 2 {
		record := requireAssessmentDiagnosticLog(t, records)
		message := record["msg"].(string)
		field := "refresh_elapsed_ms"
		switch message {
		case "control.production_assessment_refresh_failed":
		case "control.production_assessment_cleanup_failed":
			field = "cleanup_elapsed_ms"
		default:
			t.Fatalf("unexpected warning: %+v", record)
		}
		if elapsed, ok := record[field].(float64); !ok || elapsed < 0 {
			t.Fatalf("missing total elapsed duration: %+v", record)
		}
		seen[message] = true
	}
	if len(seen) != 2 {
		t.Fatal("refresh and cleanup both need diagnostic warnings")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loops failed to stop")
	}
}
