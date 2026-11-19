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
