package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/config"
)

func TestAssessmentDisabledHasNoInitialization(t *testing.T) {
	var logs bytes.Buffer
	stop := startAssessment(context.Background(), config.Assessment{Mode: "disabled", DatabaseURL: "bad-secret", ConfigFile: "missing"}, slog.New(slog.NewTextHandler(&logs, nil)))
	stop()
	if logs.Len() != 0 {
		t.Fatal(logs.String())
	}
}
func TestAssessmentFailedInitializationSanitized(t *testing.T) {
	var logs bytes.Buffer
	stop := startAssessment(context.Background(), config.Assessment{Mode: "shadow", DatabaseURL: "private-secret", ConfigFile: "missing-private-path"}, slog.New(slog.NewTextHandler(&logs, nil)))
	stop()
	if strings.Contains(logs.String(), "private") {
		t.Fatal("leaked configuration")
	}
	if !strings.Contains(logs.String(), "assessment_disabled") {
		t.Fatal(logs.String())
	}
}

type assessmentLoopStub struct{ called chan struct{} }

func (s assessmentLoopStub) Refresh(ctx context.Context) error {
	select {
	case s.called <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}
func (s assessmentLoopStub) Cleanup(context.Context) (int, error) { return 0, nil }
func TestAssessmentShutdownJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stub := assessmentLoopStub{make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() { defer close(done); runAssessmentRefresh(ctx, stub, slog.Default()) }()
	select {
	case <-stub.called:
	case <-time.After(time.Second):
		t.Fatal("loop did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not stop")
	}
}
