package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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

// The channel captures each complete JSONHandler write without concurrent
// buffer access between loop goroutines and the test.
type assessmentDiagnosticLogWriter struct{ records chan []byte }

func (w assessmentDiagnosticLogWriter) Write(p []byte) (int, error) {
	w.records <- append([]byte(nil), p...)
	return len(p), nil
}

type assessmentDiagnosticLoopStub struct{ refreshErr, cleanupErr error }

func (s assessmentDiagnosticLoopStub) Refresh(context.Context) error        { return s.refreshErr }
func (s assessmentDiagnosticLoopStub) Cleanup(context.Context) (int, error) { return 0, s.cleanupErr }

func assessmentPrivateDatabaseError() error {
	return fmt.Errorf("private-DSN: %w", &pgconn.PgError{Code: "57014", Message: "private-message", Detail: "private-parameters", Hint: "private-hint", Where: "private-query"})
}

func requireAssessmentDiagnosticLog(t *testing.T, records <-chan []byte, elapsedFields ...string) map[string]any {
	t.Helper()
	var raw []byte
	select {
	case raw = <-records:
	case <-time.After(time.Second):
		t.Fatal("diagnostic warning did not arrive")
	}
	if strings.Contains(string(raw), "private") {
		t.Fatalf("sensitive database text escaped: %s", raw)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	entries, ok := record["transaction_diagnostics"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("missing structured diagnostics: %s", raw)
	}
	diagnostic := entries[0].(map[string]any)
	if diagnostic["sqlstate"] != "57014" || diagnostic["error_class"] != "statement_canceled" || diagnostic["elapsed_ms"] != float64(-1) {
		t.Fatalf("unexpected fallback diagnostic: %s", raw)
	}
	for _, field := range elapsedFields {
		elapsed, ok := record[field].(float64)
		if !ok || elapsed < 0 {
			t.Fatalf("missing total %s: %s", field, raw)
		}
	}
	return record
}

func TestAssessmentDiagnosticWarnings(t *testing.T) {
	for _, cleanupFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "refresh", true: "cleanup"}[cleanupFailure], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stub := assessmentDiagnosticLoopStub{refreshErr: assessmentPrivateDatabaseError()}
			if cleanupFailure {
				stub = assessmentDiagnosticLoopStub{cleanupErr: assessmentPrivateDatabaseError()}
			}
			records := make(chan []byte, 4)
			logger := slog.New(slog.NewJSONHandler(assessmentDiagnosticLogWriter{records}, nil))
			done := make(chan struct{})
			go func() { defer close(done); runAssessmentRefresh(ctx, stub, logger) }()
			fields := []string{"refresh_elapsed_ms"}
			if cleanupFailure {
				fields = append(fields, "cleanup_elapsed_ms")
			}
			record := requireAssessmentDiagnosticLog(t, records, fields...)
			if record["msg"] != "control.assessment_refresh_failed" {
				t.Fatalf("unexpected message: %+v", record)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("loop failed to stop")
			}
		})
	}
}
