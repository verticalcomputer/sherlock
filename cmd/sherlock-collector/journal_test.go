package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
)

func TestJournalMetricsUseBoundedLabels(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := newJournalMetrics(registry, time.Now)
	metrics.ObserveJournalOperation("begin", time.Millisecond, nil)
	metrics.ObserveJournalOperation("store_result", time.Millisecond, errors.New("disk full"))
	metrics.ObserveJournalOperation("run-8e5dfe81d4714c01aee6cc0d091278ad", time.Millisecond, nil)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	allowedOperations := append(append([]string(nil), journalOperations...), "other")
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "operation":
					if !contains(allowedOperations, label.GetValue()) {
						t.Fatalf("unbounded operation label %q", label.GetValue())
					}
				case "outcome":
					if label.GetValue() != "ok" && label.GetValue() != "error" {
						t.Fatalf("unbounded outcome label %q", label.GetValue())
					}
				case "state":
					if !contains(journalRecordStates, label.GetValue()) {
						t.Fatalf("unbounded state label %q", label.GetValue())
					}
				default:
					t.Fatalf("unexpected metric label %q", label.GetName())
				}
			}
		}
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func TestJournalMetricsReportMaintenance(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	registry := prometheus.NewRegistry()
	metrics := newJournalMetrics(registry, func() time.Time { return now })
	var logs bytes.Buffer
	observe := journalMaintenanceObserver(slog.New(slog.NewJSONHandler(&logs, nil)), metrics)
	observe(collectorruntime.JournalMaintenanceReport{PrunedRecords: 7, Stats: collectorruntime.JournalStats{
		Claimed: 1, ResultReady: 2, Finalized: 30, LeaseReleased: 1, PayloadBytes: 81234,
		OldestPendingDelivery: now.Add(-90 * time.Second), PrunedThrough: now.Add(-3 * time.Minute),
	}}, nil)
	observe(collectorruntime.JournalMaintenanceReport{}, errors.New("database is locked"))
	if got := testutil.ToFloat64(metrics.records.WithLabelValues("FINALIZED")); got != 30 {
		t.Fatalf("finalized records gauge = %v", got)
	}
	if got := testutil.ToFloat64(metrics.payloadBytes); got != 81234 {
		t.Fatalf("payload bytes gauge = %v", got)
	}
	if got := testutil.ToFloat64(metrics.oldestPending); got != 90 {
		t.Fatalf("oldest pending delivery age = %v", got)
	}
	if got := testutil.ToFloat64(metrics.pruned); got != 7 {
		t.Fatalf("pruned records = %v", got)
	}
	if got := testutil.ToFloat64(metrics.cleanupFailures); got != 1 {
		t.Fatalf("cleanup failures = %v", got)
	}
	if !strings.Contains(logs.String(), "collector.journal_stats") || !strings.Contains(logs.String(), "collector.journal_cleanup_failed") {
		t.Fatalf("maintenance logs = %s", logs.String())
	}
}

func TestJournalStatusCommandReportsFreshStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector-journal.json")
	journal, err := collectorruntime.OpenJournal(path, systemClock{})
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if _, err := journal.Stats(); err != nil {
		t.Fatal(err)
	}
	if status := readStatusOutput(t, path); !status.StorePresent || !status.StoreLocked {
		t.Fatalf("status beside running collector = %+v", status)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	status := readStatusOutput(t, path)
	if status.LegacyJournal != "redirect" || !status.StorePresent || status.StoreLocked || status.StoreSource != "fresh" || status.Claimed+status.Started+status.ResultReady+status.Finalized != 0 {
		t.Fatalf("status = %+v", status)
	}
}

func readStatusOutput(t *testing.T, path string) journalStatusOutput {
	t.Helper()
	var output bytes.Buffer
	if err := writeJournalStatus(&output, path, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var status journalStatusOutput
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		t.Fatal("status output has trailing data")
	}
	return status
}
