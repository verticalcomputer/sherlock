package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/config"
)

const (
	journalMaintenanceInterval = time.Minute
	journalStatsLogEvery       = 15
)

var journalOperations = []string{"begin", "pending", "discard_lease", "mark_started", "store_result", "mark_finalized", "maintain", "stats"}

var journalRecordStates = []string{"CLAIMED", "STARTED", "RESULT_READY", "FINALIZED"}

// journalMetrics exposes bounded journal telemetry. Labels are limited to the
// fixed operation, outcome and state sets; no run, work, or lease identifier
// is ever used as a label.
type journalMetrics struct {
	now             func() time.Time
	operations      *prometheus.HistogramVec
	records         *prometheus.GaugeVec
	leaseReleased   prometheus.Gauge
	payloadBytes    prometheus.Gauge
	oldestPending   prometheus.Gauge
	oldestReleased  prometheus.Gauge
	prunedThrough   prometheus.Gauge
	pruned          prometheus.Counter
	cleanupFailures prometheus.Counter
}

func newJournalMetrics(registerer prometheus.Registerer, now func() time.Time) *journalMetrics {
	m := &journalMetrics{
		now: now,
		operations: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sherlock_collector_journal_operation_duration_seconds",
			Help:    "Collector journal operation latency including lock wait and durable commit.",
			Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"operation", "outcome"}),
		records: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sherlock_collector_journal_records",
			Help: "Retained collector journal attempt records by state.",
		}, []string{"state"}),
		leaseReleased: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sherlock_collector_journal_lease_released_records",
			Help: "Unfinished journal records whose lease was lost; retained until redelivered.",
		}),
		payloadBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sherlock_collector_journal_retained_payload_bytes",
			Help: "Bytes of unacknowledged result payloads retained in the journal.",
		}),
		oldestPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sherlock_collector_journal_oldest_pending_delivery_age_seconds",
			Help: "Age of the oldest journaled result that still holds a lease and awaits finalization; zero when none.",
		}),
		oldestReleased: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sherlock_collector_journal_oldest_lease_released_result_age_seconds",
			Help: "Age of the oldest journaled result whose lease was lost; zero when none.",
		}),
		prunedThrough: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sherlock_collector_journal_pruned_through_deadline_timestamp_seconds",
			Help: "Latest task deadline covered by pruned completion records; unseen work at or before it is refused.",
		}),
		pruned: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sherlock_collector_journal_pruned_records_total",
			Help: "Finalized completion records deleted by retention.",
		}),
		cleanupFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sherlock_collector_journal_cleanup_failures_total",
			Help: "Journal maintenance runs that failed.",
		}),
	}
	registerer.MustRegister(m.operations, m.records, m.leaseReleased, m.payloadBytes, m.oldestPending, m.oldestReleased, m.prunedThrough, m.pruned, m.cleanupFailures)
	return m
}

func (m *journalMetrics) ObserveJournalOperation(operation string, duration time.Duration, err error) {
	if !slices.Contains(journalOperations, operation) {
		operation = "other"
	}
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	m.operations.WithLabelValues(operation, outcome).Observe(duration.Seconds())
}

func (m *journalMetrics) observeMaintenance(report collectorruntime.JournalMaintenanceReport, err error) {
	if err != nil {
		m.cleanupFailures.Inc()
		return
	}
	m.pruned.Add(float64(report.PrunedRecords))
	stats := report.Stats
	for state, count := range map[string]int{"CLAIMED": stats.Claimed, "STARTED": stats.Started, "RESULT_READY": stats.ResultReady, "FINALIZED": stats.Finalized} {
		m.records.WithLabelValues(state).Set(float64(count))
	}
	m.leaseReleased.Set(float64(stats.LeaseReleased))
	m.payloadBytes.Set(float64(stats.PayloadBytes))
	m.oldestPending.Set(ageSeconds(m.now(), stats.OldestPendingDelivery))
	m.oldestReleased.Set(ageSeconds(m.now(), stats.OldestLeaseReleasedResult))
	if !stats.PrunedThrough.IsZero() {
		m.prunedThrough.Set(float64(stats.PrunedThrough.UnixNano()) / float64(time.Second))
	}
}

func ageSeconds(now, since time.Time) float64 {
	if since.IsZero() || now.Before(since) {
		return 0
	}
	return now.Sub(since).Seconds()
}

// journalMaintenanceObserver records metrics for every run and logs failures
// immediately and a bounded summary every journalStatsLogEvery runs.
func journalMaintenanceObserver(logger *slog.Logger, metrics *journalMetrics) func(collectorruntime.JournalMaintenanceReport, error) {
	runs, prunedSinceLog := 0, 0
	return func(report collectorruntime.JournalMaintenanceReport, err error) {
		metrics.observeMaintenance(report, err)
		if err != nil {
			logger.Warn("collector.journal_cleanup_failed", "error", err.Error(), "pruned_records", report.PrunedRecords)
			return
		}
		prunedSinceLog += report.PrunedRecords
		if runs%journalStatsLogEvery == 0 {
			logger.Info("collector.journal_stats", journalStatsAttributes(metrics.now(), report.Stats, prunedSinceLog)...)
			prunedSinceLog = 0
		}
		runs++
	}
}

func journalStatsAttributes(now time.Time, stats collectorruntime.JournalStats, pruned int) []any {
	return []any{
		"records", stats.Records(), "claimed", stats.Claimed, "started", stats.Started, "result_ready", stats.ResultReady,
		"finalized", stats.Finalized, "lease_released", stats.LeaseReleased, "retained_payload_bytes", stats.PayloadBytes,
		"oldest_pending_delivery_age_seconds", ageSeconds(now, stats.OldestPendingDelivery),
		"oldest_lease_released_result_age_seconds", ageSeconds(now, stats.OldestLeaseReleasedResult),
		"pruned_records", pruned, "pruned_through", stats.PrunedThrough,
	}
}

func logJournalPreparation(logger *slog.Logger, report *collectorruntime.JournalMigrationReport) {
	if report == nil {
		return
	}
	logger.Info("collector.journal_prepared",
		"action", report.Action, "legacy_bytes", report.LegacyBytes, "legacy_sha256", report.LegacySHA256,
		"backup", report.Backup, "archived_store", report.ArchivedStore, "entries", report.Entries,
		"claimed", report.Claimed, "started", report.Started, "result_ready", report.ResultReady, "finalized", report.Finalized,
		"lease_released", report.LeaseReleased, "finalized_lease_tokens_cleared", report.FinalizedLeaseTokensCleared,
		"retained_payload_bytes", report.RetainedPayloadBytes, "reclaimed_payload_bytes", report.ReclaimedPayloadBytes,
		"merged_completion_records", report.MergedCompletionRecords, "pruned_through", report.PrunedThrough,
		"duration_seconds", report.Duration.Seconds())
}

// runJournalCheckLegacy validates the version 1 journal in a temporary store
// without modifying it, so it can run before stopping the old collector.
func runJournalCheckLegacy(logger *slog.Logger) error {
	path, err := config.LoadCollectorJournalPath()
	if err != nil {
		return err
	}
	report, err := collectorruntime.CheckLegacyJournal(path, systemClock{})
	if err != nil {
		return err
	}
	logJournalPreparation(logger, report)
	return nil
}

// runJournalMigrate prepares the store without starting collection, so an
// operator can migrate with the service stopped and inspect the outcome.
func runJournalMigrate(logger *slog.Logger) error {
	path, err := config.LoadCollectorJournalPath()
	if err != nil {
		return err
	}
	journal, err := collectorruntime.OpenJournal(path, systemClock{})
	if err != nil {
		return err
	}
	logJournalPreparation(logger, journal.MigrationReport())
	stats, statsErr := journal.Stats()
	closeErr := journal.Close()
	if statsErr != nil {
		return statsErr
	}
	logger.Info("collector.journal_ready", journalStatsAttributes(time.Now().UTC(), stats, 0)...)
	return closeErr
}

type journalStatusOutput struct {
	LegacyJournal                       string    `json:"legacy_journal"`
	LegacyBytes                         int64     `json:"legacy_bytes"`
	StorePresent                        bool      `json:"store_present"`
	StoreLocked                         bool      `json:"store_locked"`
	StoreBytes                          int64     `json:"store_bytes"`
	StoreSource                         string    `json:"store_source,omitempty"`
	StoreCreatedAt                      time.Time `json:"store_created_at,omitzero"`
	LegacyEntriesImported               int       `json:"legacy_entries_imported"`
	Backups                             int       `json:"backups"`
	SealedStores                        int       `json:"sealed_stores"`
	Sealed                              bool      `json:"sealed"`
	Claimed                             int       `json:"claimed"`
	Started                             int       `json:"started"`
	ResultReady                         int       `json:"result_ready"`
	Finalized                           int       `json:"finalized"`
	LeaseReleased                       int       `json:"lease_released"`
	RetainedPayloadBytes                int64     `json:"retained_payload_bytes"`
	OldestPendingDeliveryAgeSeconds     float64   `json:"oldest_pending_delivery_age_seconds"`
	OldestLeaseReleasedResultAgeSeconds float64   `json:"oldest_lease_released_result_age_seconds"`
	PrunedThrough                       time.Time `json:"pruned_through,omitzero"`
}

func writeJournalStatus(output io.Writer, path string, now time.Time) error {
	status, err := collectorruntime.ReadJournalStatus(path)
	if err != nil {
		return err
	}
	stats := status.Stats
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(journalStatusOutput{
		LegacyJournal: status.LegacyJournal, LegacyBytes: status.LegacyBytes, StorePresent: status.StorePresent, StoreLocked: status.StoreLocked,
		StoreBytes: status.StoreBytes, StoreSource: status.StoreSource, StoreCreatedAt: status.StoreCreated,
		LegacyEntriesImported: status.LegacyEntries, Backups: status.Backups, SealedStores: status.SealedStores, Sealed: stats.Sealed,
		Claimed: stats.Claimed, Started: stats.Started, ResultReady: stats.ResultReady, Finalized: stats.Finalized,
		LeaseReleased: stats.LeaseReleased, RetainedPayloadBytes: stats.PayloadBytes,
		OldestPendingDeliveryAgeSeconds:     ageSeconds(now, stats.OldestPendingDelivery),
		OldestLeaseReleasedResultAgeSeconds: ageSeconds(now, stats.OldestLeaseReleasedResult),
		PrunedThrough:                       stats.PrunedThrough,
	})
}

func runJournalExportRollback(logger *slog.Logger) error {
	path, err := config.LoadCollectorJournalPath()
	if err != nil {
		return err
	}
	export, err := collectorruntime.ExportJournalForRollback(path, systemClock{})
	if err != nil {
		return err
	}
	logger.Info("collector.journal_rollback_exported",
		"path", export.Path, "sha256", export.SHA256, "bytes", export.Bytes, "entries", export.Entries,
		"claimed", export.Claimed, "started", export.Started, "result_ready", export.ResultReady,
		"omitted_completion_records", export.OmittedCompletionRecords, "pruned_through", export.PrunedThrough)
	return nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }
