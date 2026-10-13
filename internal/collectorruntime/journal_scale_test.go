package collectorruntime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// TestJournalScaleMeasurement is an opt-in measurement, not a unit test. It
// generates a synthetic version 1 journal shaped like the production journal
// observed on 2026-09-11 (20,083 entries, about 788 MB) and measures one phase
// per process so the caller can record peak RSS externally, for example:
//
//	go test -c -o journal.test ./internal/collectorruntime
//	SHERLOCK_JOURNAL_SCALE_DIR=/tmp/scale SHERLOCK_JOURNAL_SCALE_PHASE=generate ./journal.test -test.run '^TestJournalScaleMeasurement$'
//	/usr/bin/time -v env SHERLOCK_JOURNAL_SCALE_DIR=/tmp/scale SHERLOCK_JOURNAL_SCALE_PHASE=migrate ./journal.test -test.run '^TestJournalScaleMeasurement$'
//
// Phases: generate, check, migrate, reopen, operate. Output is one
// SCALE_RESULT JSON line of synthetic, non-sensitive measurements.
func TestJournalScaleMeasurement(t *testing.T) {
	directory := os.Getenv("SHERLOCK_JOURNAL_SCALE_DIR")
	phase := os.Getenv("SHERLOCK_JOURNAL_SCALE_PHASE")
	if directory == "" || phase == "" {
		t.Skip("set SHERLOCK_JOURNAL_SCALE_DIR and SHERLOCK_JOURNAL_SCALE_PHASE to measure journal scale")
	}
	entries := scaleEnv(t, "SHERLOCK_JOURNAL_SCALE_ENTRIES", 20_083)
	targetBytes := int64(scaleEnv(t, "SHERLOCK_JOURNAL_SCALE_BYTES", 788_000_000))
	cycles := scaleEnv(t, "SHERLOCK_JOURNAL_SCALE_CYCLES", 500)
	original := filepath.Join(directory, "legacy-original.json")
	journalPath := filepath.Join(directory, "store", "collector-journal-pop.json")
	result := map[string]any{"phase": phase, "goos": runtime.GOOS, "goarch": runtime.GOARCH}
	switch phase {
	case "generate":
		started := time.Now()
		size, observations := generateScaleJournal(t, original, entries, targetBytes)
		result["seconds"], result["bytes"], result["entries"], result["observations_per_result"] = time.Since(started).Seconds(), size, entries, observations
	case "check":
		started := time.Now()
		report, err := CheckLegacyJournal(original, liveClock{})
		if err != nil {
			t.Fatal(err)
		}
		result["seconds"], result["report"] = time.Since(started).Seconds(), scaleReport(report)
	case "migrate":
		if err := os.RemoveAll(filepath.Dir(journalPath)); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
			t.Fatal(err)
		}
		copyScaleFile(t, original, journalPath)
		started := time.Now()
		journal, err := OpenJournal(journalPath, liveClock{})
		if err != nil {
			t.Fatal(err)
		}
		result["open_with_migration_seconds"], result["report"] = time.Since(started).Seconds(), scaleReport(journal.MigrationReport())
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		result["store_bytes"] = scaleFileSize(storePath(journalPath))
	case "reopen":
		started := time.Now()
		journal, err := OpenJournal(journalPath, liveClock{})
		if err != nil {
			t.Fatal(err)
		}
		result["open_seconds"] = time.Since(started).Seconds()
		stats, err := journal.Stats()
		if err != nil {
			t.Fatal(err)
		}
		result["records_before_maintenance"] = stats.Records()
		started = time.Now()
		report, err := journal.Maintain()
		if err != nil {
			t.Fatal(err)
		}
		result["maintenance_seconds"], result["pruned_records"], result["records_after_maintenance"] = time.Since(started).Seconds(), report.PrunedRecords, report.Stats.Records()
		result["retained_payload_bytes"] = report.Stats.PayloadBytes
		result["go_heap_inuse_bytes"] = scaleHeapInUse()
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		result["store_bytes"] = scaleFileSize(storePath(journalPath))
	case "operate":
		journal, err := OpenJournal(journalPath, liveClock{})
		if err != nil {
			t.Fatal(err)
		}
		observations := scaleEnv(t, "SHERLOCK_JOURNAL_SCALE_OBSERVATIONS", 0)
		if observations == 0 {
			t.Fatal("SHERLOCK_JOURNAL_SCALE_OBSERVATIONS must match the generated journal")
		}
		latencies := map[string][]time.Duration{}
		measure := func(name string, operation func() error) {
			started := time.Now()
			if err := operation(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			latencies[name] = append(latencies[name], time.Since(started))
		}
		for cycle := 0; cycle < cycles; cycle++ {
			lease := fixtureLease(fmt.Sprintf("scale-operate-%06d", cycle), 1, fixtureTokenPrefix+"operate", time.Now().UTC())
			result := fixtureResult(lease.Work.Task, observations)
			measure("begin", func() error { _, _, err := journal.begin(lease); return err })
			measure("pending", func() error { _, _, err := journal.pending(); return err })
			measure("mark_started", func() error { return journal.markStarted(lease.Work.Task.RunID) })
			measure("store_result", func() error { return journal.storeResult(lease.Work.Task.RunID, result) })
			measure("mark_finalized", func() error { return journal.markFinalized(lease.Work.Task.RunID) })
		}
		summary := map[string]any{}
		for name, values := range latencies {
			summary[name] = scalePercentiles(values)
		}
		result["cycles"], result["latency_ms"] = cycles, summary
		// Pages appended to the WAL by one state change of an active record.
		lease := fixtureLease("scale-wal-probe", 1, fixtureTokenPrefix+"probe", time.Now().UTC())
		if _, _, err := journal.begin(lease); err != nil {
			t.Fatal(err)
		}
		walFrames(t, journal, "TRUNCATE")
		if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
			t.Fatal(err)
		}
		result["mark_started_wal_pages"] = walFrames(t, journal, "PASSIVE")
		stats, err := journal.Stats()
		if err != nil {
			t.Fatal(err)
		}
		result["records"], result["retained_payload_bytes"], result["go_heap_inuse_bytes"] = stats.Records(), stats.PayloadBytes, scaleHeapInUse()
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		result["store_bytes"] = scaleFileSize(storePath(journalPath))
	default:
		t.Fatalf("unknown phase %q", phase)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("SCALE_RESULT " + string(encoded))
}

func scaleEnv(t *testing.T, name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		t.Fatalf("%s must be a non-negative integer", name)
	}
	return value
}

// generateScaleJournal writes entries with the production state mix: almost
// all finalized with payloads retained, a small number unfinished. Payload
// size is solved so the file approximates targetBytes.
func generateScaleJournal(t *testing.T, path string, entries int, targetBytes int64) (int64, int) {
	if info, err := os.Stat(path); err == nil {
		return info.Size(), scaleObservationsFor(t, entries, targetBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	observations := scaleObservationsFor(t, entries, targetBytes)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriterSize(file, 1<<20)
	now := time.Now().UTC()
	_, _ = io.WriteString(writer, `{"version":1,"entries":{`)
	for index := 0; index < entries; index++ {
		runID := fmt.Sprintf("scale-%032x", index)
		// About one collection every 100 seconds, ending now.
		scheduled := now.Add(-time.Duration(entries-index) * 100 * time.Second)
		task := fixtureTask(runID, scheduled)
		entry := journalEntry{WorkID: domain.WorkID("collection-" + runID), RunID: task.RunID, Attempt: 1, Task: task, State: journalFinalized, UpdatedAt: scheduled.Add(20 * time.Second)}
		switch {
		case index < 20:
			entry.State, entry.LeaseToken = journalClaimed, fixtureTokenPrefix+runID
		case index < 40:
			entry.State, entry.LeaseToken = journalStarted, fixtureTokenPrefix+runID
		case index < 70:
			entry.State, entry.LeaseToken = journalReady, fixtureTokenPrefix+runID
		case index < 100:
			entry.State = journalReady
		}
		if entry.State == journalReady || entry.State == journalFinalized {
			result := fixtureResult(task, observations)
			entry.Result = &result
		}
		if index > 0 {
			_ = writer.WriteByte(',')
		}
		key, _ := json.Marshal(runID)
		value, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = writer.Write(key)
		_ = writer.WriteByte(':')
		if _, err := writer.Write(value); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = io.WriteString(writer, `}}`)
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return scaleFileSize(path), observations
}

func scaleObservationsFor(t *testing.T, entries int, targetBytes int64) int {
	task := fixtureTask("scale-00000000000000000000000000000000", time.Now().UTC())
	measure := func(observations int) int64 {
		result := fixtureResult(task, observations)
		entry := journalEntry{WorkID: "collection-" + domain.WorkID(task.RunID), RunID: task.RunID, Attempt: 1, Task: task, State: journalFinalized, Result: &result, UpdatedAt: time.Now().UTC()}
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		return int64(len(encoded) + len(task.RunID) + 4)
	}
	base, per := measure(0), measure(100)-measure(0)
	observations := int((targetBytes/int64(entries) - base) * 100 / per)
	return max(observations, 1)
}

func copyScaleFile(t *testing.T, source, destination string) {
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func scaleFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

func scaleHeapInUse() uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapInuse
}

func scaleReport(report *JournalMigrationReport) map[string]any {
	if report == nil {
		return nil
	}
	return map[string]any{
		"action": report.Action, "entries": report.Entries, "claimed": report.Claimed, "started": report.Started,
		"result_ready": report.ResultReady, "finalized": report.Finalized, "lease_released": report.LeaseReleased,
		"retained_payload_bytes": report.RetainedPayloadBytes, "reclaimed_payload_bytes": report.ReclaimedPayloadBytes,
		"legacy_bytes": report.LegacyBytes, "duration_seconds": report.Duration.Seconds(),
	}
}

func scalePercentiles(values []time.Duration) map[string]float64 {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	at := func(fraction float64) float64 {
		index := int(float64(len(sorted)-1) * fraction)
		return float64(sorted[index].Microseconds()) / 1000
	}
	return map[string]float64{"p50": at(0.50), "p95": at(0.95), "p99": at(0.99), "max": at(1)}
}
