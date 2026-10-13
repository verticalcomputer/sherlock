package collectorruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// fixtureTokenPrefix marks synthetic lease tokens; tests assert that no error,
// report, or status output ever contains it.
const fixtureTokenPrefix = "fixture-lease-token-must-never-appear-in-output-"

// Journal fixtures use head-prometheus; the runtime must select that same
// local source before exercising receipt/replay behavior.
func newJournalTestRuntime(t *testing.T, client ControlClient, executor executorFunc, journal *Journal, clock Clock) *Runtime {
	runtime := newTestRuntime(t, client, executor, journal, clock)
	runtime.cfg.SourceID = "head-prometheus"
	return runtime
}

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func fixtureTask(runID string, scheduled time.Time) domain.CollectionTask {
	return domain.CollectionTask{
		RunID: domain.RunID(runID), ClusterID: "pilot-cluster", SourceID: "head-prometheus", Query: domain.QueryGPUUtilization,
		ScheduledFor: scheduled.UTC(), Deadline: scheduled.UTC().Add(30 * time.Second), MaxSeries: 10_000, MaxBytes: 10 << 20,
		IdempotencyKey: "m1/head-prometheus/dcgm_gpu_utilization/" + runID,
	}
}

func fixtureLease(runID string, attempt int, token string, scheduled time.Time) domain.WorkLease {
	task := fixtureTask(runID, scheduled)
	return domain.WorkLease{
		CollectorID: "collector-1", Attempt: attempt, LeaseToken: token, LeaseExpires: scheduled.Add(time.Minute),
		Work: domain.CollectorWork{WorkID: domain.WorkID("work-" + runID), Task: task, Status: domain.WorkLeased, AvailableAt: scheduled, WorkExpiresAt: task.Deadline},
	}
}

// fixtureResult carries nanosecond timestamps and a non-UTC zone so that
// round trips through the store expose any precision loss.
func fixtureResult(task domain.CollectionTask, observations int) domain.CollectionResult {
	ist := time.FixedZone("IST", 5*3600+30*60)
	started := task.ScheduledFor.Add(5*time.Millisecond + 7*time.Nanosecond)
	completed := started.Add(3*time.Millisecond + 11*time.Nanosecond)
	values := make([]domain.Observation, 0, observations)
	for index := 0; index < observations; index++ {
		values = append(values, domain.Observation{
			ID: domain.ObservationID(fmt.Sprintf("%s-observation-%05d", task.RunID, index)), SchemaVersion: 1,
			ClusterID: task.ClusterID, SourceID: task.SourceID, Kind: "gpu_utilization",
			EntityKey: fmt.Sprintf("node-%03d/gpu-%d", index%80, index%8), Metric: "DCGM_FI_DEV_GPU_UTIL",
			Labels: []domain.Label{{Name: "Hostname", Value: fmt.Sprintf("fixture1-zone1-comp%03d", index%80)}, {Name: "UUID", Value: fmt.Sprintf("GPU-%032x", index)}, {Name: "gpu", Value: fmt.Sprint(index % 8)}},
			Value:  97.125 + float64(index%13), Unit: "percent",
			ObservedAt:      task.ScheduledFor.Add(time.Millisecond + time.Duration(index)*time.Nanosecond).In(ist),
			CollectedAt:     completed,
			SourceReference: "prometheus:instant:DCGM_FI_DEV_GPU_UTIL",
		})
	}
	expected := observations
	return domain.CollectionResult{
		Task: task, Status: domain.ResultSucceeded, StartedAt: started, CompletedAt: completed,
		Coverage:     domain.Coverage{SeriesExpected: &expected, SeriesReturned: observations, BytesRead: int64(observations) * 180, Complete: true},
		Observations: values,
	}
}

func newLegacyFixture(now time.Time) journalFile {
	entries := make(map[string]journalEntry)
	add := func(runID string, state journalState, token string, withResult bool) {
		task := fixtureTask(runID, now.Add(-time.Minute))
		entry := journalEntry{WorkID: domain.WorkID("work-" + runID), RunID: domain.RunID(runID), Attempt: 2, LeaseToken: token, Task: task, State: state, UpdatedAt: now.Add(-30 * time.Second)}
		if withResult {
			result := fixtureResult(task, 6)
			entry.Result = &result
		}
		entries[runID] = entry
	}
	add("run-claimed", journalClaimed, fixtureTokenPrefix+"claimed", false)
	add("run-started", journalStarted, fixtureTokenPrefix+"started", false)
	add("run-ready", journalReady, fixtureTokenPrefix+"ready", true)
	add("run-ready-released", journalReady, "", true)
	add("run-finalized", journalFinalized, "", true)
	add("run-finalized-token", journalFinalized, fixtureTokenPrefix+"finalized", true)
	return journalFile{Version: 1, Entries: entries}
}

func writeLegacyJournal(t *testing.T, path string, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func storePath(path string) string { return strings.TrimSuffix(path, ".json") + ".sqlite" }

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists: %v", filepath.Base(path), err)
	}
}

func assertNoFixtureToken(t *testing.T, text string) {
	t.Helper()
	if strings.Contains(text, fixtureTokenPrefix) {
		t.Fatal("output contains a lease token")
	}
}

func countRows(t *testing.T, journal *Journal, query string, args ...any) int {
	t.Helper()
	var count int
	if err := journal.db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestJournalMigrationImportsLegacyStateAndPreservesBackup(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 37, 4, 448611000, time.UTC)
	clock := testClock{now: now}
	directory := t.TempDir()
	path := filepath.Join(directory, "collector-journal-pop.json")
	legacy := newLegacyFixture(now)
	original := writeLegacyJournal(t, path, legacy)
	originalSum := sha256.Sum256(original)

	journal := openTestJournal(t, path, clock)
	report := journal.MigrationReport()
	if report == nil || report.Action != "migrated" || report.Entries != 6 || report.Claimed != 1 || report.Started != 1 ||
		report.ResultReady != 2 || report.Finalized != 2 || report.LeaseReleased != 1 || report.FinalizedLeaseTokensCleared != 1 ||
		report.LegacySHA256 != hex.EncodeToString(originalSum[:]) || report.LegacyBytes != int64(len(original)) ||
		report.RetainedPayloadBytes <= 0 || report.ReclaimedPayloadBytes <= 0 {
		t.Fatalf("migration report = %+v", report)
	}
	assertNoFixtureToken(t, fmt.Sprintf("%+v", *report))

	backup := filepath.Join(directory, report.Backup)
	backupData, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backupData, original) {
		t.Fatal("legacy backup is not byte-identical to the original journal")
	}
	for _, name := range []string{backup, path, storePath(path)} {
		if info, err := os.Stat(name); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v err=%v", filepath.Base(name), info, err)
		}
	}

	// A version 1 collector decodes the redirect but must refuse its version.
	var old journalFile
	redirect, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(redirect, &old); err != nil || old.Version == 1 {
		t.Fatalf("redirect would be accepted by a version 1 collector: version=%d err=%v", old.Version, err)
	}

	for runID, want := range legacy.Entries {
		got, ok := journal.entry(domain.RunID(runID))
		if !ok {
			t.Fatalf("run %s was not imported", runID)
		}
		if got.WorkID != want.WorkID || got.Attempt != want.Attempt || got.State != want.State || !got.UpdatedAt.Equal(want.UpdatedAt) || !bytes.Equal(mustJSON(t, got.Task), mustJSON(t, want.Task)) {
			t.Fatalf("run %s identity changed during import", runID)
		}
		switch want.State {
		case journalFinalized:
			if got.Result != nil || got.LeaseToken != "" {
				t.Fatalf("finalized run %s kept its payload or token", runID)
			}
		case journalReady:
			if got.LeaseToken != want.LeaseToken || got.Result == nil || !bytes.Equal(mustJSON(t, got.Result), mustJSON(t, want.Result)) {
				t.Fatalf("result-ready run %s changed during import", runID)
			}
		default:
			if got.LeaseToken != want.LeaseToken || got.Result != nil {
				t.Fatalf("in-flight run %s changed during import", runID)
			}
		}
	}
	if payloads := countRows(t, journal, `SELECT count(*) FROM results`); payloads != 2 {
		t.Fatalf("retained payloads = %d, want 2", payloads)
	}
}

func TestJournalMigrationFailsClosedOnMalformedRecords(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	legacy := newLegacyFixture(now)
	encoded := mustJSON(t, legacy)
	claimed := mustJSON(t, legacy.Entries["run-claimed"])
	generic := func(t *testing.T) (map[string]any, map[string]any) {
		var document map[string]any
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatal(err)
		}
		return document, document["entries"].(map[string]any)
	}
	entry := func(entries map[string]any, runID string) map[string]any { return entries[runID].(map[string]any) }
	cases := []struct {
		name   string
		mutate func(document, entries map[string]any)
		raw    func() []byte
	}{
		{name: "unknown top-level field", mutate: func(document, _ map[string]any) { document["extra"] = 1 }},
		{name: "unsupported version", mutate: func(document, _ map[string]any) { document["version"] = 3 }},
		{name: "null entries", mutate: func(document, _ map[string]any) { document["entries"] = nil }},
		{name: "key does not match run", mutate: func(_, entries map[string]any) {
			entries["run-other"] = entries["run-claimed"]
			delete(entries, "run-claimed")
		}},
		{name: "ready without result", mutate: func(_, entries map[string]any) { delete(entry(entries, "run-ready"), "result") }},
		{name: "finalized without result", mutate: func(_, entries map[string]any) { delete(entry(entries, "run-finalized"), "result") }},
		{name: "claimed with result", mutate: func(_, entries map[string]any) {
			entry(entries, "run-claimed")["result"] = entry(entries, "run-ready")["result"]
		}},
		{name: "unknown state", mutate: func(_, entries map[string]any) { entry(entries, "run-claimed")["state"] = "RUNNING" }},
		{name: "zero attempt", mutate: func(_, entries map[string]any) { entry(entries, "run-started")["attempt"] = 0 }},
		{name: "invalid task", mutate: func(_, entries map[string]any) {
			task := entry(entries, "run-started")["task"].(map[string]any)
			task["Deadline"] = task["ScheduledFor"]
		}},
		{name: "task for another run", mutate: func(_, entries map[string]any) {
			entry(entries, "run-started")["task"].(map[string]any)["RunID"] = "run-other"
		}},
		{name: "duplicate work identifier", mutate: func(_, entries map[string]any) {
			entry(entries, "run-started")["work_id"] = entry(entries, "run-claimed")["work_id"]
		}},
		{name: "unknown entry field", mutate: func(_, entries map[string]any) { entry(entries, "run-claimed")["lease_secret"] = "x" }},
		{name: "result for another run", mutate: func(_, entries map[string]any) {
			entry(entries, "run-ready")["result"].(map[string]any)["Task"].(map[string]any)["RunID"] = "run-other"
		}},
		{name: "result unknown field", mutate: func(_, entries map[string]any) {
			entry(entries, "run-finalized")["result"].(map[string]any)["Extra"] = true
		}},
		{name: "truncated", raw: func() []byte { return encoded[:len(encoded)/2] }},
		{name: "trailing data", raw: func() []byte { return append(append([]byte(nil), encoded...), []byte(`{}`)...) }},
		{name: "duplicate run key", raw: func() []byte {
			return bytes.Replace(encoded, []byte(`"entries":{`), []byte(`"entries":{"run-claimed":`+string(claimed)+`,`), 1)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "collector-journal.json")
			var data []byte
			if test.raw != nil {
				data = test.raw()
			} else {
				document, entries := generic(t)
				test.mutate(document, entries)
				data = mustJSON(t, document)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			before := fileDigest(t, path)
			for attempt := 0; attempt < 2; attempt++ {
				journal, err := OpenJournal(path, testClock{now: now})
				if err == nil {
					_ = journal.Close()
					t.Fatal("malformed legacy journal was accepted")
				}
				if errors.Is(err, ErrJournalInUse) {
					t.Fatal("failed migration leaked the journal lock")
				}
				assertNoFixtureToken(t, err.Error())
			}
			if fileDigest(t, path) != before {
				t.Fatal("failed migration modified the legacy journal")
			}
			assertMissing(t, storePath(path))
			assertMissing(t, storePath(path)+".importing")
		})
	}
}

func TestJournalMigrationResumesAfterInterruption(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	for _, stage := range []string{"after_backup", "before_store_rename", "after_store_rename"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "collector-journal.json")
			original := writeLegacyJournal(t, path, newLegacyFixture(now))
			injected := errors.New("injected crash")
			journalMigrationFault = func(current string) error {
				if current == stage {
					return injected
				}
				return nil
			}
			t.Cleanup(func() { journalMigrationFault = nil })
			if _, err := OpenJournal(path, testClock{now: now}); !errors.Is(err, injected) {
				t.Fatalf("interrupted open error = %v", err)
			}
			journalMigrationFault = nil
			if stage != "after_store_rename" {
				if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, original) {
					t.Fatal("legacy journal changed before the store was installed")
				}
				assertMissing(t, storePath(path))
			}

			journal, err := OpenJournal(path, testClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			wantAction := "migrated"
			if stage == "after_store_rename" {
				wantAction = "migration_completed"
			}
			if report := journal.MigrationReport(); report == nil || report.Action != wantAction {
				t.Fatalf("resumed report = %+v, want %s", report, wantAction)
			}
			if count := countRows(t, journal, `SELECT count(*) FROM attempts`); count != 6 {
				t.Fatalf("resumed store has %d attempts", count)
			}
			if entry, ok := journal.entry("run-ready"); !ok || entry.Result == nil || entry.LeaseToken != fixtureTokenPrefix+"ready" {
				t.Fatal("resumed store lost an unacknowledged result")
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			backups, _, err := journalArtifacts(journalPaths{legacy: path, store: storePath(path), directory: filepath.Dir(path)})
			if err != nil || len(backups) != 1 {
				t.Fatalf("backups = %v err=%v", backups, err)
			}
			if data, err := os.ReadFile(backups[0]); err != nil || !bytes.Equal(data, original) {
				t.Fatal("backup changed across interrupted migration")
			}
			assertMissing(t, storePath(path)+".importing")

			again := openTestJournal(t, path, testClock{now: now})
			if report := again.MigrationReport(); report != nil {
				t.Fatalf("repeated startup performed %+v", report)
			}
			if count := countRows(t, again, `SELECT count(*) FROM attempts`); count != 6 {
				t.Fatalf("repeated startup changed attempts to %d", count)
			}
		})
	}
	t.Run("partial import file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "collector-journal.json")
		writeLegacyJournal(t, path, newLegacyFixture(now))
		if err := os.WriteFile(storePath(path)+".importing", []byte("partial SQLite file"), 0o600); err != nil {
			t.Fatal(err)
		}
		journal := openTestJournal(t, path, testClock{now: now})
		if count := countRows(t, journal, `SELECT count(*) FROM attempts`); count != 6 {
			t.Fatalf("store after partial import has %d attempts", count)
		}
		assertMissing(t, storePath(path)+".importing")
	})
}

func TestJournalRefusesAmbiguousOrMissingState(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	migrated := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "collector-journal.json")
		writeLegacyJournal(t, path, newLegacyFixture(now))
		journal, err := OpenJournal(path, testClock{now: now})
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("legacy journal restored beside store", func(t *testing.T) {
		path := migrated(t)
		restored := newLegacyFixture(now.Add(time.Hour))
		writeLegacyJournal(t, path, restored)
		before := fileDigest(t, path)
		if _, err := OpenJournal(path, testClock{now: now}); err == nil || !strings.Contains(err.Error(), "Refusing to choose") {
			t.Fatalf("ambiguous journal error = %v", err)
		}
		if fileDigest(t, path) != before {
			t.Fatal("refusal modified the legacy journal")
		}
	})
	t.Run("store removed after migration", func(t *testing.T) {
		path := migrated(t)
		for _, suffix := range []string{"", "-wal", "-shm"} {
			_ = os.Remove(storePath(path) + suffix)
		}
		if _, err := OpenJournal(path, testClock{now: now}); err == nil || !strings.Contains(err.Error(), "store is missing") {
			t.Fatalf("missing store error = %v", err)
		}
	})
	t.Run("journal and store removed with backup present", func(t *testing.T) {
		path := migrated(t)
		for _, name := range []string{path, storePath(path), storePath(path) + "-wal", storePath(path) + "-shm"} {
			_ = os.Remove(name)
		}
		if _, err := OpenJournal(path, testClock{now: now}); err == nil || !strings.Contains(err.Error(), "backups or sealed stores exist") {
			t.Fatalf("missing state error = %v", err)
		}
		assertMissing(t, storePath(path))
	})
	t.Run("redirect names another store", func(t *testing.T) {
		path := migrated(t)
		if err := os.WriteFile(path, []byte(`{"version":2,"entries":{},"format":"sherlock-collector-journal-redirect","store":"other.sqlite"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenJournal(path, testClock{now: now}); err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Fatalf("foreign redirect error = %v", err)
		}
	})
	t.Run("symlinked journal", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.json")
		writeLegacyJournal(t, target, newLegacyFixture(now))
		path := filepath.Join(directory, "collector-journal.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenJournal(path, testClock{now: now}); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlink error = %v", err)
		}
	})
}

func TestJournalConcurrentProcessesAreFenced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector-journal.json")
	first, err := OpenJournal(path, liveClock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(path, liveClock{}); !errors.Is(err, ErrJournalInUse) {
		t.Fatalf("second in-process open error = %v", err)
	}
	if _, err := ExportJournalForRollback(path, liveClock{}); !errors.Is(err, ErrJournalInUse) {
		t.Fatalf("export while running error = %v", err)
	}
	helper := func() int {
		command := exec.Command(os.Args[0], "-test.run=^TestJournalLockHelperProcess$", "-test.count=1")
		command.Env = append(os.Environ(), "SHERLOCK_JOURNAL_LOCK_HELPER_PATH="+path)
		if err := command.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return exit.ExitCode()
			}
			t.Fatal(err)
		}
		return 0
	}
	if code := helper(); code != 3 {
		t.Fatalf("second process exit code = %d, want 3 (journal in use)", code)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if code := helper(); code != 0 {
		t.Fatalf("process after release exit code = %d, want 0", code)
	}
}

func TestJournalLockHelperProcess(t *testing.T) {
	path := os.Getenv("SHERLOCK_JOURNAL_LOCK_HELPER_PATH")
	if path == "" {
		t.Skip("helper process for TestJournalConcurrentProcessesAreFenced")
	}
	journal, err := OpenJournal(path, liveClock{})
	if errors.Is(err, ErrJournalInUse) {
		os.Exit(3)
	}
	if err != nil {
		os.Exit(4)
	}
	_ = journal.Close()
	os.Exit(0)
}

// TestJournalSurvivesAbruptProcessTermination kills a process holding the
// store without closing it, so recovery relies on SQLite's WAL replay and the
// kernel releasing the process lock rather than on an orderly checkpoint.
func TestJournalSurvivesAbruptProcessTermination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector-journal.json")
	command := exec.Command(os.Args[0], "-test.run=^TestJournalCrashHelperProcess$", "-test.count=1")
	command.Env = append(os.Environ(), "SHERLOCK_JOURNAL_CRASH_HELPER_PATH="+path)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("helper did not terminate abnormally: %v", err)
	}
	if status, ok := exit.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("helper exit = %v, want SIGKILL", err)
	}
	if _, err := os.Lstat(storePath(path) + "-wal"); err != nil {
		t.Fatalf("killed process left no write-ahead log to recover: %v", err)
	}

	clock := liveClock{}
	journal := openTestJournal(t, path, clock)
	ready, ok := journal.entry("run-crash-ready")
	if !ok || ready.State != journalReady || ready.LeaseToken != fixtureTokenPrefix+"crash-ready" || ready.Result == nil || len(ready.Result.Observations) != 3 {
		t.Fatalf("committed result lost after SIGKILL: %+v", ready)
	}
	if started, ok := journal.entry("run-crash-started"); !ok || started.State != journalStarted {
		t.Fatalf("committed start lost after SIGKILL: %+v", started)
	}
	client := &fakeControl{}
	neverExecute := executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult {
		t.Error("work was re-executed after SIGKILL")
		return domain.CollectionResult{}
	})
	runtime := newJournalTestRuntime(t, client, neverExecute, journal, clock)
	for _, runID := range []string{"run-crash-ready", "run-crash-started"} {
		pending, found, err := journal.pending()
		if err != nil || !found {
			t.Fatalf("pending after SIGKILL = %v %v", found, err)
		}
		if err := runtime.process(context.Background(), pendingLease("collector-1", pending)); err != nil {
			t.Fatalf("recover %s: %v", runID, err)
		}
	}
	if _, found, _ := journal.pending(); found || client.finalizations != 2 || client.starts != 0 {
		t.Fatalf("recovery finalizations=%d starts=%d pending=%v", client.finalizations, client.starts, found)
	}
}

func TestJournalCrashHelperProcess(t *testing.T) {
	path := os.Getenv("SHERLOCK_JOURNAL_CRASH_HELPER_PATH")
	if path == "" {
		t.Skip("helper process for TestJournalSurvivesAbruptProcessTermination")
	}
	journal, err := OpenJournal(path, liveClock{})
	if err != nil {
		os.Exit(4)
	}
	now := time.Now().UTC()
	ready := fixtureLease("run-crash-ready", 1, fixtureTokenPrefix+"crash-ready", now)
	started := fixtureLease("run-crash-started", 1, fixtureTokenPrefix+"crash-started", now)
	for _, lease := range []domain.WorkLease{ready, started} {
		if _, _, err := journal.begin(lease); err != nil {
			os.Exit(5)
		}
		if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
			os.Exit(6)
		}
	}
	if err := journal.storeResult(ready.Work.Task.RunID, fixtureResult(ready.Work.Task, 3)); err != nil {
		os.Exit(7)
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {}
}

func concatenatedUploads(client *fakeControl, attempt int) []byte {
	client.mu.Lock()
	defer client.mu.Unlock()
	var encoded []byte
	for _, chunk := range client.uploads {
		if chunk.Attempt == attempt {
			encoded = append(encoded, chunk.Payload...)
		}
	}
	return encoded
}

func TestJournalLostFinalizeAcknowledgementRedeliversIdenticalResult(t *testing.T) {
	now := time.Now().UTC()
	clock := liveClock{}
	path := filepath.Join(t.TempDir(), "collector-journal.json")
	journal := openTestJournal(t, path, clock)
	lease := fixtureLease("run-lost-ack", 1, fixtureTokenPrefix+"lost-ack", now)
	expected := fixtureResult(lease.Work.Task, 4)
	var executions atomic.Int32
	executor := executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult {
		executions.Add(1)
		return expected
	})
	// The server durably finalizes but the reply never reaches the collector.
	first := &fakeControl{finalizationFail: errors.New("finalize reply lost after server commit")}
	if err := newJournalTestRuntime(t, first, executor, journal, clock).process(context.Background(), lease); err == nil {
		t.Fatal("lost finalize reply was treated as success")
	}
	delivered := concatenatedUploads(first, 1)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestJournal(t, path, clock)
	ctx, cancel := context.WithCancel(context.Background())
	second := &fakeControl{finalize: cancel}
	neverExecute := executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult {
		t.Error("unacknowledged result was re-executed")
		return domain.CollectionResult{}
	})
	if err := newJournalTestRuntime(t, second, neverExecute, reopened, clock).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if executions.Load() != 1 || second.claims != 0 || second.finalizations != 1 || second.uploads[0].LeaseToken != lease.LeaseToken {
		t.Fatalf("executions=%d claims=%d finalizations=%d", executions.Load(), second.claims, second.finalizations)
	}
	redelivered := concatenatedUploads(second, 1)
	if len(delivered) == 0 || !bytes.Equal(delivered, redelivered) {
		t.Fatal("redelivered canonical result differs from the original delivery")
	}
	document, err := domain.DecodeCollectorResult(redelivered)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Result.Observations) != len(expected.Observations) || !document.Result.CompletedAt.Equal(expected.CompletedAt) {
		t.Fatalf("delivered result was replaced: %+v", document.Result.Failures)
	}
	for index, observation := range document.Result.Observations {
		if observation.ObservedAt.UnixNano() != expected.Observations[index].ObservedAt.UnixNano() {
			t.Fatalf("observation %d timestamp lost precision", index)
		}
	}
	if entry, ok := reopened.entry(lease.Work.Task.RunID); !ok || entry.State != journalFinalized || entry.Result != nil {
		t.Fatalf("receipt after acknowledgement = %+v", entry)
	}
	if payloads := countRows(t, reopened, `SELECT count(*) FROM results`); payloads != 0 {
		t.Fatalf("acknowledged payload was retained (%d rows)", payloads)
	}
}

func TestJournalRefusesRedeliveryOfFinalizedRun(t *testing.T) {
	now := time.Now().UTC()
	clock := liveClock{}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "collector-journal.json"), clock)
	var executions atomic.Int32
	executor := executorFunc(func(_ context.Context, task domain.CollectionTask) domain.CollectionResult {
		executions.Add(1)
		return fixtureResult(task, 2)
	})
	client := &fakeControl{}
	runtime := newJournalTestRuntime(t, client, executor, journal, clock)
	lease := fixtureLease("run-duplicate", 1, fixtureTokenPrefix+"one", now)
	if err := runtime.process(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	duplicate := fixtureLease("run-duplicate", 2, fixtureTokenPrefix+"two", now)
	err := runtime.process(context.Background(), duplicate)
	if !errors.Is(err, ErrJournalDeliveryRefused) {
		t.Fatalf("duplicate delivery error = %v", err)
	}
	assertNoFixtureToken(t, err.Error())
	if executions.Load() != 1 || client.starts != 1 || client.finalizations != 1 || len(concatenatedUploads(client, 2)) != 0 {
		t.Fatalf("duplicate delivery executed or uploaded: executions=%d starts=%d finalizations=%d", executions.Load(), client.starts, client.finalizations)
	}
}

func TestJournalStaleLeaseIsDiscardedAndReassignedWithoutReexecution(t *testing.T) {
	now := time.Now().UTC()
	clock := liveClock{}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "collector-journal.json"), clock)
	first := fixtureLease("run-stale", 1, fixtureTokenPrefix+"stale", now)
	second := fixtureLease("run-stale", 2, fixtureTokenPrefix+"reassigned", now)
	var executions, claims atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	client := &fakeControl{finalizationFail: fmt.Errorf("%w: collector control returned HTTP 409", ErrLeaseLost), finalize: cancel}
	client.claim = func(context.Context, ClaimRequest) (*domain.WorkLease, error) {
		switch claims.Add(1) {
		case 1:
			lease := first
			return &lease, nil
		case 2:
			if _, pending, err := journal.pending(); err != nil || pending {
				t.Errorf("stale lease still pending: %v %v", pending, err)
			}
			if entry, ok := journal.entry(first.Work.Task.RunID); !ok || entry.LeaseToken != "" || entry.State != journalReady || entry.Result == nil {
				t.Errorf("stale lease discard lost the result: %+v", entry)
			}
			if stats, err := journal.Stats(); err != nil || stats.LeaseReleased != 1 || stats.PayloadBytes == 0 {
				t.Errorf("stats after discard = %+v %v", stats, err)
			}
			lease := second
			return &lease, nil
		default:
			return nil, nil
		}
	}
	executor := executorFunc(func(_ context.Context, task domain.CollectionTask) domain.CollectionResult {
		executions.Add(1)
		return fixtureResult(task, 3)
	})
	if err := newJournalTestRuntime(t, client, executor, journal, clock).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if executions.Load() != 1 || client.starts != 1 || client.finalizations != 2 {
		t.Fatalf("executions=%d starts=%d finalizations=%d", executions.Load(), client.starts, client.finalizations)
	}
	stale, err := domain.DecodeCollectorResult(concatenatedUploads(client, 1))
	if err != nil {
		t.Fatal(err)
	}
	reassigned, err := domain.DecodeCollectorResult(concatenatedUploads(client, 2))
	if err != nil {
		t.Fatal(err)
	}
	if reassigned.Attempt != 2 || !bytes.Equal(mustJSON(t, stale.Result), mustJSON(t, reassigned.Result)) {
		t.Fatal("reassigned attempt did not deliver the journaled result")
	}
}

func TestJournalRejectsInconsistentWorkAndRunIdentifiers(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "collector-journal.json")
	journal := openTestJournal(t, path, testClock{now: now})
	lease := fixtureLease("run-identity", 1, fixtureTokenPrefix+"identity", now)
	if _, _, err := journal.begin(lease); err != nil {
		t.Fatal(err)
	}
	check := func(journal *Journal) {
		otherWork := lease
		otherWork.Work.WorkID = "work-other"
		if _, existed, err := journal.begin(otherWork); err == nil || !existed || !strings.Contains(err.Error(), "different work identifier") {
			t.Fatalf("same run with another work = existed %v err %v", existed, err)
		} else {
			assertNoFixtureToken(t, err.Error())
		}
		otherRun := fixtureLease("run-other", 1, fixtureTokenPrefix+"other", now)
		otherRun.Work.WorkID = lease.Work.WorkID
		if _, _, err := journal.begin(otherRun); err == nil || !strings.Contains(err.Error(), "different run identifier") {
			t.Fatalf("same work with another run error = %v", err)
		}
		if entry, ok := journal.entry(lease.Work.Task.RunID); !ok || entry.LeaseToken != lease.LeaseToken || entry.Attempt != 1 {
			t.Fatal("rejected delivery modified the receipt")
		}
	}
	check(journal)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	check(openTestJournal(t, path, testClock{now: now}))
}

func insertFinalizedForTest(t *testing.T, journal *Journal, deadlines map[string]time.Time) {
	t.Helper()
	tx, err := journal.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for runID, deadline := range deadlines {
		task := fixtureTask(runID, deadline.Add(-30*time.Second))
		if _, err := tx.Exec(`INSERT INTO attempts (run_id, work_id, attempt, lease_token, state, task, deadline_ns, updated_at_ns,
			result_status, result_bytes, result_sha256, ready_at_ns) VALUES (?, ?, 1, '', 'FINALIZED', ?, ?, ?, 'SUCCEEDED', 10, ?, ?)`,
			runID, "work-"+runID, mustJSON(t, task), deadline.UnixNano(), deadline.UnixNano(), make([]byte, 32), deadline.UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestJournalRetentionBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	path := filepath.Join(t.TempDir(), "collector-journal.json")
	journal := openTestJournal(t, path, clock)
	ancient := now.Add(-24 * time.Hour)
	for _, runID := range []string{"old-claimed", "old-started", "old-ready"} {
		lease := fixtureLease(runID, 1, fixtureTokenPrefix+runID, ancient.Add(-30*time.Second))
		if _, _, err := journal.begin(lease); err != nil {
			t.Fatal(err)
		}
		if runID != "old-claimed" {
			if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
				t.Fatal(err)
			}
		}
		if runID == "old-ready" {
			if err := journal.storeResult(lease.Work.Task.RunID, fixtureResult(lease.Work.Task, 2)); err != nil {
				t.Fatal(err)
			}
			if err := journal.discardLease(lease.Work.Task.RunID); err != nil {
				t.Fatal(err)
			}
		}
	}
	boundary := now.Add(-journalReplayGrace)
	afterBoundary := boundary.Add(time.Nanosecond)
	deadlines := map[string]time.Time{"final-boundary": boundary, "final-after-boundary": afterBoundary}
	for index := 0; index < 1100; index++ {
		deadlines[fmt.Sprintf("final-old-%04d", index)] = now.Add(-time.Hour).Add(time.Duration(index) * time.Millisecond)
	}
	insertFinalizedForTest(t, journal, deadlines)

	report, err := journal.Maintain()
	if err != nil {
		t.Fatal(err)
	}
	stats := report.Stats
	if report.PrunedRecords != 1101 || stats.Finalized != 1 || stats.Claimed != 1 || stats.Started != 1 || stats.ResultReady != 1 ||
		stats.LeaseReleased != 1 || !stats.PrunedThrough.Equal(boundary) || stats.PayloadBytes == 0 {
		t.Fatalf("maintenance report = %+v", report)
	}
	if _, ok := journal.entry("final-after-boundary"); !ok {
		t.Fatal("record one nanosecond inside the replay grace was pruned")
	}

	atWatermark := fixtureLease("new-at-watermark", 1, fixtureTokenPrefix+"at", boundary.Add(-30*time.Second))
	if _, _, err := journal.begin(atWatermark); !errors.Is(err, ErrJournalDeliveryRefused) {
		t.Fatalf("delivery at the pruned horizon error = %v", err)
	}
	aboveWatermark := fixtureLease("new-above-watermark", 1, fixtureTokenPrefix+"above", afterBoundary.Add(-30*time.Second))
	if _, _, err := journal.begin(aboveWatermark); err != nil {
		t.Fatalf("delivery above the pruned horizon error = %v", err)
	}
	// Unfinished receipts stay deliverable regardless of their age.
	if entry, existed, err := journal.begin(fixtureLease("old-ready", 2, fixtureTokenPrefix+"old-ready-2", ancient.Add(-30*time.Second))); err != nil || !existed || entry.Result == nil {
		t.Fatalf("aged unacknowledged result redelivery = %+v %v %v", entry, existed, err)
	}

	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestJournal(t, path, clock)
	if stats, err := reopened.Stats(); err != nil || !stats.PrunedThrough.Equal(boundary) {
		t.Fatalf("watermark after restart = %+v %v", stats, err)
	}
	if _, _, err := reopened.begin(fixtureLease("new-after-restart", 1, fixtureTokenPrefix+"restart", boundary.Add(-30*time.Second))); !errors.Is(err, ErrJournalDeliveryRefused) {
		t.Fatalf("pruned horizon was not durable: %v", err)
	}
	clock.Set(now.Add(time.Nanosecond))
	if report, err := reopened.Maintain(); err != nil || report.PrunedRecords != 1 || !report.Stats.PrunedThrough.Equal(afterBoundary) {
		t.Fatalf("second maintenance = %+v %v", report, err)
	}
	// Claimed includes new-above-watermark, begun after the first pruning.
	if stats, _ := reopened.Stats(); stats.Claimed != 2 || stats.Started != 1 || stats.ResultReady != 1 {
		t.Fatalf("unfinished receipts were pruned: %+v", stats)
	}
}

func TestJournalStorageFailuresDoNotAdvanceState(t *testing.T) {
	now := time.Now().UTC()
	clock := liveClock{}
	neverExecute := executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult {
		t.Error("work executed despite a journal failure")
		return domain.CollectionResult{}
	})

	t.Run("failed result write rolls back", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "collector-journal.json")
		journal := openTestJournal(t, path, clock)
		lease := fixtureLease("run-rollback", 1, fixtureTokenPrefix+"rollback", now)
		if _, _, err := journal.begin(lease); err != nil {
			t.Fatal(err)
		}
		if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.db.Exec(`INSERT INTO results (run_id, payload) VALUES (?, x'00')`, "run-rollback"); err != nil {
			t.Fatal(err)
		}
		if err := journal.storeResult(lease.Work.Task.RunID, fixtureResult(lease.Work.Task, 1)); err == nil {
			t.Fatal("conflicting result write succeeded")
		}
		if entry, ok := journal.entry(lease.Work.Task.RunID); !ok || entry.State != journalStarted {
			t.Fatalf("failed transaction advanced state: %+v", entry)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenJournal(path, clock); err == nil || !strings.Contains(err.Error(), "does not match their state") {
			t.Fatalf("inconsistent store opened: %v", err)
		}
	})

	t.Run("corrupted payload is never delivered", func(t *testing.T) {
		journal := openTestJournal(t, filepath.Join(t.TempDir(), "collector-journal.json"), clock)
		lease := fixtureLease("run-corrupt", 1, fixtureTokenPrefix+"corrupt", now)
		if _, _, err := journal.begin(lease); err != nil {
			t.Fatal(err)
		}
		if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
			t.Fatal(err)
		}
		if err := journal.storeResult(lease.Work.Task.RunID, fixtureResult(lease.Work.Task, 1)); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.db.Exec(`UPDATE results SET payload = x'7b7d' WHERE run_id = ?`, "run-corrupt"); err != nil {
			t.Fatal(err)
		}
		client := &fakeControl{}
		err := newJournalTestRuntime(t, client, neverExecute, journal, clock).process(context.Background(), fixtureLease("run-corrupt", 2, fixtureTokenPrefix+"corrupt-2", now))
		if err == nil || !strings.Contains(err.Error(), "integrity") {
			t.Fatalf("corrupted payload error = %v", err)
		}
		var attempt int
		var token string
		if err := journal.db.QueryRow(`SELECT attempt, lease_token FROM attempts WHERE run_id = ?`, "run-corrupt").Scan(&attempt, &token); err != nil || attempt != 1 || token != lease.LeaseToken {
			t.Fatal("failed redelivery changed the stored lease")
		}
		if client.starts != 0 || len(client.uploads) != 0 {
			t.Fatal("corrupted payload was uploaded")
		}
	})

	t.Run("closed store blocks execution and claims", func(t *testing.T) {
		journal := openTestJournal(t, filepath.Join(t.TempDir(), "collector-journal.json"), clock)
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		client := &fakeControl{}
		runtime := newJournalTestRuntime(t, client, neverExecute, journal, clock)
		if err := runtime.process(context.Background(), fixtureLease("run-closed", 1, fixtureTokenPrefix+"closed", now)); err == nil {
			t.Fatal("process succeeded without a journal")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := runtime.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Run error = %v", err)
		}
		if client.starts != 0 || client.claims != 0 || client.heartbeats == 0 {
			t.Fatalf("starts=%d claims=%d heartbeats=%d", client.starts, client.claims, client.heartbeats)
		}
	})

	t.Run("finalization record failure after acknowledgement redelivers", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "collector-journal.json")
		journal := openTestJournal(t, path, clock)
		var executions atomic.Int32
		first := &fakeControl{}
		first.finalize = func() { _ = journal.Close() }
		executor := executorFunc(func(_ context.Context, task domain.CollectionTask) domain.CollectionResult {
			executions.Add(1)
			return fixtureResult(task, 2)
		})
		lease := fixtureLease("run-ack-write", 1, fixtureTokenPrefix+"ack-write", now)
		if err := newJournalTestRuntime(t, first, executor, journal, clock).process(context.Background(), lease); err == nil {
			t.Fatal("finalization record failure was ignored")
		}
		reopened := openTestJournal(t, path, clock)
		if entry, ok := reopened.entry(lease.Work.Task.RunID); !ok || entry.State != journalReady || entry.LeaseToken != lease.LeaseToken {
			t.Fatalf("receipt after failed finalization record = %+v", entry)
		}
		ctx, cancel := context.WithCancel(context.Background())
		second := &fakeControl{finalize: cancel}
		if err := newJournalTestRuntime(t, second, neverExecute, reopened, clock).Run(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v", err)
		}
		if executions.Load() != 1 || second.finalizations != 1 || second.claims != 0 {
			t.Fatalf("executions=%d finalizations=%d claims=%d", executions.Load(), second.finalizations, second.claims)
		}
	})
}

func walFrames(t *testing.T, journal *Journal, mode string) int {
	t.Helper()
	var busy, frames, checkpointed int
	if err := journal.db.QueryRow(`PRAGMA wal_checkpoint(`+mode+`)`).Scan(&busy, &frames, &checkpointed); err != nil || busy != 0 {
		t.Fatalf("checkpoint busy=%d err=%v", busy, err)
	}
	return frames
}

// TestJournalActiveUpdateDoesNotRewriteHistoricalPayloads measures the pages
// each operation appends to the write-ahead log. With the old JSON journal the
// bytes written per update grew with every retained payload.
func TestJournalActiveUpdateDoesNotRewriteHistoricalPayloads(t *testing.T) {
	now := time.Now().UTC()
	historical := fixtureResult(fixtureTask("history-template", now), 700)
	measure := func(t *testing.T, history int) (map[string]int, int64) {
		journal := openTestJournal(t, filepath.Join(t.TempDir(), "collector-journal.json"), liveClock{})
		for index := 0; index < history; index++ {
			lease := fixtureLease(fmt.Sprintf("history-%03d", index), 1, fixtureTokenPrefix+"history", now)
			result := historical
			result.Task = lease.Work.Task
			if _, _, err := journal.begin(lease); err != nil {
				t.Fatal(err)
			}
			if err := journal.markStarted(lease.Work.Task.RunID); err != nil {
				t.Fatal(err)
			}
			if err := journal.storeResult(lease.Work.Task.RunID, result); err != nil {
				t.Fatal(err)
			}
			if err := journal.discardLease(lease.Work.Task.RunID); err != nil {
				t.Fatal(err)
			}
		}
		lease := fixtureLease("active", 1, fixtureTokenPrefix+"active", now)
		frames := make(map[string]int)
		operations := []struct {
			name string
			run  func() error
		}{
			{"begin", func() error { _, _, err := journal.begin(lease); return err }},
			{"mark_started", func() error { return journal.markStarted(lease.Work.Task.RunID) }},
			{"store_result", func() error { return journal.storeResult(lease.Work.Task.RunID, fixtureResult(lease.Work.Task, 4)) }},
			{"mark_finalized", func() error { return journal.markFinalized(lease.Work.Task.RunID) }},
		}
		for _, operation := range operations {
			walFrames(t, journal, "TRUNCATE")
			if err := operation.run(); err != nil {
				t.Fatal(err)
			}
			frames[operation.name] = walFrames(t, journal, "PASSIVE")
		}
		stats, err := journal.Stats()
		if err != nil {
			t.Fatal(err)
		}
		return frames, stats.PayloadBytes
	}
	small, smallBytes := measure(t, 4)
	large, largeBytes := measure(t, 32)
	if largeBytes < 8*smallBytes-1 || largeBytes < 32*200_000 {
		t.Fatalf("historical payload bytes small=%d large=%d", smallBytes, largeBytes)
	}
	for name, frames := range large {
		t.Logf("%s: %d WAL pages with %d KiB history, %d pages with %d KiB history", name, small[name], smallBytes>>10, frames, largeBytes>>10)
		if frames > 12 || frames > small[name]+2 {
			t.Fatalf("%s appended %d pages with 8x history (%d before); update cost depends on history", name, frames, small[name])
		}
	}
}

func TestJournalConcurrentRuntimeOperationsAndMaintenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector-journal.json")
	journal := openTestJournal(t, path, liveClock{})
	base := time.Now().UTC().Add(-3 * time.Minute)
	var sequence atomic.Int64
	var workers sync.WaitGroup
	done := make(chan struct{})
	maintenanceErrors := make(chan error, 1)
	var maintained sync.WaitGroup
	maintained.Add(1)
	go func() {
		defer maintained.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := journal.Maintain(); err != nil {
				maintenanceErrors <- err
				return
			}
		}
	}()
	const goroutines, cycles = 8, 20
	failures := make(chan error, goroutines)
	for worker := 0; worker < goroutines; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for cycle := 0; cycle < cycles; cycle++ {
				// Deadlines increase with every begin, so none precede a watermark
				// raised by concurrently pruned, earlier runs.
				deadline := base.Add(time.Duration(sequence.Add(1)))
				lease := fixtureLease(fmt.Sprintf("concurrent-%d-%d", worker, cycle), 1, fixtureTokenPrefix+"concurrent", deadline.Add(-30*time.Second))
				runID := lease.Work.Task.RunID
				if _, _, err := journal.begin(lease); err != nil {
					failures <- err
					return
				}
				if err := journal.markStarted(runID); err != nil {
					failures <- err
					return
				}
				if err := journal.storeResult(runID, fixtureResult(lease.Work.Task, 2)); err != nil {
					failures <- err
					return
				}
				if _, _, err := journal.pending(); err != nil {
					failures <- err
					return
				}
				if err := journal.markFinalized(runID); err != nil {
					failures <- err
					return
				}
			}
		}(worker)
	}
	workers.Wait()
	close(done)
	maintained.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	select {
	case err := <-maintenanceErrors:
		t.Fatal(err)
	default:
	}
	report, err := journal.Maintain()
	if err != nil {
		t.Fatal(err)
	}
	if stats := report.Stats; stats.Records() != 0 || stats.PayloadBytes != 0 {
		t.Fatalf("records after concurrent finalization and maintenance = %+v", stats)
	}
	if err := verifyJournalDatabase(journal.db, false); err != nil {
		t.Fatal(err)
	}
}

func TestJournalRollbackExportRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	setup := func(t *testing.T) (string, string) {
		directory := t.TempDir()
		path := filepath.Join(directory, "collector-journal.json")
		writeLegacyJournal(t, path, newLegacyFixture(now.Add(-time.Hour)))
		journal, err := OpenJournal(path, clock)
		if err != nil {
			t.Fatal(err)
		}
		backup := filepath.Join(directory, journal.MigrationReport().Backup)
		// New work enters the replacement store after migration.
		finalized := fixtureLease("run-new-finalized", 1, fixtureTokenPrefix+"new-final", now)
		claimed := fixtureLease("run-new-claimed", 1, fixtureTokenPrefix+"new-claimed", now)
		for _, lease := range []domain.WorkLease{finalized, claimed} {
			if _, _, err := journal.begin(lease); err != nil {
				t.Fatal(err)
			}
		}
		if err := journal.markStarted(finalized.Work.Task.RunID); err != nil {
			t.Fatal(err)
		}
		if err := journal.storeResult(finalized.Work.Task.RunID, fixtureResult(finalized.Work.Task, 2)); err != nil {
			t.Fatal(err)
		}
		if err := journal.markFinalized(finalized.Work.Task.RunID); err != nil {
			t.Fatal(err)
		}
		insertFinalizedForTest(t, journal, map[string]time.Time{"run-pruned": now.Add(-time.Hour)})
		if _, err := journal.Maintain(); err != nil {
			t.Fatal(err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		return path, backup
	}
	export := func(t *testing.T, path string) JournalRollbackExport {
		clock.Set(clock.Now().Add(time.Second))
		exported, err := ExportJournalForRollback(path, clock)
		if err != nil {
			t.Fatal(err)
		}
		assertNoFixtureToken(t, fmt.Sprintf("%+v", exported))
		return exported
	}
	watermark := now.Add(-time.Hour)

	t.Run("export is a valid version 1 journal", func(t *testing.T) {
		path, _ := setup(t)
		exported := export(t, path)
		info, err := os.Stat(exported.Path)
		if err != nil || info.Mode().Perm() != 0o600 || fileDigest(t, exported.Path) != exported.SHA256 {
			t.Fatalf("export file = %v err=%v", info, err)
		}
		data, err := os.ReadFile(exported.Path)
		if err != nil {
			t.Fatal(err)
		}
		var old journalFile
		if err := json.Unmarshal(data, &old); err != nil || old.Version != 1 {
			t.Fatalf("version 1 decode = %d %v", old.Version, err)
		}
		// The imported finalized records and run-pruned fall below the replay
		// horizon during setup maintenance; only run-new-finalized remains.
		if exported.Entries != 5 || exported.OmittedCompletionRecords != 1 || !exported.PrunedThrough.Equal(watermark) || len(old.Entries) != 5 {
			t.Fatalf("export = %+v entries=%d", exported, len(old.Entries))
		}
		for _, runID := range []string{"run-claimed", "run-started", "run-ready", "run-ready-released", "run-new-claimed"} {
			if _, ok := old.Entries[runID]; !ok {
				t.Fatalf("export omitted unfinished run %s", runID)
			}
		}
		if ready := old.Entries["run-ready"]; ready.Result == nil || ready.LeaseToken != fixtureTokenPrefix+"ready" {
			t.Fatal("export lost an unacknowledged result or its lease")
		}
		if released := old.Entries["run-ready-released"]; released.Result == nil || released.LeaseToken != "" {
			t.Fatal("export changed a lease-released result")
		}
		if _, ok := old.Entries["run-new-finalized"]; ok {
			t.Fatal("export unexpectedly contains a finalized run")
		}
	})

	t.Run("unapplied export is unsealed on restart", func(t *testing.T) {
		path, _ := setup(t)
		export(t, path)
		journal := openTestJournal(t, path, clock)
		if report := journal.MigrationReport(); report == nil || report.Action != "rollback_export_unsealed" {
			t.Fatalf("report = %+v", report)
		}
		if entry, ok := journal.entry("run-new-claimed"); !ok || entry.LeaseToken != fixtureTokenPrefix+"new-claimed" {
			t.Fatal("unsealed store lost new work")
		}
	})

	t.Run("old snapshot instead of export is refused", func(t *testing.T) {
		path, backup := setup(t)
		export(t, path)
		original, err := os.ReadFile(backup)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenJournal(path, clock); err == nil || !strings.Contains(err.Error(), "lacks unfinished work") {
			t.Fatalf("old snapshot error = %v", err)
		}
		if exists, err := regularJournalFileExists(storePath(path)); err != nil || !exists {
			t.Fatal("refused rollback removed the sealed store")
		}
		assertMissing(t, storePath(path)+".importing")
	})

	t.Run("re-forward keeps legacy progress, completion records and watermark", func(t *testing.T) {
		path, _ := setup(t)
		exported := export(t, path)
		data, err := os.ReadFile(exported.Path)
		if err != nil {
			t.Fatal(err)
		}
		// Simulate the version 1 collector: finalize one result and claim new work.
		var old journalFile
		if err := json.Unmarshal(data, &old); err != nil {
			t.Fatal(err)
		}
		ready := old.Entries["run-ready"]
		ready.State, ready.LeaseToken = journalFinalized, ""
		old.Entries["run-ready"] = ready
		rollbackLease := fixtureLease("run-during-rollback", 1, fixtureTokenPrefix+"rollback", now)
		old.Entries["run-during-rollback"] = journalEntry{WorkID: rollbackLease.Work.WorkID, RunID: rollbackLease.Work.Task.RunID, Attempt: 1, LeaseToken: rollbackLease.LeaseToken, Task: rollbackLease.Work.Task, State: journalClaimed, UpdatedAt: now}
		writeLegacyJournal(t, path, old)

		clock.Set(clock.Now().Add(time.Second))
		journal := openTestJournal(t, path, clock)
		report := journal.MigrationReport()
		if report == nil || report.Action != "rollback_reforwarded" || report.ArchivedStore == "" || report.MergedCompletionRecords != 1 || !report.PrunedThrough.Equal(watermark) {
			t.Fatalf("re-forward report = %+v", report)
		}
		if exists, err := regularJournalFileExists(filepath.Join(filepath.Dir(path), report.ArchivedStore)); err != nil || !exists {
			t.Fatal("sealed store was not archived")
		}
		if entry, ok := journal.entry("run-during-rollback"); !ok || entry.LeaseToken != rollbackLease.LeaseToken {
			t.Fatal("work claimed during rollback was lost")
		}
		if entry, ok := journal.entry("run-ready"); !ok || entry.State != journalFinalized {
			t.Fatal("finalization performed during rollback was lost")
		}
		if _, _, err := journal.begin(fixtureLease("run-new-finalized", 2, fixtureTokenPrefix+"again", now)); !errors.Is(err, ErrJournalDeliveryRefused) {
			t.Fatalf("completion record was not carried across rollback: %v", err)
		}
		if _, _, err := journal.begin(fixtureLease("run-below-watermark", 1, fixtureTokenPrefix+"below", watermark.Add(-30*time.Second))); !errors.Is(err, ErrJournalDeliveryRefused) {
			t.Fatalf("watermark was not carried across rollback: %v", err)
		}
	})
}

func TestJournalStatusIsReadOnlyAndNonSensitive(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "collector-journal.json")
	writeLegacyJournal(t, path, newLegacyFixture(now))
	before := fileDigest(t, path)
	status, err := ReadJournalStatus(path)
	if err != nil || status.LegacyJournal != "legacy_v1" || status.StorePresent || status.Backups != 0 {
		t.Fatalf("pre-migration status = %+v %v", status, err)
	}
	if fileDigest(t, path) != before {
		t.Fatal("status modified the legacy journal")
	}
	assertMissing(t, storePath(path))

	journal := openTestJournal(t, path, testClock{now: now})
	if _, err := journal.Stats(); err != nil {
		t.Fatal(err)
	}
	status, err = ReadJournalStatus(path)
	if err != nil || status.LegacyJournal != "redirect" || !status.StorePresent || !status.StoreLocked || status.Backups != 1 || status.Stats.Records() != 0 {
		t.Fatalf("status beside running journal = %+v %v", status, err)
	}
	if _, err := journal.Stats(); err != nil {
		t.Fatalf("status disturbed the running journal: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	status, err = ReadJournalStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if status.StoreLocked || status.LegacyEntries != 6 || status.Stats.Records() != 6 || status.Stats.ResultReady != 2 ||
		status.Stats.PayloadBytes == 0 || status.Stats.OldestPendingDelivery.IsZero() {
		t.Fatalf("status of stopped journal = %+v", status)
	}
	assertNoFixtureToken(t, string(mustJSON(t, status)))
	assertMissing(t, storePath(path)+"-shm")
}

func TestCheckLegacyJournalValidatesWithoutSideEffects(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	path := filepath.Join(directory, "collector-journal.json")
	original := writeLegacyJournal(t, path, newLegacyFixture(now))
	report, err := CheckLegacyJournal(path, testClock{now: now})
	if err != nil || report.Action != "checked" || report.Entries != 6 || report.ResultReady != 2 || report.Finalized != 2 || report.LegacyBytes != int64(len(original)) {
		t.Fatalf("check report = %+v %v", report, err)
	}
	assertNoFixtureToken(t, fmt.Sprintf("%+v", *report))
	names, err := os.ReadDir(directory)
	if err != nil || len(names) != 1 {
		t.Fatalf("check created files beside the journal: %v %v", names, err)
	}
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, original) {
		t.Fatal("check modified the legacy journal")
	}

	malformed := newLegacyFixture(now)
	entry := malformed.Entries["run-ready"]
	entry.Result = nil
	malformed.Entries["run-ready"] = entry
	writeLegacyJournal(t, path, malformed)
	if _, err := CheckLegacyJournal(path, testClock{now: now}); err == nil || !strings.Contains(err.Error(), "missing its result") {
		t.Fatalf("malformed check error = %v", err)
	} else {
		assertNoFixtureToken(t, err.Error())
	}

	writeLegacyJournal(t, path, newLegacyFixture(now))
	openTestJournal(t, path, testClock{now: now})
	if _, err := CheckLegacyJournal(path, testClock{now: now}); err == nil || !strings.Contains(err.Error(), "no legacy JSON journal") {
		t.Fatalf("check after migration error = %v", err)
	}
}
