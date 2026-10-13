package collectorruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type journalState string

const (
	journalClaimed   journalState = "CLAIMED"
	journalStarted   journalState = "STARTED"
	journalReady     journalState = "RESULT_READY"
	journalFinalized journalState = "FINALIZED"
)

// journalEntry is the logical attempt receipt. Its JSON shape is the version 1
// journal format, which migration imports and rollback export reproduces.
type journalEntry struct {
	WorkID      domain.WorkID                `json:"work_id"`
	RunID       domain.RunID                 `json:"run_id"`
	Attempt     int                          `json:"attempt"`
	LeaseToken  string                       `json:"lease_token"`
	Task        domain.CollectionTask        `json:"task"`
	State       journalState                 `json:"state"`
	Result      *domain.CollectionResult     `json:"result,omitempty"`
	TypedPlan   *domain.CollectionPlan       `json:"typed_plan,omitempty"`
	TypedResult *domain.TypedCollectorResult `json:"typed_result,omitempty"`
	UpdatedAt   time.Time                    `json:"updated_at"`
}

type journalFile struct {
	Version int                     `json:"version"`
	Entries map[string]journalEntry `json:"entries"`
}

const (
	journalSchemaVersion      = 1
	journalStoreFormatVersion = 1
	journalSourceFresh        = "fresh"
	journalSourceLegacy       = "legacy_v1"

	// journalReplayGrace bounds how long a finalized completion record outlives
	// its task deadline. The control plane only delivers work through Claim,
	// whose SQL requires deadline > now and work_expires_at > now, and never
	// reopens terminal work, so no delivery of a run can follow its deadline on
	// the database clock. The grace mirrors the control plane's two-minute
	// collector clock-skew allowance (collectorcontrol.maximumPoPClockSkew). It
	// affects liveness only: begin refuses any unseen run whose deadline is at or
	// below the durable pruning watermark, so a larger skew fails closed.
	journalReplayGrace     = 2 * time.Minute
	journalPruneBatch      = 512
	journalMaxPruneBatches = 64
)

// ErrJournalDeliveryRefused reports delivered work that the journal will not
// execute because doing so could repeat a completed collection.
var ErrJournalDeliveryRefused = errors.New("collector journal refused delivered work")

var errJournalClosed = errors.New("collector journal is closed")

// JournalObserver receives bounded, non-sensitive persistence telemetry.
// Operation names are a fixed set; errors must not be logged verbatim with
// request data because none is included in them.
type JournalObserver interface {
	ObserveJournalOperation(operation string, duration time.Duration, err error)
}

type JournalOption func(*journalSettings)

type journalSettings struct {
	observer JournalObserver
}

func WithJournalObserver(observer JournalObserver) JournalOption {
	return func(settings *journalSettings) { settings.observer = observer }
}

// Journal persists collector attempt receipts in an owner-only SQLite store.
// Each state change is one transaction over one attempt row; result payloads
// live in a separate table so that no update rewrites unrelated payload pages.
// Rows contain live lease tokens, so every journal file is created 0600 and
// nothing in this package formats tokens or payloads into errors.
type Journal struct {
	mu        sync.Mutex
	paths     journalPaths
	clock     Clock
	db        *sql.DB
	lock      *journalLock
	observer  JournalObserver
	migration *JournalMigrationReport
}

type journalPaths struct {
	legacy    string
	store     string
	lock      string
	importing string
	directory string
}

func newJournalPaths(legacy string) (journalPaths, error) {
	cleaned := filepath.Clean(legacy)
	if strings.ContainsRune(cleaned, '?') {
		return journalPaths{}, fmt.Errorf("collector journal path must not contain '?'")
	}
	store := strings.TrimSuffix(cleaned, ".json") + ".sqlite"
	return journalPaths{
		legacy: cleaned, store: store, lock: store + ".lock", importing: store + ".importing",
		directory: filepath.Dir(cleaned),
	}, nil
}

// OpenJournal opens the durable store derived from the configured journal
// path, migrating a version 1 JSON journal at that path first. The JSON path is
// then replaced by a redirect that version 1 collectors refuse to load.
func OpenJournal(path string, clock Clock, options ...JournalOption) (*Journal, error) {
	if path == "" || clock == nil {
		return nil, fmt.Errorf("journal path and clock are required")
	}
	settings := journalSettings{}
	for _, option := range options {
		option(&settings)
	}
	paths, err := newJournalPaths(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(paths.directory, 0o700); err != nil {
		return nil, fmt.Errorf("create collector journal directory: %w", err)
	}
	lock, err := acquireJournalLock(paths.lock)
	if err != nil {
		return nil, err
	}
	migration, err := prepareJournalStore(paths, clock)
	if err != nil {
		_ = lock.release()
		return nil, err
	}
	db, err := openJournalDatabase(paths.store, journalDatabaseReadWrite)
	if err != nil {
		_ = lock.release()
		return nil, err
	}
	if err := verifyJournalDatabase(db, false); err != nil {
		_ = db.Close()
		_ = lock.release()
		return nil, err
	}
	return &Journal{paths: paths, clock: clock, db: db, lock: lock, observer: settings.observer, migration: migration}, nil
}

// MigrationReport describes the store preparation performed by this open, or
// nil when an existing store was opened unchanged.
func (j *Journal) MigrationReport() *JournalMigrationReport {
	if j.migration == nil {
		return nil
	}
	report := *j.migration
	return &report
}

// Close releases the database and the process lock.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var errs []error
	if j.db != nil {
		errs = append(errs, j.db.Close())
		j.db = nil
	}
	if j.lock != nil {
		errs = append(errs, j.lock.release())
		j.lock = nil
	}
	return errors.Join(errs...)
}

type journalDatabaseMode int

const (
	journalDatabaseReadWrite journalDatabaseMode = iota
	journalDatabaseBuild
	journalDatabaseReadOnly
	journalDatabaseStatus
)

// journalConnector applies connection settings in a fixed order on every
// physical connection. DSN _pragma parameters are applied alphabetically,
// which would enter WAL mode before exclusive locking.
type journalConnector struct {
	driver.Connector
	pragmas []string
}

func (c journalConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("collector journal SQLite driver cannot execute statements")
	}
	for _, pragma := range c.pragmas {
		if _, err := execer.ExecContext(ctx, "PRAGMA "+pragma, nil); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("configure collector journal store: %w", err)
		}
	}
	return conn, nil
}

func openJournalDatabase(path string, mode journalDatabaseMode) (*sql.DB, error) {
	if err := restrictJournalDatabaseFiles(path, mode == journalDatabaseReadWrite || mode == journalDatabaseBuild); err != nil {
		return nil, err
	}
	var pragmas []string
	switch mode {
	case journalDatabaseReadWrite:
		// Exclusive locking before WAL keeps the WAL index in process memory:
		// SQLite creates no -shm file, so the store needs no shared memory on the
		// journal's filesystem, and no other process can read or write it while
		// the collector runs. WAL with synchronous=FULL fsyncs every commit;
		// fullfsync only affects Darwin, matching os.File.Sync's F_FULLFSYNC.
		pragmas = []string{"busy_timeout = 5000", "locking_mode = EXCLUSIVE", "journal_mode = WAL", "synchronous = FULL", "fullfsync = 1", "checkpoint_fullfsync = 1", "foreign_keys = 1", "secure_delete = 1", "trusted_schema = 0", "journal_size_limit = 8388608"}
	case journalDatabaseBuild:
		// A build database is discarded unless it completes, is fsynced and is
		// renamed into place, so it needs no rollback journal.
		pragmas = []string{"journal_mode = OFF", "synchronous = OFF", "foreign_keys = 1", "secure_delete = 1", "trusted_schema = 0"}
	case journalDatabaseReadOnly:
		pragmas = []string{"busy_timeout = 5000", "query_only = 1", "trusted_schema = 0"}
	case journalDatabaseStatus:
		pragmas = []string{"busy_timeout = 250", "query_only = 1", "trusted_schema = 0"}
	}
	base, err := sqlite.NewConnector(path)
	if err != nil {
		return nil, fmt.Errorf("open collector journal store: %w", err)
	}
	db := sql.OpenDB(journalConnector{Connector: base, pragmas: pragmas})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open collector journal store: %w", err)
	}
	if mode == journalDatabaseReadWrite {
		var journalMode, lockingMode string
		if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil || !strings.EqualFold(journalMode, "wal") {
			_ = db.Close()
			return nil, fmt.Errorf("collector journal store could not enable write-ahead logging")
		}
		if err := db.QueryRow(`PRAGMA locking_mode`).Scan(&lockingMode); err != nil || !strings.EqualFold(lockingMode, "exclusive") {
			_ = db.Close()
			return nil, fmt.Errorf("collector journal store could not enable exclusive locking")
		}
		if err := restrictJournalDatabaseFiles(path, true); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return db, nil
}

func journalStoreBusy(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	code := sqliteErr.Code() & 0xff
	return code == sqlite3.SQLITE_BUSY || code == sqlite3.SQLITE_LOCKED
}

// restrictJournalDatabaseFiles rejects symlinked or special files and, unless
// the open is read-only, forces owner-only permissions on the database and its
// SQLite sidecars. SQLite creates sidecars with the database file's mode.
func restrictJournalDatabaseFiles(path string, restrict bool) error {
	for _, name := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		info, err := os.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			if name == path {
				return fmt.Errorf("collector journal store does not exist")
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect collector journal store: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("collector journal store files must be regular files")
		}
		if restrict {
			if err := os.Chmod(name, 0o600); err != nil {
				return fmt.Errorf("restrict collector journal store permissions: %w", err)
			}
		}
	}
	return nil
}

var journalSchemaStatements = []string{
	`CREATE TABLE journal_store (
		singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
		format_version INTEGER NOT NULL,
		created_at_ns INTEGER NOT NULL,
		source TEXT NOT NULL CHECK (source IN ('fresh', 'legacy_v1')),
		legacy_sha256 TEXT NOT NULL,
		legacy_bytes INTEGER NOT NULL,
		legacy_entries INTEGER NOT NULL,
		reclaimed_payload_bytes INTEGER NOT NULL,
		pruned_through_deadline_ns INTEGER NOT NULL,
		sealed_at_ns INTEGER NOT NULL,
		sealed_export TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE attempts (
		run_id TEXT PRIMARY KEY NOT NULL,
		work_id TEXT NOT NULL UNIQUE,
		attempt INTEGER NOT NULL CHECK (attempt >= 1),
		lease_token TEXT NOT NULL,
		state TEXT NOT NULL CHECK (state IN ('CLAIMED', 'STARTED', 'RESULT_READY', 'FINALIZED')),
		task BLOB NOT NULL,
		deadline_ns INTEGER NOT NULL,
		updated_at_ns INTEGER NOT NULL,
		result_status TEXT NOT NULL,
		result_bytes INTEGER NOT NULL CHECK (result_bytes >= 0),
		result_sha256 BLOB,
		ready_at_ns INTEGER NOT NULL,
		CHECK (state <> 'FINALIZED' OR lease_token = ''),
		CHECK ((state IN ('CLAIMED', 'STARTED')) = (result_sha256 IS NULL))
	) STRICT`,
	`CREATE TABLE results (
		run_id TEXT PRIMARY KEY NOT NULL REFERENCES attempts(run_id) ON DELETE CASCADE,
		payload BLOB NOT NULL
	) STRICT`,
	`CREATE INDEX attempts_pending_idx ON attempts (updated_at_ns, run_id)
		WHERE state <> 'FINALIZED' AND lease_token <> ''`,
	`CREATE INDEX attempts_finalized_deadline_idx ON attempts (deadline_ns, run_id)
		WHERE state = 'FINALIZED'`,
	`PRAGMA user_version = 1`,
}

type journalQuerier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type journalStoreInfo struct {
	FormatVersion         int
	CreatedAt             time.Time
	Source                string
	LegacySHA256          string
	LegacyBytes           int64
	LegacyEntries         int
	ReclaimedPayloadBytes int64
	PrunedThroughNanos    int64
	SealedAtNanos         int64
	SealedExport          string
}

func (info journalStoreInfo) sealed() bool { return info.SealedAtNanos != 0 }

func readJournalStoreInfo(ctx context.Context, q journalQuerier) (journalStoreInfo, error) {
	var userVersion int
	if err := q.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&userVersion); err != nil {
		return journalStoreInfo{}, fmt.Errorf("read collector journal store schema: %w", err)
	}
	if userVersion != journalSchemaVersion {
		return journalStoreInfo{}, fmt.Errorf("collector journal store schema version %d is not supported by this collector", userVersion)
	}
	var info journalStoreInfo
	var created int64
	err := q.QueryRowContext(ctx, `SELECT format_version, created_at_ns, source, legacy_sha256, legacy_bytes, legacy_entries,
		reclaimed_payload_bytes, pruned_through_deadline_ns, sealed_at_ns, sealed_export FROM journal_store WHERE singleton = 1`).Scan(
		&info.FormatVersion, &created, &info.Source, &info.LegacySHA256, &info.LegacyBytes, &info.LegacyEntries,
		&info.ReclaimedPayloadBytes, &info.PrunedThroughNanos, &info.SealedAtNanos, &info.SealedExport)
	if err != nil {
		return journalStoreInfo{}, fmt.Errorf("read collector journal store metadata: %w", err)
	}
	if info.FormatVersion != journalStoreFormatVersion && info.FormatVersion != 2 {
		return journalStoreInfo{}, fmt.Errorf("collector journal store format version %d is not supported by this collector", info.FormatVersion)
	}
	info.CreatedAt = time.Unix(0, created).UTC()
	return info, nil
}

func verifyJournalDatabase(db *sql.DB, allowSealed bool) error {
	ctx := context.Background()
	info, err := readJournalStoreInfo(ctx, db)
	if err != nil {
		return err
	}
	if info.sealed() && !allowSealed {
		return fmt.Errorf("collector journal store is sealed for rollback")
	}
	var check string
	if err := db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("collector journal store failed its integrity check")
	}
	var inconsistent int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM attempts a LEFT JOIN results r ON r.run_id = a.run_id
		WHERE (a.state = 'RESULT_READY') <> (r.run_id IS NOT NULL)`).Scan(&inconsistent); err != nil {
		return fmt.Errorf("verify collector journal store: %w", err)
	}
	if inconsistent != 0 {
		return fmt.Errorf("collector journal store has %d attempts whose result payload does not match their state", inconsistent)
	}
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("verify collector journal store references: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return fmt.Errorf("collector journal store has orphaned result payloads")
	}
	return rows.Err()
}

const journalAttemptColumns = `run_id, work_id, attempt, lease_token, state, task, updated_at_ns, result_sha256`

type journalAttemptRow struct {
	entry        journalEntry
	resultSHA256 []byte
}

func scanJournalAttempt(scanner interface{ Scan(...any) error }) (journalAttemptRow, error) {
	var runID, workID, token, state string
	var attempt int
	var task, digest []byte
	var updated int64
	if err := scanner.Scan(&runID, &workID, &attempt, &token, &state, &task, &updated, &digest); err != nil {
		return journalAttemptRow{}, err
	}
	row := journalAttemptRow{
		entry: journalEntry{
			WorkID: domain.WorkID(workID), RunID: domain.RunID(runID), Attempt: attempt, LeaseToken: token,
			State: journalState(state), UpdatedAt: time.Unix(0, updated).UTC(),
		},
		resultSHA256: digest,
	}
	if err := json.Unmarshal(task, &row.entry.Task); err != nil {
		return journalAttemptRow{}, fmt.Errorf("decode collector journal task for run %s", runID)
	}
	var typed struct {
		Plan *domain.CollectionPlan `json:"typed_plan"`
	}
	if err := json.Unmarshal(task, &typed); err != nil {
		return journalAttemptRow{}, fmt.Errorf("decode typed journal plan")
	}
	row.entry.TypedPlan = typed.Plan
	return row, nil
}

func loadJournalAttempt(ctx context.Context, q journalQuerier, runID domain.RunID) (journalAttemptRow, bool, error) {
	row, err := scanJournalAttempt(q.QueryRowContext(ctx, `SELECT `+journalAttemptColumns+` FROM attempts WHERE run_id = ?`, string(runID)))
	if errors.Is(err, sql.ErrNoRows) {
		return journalAttemptRow{}, false, nil
	}
	if err != nil {
		return journalAttemptRow{}, false, fmt.Errorf("read collector journal run %s: %w", runID, err)
	}
	return row, true, nil
}

func loadJournalResult(ctx context.Context, q journalQuerier, runID domain.RunID, digest []byte) (*domain.CollectionResult, []byte, error) {
	var payload []byte
	if err := q.QueryRowContext(ctx, `SELECT payload FROM results WHERE run_id = ?`, string(runID)).Scan(&payload); err != nil {
		return nil, nil, fmt.Errorf("read collector journal result for run %s: %w", runID, err)
	}
	actual := sha256.Sum256(payload)
	if !bytes.Equal(actual[:], digest) {
		return nil, nil, fmt.Errorf("collector journal result for run %s failed integrity verification", runID)
	}
	var result domain.CollectionResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return nil, nil, fmt.Errorf("decode collector journal result for run %s", runID)
	}
	return &result, payload, nil
}

func (j *Journal) observe(operation string, started time.Time, err *error) {
	if j.observer != nil {
		j.observer.ObserveJournalOperation(operation, time.Since(started), *err)
	}
}

func (j *Journal) transaction(operation func(context.Context, *sql.Tx) error) error {
	if j.db == nil {
		return errJournalClosed
	}
	ctx := context.Background()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin collector journal transaction: %w", err)
	}
	if err := operation(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collector journal transaction: %w", err)
	}
	return nil
}

func (j *Journal) begin(lease domain.WorkLease) (entry journalEntry, existed bool, err error) {
	return j.beginEntry(lease, nil)
}

func (j *Journal) beginEntry(lease domain.WorkLease, plan *domain.CollectionPlan) (entry journalEntry, existed bool, err error) {
	defer j.observe("begin", time.Now(), &err)
	j.mu.Lock()
	defer j.mu.Unlock()
	runID := lease.Work.Task.RunID
	now := j.clock.Now().UTC()
	err = j.transaction(func(ctx context.Context, tx *sql.Tx) error {
		current, found, err := loadJournalAttempt(ctx, tx, runID)
		if err != nil {
			return err
		}
		if found {
			existed = true
			if current.entry.WorkID != lease.Work.WorkID {
				return fmt.Errorf("run %s was delivered with a different work identifier", runID)
			}
			actual, _ := json.Marshal(current.entry.TypedPlan)
			expected, _ := json.Marshal(plan)
			if !bytes.Equal(actual, expected) {
				return fmt.Errorf("collector journal plan changed")
			}
			if current.entry.State == journalFinalized {
				return fmt.Errorf("%w: run %s was already finalized", ErrJournalDeliveryRefused, runID)
			}
			if current.entry.State == journalReady {
				if plan == nil {
					result, _, err := loadJournalResult(ctx, tx, runID, current.resultSHA256)
					if err != nil {
						return err
					}
					current.entry.Result = result
				} else {
					result, err := loadJournalTypedResult(ctx, tx, runID, current.resultSHA256)
					if err != nil {
						return err
					}
					if result.Attempt != lease.Attempt {
						result.Attempt = lease.Attempt
						payload, err := domain.EncodeTypedCollectorResult(*result)
						if err != nil {
							return fmt.Errorf("invalid typed journal result")
						}
						digest := sha256.Sum256(payload)
						if _, err := tx.ExecContext(ctx, `UPDATE results SET payload=? WHERE run_id=?`, payload, string(runID)); err != nil {
							return err
						}
						if _, err := tx.ExecContext(ctx, `UPDATE attempts SET result_bytes=?, result_sha256=? WHERE run_id=?`, len(payload), digest[:], string(runID)); err != nil {
							return err
						}
					}
					current.entry.TypedResult = result
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE attempts SET attempt = ?, lease_token = ?, updated_at_ns = ? WHERE run_id = ?`,
				lease.Attempt, lease.LeaseToken, now.UnixNano(), string(runID)); err != nil {
				return fmt.Errorf("record collector journal lease for run %s: %w", runID, err)
			}
			current.entry.Attempt, current.entry.LeaseToken, current.entry.UpdatedAt = lease.Attempt, lease.LeaseToken, now
			entry = current.entry
			return nil
		}
		var otherRun string
		err = tx.QueryRowContext(ctx, `SELECT run_id FROM attempts WHERE work_id = ?`, string(lease.Work.WorkID)).Scan(&otherRun)
		if err == nil {
			return fmt.Errorf("work %s was delivered with a different run identifier", lease.Work.WorkID)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read collector journal work %s: %w", lease.Work.WorkID, err)
		}
		var prunedThrough int64
		if err := tx.QueryRowContext(ctx, `SELECT pruned_through_deadline_ns FROM journal_store WHERE singleton = 1`).Scan(&prunedThrough); err != nil {
			return fmt.Errorf("read collector journal retention watermark: %w", err)
		}
		if lease.Work.Task.Deadline.UnixNano() <= prunedThrough {
			return fmt.Errorf("%w: run %s deadline is not after the pruned completion-record horizon", ErrJournalDeliveryRefused, runID)
		}
		if plan != nil {
			// Older binaries reject this format before reading any receipt. v1
			// journals retain format 1 until their first typed claim is durable.
			if _, err := tx.ExecContext(ctx, `UPDATE journal_store SET format_version=2 WHERE singleton=1`); err != nil {
				return err
			}
		}
		task, err := json.Marshal(struct {
			domain.CollectionTask
			TypedPlan *domain.CollectionPlan `json:"typed_plan,omitempty"`
		}{lease.Work.Task, plan})
		if err != nil {
			return fmt.Errorf("encode collector journal task for run %s", runID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO attempts (run_id, work_id, attempt, lease_token, state, task, deadline_ns,
			updated_at_ns, result_status, result_bytes, result_sha256, ready_at_ns) VALUES (?, ?, ?, ?, 'CLAIMED', ?, ?, ?, '', 0, NULL, 0)`,
			string(runID), string(lease.Work.WorkID), lease.Attempt, lease.LeaseToken, task, lease.Work.Task.Deadline.UnixNano(), now.UnixNano()); err != nil {
			return fmt.Errorf("record collector journal receipt for run %s: %w", runID, err)
		}
		entry = journalEntry{
			WorkID: lease.Work.WorkID, RunID: runID, Attempt: lease.Attempt, LeaseToken: lease.LeaseToken,
			Task: lease.Work.Task, TypedPlan: plan, State: journalClaimed, UpdatedAt: now,
		}
		return nil
	})
	if err != nil {
		return journalEntry{}, existed, err
	}
	return entry, existed, nil
}

// pending returns one unfinished receipt that still holds a lease. It does not
// load result payloads; process reloads the receipt through begin.
func (j *Journal) pending() (entry journalEntry, found bool, err error) {
	defer j.observe("pending", time.Now(), &err)
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.db == nil {
		return journalEntry{}, false, errJournalClosed
	}
	row, err := scanJournalAttempt(j.db.QueryRowContext(context.Background(), `SELECT `+journalAttemptColumns+` FROM attempts
		WHERE state <> 'FINALIZED' AND lease_token <> '' ORDER BY updated_at_ns, run_id LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return journalEntry{}, false, nil
	}
	if err != nil {
		return journalEntry{}, false, fmt.Errorf("read pending collector journal receipt: %w", err)
	}
	return row.entry, true, nil
}

func (j *Journal) discardLease(runID domain.RunID) (err error) {
	defer j.observe("discard_lease", time.Now(), &err)
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.transaction(func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE attempts SET lease_token = '', updated_at_ns = ? WHERE run_id = ?`,
			j.clock.Now().UTC().UnixNano(), string(runID)); err != nil {
			return fmt.Errorf("discard collector journal lease for run %s: %w", runID, err)
		}
		return nil
	})
}

func (j *Journal) markStarted(runID domain.RunID) (err error) {
	defer j.observe("mark_started", time.Now(), &err)
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.transaction(func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE attempts SET state = 'STARTED', updated_at_ns = ? WHERE run_id = ? AND state = 'CLAIMED'`,
			j.clock.Now().UTC().UnixNano(), string(runID))
		if err != nil {
			return fmt.Errorf("mark collector journal run %s started: %w", runID, err)
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return fmt.Errorf("collector journal run %s is not claimed", runID)
		}
		return nil
	})
}

func (j *Journal) storeResult(runID domain.RunID, result domain.CollectionResult) (err error) {
	defer j.observe("store_result", time.Now(), &err)
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode collector journal result for run %s", runID)
	}
	return j.storeResultPayload(runID, result.Status, payload)
}

func (j *Journal) storeResultPayload(runID domain.RunID, status domain.ResultStatus, payload []byte) error {
	digest := sha256.Sum256(payload)
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.clock.Now().UTC().UnixNano()
	return j.transaction(func(ctx context.Context, tx *sql.Tx) error {
		changed, err := tx.ExecContext(ctx, `UPDATE attempts SET state = 'RESULT_READY', result_status = ?, result_bytes = ?,
			result_sha256 = ?, ready_at_ns = ?, updated_at_ns = ? WHERE run_id = ? AND state IN ('CLAIMED', 'STARTED')`,
			string(status), len(payload), digest[:], now, now, string(runID))
		if err != nil {
			return fmt.Errorf("record collector journal result for run %s: %w", runID, err)
		}
		if count, err := changed.RowsAffected(); err != nil || count != 1 {
			if _, found, loadErr := loadJournalAttempt(ctx, tx, runID); loadErr != nil || !found {
				return fmt.Errorf("collector journal has no receipt for run %s", runID)
			}
			return fmt.Errorf("collector journal run %s already has a result", runID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO results (run_id, payload) VALUES (?, ?)`, string(runID), payload); err != nil {
			return fmt.Errorf("record collector journal result payload for run %s: %w", runID, err)
		}
		return nil
	})
}

// markFinalized records the control plane's durable finalization and, in the
// same transaction, reclaims the result payload. The compact attempt row stays
// until retention proves no later delivery of the run is possible.
func (j *Journal) markFinalized(runID domain.RunID) (err error) {
	defer j.observe("mark_finalized", time.Now(), &err)
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.transaction(func(ctx context.Context, tx *sql.Tx) error {
		current, found, err := loadJournalAttempt(ctx, tx, runID)
		if err != nil {
			return err
		}
		if found && current.entry.State == journalFinalized {
			return nil
		}
		if !found || current.entry.State != journalReady {
			return fmt.Errorf("collector journal has no result for run %s", runID)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE attempts SET state = 'FINALIZED', lease_token = '', updated_at_ns = ? WHERE run_id = ?`,
			j.clock.Now().UTC().UnixNano(), string(runID)); err != nil {
			return fmt.Errorf("finalize collector journal run %s: %w", runID, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM results WHERE run_id = ?`, string(runID)); err != nil {
			return fmt.Errorf("reclaim collector journal result for run %s: %w", runID, err)
		}
		return nil
	})
}

func (j *Journal) entry(runID domain.RunID) (journalEntry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.db == nil {
		return journalEntry{}, false
	}
	ctx := context.Background()
	row, found, err := loadJournalAttempt(ctx, j.db, runID)
	if err != nil || !found {
		return journalEntry{}, false
	}
	if row.entry.State == journalReady {
		result, _, err := loadJournalResult(ctx, j.db, runID, row.resultSHA256)
		if err != nil {
			return journalEntry{}, false
		}
		row.entry.Result = result
	}
	return row.entry, true
}

// JournalStats is a bounded, non-sensitive summary of retained state.
type JournalStats struct {
	Claimed                   int
	Started                   int
	ResultReady               int
	Finalized                 int
	LeaseReleased             int
	PayloadBytes              int64
	OldestPendingDelivery     time.Time
	OldestLeaseReleasedResult time.Time
	PrunedThrough             time.Time
	Sealed                    bool
}

func (stats JournalStats) Records() int {
	return stats.Claimed + stats.Started + stats.ResultReady + stats.Finalized
}

func queryJournalStats(ctx context.Context, q journalQuerier) (JournalStats, error) {
	info, err := readJournalStoreInfo(ctx, q)
	if err != nil {
		return JournalStats{}, err
	}
	stats := JournalStats{Sealed: info.sealed()}
	if info.PrunedThroughNanos > 0 {
		stats.PrunedThrough = time.Unix(0, info.PrunedThroughNanos).UTC()
	}
	rows, err := q.QueryContext(ctx, `SELECT state, lease_token <> '', count(*),
		coalesce(sum(CASE WHEN state = 'RESULT_READY' THEN result_bytes ELSE 0 END), 0),
		coalesce(min(CASE WHEN state = 'RESULT_READY' THEN ready_at_ns END), 0)
		FROM attempts GROUP BY state, lease_token <> ''`)
	if err != nil {
		return JournalStats{}, fmt.Errorf("summarize collector journal: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var leased bool
		var count int
		var payloadBytes, oldestReady int64
		if err := rows.Scan(&state, &leased, &count, &payloadBytes, &oldestReady); err != nil {
			return JournalStats{}, fmt.Errorf("summarize collector journal: %w", err)
		}
		switch journalState(state) {
		case journalClaimed:
			stats.Claimed += count
		case journalStarted:
			stats.Started += count
		case journalReady:
			stats.ResultReady += count
			stats.PayloadBytes += payloadBytes
			oldest := time.Unix(0, oldestReady).UTC()
			if leased && (stats.OldestPendingDelivery.IsZero() || oldest.Before(stats.OldestPendingDelivery)) {
				stats.OldestPendingDelivery = oldest
			}
			if !leased && (stats.OldestLeaseReleasedResult.IsZero() || oldest.Before(stats.OldestLeaseReleasedResult)) {
				stats.OldestLeaseReleasedResult = oldest
			}
		case journalFinalized:
			stats.Finalized += count
		}
		if !leased && journalState(state) != journalFinalized {
			stats.LeaseReleased += count
		}
	}
	return stats, rows.Err()
}

func (j *Journal) Stats() (stats JournalStats, err error) {
	defer j.observe("stats", time.Now(), &err)
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.db == nil {
		return JournalStats{}, errJournalClosed
	}
	return queryJournalStats(context.Background(), j.db)
}

type JournalMaintenanceReport struct {
	PrunedRecords int
	Stats         JournalStats
}

// Maintain deletes finalized completion records whose task deadline is older
// than the replay grace, in bounded batches, raising the durable watermark in
// the same transaction as each deletion. Unfinished receipts and unacknowledged
// results are never deleted.
func (j *Journal) Maintain() (report JournalMaintenanceReport, err error) {
	defer j.observe("maintain", time.Now(), &err)
	cutoff := j.clock.Now().UTC().Add(-journalReplayGrace).UnixNano()
	for batch := 0; batch < journalMaxPruneBatches; batch++ {
		pruned, err := j.pruneBatch(cutoff)
		report.PrunedRecords += pruned
		if err != nil {
			return report, err
		}
		if pruned < journalPruneBatch {
			break
		}
	}
	report.Stats, err = j.Stats()
	return report, err
}

func (j *Journal) pruneBatch(cutoff int64) (pruned int, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	err = j.transaction(func(ctx context.Context, tx *sql.Tx) error {
		const selection = `SELECT run_id, deadline_ns FROM attempts WHERE state = 'FINALIZED' AND deadline_ns <= ?
			ORDER BY deadline_ns, run_id LIMIT ?`
		var maximum int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*), coalesce(max(deadline_ns), 0) FROM (`+selection+`)`, cutoff, journalPruneBatch).Scan(&pruned, &maximum); err != nil {
			return fmt.Errorf("select expired collector journal completion records: %w", err)
		}
		if pruned == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE journal_store SET pruned_through_deadline_ns = max(pruned_through_deadline_ns, ?) WHERE singleton = 1`, maximum); err != nil {
			return fmt.Errorf("advance collector journal retention watermark: %w", err)
		}
		deleted, err := tx.ExecContext(ctx, `DELETE FROM attempts WHERE run_id IN (SELECT run_id FROM (`+selection+`))`, cutoff, journalPruneBatch)
		if err != nil {
			return fmt.Errorf("delete expired collector journal completion records: %w", err)
		}
		if count, err := deleted.RowsAffected(); err != nil || int(count) != pruned {
			return fmt.Errorf("collector journal retention deleted an unexpected number of records")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return pruned, nil
}

// RunJournalMaintenance runs Maintain immediately and then on every interval
// until the context ends, reporting each outcome to observe.
func RunJournalMaintenance(ctx context.Context, journal *Journal, interval time.Duration, observe func(JournalMaintenanceReport, error)) error {
	if journal == nil || interval <= 0 || observe == nil {
		return fmt.Errorf("journal maintenance requires a journal, positive interval, and observer")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		report, err := journal.Maintain()
		observe(report, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
