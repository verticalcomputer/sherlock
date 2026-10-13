package collectorruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"golang.org/x/sys/unix"
)

const (
	// journalRedirectVersion replaces a migrated version 1 journal. Version 1
	// collectors decode it and exit with "unsupported collector journal version".
	journalRedirectVersion  = 2
	journalRedirectFormat   = "sherlock-collector-journal-redirect"
	journalRedirectMaxBytes = 4096
	journalBackupInfix      = ".v1-backup-"
	journalRollbackInfix    = ".rollback-v1-"
	journalSealedInfix      = ".sealed-"
	journalFileTimeLayout   = "20060102T150405.000000000Z"
)

// journalMigrationFault lets tests stop preparation at durable boundaries.
var journalMigrationFault func(stage string) error

func journalFault(stage string) error {
	if journalMigrationFault == nil {
		return nil
	}
	return journalMigrationFault(stage)
}

// JournalMigrationReport is a non-sensitive account of store preparation.
type JournalMigrationReport struct {
	Action                      string
	LegacyBytes                 int64
	LegacySHA256                string
	Backup                      string
	ArchivedStore               string
	Entries                     int
	Claimed                     int
	Started                     int
	ResultReady                 int
	Finalized                   int
	LeaseReleased               int
	FinalizedLeaseTokensCleared int
	RetainedPayloadBytes        int64
	ReclaimedPayloadBytes       int64
	MergedCompletionRecords     int
	PrunedThrough               time.Time
	Duration                    time.Duration
}

type legacyJournalKind int

const (
	legacyJournalMissing legacyJournalKind = iota
	legacyJournalRedirect
	legacyJournalPresent
)

func (kind legacyJournalKind) String() string {
	switch kind {
	case legacyJournalRedirect:
		return "redirect"
	case legacyJournalPresent:
		return "legacy_v1"
	default:
		return "missing"
	}
}

type journalRedirect struct {
	Version int                        `json:"version"`
	Entries map[string]json.RawMessage `json:"entries"`
	Format  string                     `json:"format"`
	Store   string                     `json:"store"`
}

func classifyLegacyJournal(paths journalPaths) (legacyJournalKind, int64, error) {
	info, err := os.Lstat(paths.legacy)
	if errors.Is(err, fs.ErrNotExist) {
		return legacyJournalMissing, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("inspect collector journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return 0, 0, fmt.Errorf("collector journal must be a regular file")
	}
	if info.Size() > journalRedirectMaxBytes {
		return legacyJournalPresent, info.Size(), nil
	}
	data, err := os.ReadFile(paths.legacy)
	if err != nil {
		return 0, 0, fmt.Errorf("read collector journal: %w", err)
	}
	var redirect journalRedirect
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&redirect) != nil || redirect.Format != journalRedirectFormat || !jsonAtEOF(decoder) {
		return legacyJournalPresent, info.Size(), nil
	}
	if redirect.Version != journalRedirectVersion || len(redirect.Entries) != 0 || redirect.Store != filepath.Base(paths.store) {
		return 0, 0, fmt.Errorf("collector journal redirect does not name this collector's store")
	}
	return legacyJournalRedirect, info.Size(), nil
}

func jsonAtEOF(decoder *json.Decoder) bool {
	_, err := decoder.Token()
	return err == io.EOF
}

func writeJournalRedirect(paths journalPaths) error {
	data, err := json.Marshal(journalRedirect{
		Version: journalRedirectVersion, Entries: map[string]json.RawMessage{}, Format: journalRedirectFormat,
		Store: filepath.Base(paths.store),
	})
	if err != nil {
		return fmt.Errorf("encode collector journal redirect: %w", err)
	}
	return writeFileAtomically(paths.legacy, data)
}

func writeFileAtomically(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".collector-journal-*")
	if err != nil {
		return fmt.Errorf("create collector journal temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("restrict collector journal temporary file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write collector journal file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync collector journal file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close collector journal file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace collector journal file: %w", err)
	}
	return syncJournalDirectory(directory)
}

func syncJournalDirectory(directory string) error {
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open collector journal directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync collector journal directory: %w", err)
	}
	return nil
}

func syncJournalFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open collector journal file for sync: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync collector journal file: %w", err)
	}
	return nil
}

func regularJournalFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect collector journal file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("collector journal files must be regular files")
	}
	return true, nil
}

func digestJournalFile(path string) (string, int64, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, fmt.Errorf("open collector journal for digest: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, fmt.Errorf("digest collector journal: %w", err)
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func removeInterruptedJournalImport(paths journalPaths) error {
	for _, name := range []string{paths.importing, paths.importing + "-journal", paths.importing + "-wal", paths.importing + "-shm"} {
		if err := os.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove interrupted collector journal import: %w", err)
		}
	}
	return nil
}

// journalArtifacts lists backups and sealed stores that prove prior journal
// state existed for this path.
func journalArtifacts(paths journalPaths) (backups, sealed []string, err error) {
	entries, err := os.ReadDir(paths.directory)
	if err != nil {
		return nil, nil, fmt.Errorf("list collector journal directory: %w", err)
	}
	backupPrefix := filepath.Base(paths.legacy) + journalBackupInfix
	sealedPrefix := filepath.Base(paths.store) + journalSealedInfix
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, backupPrefix):
			backups = append(backups, filepath.Join(paths.directory, name))
		case strings.HasPrefix(name, sealedPrefix) && !strings.HasSuffix(name, "-wal") && !strings.HasSuffix(name, "-shm") && !strings.HasSuffix(name, "-journal"):
			sealed = append(sealed, filepath.Join(paths.directory, name))
		}
	}
	sort.Strings(backups)
	sort.Strings(sealed)
	return backups, sealed, nil
}

// prepareJournalStore resolves the durable state at the configured path under
// the journal lock. Every branch either leaves a complete store plus redirect
// or fails without deleting state. See docs/COLLECTOR_JOURNAL_STORAGE.md.
func prepareJournalStore(paths journalPaths, clock Clock) (*JournalMigrationReport, error) {
	if err := removeInterruptedJournalImport(paths); err != nil {
		return nil, err
	}
	legacy, _, err := classifyLegacyJournal(paths)
	if err != nil {
		return nil, err
	}
	storeExists, err := regularJournalFileExists(paths.store)
	if err != nil {
		return nil, err
	}
	if !storeExists {
		switch legacy {
		case legacyJournalRedirect:
			return nil, errors.New("collector journal was migrated but its store is missing; refusing to start without completion records")
		case legacyJournalMissing:
			backups, sealed, err := journalArtifacts(paths)
			if err != nil {
				return nil, err
			}
			if len(backups) > 0 || len(sealed) > 0 {
				return nil, errors.New("collector journal backups or sealed stores exist but the journal and its store are missing; refusing to start without completion records")
			}
			started := time.Now()
			if err := buildJournalStore(paths, clock, nil, nil); err != nil {
				return nil, err
			}
			if err := writeJournalRedirect(paths); err != nil {
				return nil, err
			}
			return &JournalMigrationReport{Action: "created", Duration: time.Since(started)}, nil
		default:
			return migrateLegacyJournal(paths, clock, false)
		}
	}
	info, err := inspectJournalStore(paths.store)
	if err != nil {
		return nil, err
	}
	if info.sealed() {
		if legacy == legacyJournalPresent {
			return migrateLegacyJournal(paths, clock, true)
		}
		// Nothing else can write while the redirect is in place, so an export
		// that was never applied leaves the sealed store authoritative.
		if err := unsealJournalStore(paths.store); err != nil {
			return nil, err
		}
		if legacy == legacyJournalMissing {
			if err := writeJournalRedirect(paths); err != nil {
				return nil, err
			}
		}
		return &JournalMigrationReport{Action: "rollback_export_unsealed"}, nil
	}
	switch legacy {
	case legacyJournalRedirect:
		return nil, nil
	case legacyJournalMissing:
		if err := writeJournalRedirect(paths); err != nil {
			return nil, err
		}
		return &JournalMigrationReport{Action: "redirect_restored"}, nil
	}
	digest, size, err := digestJournalFile(paths.legacy)
	if err != nil {
		return nil, err
	}
	if info.Source == journalSourceLegacy && digest == info.LegacySHA256 && size == info.LegacyBytes {
		if err := writeJournalRedirect(paths); err != nil {
			return nil, err
		}
		return &JournalMigrationReport{Action: "migration_completed", LegacySHA256: digest, LegacyBytes: size}, nil
	}
	return nil, errors.New("collector journal store and a different legacy JSON journal both exist; an older collector may have written the JSON journal after migration without a rollback export. Refusing to choose between them; follow the recovery procedure in docs/COLLECTOR_JOURNAL_STORAGE.md")
}

func inspectJournalStore(path string) (journalStoreInfo, error) {
	db, err := openJournalDatabase(path, journalDatabaseReadOnly)
	if err != nil {
		return journalStoreInfo{}, err
	}
	defer db.Close()
	return readJournalStoreInfo(context.Background(), db)
}

func unsealJournalStore(path string) error {
	db, err := openJournalDatabase(path, journalDatabaseReadWrite)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE journal_store SET sealed_at_ns = 0, sealed_export = '' WHERE singleton = 1`); err != nil {
		return fmt.Errorf("unseal collector journal store: %w", err)
	}
	return db.Close()
}

type legacyJournalSource struct {
	path   string
	sha256 string
	bytes  int64
}

type journalBuildInput struct {
	legacy *legacyJournalSource
	// carry lists stores whose finalized completion records and retention
	// watermark must survive a rollback round trip.
	carry []string
	// requireUnfinishedFrom names the sealed store whose unfinished receipts
	// must all appear in the imported journal.
	requireUnfinishedFrom string
	report                *JournalMigrationReport
}

func migrateLegacyJournal(paths journalPaths, clock Clock, sealedStore bool) (*JournalMigrationReport, error) {
	started := time.Now()
	digest, size, err := digestJournalFile(paths.legacy)
	if err != nil {
		return nil, err
	}
	backup, err := preserveLegacyJournalBackup(paths, digest)
	if err != nil {
		return nil, err
	}
	if err := journalFault("after_backup"); err != nil {
		return nil, err
	}
	_, archives, err := journalArtifacts(paths)
	if err != nil {
		return nil, err
	}
	report := &JournalMigrationReport{Action: "migrated", LegacyBytes: size, LegacySHA256: digest, Backup: filepath.Base(backup)}
	input := &journalBuildInput{legacy: &legacyJournalSource{path: backup, sha256: digest, bytes: size}, carry: archives, report: report}
	if len(archives) > 0 {
		input.requireUnfinishedFrom = archives[len(archives)-1]
		report.Action = "rollback_reforwarded"
	}
	if sealedStore {
		input.carry = append(input.carry, paths.store)
		input.requireUnfinishedFrom = paths.store
		report.Action = "rollback_reforwarded"
	}
	beforeRename := func() error {
		unchanged, err := legacyJournalUnchanged(paths.legacy, backup, digest)
		if err != nil {
			return err
		}
		if !unchanged {
			return errors.New("legacy collector journal changed during migration; stop every collector process using this journal and retry")
		}
		if sealedStore {
			archive := paths.store + journalSealedInfix + clock.Now().UTC().Format(journalFileTimeLayout)
			if err := archiveSealedJournalStore(paths.store, archive); err != nil {
				return err
			}
			report.ArchivedStore = filepath.Base(archive)
		}
		return journalFault("before_store_rename")
	}
	if err := buildJournalStore(paths, clock, input, beforeRename); err != nil {
		return nil, err
	}
	if err := journalFault("after_store_rename"); err != nil {
		return nil, err
	}
	if err := writeJournalRedirect(paths); err != nil {
		return nil, err
	}
	report.Duration = time.Since(started)
	return report, nil
}

// preserveLegacyJournalBackup keeps the exact bytes being imported under a
// digest-derived name. A hard link costs no space and survives the redirect
// replacing the original name; copying is the fallback.
func preserveLegacyJournalBackup(paths journalPaths, digest string) (string, error) {
	backup := paths.legacy + journalBackupInfix + digest[:16]
	exists, err := regularJournalFileExists(backup)
	if err != nil {
		return "", err
	}
	if exists {
		unchanged, err := legacyJournalUnchanged(paths.legacy, backup, digest)
		if err != nil {
			return "", err
		}
		if !unchanged {
			return "", errors.New("existing legacy collector journal backup does not match the journal; refusing to replace it")
		}
	} else {
		if err := os.Link(paths.legacy, backup); err != nil {
			if err := copyJournalFileDurably(paths.legacy, backup); err != nil {
				return "", err
			}
		}
		if err := syncJournalDirectory(paths.directory); err != nil {
			return "", err
		}
	}
	if err := os.Chmod(backup, 0o600); err != nil {
		return "", fmt.Errorf("restrict legacy collector journal backup: %w", err)
	}
	backupDigest, _, err := digestJournalFile(backup)
	if err != nil {
		return "", err
	}
	if backupDigest != digest {
		return "", errors.New("legacy collector journal backup does not match the journal digest")
	}
	return backup, nil
}

func legacyJournalUnchanged(legacy, backup, digest string) (bool, error) {
	legacyInfo, err := os.Lstat(legacy)
	if err != nil {
		return false, fmt.Errorf("inspect legacy collector journal: %w", err)
	}
	backupInfo, err := os.Lstat(backup)
	if err != nil {
		return false, fmt.Errorf("inspect legacy collector journal backup: %w", err)
	}
	if os.SameFile(legacyInfo, backupInfo) {
		return true, nil
	}
	current, _, err := digestJournalFile(legacy)
	if err != nil {
		return false, err
	}
	return current == digest, nil
}

func copyJournalFileDurably(source, destination string) error {
	input, err := os.OpenFile(source, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open legacy collector journal for backup: %w", err)
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".collector-journal-backup-*")
	if err != nil {
		return fmt.Errorf("create legacy collector journal backup: %w", err)
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("restrict legacy collector journal backup: %w", err)
	}
	if _, err := io.Copy(temporary, input); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("copy legacy collector journal backup: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync legacy collector journal backup: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close legacy collector journal backup: %w", err)
	}
	if err := os.Link(name, destination); err != nil {
		return fmt.Errorf("install legacy collector journal backup: %w", err)
	}
	return nil
}

func archiveSealedJournalStore(store, archive string) error {
	for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
		if exists, err := regularJournalFileExists(store + sidecar); err != nil || exists {
			return errors.New("sealed collector journal store has an active SQLite sidecar; refusing to archive it")
		}
	}
	if exists, err := regularJournalFileExists(archive); err != nil || exists {
		return errors.New("sealed collector journal archive name is already in use")
	}
	if err := os.Rename(store, archive); err != nil {
		return fmt.Errorf("archive sealed collector journal store: %w", err)
	}
	return syncJournalDirectory(filepath.Dir(store))
}

// buildJournalStore creates a complete store at the import path and renames it
// into place only after commit, integrity check and fsync. A crash at any
// earlier point leaves no store, and the next start discards the partial file.
func buildJournalStore(paths journalPaths, clock Clock, input *journalBuildInput, beforeRename func() error) (err error) {
	file, err := os.OpenFile(paths.importing, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create collector journal store: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("create collector journal store: %w", err)
	}
	defer func() {
		if err != nil {
			_ = removeInterruptedJournalImport(paths)
		}
	}()
	db, err := openJournalDatabase(paths.importing, journalDatabaseBuild)
	if err != nil {
		return err
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	ctx := context.Background()
	for _, statement := range journalSchemaStatements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create collector journal schema: %w", err)
		}
	}
	info := journalStoreInfo{FormatVersion: journalStoreFormatVersion, CreatedAt: clock.Now().UTC(), Source: journalSourceFresh}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin collector journal import: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if input != nil {
		if input.legacy != nil {
			if err := importLegacyJournal(ctx, tx, *input.legacy, input.report); err != nil {
				return err
			}
			info.Source, info.LegacySHA256, info.LegacyBytes = journalSourceLegacy, input.report.LegacySHA256, input.report.LegacyBytes
			info.LegacyEntries, info.ReclaimedPayloadBytes = input.report.Entries, input.report.ReclaimedPayloadBytes
		}
		prunedThrough, err := mergeJournalCompletionRecords(ctx, tx, input.carry, input.report)
		if err != nil {
			return err
		}
		info.PrunedThroughNanos = prunedThrough
		if prunedThrough > 0 {
			input.report.PrunedThrough = time.Unix(0, prunedThrough).UTC()
		}
		if input.requireUnfinishedFrom != "" {
			if err := requireUnfinishedJournalWork(ctx, tx, input.requireUnfinishedFrom); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO journal_store (singleton, format_version, created_at_ns, source, legacy_sha256,
		legacy_bytes, legacy_entries, reclaimed_payload_bytes, pruned_through_deadline_ns, sealed_at_ns, sealed_export)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, '')`,
		info.FormatVersion, info.CreatedAt.UnixNano(), info.Source, info.LegacySHA256, info.LegacyBytes, info.LegacyEntries,
		info.ReclaimedPayloadBytes, info.PrunedThroughNanos); err != nil {
		return fmt.Errorf("record collector journal store metadata: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collector journal import: %w", err)
	}
	if err := verifyJournalDatabase(db, false); err != nil {
		return err
	}
	closeErr := db.Close()
	db = nil
	if closeErr != nil {
		return fmt.Errorf("close collector journal import: %w", closeErr)
	}
	if err := syncJournalFile(paths.importing); err != nil {
		return err
	}
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			return err
		}
	}
	if err := os.Rename(paths.importing, paths.store); err != nil {
		return fmt.Errorf("install collector journal store: %w", err)
	}
	return syncJournalDirectory(paths.directory)
}

type legacyJournalEntry struct {
	WorkID     domain.WorkID         `json:"work_id"`
	RunID      domain.RunID          `json:"run_id"`
	Attempt    int                   `json:"attempt"`
	LeaseToken string                `json:"lease_token"`
	Task       domain.CollectionTask `json:"task"`
	State      journalState          `json:"state"`
	Result     json.RawMessage       `json:"result,omitempty"`
	UpdatedAt  time.Time             `json:"updated_at"`
}

type countingHashReader struct {
	reader io.Reader
	hash   hash.Hash
	bytes  int64
}

func (r *countingHashReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 {
		_, _ = r.hash.Write(buffer[:n])
		r.bytes += int64(n)
	}
	return n, err
}

// importLegacyJournal streams a version 1 journal one entry at a time, so
// memory is bounded by the largest entry rather than the journal. Decoder
// errors are replaced by offsets because their text can quote input bytes.
func importLegacyJournal(ctx context.Context, tx *sql.Tx, source legacyJournalSource, report *JournalMigrationReport) error {
	file, err := os.OpenFile(source.path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open legacy collector journal backup: %w", err)
	}
	defer file.Close()
	reader := &countingHashReader{reader: file, hash: sha256.New()}
	decoder := json.NewDecoder(bufio.NewReaderSize(reader, 1<<20))
	decoder.DisallowUnknownFields()
	malformed := func() error {
		return fmt.Errorf("legacy collector journal is malformed near byte offset %d", decoder.InputOffset())
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return malformed()
	}
	versionSeen, entriesSeen, version := false, false, 0
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return malformed()
		}
		switch {
		case key == "version" && !versionSeen:
			versionSeen = true
			if err := decoder.Decode(&version); err != nil {
				return malformed()
			}
		case key == "entries" && !entriesSeen:
			entriesSeen = true
			if err := importLegacyJournalEntries(ctx, tx, decoder, report); err != nil {
				return err
			}
		default:
			return fmt.Errorf("legacy collector journal has an unsupported or repeated top-level field near byte offset %d", decoder.InputOffset())
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return malformed()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("legacy collector journal has trailing data")
	}
	if !versionSeen || version != 1 {
		return fmt.Errorf("unsupported legacy collector journal version")
	}
	if !entriesSeen {
		return fmt.Errorf("legacy collector journal has no entries object")
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("read legacy collector journal backup: %w", err)
	}
	digest := hex.EncodeToString(reader.hash.Sum(nil))
	if source.sha256 != "" && (digest != source.sha256 || reader.bytes != source.bytes) {
		return fmt.Errorf("legacy collector journal backup changed while it was imported")
	}
	report.LegacySHA256, report.LegacyBytes = digest, reader.bytes
	return nil
}

func importLegacyJournalEntries(ctx context.Context, tx *sql.Tx, decoder *json.Decoder, report *JournalMigrationReport) error {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return fmt.Errorf("legacy collector journal entries must be an object")
	}
	for index := 0; decoder.More(); index++ {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return fmt.Errorf("legacy collector journal entry %d has a malformed key near byte offset %d", index, decoder.InputOffset())
		}
		var entry legacyJournalEntry
		if err := decoder.Decode(&entry); err != nil {
			return fmt.Errorf("legacy collector journal entry %d is malformed near byte offset %d", index, decoder.InputOffset())
		}
		if err := insertLegacyJournalEntry(ctx, tx, index, key, entry, report); err != nil {
			return err
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("legacy collector journal entries object is malformed near byte offset %d", decoder.InputOffset())
	}
	return nil
}

// printableJournalIdentifier returns an identifier only when it has the shape
// of a control-plane identifier, so malformed input is never echoed.
func printableJournalIdentifier(value string) string {
	if len(value) == 0 || len(value) > 128 {
		return "<invalid>"
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') &&
			character != '.' && character != '_' && character != ':' && character != '-' && character != '/' {
			return "<invalid>"
		}
	}
	return value
}

func insertLegacyJournalEntry(ctx context.Context, tx *sql.Tx, index int, key string, entry legacyJournalEntry, report *JournalMigrationReport) error {
	run := printableJournalIdentifier(string(entry.RunID))
	invalid := func(reason string) error {
		return fmt.Errorf("legacy collector journal entry %d (run %s) %s", index, run, reason)
	}
	if entry.RunID == "" || key != string(entry.RunID) {
		return invalid("is not keyed by its run identifier")
	}
	if !domain.ValidCollectorWorkID(string(entry.WorkID)) || entry.Attempt < 1 || entry.UpdatedAt.IsZero() {
		return invalid("has an invalid work identifier, attempt, or update time")
	}
	if entry.Task.RunID != entry.RunID {
		return invalid("has a task for a different run")
	}
	if err := domain.ValidateCollectorWork(domain.CollectorWork{
		WorkID: entry.WorkID, Task: entry.Task, Status: domain.WorkLeased,
		AvailableAt: entry.Task.ScheduledFor, WorkExpiresAt: entry.Task.Deadline,
	}); err != nil {
		return invalid("has an invalid task")
	}
	hasResult := len(entry.Result) > 0 && !bytes.Equal(entry.Result, []byte("null"))
	switch entry.State {
	case journalClaimed, journalStarted:
		if hasResult {
			return invalid("is in flight but carries a result")
		}
	case journalReady, journalFinalized:
		if !hasResult {
			return invalid("is missing its result")
		}
	default:
		return invalid("has an unknown state")
	}
	token := entry.LeaseToken
	if entry.State == journalFinalized && token != "" {
		token = ""
		report.FinalizedLeaseTokensCleared++
	}
	task, err := json.Marshal(entry.Task)
	if err != nil {
		return invalid("has a task that cannot be encoded")
	}
	var digest any
	var payload []byte
	var status string
	var readyAt int64
	if hasResult {
		var compact bytes.Buffer
		if err := json.Compact(&compact, entry.Result); err != nil {
			return invalid("has a malformed result")
		}
		payload = compact.Bytes()
		var result domain.CollectionResult
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || !jsonAtEOF(decoder) {
			return invalid("has a malformed result")
		}
		if result.Task.RunID != entry.RunID || result.Status == "" {
			return invalid("has a result for a different run or without a status")
		}
		sum := sha256.Sum256(payload)
		digest, status, readyAt = sum[:], string(result.Status), entry.UpdatedAt.UnixNano()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO attempts (run_id, work_id, attempt, lease_token, state, task, deadline_ns,
		updated_at_ns, result_status, result_bytes, result_sha256, ready_at_ns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(entry.RunID), string(entry.WorkID), entry.Attempt, token, string(entry.State), task, entry.Task.Deadline.UnixNano(),
		entry.UpdatedAt.UnixNano(), status, len(payload), digest, readyAt); err != nil {
		return invalid(fmt.Sprintf("could not be imported (duplicate run or work identifier?): %v", err))
	}
	report.Entries++
	switch entry.State {
	case journalClaimed:
		report.Claimed++
	case journalStarted:
		report.Started++
	case journalReady:
		report.ResultReady++
		report.RetainedPayloadBytes += int64(len(payload))
		if _, err := tx.ExecContext(ctx, `INSERT INTO results (run_id, payload) VALUES (?, ?)`, string(entry.RunID), payload); err != nil {
			return invalid(fmt.Sprintf("result could not be imported: %v", err))
		}
	case journalFinalized:
		report.Finalized++
		report.ReclaimedPayloadBytes += int64(len(payload))
	}
	if token == "" && entry.State != journalFinalized {
		report.LeaseReleased++
	}
	return nil
}

// mergeJournalCompletionRecords restores finalized completion records and the
// retention watermark from sealed stores. Records at or below the combined
// watermark are already covered by it. Imported state always wins.
func mergeJournalCompletionRecords(ctx context.Context, tx *sql.Tx, stores []string, report *JournalMigrationReport) (int64, error) {
	var prunedThrough int64
	for _, store := range stores {
		info, err := inspectJournalStore(store)
		if err != nil {
			return 0, err
		}
		prunedThrough = max(prunedThrough, info.PrunedThroughNanos)
	}
	for _, store := range stores {
		if err := mergeJournalCompletionRecordsFrom(ctx, tx, store, prunedThrough, report); err != nil {
			return 0, err
		}
	}
	return prunedThrough, nil
}

func mergeJournalCompletionRecordsFrom(ctx context.Context, tx *sql.Tx, store string, prunedThrough int64, report *JournalMigrationReport) error {
	source, err := openJournalDatabase(store, journalDatabaseReadOnly)
	if err != nil {
		return err
	}
	defer source.Close()
	rows, err := source.QueryContext(ctx, `SELECT run_id, work_id, attempt, task, deadline_ns, updated_at_ns, result_status,
		result_bytes, result_sha256, ready_at_ns FROM attempts WHERE state = 'FINALIZED' AND deadline_ns > ? ORDER BY run_id`, prunedThrough)
	if err != nil {
		return fmt.Errorf("read sealed collector journal completion records: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var runID, workID, status string
		var attempt int
		var task, digest []byte
		var deadline, updated, resultBytes, readyAt int64
		if err := rows.Scan(&runID, &workID, &attempt, &task, &deadline, &updated, &status, &resultBytes, &digest, &readyAt); err != nil {
			return fmt.Errorf("read sealed collector journal completion record: %w", err)
		}
		var existingWork string
		err := tx.QueryRowContext(ctx, `SELECT work_id FROM attempts WHERE run_id = ?`, runID).Scan(&existingWork)
		if err == nil {
			if existingWork != workID {
				return fmt.Errorf("sealed collector journal run %s conflicts with the imported journal's work identifier", printableJournalIdentifier(runID))
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("merge sealed collector journal completion records: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO attempts (run_id, work_id, attempt, lease_token, state, task, deadline_ns,
			updated_at_ns, result_status, result_bytes, result_sha256, ready_at_ns) VALUES (?, ?, ?, '', 'FINALIZED', ?, ?, ?, ?, ?, ?, ?)`,
			runID, workID, attempt, task, deadline, updated, status, resultBytes, digest, readyAt); err != nil {
			return fmt.Errorf("merge sealed collector journal run %s (duplicate work identifier?): %w", printableJournalIdentifier(runID), err)
		}
		report.MergedCompletionRecords++
	}
	return rows.Err()
}

func requireUnfinishedJournalWork(ctx context.Context, tx *sql.Tx, store string) error {
	source, err := openJournalDatabase(store, journalDatabaseReadOnly)
	if err != nil {
		return err
	}
	defer source.Close()
	rows, err := source.QueryContext(ctx, `SELECT run_id FROM attempts WHERE state <> 'FINALIZED' ORDER BY run_id`)
	if err != nil {
		return fmt.Errorf("read sealed collector journal receipts: %w", err)
	}
	var runs []string
	for rows.Next() {
		var runID string
		if err := rows.Scan(&runID); err != nil {
			rows.Close()
			return fmt.Errorf("read sealed collector journal receipt: %w", err)
		}
		runs = append(runs, runID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, runID := range runs {
		var present int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM attempts WHERE run_id = ?`, runID).Scan(&present); err != nil {
			return fmt.Errorf("verify sealed collector journal receipts: %w", err)
		}
		if present != 1 {
			return errors.New("legacy collector journal lacks unfinished work recorded in the sealed store, so it was not produced from the rollback export; restore the rollback export instead of an older backup")
		}
	}
	return nil
}

// JournalRollbackExport describes a version 1 journal written for rollback.
type JournalRollbackExport struct {
	Path                     string
	SHA256                   string
	Bytes                    int64
	Entries                  int
	Claimed                  int
	Started                  int
	ResultReady              int
	OmittedCompletionRecords int
	PrunedThrough            time.Time
}

type rollbackJournalEntry struct {
	WorkID     domain.WorkID         `json:"work_id"`
	RunID      domain.RunID          `json:"run_id"`
	Attempt    int                   `json:"attempt"`
	LeaseToken string                `json:"lease_token"`
	Task       domain.CollectionTask `json:"task"`
	State      journalState          `json:"state"`
	Result     json.RawMessage       `json:"result,omitempty"`
	UpdatedAt  time.Time             `json:"updated_at"`
}

// ExportJournalForRollback seals the store and writes every unfinished receipt,
// including lease tokens and unacknowledged results, to a new owner-only
// version 1 journal beside the configured path. The collector must be stopped.
// Finalized completion records are omitted; they and the retention watermark
// stay in the sealed store and are merged back when the operator returns to
// this version.
func ExportJournalForRollback(legacyPath string, clock Clock) (JournalRollbackExport, error) {
	if legacyPath == "" || clock == nil {
		return JournalRollbackExport{}, fmt.Errorf("journal path and clock are required")
	}
	paths, err := newJournalPaths(legacyPath)
	if err != nil {
		return JournalRollbackExport{}, err
	}
	lock, err := acquireJournalLock(paths.lock)
	if err != nil {
		return JournalRollbackExport{}, err
	}
	defer func() { _ = lock.release() }()
	legacy, _, err := classifyLegacyJournal(paths)
	if err != nil {
		return JournalRollbackExport{}, err
	}
	if legacy == legacyJournalPresent {
		return JournalRollbackExport{}, errors.New("a legacy JSON journal is active at the configured path; there is no store state to export")
	}
	if exists, err := regularJournalFileExists(paths.store); err != nil || !exists {
		return JournalRollbackExport{}, errors.New("collector journal store does not exist")
	}
	db, err := openJournalDatabase(paths.store, journalDatabaseReadWrite)
	if err != nil {
		return JournalRollbackExport{}, err
	}
	defer db.Close()
	if err := verifyJournalDatabase(db, true); err != nil {
		return JournalRollbackExport{}, err
	}
	ctx := context.Background()
	now := clock.Now().UTC()
	export := JournalRollbackExport{Path: paths.legacy + journalRollbackInfix + now.Format(journalFileTimeLayout) + ".json"}
	format, err := readJournalStoreInfo(ctx, db)
	if err != nil {
		return JournalRollbackExport{}, err
	}
	if format.FormatVersion != journalStoreFormatVersion {
		return JournalRollbackExport{}, fmt.Errorf("typed collector journal cannot be exported to a v1 collector")
	}
	// Seal before writing: an interrupted export leaves a sealed store, which
	// the next start unseals because the redirect still blocks older binaries.
	if _, err := db.ExecContext(ctx, `UPDATE journal_store SET sealed_at_ns = ?, sealed_export = ? WHERE singleton = 1`,
		now.UnixNano(), filepath.Base(export.Path)); err != nil {
		return JournalRollbackExport{}, fmt.Errorf("seal collector journal store: %w", err)
	}
	info, err := readJournalStoreInfo(ctx, db)
	if err != nil {
		return JournalRollbackExport{}, err
	}
	if info.PrunedThroughNanos > 0 {
		export.PrunedThrough = time.Unix(0, info.PrunedThroughNanos).UTC()
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM attempts WHERE state = 'FINALIZED'`).Scan(&export.OmittedCompletionRecords); err != nil {
		return JournalRollbackExport{}, fmt.Errorf("count collector journal completion records: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT `+journalAttemptColumns+` FROM attempts WHERE state <> 'FINALIZED' ORDER BY run_id`)
	if err != nil {
		return JournalRollbackExport{}, fmt.Errorf("read collector journal receipts: %w", err)
	}
	var receipts []journalAttemptRow
	for rows.Next() {
		row, err := scanJournalAttempt(rows)
		if err != nil {
			rows.Close()
			return JournalRollbackExport{}, err
		}
		receipts = append(receipts, row)
	}
	if err := rows.Close(); err != nil {
		return JournalRollbackExport{}, err
	}
	file, err := os.OpenFile(export.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return JournalRollbackExport{}, fmt.Errorf("create collector journal rollback export: %w", err)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(export.Path)
		}
	}()
	digest := sha256.New()
	writer := bufio.NewWriter(io.MultiWriter(file, digest))
	if _, err := writer.WriteString(`{"version":1,"entries":{`); err != nil {
		return JournalRollbackExport{}, fmt.Errorf("write collector journal rollback export: %w", err)
	}
	for index, receipt := range receipts {
		entry := rollbackJournalEntry{
			WorkID: receipt.entry.WorkID, RunID: receipt.entry.RunID, Attempt: receipt.entry.Attempt, LeaseToken: receipt.entry.LeaseToken,
			Task: receipt.entry.Task, State: receipt.entry.State, UpdatedAt: receipt.entry.UpdatedAt,
		}
		if receipt.entry.State == journalReady {
			_, payload, err := loadJournalResult(ctx, db, receipt.entry.RunID, receipt.resultSHA256)
			if err != nil {
				return JournalRollbackExport{}, err
			}
			entry.Result = payload
			export.ResultReady++
		} else if receipt.entry.State == journalClaimed {
			export.Claimed++
		} else {
			export.Started++
		}
		key, err := json.Marshal(string(receipt.entry.RunID))
		if err != nil {
			return JournalRollbackExport{}, fmt.Errorf("encode collector journal rollback export")
		}
		value, err := json.Marshal(entry)
		if err != nil {
			return JournalRollbackExport{}, fmt.Errorf("encode collector journal rollback export")
		}
		if index > 0 {
			_ = writer.WriteByte(',')
		}
		_, _ = writer.Write(key)
		_ = writer.WriteByte(':')
		if _, err := writer.Write(value); err != nil {
			return JournalRollbackExport{}, fmt.Errorf("write collector journal rollback export: %w", err)
		}
		export.Entries++
	}
	if _, err := writer.WriteString(`}}`); err != nil {
		return JournalRollbackExport{}, fmt.Errorf("write collector journal rollback export: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return JournalRollbackExport{}, fmt.Errorf("write collector journal rollback export: %w", err)
	}
	if err := file.Sync(); err != nil {
		return JournalRollbackExport{}, fmt.Errorf("sync collector journal rollback export: %w", err)
	}
	info2, err := file.Stat()
	if err != nil {
		return JournalRollbackExport{}, fmt.Errorf("inspect collector journal rollback export: %w", err)
	}
	if err := syncJournalDirectory(paths.directory); err != nil {
		return JournalRollbackExport{}, err
	}
	// Leave no WAL sidecar so a later re-forward can archive the sealed store
	// by renaming a single file.
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode = DELETE`).Scan(&mode); err != nil || !strings.EqualFold(mode, "delete") {
		return JournalRollbackExport{}, errors.New("collector journal store could not leave write-ahead logging after export")
	}
	export.Bytes = info2.Size()
	export.SHA256 = hex.EncodeToString(digest.Sum(nil))
	complete = true
	return export, nil
}

// CheckLegacyJournal validates a version 1 journal by importing it into a
// temporary store that is deleted afterwards. It creates no backup, store or
// redirect beside the journal and takes no lock, so it can run while a version
// 1 collector is still writing: it reads one consistent file generation.
func CheckLegacyJournal(legacyPath string, clock Clock) (*JournalMigrationReport, error) {
	if legacyPath == "" || clock == nil {
		return nil, fmt.Errorf("journal path and clock are required")
	}
	paths, err := newJournalPaths(legacyPath)
	if err != nil {
		return nil, err
	}
	if kind, _, err := classifyLegacyJournal(paths); err != nil {
		return nil, err
	} else if kind != legacyJournalPresent {
		return nil, fmt.Errorf("no legacy JSON journal exists at the configured path (found %s)", kind)
	}
	directory, err := os.MkdirTemp("", "sherlock-journal-check-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary collector journal check directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(directory) }()
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("restrict temporary collector journal check directory: %w", err)
	}
	check := journalPaths{store: filepath.Join(directory, "check.sqlite"), importing: filepath.Join(directory, "check.sqlite.importing"), directory: directory}
	started := time.Now()
	report := &JournalMigrationReport{Action: "checked"}
	if err := buildJournalStore(check, clock, &journalBuildInput{legacy: &legacyJournalSource{path: paths.legacy}, report: report}, nil); err != nil {
		return nil, err
	}
	report.Duration = time.Since(started)
	return report, nil
}

// JournalStatus is a read-only, non-sensitive view for operators.
type JournalStatus struct {
	LegacyJournal string
	LegacyBytes   int64
	StorePresent  bool
	StoreLocked   bool
	StoreBytes    int64
	StoreSource   string
	StoreCreated  time.Time
	LegacyEntries int
	Backups       int
	SealedStores  int
	Stats         JournalStats
}

// ReadJournalStatus inspects the journal without taking the lock or migrating.
// A running collector holds the store exclusively; status then reports
// StoreLocked and the running process's metrics and logs carry the counts.
func ReadJournalStatus(legacyPath string) (JournalStatus, error) {
	paths, err := newJournalPaths(legacyPath)
	if err != nil {
		return JournalStatus{}, err
	}
	legacy, legacyBytes, err := classifyLegacyJournal(paths)
	if err != nil {
		return JournalStatus{}, err
	}
	status := JournalStatus{LegacyJournal: legacy.String(), LegacyBytes: legacyBytes}
	backups, sealed, err := journalArtifacts(paths)
	if err != nil {
		return JournalStatus{}, err
	}
	status.Backups, status.SealedStores = len(backups), len(sealed)
	if status.StorePresent, err = regularJournalFileExists(paths.store); err != nil || !status.StorePresent {
		return status, err
	}
	for _, name := range []string{paths.store, paths.store + "-wal"} {
		if info, err := os.Lstat(name); err == nil {
			status.StoreBytes += info.Size()
		}
	}
	db, err := openJournalDatabase(paths.store, journalDatabaseStatus)
	if journalStoreBusy(err) {
		status.StoreLocked = true
		return status, nil
	}
	if err != nil {
		return JournalStatus{}, err
	}
	defer db.Close()
	ctx := context.Background()
	info, err := readJournalStoreInfo(ctx, db)
	if journalStoreBusy(err) {
		status.StoreLocked = true
		return status, nil
	}
	if err != nil {
		return JournalStatus{}, err
	}
	status.StoreSource, status.StoreCreated, status.LegacyEntries = info.Source, info.CreatedAt, info.LegacyEntries
	status.Stats, err = queryJournalStats(ctx, db)
	return status, err
}
