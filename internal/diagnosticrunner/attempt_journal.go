package diagnosticrunner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	diagnosticJournalVersion        = 1
	maximumDiagnosticJournalSize    = 64 << 20
	maximumDiagnosticJournalEntries = 256
)

type diagnosticJournalState string

const (
	diagnosticJournalClaimed   diagnosticJournalState = "CLAIMED"
	diagnosticJournalStarted   diagnosticJournalState = "STARTED"
	diagnosticJournalReady     diagnosticJournalState = "RESULT_READY"
	diagnosticJournalLeaseLost diagnosticJournalState = "LEASE_LOST"
)

type diagnosticJournalRecord struct {
	WorkID       domain.DiagnosticWorkID         `json:"work_id"`
	Attempt      int                             `json:"attempt"`
	RunnerID     string                          `json:"runner_id"`
	LeaseToken   string                          `json:"lease_token,omitempty"`
	LeaseExpires time.Time                       `json:"lease_expires_at"`
	AvailableAt  time.Time                       `json:"available_at"`
	Deadline     time.Time                       `json:"deadline"`
	MaxAttempts  int                             `json:"max_attempts"`
	Request      domain.DiagnosticRequest        `json:"request"`
	State        diagnosticJournalState          `json:"state"`
	DoNotExecute bool                            `json:"do_not_execute,omitempty"`
	Result       *domain.DiagnosticAttemptResult `json:"result,omitempty"`
	UpdatedAt    time.Time                       `json:"updated_at"`
}

type diagnosticJournalFile struct {
	Version int                                `json:"version"`
	Entries map[string]diagnosticJournalRecord `json:"entries"`
}

// DiagnosticJournal persists the execution boundary before a remote command
// starts and its complete safe result before acknowledgement. It contains a
// live lease token and is therefore owner-readable only.
type DiagnosticJournal struct {
	mu      sync.Mutex
	path    string
	clock   func() time.Time
	content diagnosticJournalFile
}

func OpenDiagnosticJournal(path string, clock func() time.Time) (*DiagnosticJournal, error) {
	if path == "" || clock == nil {
		return nil, errors.New("diagnostic journal path and clock are required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create diagnostic journal directory: %w", err)
	}
	journal := &DiagnosticJournal{
		path: path, clock: clock,
		content: diagnosticJournalFile{Version: diagnosticJournalVersion, Entries: make(map[string]diagnosticJournalRecord)},
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := journal.persistLocked(); err != nil {
			return nil, err
		}
		return journal, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect diagnostic journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maximumDiagnosticJournalSize {
		return nil, errors.New("diagnostic journal must be a bounded regular file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("restrict diagnostic journal permissions: %w", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil || len(payload) == 0 || len(payload) > maximumDiagnosticJournalSize {
		return nil, errors.New("read diagnostic journal")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal.content); err != nil {
		return nil, errors.New("decode diagnostic journal")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("diagnostic journal has trailing data")
	}
	if journal.content.Version != diagnosticJournalVersion || journal.content.Entries == nil || len(journal.content.Entries) > maximumDiagnosticJournalEntries {
		return nil, errors.New("unsupported diagnostic journal")
	}
	for key, record := range journal.content.Entries {
		if key != diagnosticJournalKey(record.WorkID, record.Attempt) || validateDiagnosticJournalRecord(record) != nil {
			return nil, errors.New("diagnostic journal contains an invalid record")
		}
	}
	return journal, nil
}

func (journal *DiagnosticJournal) begin(lease domain.DiagnosticWorkLease) (diagnosticJournalRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, err := diagnosticRecordFromLease(lease, journal.clock().UTC())
	if err != nil {
		return diagnosticJournalRecord{}, err
	}
	key := diagnosticJournalKey(record.WorkID, record.Attempt)
	if existing, exists := journal.content.Entries[key]; exists {
		if existing.State == diagnosticJournalLeaseLost {
			return diagnosticJournalRecord{}, errors.New("diagnostic journal attempt lost its lease")
		}
		return cloneDiagnosticJournalRecord(existing), nil
	}
	for _, existing := range journal.content.Entries {
		if diagnosticJournalPending(existing.State) {
			return diagnosticJournalRecord{}, errors.New("diagnostic journal already has a pending attempt")
		}
		if existing.WorkID == record.WorkID && existing.State == diagnosticJournalLeaseLost {
			record.DoNotExecute = true
		}
	}
	if len(journal.content.Entries) >= maximumDiagnosticJournalEntries {
		return diagnosticJournalRecord{}, errors.New("diagnostic journal entry limit reached")
	}
	journal.content.Entries[key] = record
	if err := journal.persistLocked(); err != nil {
		delete(journal.content.Entries, key)
		return diagnosticJournalRecord{}, err
	}
	return cloneDiagnosticJournalRecord(record), nil
}

func (journal *DiagnosticJournal) pending() (diagnosticJournalRecord, bool) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	for _, record := range journal.content.Entries {
		if diagnosticJournalPending(record.State) {
			return cloneDiagnosticJournalRecord(record), true
		}
	}
	return diagnosticJournalRecord{}, false
}

func (journal *DiagnosticJournal) markStarted(workID domain.DiagnosticWorkID, attempt int) error {
	return journal.transition(workID, attempt, diagnosticJournalClaimed, diagnosticJournalStarted, nil, false)
}

func (journal *DiagnosticJournal) storeResult(workID domain.DiagnosticWorkID, attempt int, result domain.DiagnosticAttemptResult) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	key := diagnosticJournalKey(workID, attempt)
	record, exists := journal.content.Entries[key]
	if !exists || (record.State != diagnosticJournalClaimed && record.State != diagnosticJournalStarted) || result.WorkID != workID || result.Attempt != attempt || result.RunnerID != record.RunnerID || result.Validate(record.Request.Targets) != nil {
		return errors.New("diagnostic journal cannot store this result")
	}
	previous := cloneDiagnosticJournalRecord(record)
	copyResult := cloneDiagnosticAttemptResult(result)
	record.Result = &copyResult
	record.State = diagnosticJournalReady
	record.UpdatedAt = journal.clock().UTC()
	journal.content.Entries[key] = record
	if err := journal.persistLocked(); err != nil {
		journal.content.Entries[key] = previous
		return err
	}
	return nil
}

func (journal *DiagnosticJournal) markFinalized(workID domain.DiagnosticWorkID, attempt int) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	key := diagnosticJournalKey(workID, attempt)
	record, exists := journal.content.Entries[key]
	if !exists || record.State != diagnosticJournalReady {
		return errors.New("diagnostic journal transition is invalid")
	}
	removed := make(map[string]diagnosticJournalRecord)
	for entryKey, entry := range journal.content.Entries {
		if entryKey == key || entry.WorkID == workID && entry.State == diagnosticJournalLeaseLost {
			removed[entryKey] = entry
			delete(journal.content.Entries, entryKey)
		}
	}
	if err := journal.persistLocked(); err != nil {
		for entryKey, entry := range removed {
			journal.content.Entries[entryKey] = entry
		}
		return err
	}
	return nil
}

func (journal *DiagnosticJournal) markLeaseLost(workID domain.DiagnosticWorkID, attempt int) error {
	return journal.transition(workID, attempt, diagnosticJournalReady, diagnosticJournalLeaseLost, nil, true)
}

func (journal *DiagnosticJournal) transition(workID domain.DiagnosticWorkID, attempt int, from, to diagnosticJournalState, result *domain.DiagnosticAttemptResult, clearToken bool) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	key := diagnosticJournalKey(workID, attempt)
	record, exists := journal.content.Entries[key]
	if !exists || record.State != from {
		return errors.New("diagnostic journal transition is invalid")
	}
	previous := cloneDiagnosticJournalRecord(record)
	record.State = to
	if result != nil {
		copyResult := cloneDiagnosticAttemptResult(*result)
		record.Result = &copyResult
	}
	if clearToken {
		record.LeaseToken = ""
	}
	record.UpdatedAt = journal.clock().UTC()
	journal.content.Entries[key] = record
	if err := journal.persistLocked(); err != nil {
		journal.content.Entries[key] = previous
		return err
	}
	return nil
}

func (record diagnosticJournalRecord) lease() (domain.DiagnosticWorkLease, error) {
	run, err := domain.ReconstituteDiagnosticRun(record.Request, domain.DiagnosticRunning, 1)
	if err != nil {
		return domain.DiagnosticWorkLease{}, err
	}
	return domain.DiagnosticWorkLease{
		Work:    domain.DiagnosticWork{WorkID: record.WorkID, Run: run, AvailableAt: record.AvailableAt, Deadline: record.Deadline, MaxAttempts: record.MaxAttempts},
		Attempt: record.Attempt, RunnerID: record.RunnerID, LeaseToken: record.LeaseToken, LeaseExpires: record.LeaseExpires,
	}, nil
}

func diagnosticRecordFromLease(lease domain.DiagnosticWorkLease, now time.Time) (diagnosticJournalRecord, error) {
	record := diagnosticJournalRecord{
		WorkID: lease.Work.WorkID, Attempt: lease.Attempt, RunnerID: lease.RunnerID,
		LeaseToken: lease.LeaseToken, LeaseExpires: lease.LeaseExpires.UTC(), AvailableAt: lease.Work.AvailableAt.UTC(),
		Deadline: lease.Work.Deadline.UTC(), MaxAttempts: lease.Work.MaxAttempts, Request: lease.Work.Run.Request(),
		State: diagnosticJournalClaimed, UpdatedAt: now,
	}
	if err := validateDiagnosticJournalRecord(record); err != nil {
		return diagnosticJournalRecord{}, err
	}
	return record, nil
}

func validateDiagnosticJournalRecord(record diagnosticJournalRecord) error {
	if record.WorkID == "" || record.Attempt < 1 || record.Attempt > record.MaxAttempts || record.RunnerID == "" || record.UpdatedAt.IsZero() || record.LeaseExpires.IsZero() || record.Deadline.IsZero() || !record.Deadline.Equal(record.Request.Deadline) || record.MaxAttempts != record.Request.MaxAttempts || record.Request.Validate() != nil {
		return errors.New("diagnostic journal record identity is invalid")
	}
	if record.LeaseToken != "" && (len(record.LeaseToken) < 16 || len(record.LeaseToken) > 512 || strings.ContainsAny(record.LeaseToken, "\x00\r\n")) {
		return errors.New("diagnostic journal lease token is invalid")
	}
	switch record.State {
	case diagnosticJournalClaimed, diagnosticJournalStarted:
		if record.LeaseToken == "" || record.Result != nil {
			return errors.New("diagnostic journal in-flight record is invalid")
		}
	case diagnosticJournalReady:
		if record.LeaseToken == "" || record.Result == nil {
			return errors.New("diagnostic journal ready record is invalid")
		}
	case diagnosticJournalLeaseLost:
		if record.LeaseToken != "" || record.Result == nil {
			return errors.New("diagnostic journal terminal record is invalid")
		}
	default:
		return errors.New("diagnostic journal state is invalid")
	}
	if record.Result != nil && (record.Result.WorkID != record.WorkID || record.Result.Attempt != record.Attempt || record.Result.RunnerID != record.RunnerID || record.Result.Validate(record.Request.Targets) != nil) {
		return errors.New("diagnostic journal result is invalid")
	}
	return nil
}

func diagnosticJournalPending(state diagnosticJournalState) bool {
	return state == diagnosticJournalClaimed || state == diagnosticJournalStarted || state == diagnosticJournalReady
}

func diagnosticJournalKey(workID domain.DiagnosticWorkID, attempt int) string {
	return fmt.Sprintf("%s/%d", workID, attempt)
}

func cloneDiagnosticJournalRecord(record diagnosticJournalRecord) diagnosticJournalRecord {
	record.Request.Targets = append([]domain.DiagnosticTarget(nil), record.Request.Targets...)
	record.Request.Arguments = append([]domain.DiagnosticArgument(nil), record.Request.Arguments...)
	if record.Result != nil {
		copyResult := cloneDiagnosticAttemptResult(*record.Result)
		record.Result = &copyResult
	}
	return record
}

func cloneDiagnosticAttemptResult(result domain.DiagnosticAttemptResult) domain.DiagnosticAttemptResult {
	result.Targets = append([]domain.DiagnosticTargetResult(nil), result.Targets...)
	for index := range result.Targets {
		if result.Targets[index].ExitCode != nil {
			value := *result.Targets[index].ExitCode
			result.Targets[index].ExitCode = &value
		}
	}
	return result
}

func (journal *DiagnosticJournal) persistLocked() error {
	payload, err := json.Marshal(journal.content)
	if err != nil || len(payload) > maximumDiagnosticJournalSize {
		return errors.New("encode diagnostic journal")
	}
	directory := filepath.Dir(journal.path)
	temporary, err := os.CreateTemp(directory, ".diagnostic-journal-*")
	if err != nil {
		return fmt.Errorf("create diagnostic journal temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("restrict diagnostic journal temporary file: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write diagnostic journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync diagnostic journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close diagnostic journal: %w", err)
	}
	if err := os.Rename(temporaryName, journal.path); err != nil {
		return fmt.Errorf("replace diagnostic journal: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open diagnostic journal directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync diagnostic journal directory: %w", err)
	}
	return nil
}
