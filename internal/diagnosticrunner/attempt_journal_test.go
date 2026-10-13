package diagnosticrunner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiagnosticJournalIsOwnerOnlyAndRejectsUnsafeOrMalformedFiles(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "journal.json")
	journal, err := OpenDiagnosticJournal(path, func() time.Time { return now })
	if err != nil || journal == nil {
		t.Fatalf("OpenDiagnosticJournal() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal permissions = %o", info.Mode().Perm())
	}

	malformed := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"version":1,"entries":{},"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDiagnosticJournal(malformed, func() time.Time { return now }); err == nil {
		t.Fatal("journal with an unknown field was accepted")
	}

	symlink := filepath.Join(t.TempDir(), "journal-link.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDiagnosticJournal(symlink, func() time.Time { return now }); err == nil {
		t.Fatal("symlink journal was accepted")
	}
}
