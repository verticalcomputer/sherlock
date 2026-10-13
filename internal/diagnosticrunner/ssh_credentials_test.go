package diagnosticrunner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSSHCredentialProviderBoundsExposureAndClearsBuffer(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	password := []byte("head-local-test-password")
	if err := os.WriteFile(filepath.Join(directory, "pilot-password-v1"), password, 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewFileSSHCredentialProvider(directory)
	if err != nil {
		t.Fatal(err)
	}
	var exposed []byte
	if err := provider.WithPassword(context.Background(), "pilot-password-v1", func(candidate []byte) error {
		if !bytes.Equal(candidate, password) {
			t.Fatalf("credential bytes = %q", candidate)
		}
		exposed = candidate
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !allZero(exposed) {
		t.Fatal("provider credential buffer survived callback")
	}
}

func TestFileSSHCredentialProviderRejectsUnsafeStorageAndContent(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T) string{
		"writable directory": func(t *testing.T) string {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			return directory
		},
		"relative directory": func(t *testing.T) string { return "credentials" },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewFileSSHCredentialProvider(prepare(t)); err == nil {
				t.Fatal("unsafe provider directory was accepted")
			}
		})
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	provider, err := NewFileSSHCredentialProvider(directory)
	if err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(directory, "unsafe")
	if err := os.WriteFile(unsafe, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provider.WithPassword(context.Background(), "unsafe", func([]byte) error { return nil }); err == nil {
		t.Fatal("newline-bearing credential was accepted")
	}
	if err := os.Chmod(unsafe, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := provider.WithPassword(context.Background(), "unsafe", func([]byte) error { return nil }); err == nil {
		t.Fatal("group-readable credential was accepted")
	}
	if err := os.Symlink(unsafe, filepath.Join(directory, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := provider.WithPassword(context.Background(), "linked", func([]byte) error { return nil }); err == nil {
		t.Fatal("credential symlink was accepted")
	}
}

func allZero(payload []byte) bool {
	for _, value := range payload {
		if value != 0 {
			return false
		}
	}
	return true
}
