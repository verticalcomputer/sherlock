package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnvFileLoadsSherlockValuesWithoutOverwritingProcessEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("SHERLOCK_DOTENV_FILE_ONLY='from file'\nSHERLOCK_DOTENV_OVERRIDE=from-file\nSHERLOCK_DOTENV_QUOTED=\"quoted\\nvalue\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SHERLOCK_DOTENV_FILE_ONLY", "SHERLOCK_DOTENV_QUOTED"} {
		old, existed := os.LookupEnv(name)
		_ = os.Unsetenv(name)
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(name, old)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
	t.Setenv("SHERLOCK_DOTENV_OVERRIDE", "from-process")
	if err := loadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SHERLOCK_DOTENV_FILE_ONLY") != "from file" || os.Getenv("SHERLOCK_DOTENV_OVERRIDE") != "from-process" || os.Getenv("SHERLOCK_DOTENV_QUOTED") != "quoted\nvalue" {
		t.Fatal("local environment precedence or decoding is incorrect")
	}
}

func TestLoadEnvFileRejectsUnsafeOrMalformedFilesWithoutPartialLoad(t *testing.T) {
	directory := t.TempDir()
	insecure := filepath.Join(directory, "insecure.env")
	if err := os.WriteFile(insecure, []byte("SHERLOCK_SAFE=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecure, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loadEnvFile(insecure); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("insecure file error=%v", err)
	}
	malformed := filepath.Join(directory, "malformed.env")
	if err := os.WriteFile(malformed, []byte("SHERLOCK_DOTENV_PARTIAL=value\nPATH=/tmp/injected\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, existed := os.LookupEnv("SHERLOCK_DOTENV_PARTIAL")
	_ = os.Unsetenv("SHERLOCK_DOTENV_PARTIAL")
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv("SHERLOCK_DOTENV_PARTIAL", old)
		} else {
			_ = os.Unsetenv("SHERLOCK_DOTENV_PARTIAL")
		}
	})
	if err := loadEnvFile(malformed); err == nil || os.Getenv("SHERLOCK_DOTENV_PARTIAL") != "" {
		t.Fatalf("malformed file partially loaded: %v", err)
	}
}
