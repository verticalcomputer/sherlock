package config

import (
	"strings"
	"testing"
)

func TestArtifactStorageRequiresCompleteSafeR2Configuration(t *testing.T) {
	t.Setenv("SHERLOCK_ARTIFACT_BACKEND", "r2")
	t.Setenv("SHERLOCK_R2_ENDPOINT", "https://account.r2.cloudflarestorage.com")
	t.Setenv("SHERLOCK_R2_BUCKET", "sherlock-audit")
	t.Setenv("SHERLOCK_R2_ACCESS_KEY_ID", "access-id")
	t.Setenv("SHERLOCK_R2_SECRET_ACCESS_KEY", "")
	if _, err := loadArtifactStorage(""); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial R2 config error=%v", err)
	}
	t.Setenv("SHERLOCK_R2_SECRET_ACCESS_KEY", "secret")
	t.Setenv("SHERLOCK_R2_PREFIX", "../escape")
	if _, err := loadArtifactStorage(""); err == nil || !strings.Contains(err.Error(), "PREFIX") {
		t.Fatalf("unsafe prefix error=%v", err)
	}
}

func TestArtifactStoragePreservesLegacyLocalConfiguration(t *testing.T) {
	t.Setenv("SHERLOCK_ARTIFACT_BACKEND", "")
	t.Setenv("SHERLOCK_R2_ENDPOINT", "")
	t.Setenv("SHERLOCK_R2_BUCKET", "")
	t.Setenv("SHERLOCK_R2_ACCESS_KEY_ID", "")
	t.Setenv("SHERLOCK_R2_SECRET_ACCESS_KEY", "")
	t.Setenv("SHERLOCK_R2_PREFIX", "")
	storage, err := loadArtifactStorage("/var/lib/sherlock/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	if storage.Backend != ArtifactBackendLocal {
		t.Fatalf("legacy backend=%q", storage.Backend)
	}
}
