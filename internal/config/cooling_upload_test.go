package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const testCoolingProfileJSON = `{
	"version":2,"profile_id":"pilot","revision":1,
	"cluster_id":"cluster","source_id":"dcgm","collector_id":"collector",
	"inventory_revision":"inventory","starts_at":"2026-11-18T08:00:00Z","ends_at":"2026-11-18T09:00:00Z",
	"assets":[{"node_id":"node","gpu_uuid":"GPU-a"}]
}`

func TestLoadCoolingUploadProfileBindsExactProtectedBytes(t *testing.T) {
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", "")
	p, hash, err := LoadCoolingUploadProfile()
	if err != nil || hash != "" || p.ProfileID != "" {
		t.Fatalf("empty opt-in = (%+v, %q, %v)", p, hash, err)
	}

	path := filepath.Join(t.TempDir(), "cooling.json")
	if err := os.WriteFile(path, []byte(testCoolingProfileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", path)
	p, hash, err = LoadCoolingUploadProfile()
	if err != nil || hash != domain.ChecksumSHA256([]byte(testCoolingProfileJSON)).String() || p.ProfileID != "pilot" {
		t.Fatalf("load profile = (%+v, %q, %v)", p, hash, err)
	}
	if err := os.WriteFile(path, []byte(testCoolingProfileJSON+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, different, err := LoadCoolingUploadProfile(); err != nil || different == hash {
		t.Fatalf("different exact bytes returned the same hash or invalid profile: %q, %v", different, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCoolingUploadProfile(); err == nil {
		t.Fatal("group/world readable profile accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "configuration-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", link)
	if _, _, err := LoadCoolingUploadProfile(); err == nil {
		t.Fatal("profile symlink accepted")
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", path)
	for _, raw := range []string{
		strings.Replace(testCoolingProfileJSON, `"version":2`, `"version":2,"version":2`, 1),
		strings.Replace(testCoolingProfileJSON, `"version":2`, `"version":2,"custom_selector":"metric"`, 1),
		testCoolingProfileJSON + `{}`,
		strings.Repeat(" ", coolingUploadProfileMaxBytes+1),
	} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadCoolingUploadProfile(); err == nil {
			t.Fatal("invalid profile JSON accepted")
		}
	}
}

func TestLoadContinuousCoolingProfile(t *testing.T) {
	raw := strings.Replace(testCoolingProfileJSON, `"version":2`, `"version":3,"state":"ENABLED"`, 1)
	raw = strings.Replace(raw, `,"ends_at":"2026-11-18T09:00:00Z"`, "", 1)
	path := filepath.Join(t.TempDir(), "continuous.json")
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", path)
	for _, state := range []string{"ENABLED", "DISABLED"} {
		body := strings.Replace(raw, `"state":"ENABLED"`, `"state":"`+state+`"`, 1)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		profile, hash, err := LoadCoolingUploadProfile()
		if err != nil || profile.Version != 3 || profile.State != state || !profile.EndsAt.IsZero() || hash != domain.ChecksumSHA256([]byte(body)).String() {
			t.Fatalf("profile=%+v hash=%s err=%v", profile, hash, err)
		}
	}
}
