package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestLocalCoolingOptInBindsScopeAndIndependentPrivateSpool(t *testing.T) {
	root := t.TempDir()
	minute, cooling := filepath.Join(root, "minute"), filepath.Join(root, "cooling")
	for _, name := range []string{minute, cooling, filepath.Join(minute, "subdir")} {
		if err := os.Mkdir(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "cooling.json")
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", "")
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_SPOOL", "")
	cfg := config.Collector{CollectorID: "collector", ClusterID: "cluster", SourceID: "source"}
	if _, hash, _, err := loadLocalCoolingUpload(cfg, minute); err != nil || hash != "" {
		t.Fatalf("default opted in to cooling: %q %v", hash, err)
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", configPath)
	slot := time.Now().UTC().Truncate(domain.CoolingUploadInterval)
	profile := domain.CoolingUploadProfile{Version: 2, ProfileID: "pilot", Revision: 1, CollectorID: "collector",
		ClusterID: "cluster", SourceID: "source", InventoryRevision: "inventory", StartsAt: slot, EndsAt: slot.Add(time.Hour),
		Assets: []domain.CoolingUploadAsset{{NodeID: "node", GPUUUID: "GPU-a"}},
	}
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", minute, filepath.Join(minute, "subdir"), root} {
		t.Setenv("SHERLOCK_PROMETHEUS_COOLING_SPOOL", invalid)
		if _, _, _, err := loadLocalCoolingUpload(cfg, minute); err == nil {
			t.Fatal("accepted missing/unseparated cooling spool")
		}
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_SPOOL", cooling)
	p, hash, dir, err := loadLocalCoolingUpload(cfg, minute)
	if err != nil || p.ProfileID != "pilot" || hash != domain.ChecksumSHA256(body).String() || dir != cooling {
		t.Fatalf("invalid cooling opt-in (%+v, %s, %s, %v)", p, hash, dir, err)
	}
	cfg.CollectorID = "wrong-identity"
	if _, _, _, err := loadLocalCoolingUpload(cfg, minute); err == nil {
		t.Fatal("accepted cooling profile issued for a different collector")
	}
}
