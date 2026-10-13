package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestLoadGPUProcessObservationIsDefaultOff(t *testing.T) {
	t.Setenv("SHERLOCK_GPU_PROCESS_OBSERVATIONS_ENABLED", "")
	cfg, err := loadGPUProcessObservation("pilot-cluster")
	if err != nil || cfg.Enabled || len(cfg.Nodes) != 0 {
		t.Fatalf("default GPU observation config = %+v, err=%v", cfg, err)
	}
}

func TestLoadGPUProcessObservationRequiresProtectedInventoryAndMapsGPUs(t *testing.T) {
	directory := t.TempDir()
	writeProtected := func(name, content string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, name := range []string{"pack", "roots", "known", "auth", "policy"} {
		writeProtected(name, "x")
	}
	inventory := writeProtected("inventory.json", `{"nodes":[{"stable_id":"node-1","gpus":[{"uuid":"GPU-11111111-2222-3333-4444-555555555555"}]}]}`)
	for key, value := range map[string]string{
		"SHERLOCK_GPU_PROCESS_OBSERVATIONS_ENABLED": "true", "SHERLOCK_CLUSTER_ID": "pilot-cluster", "SHERLOCK_GPU_PROCESS_COMMAND_PACK_FILE": filepath.Join(directory, "pack"),
		"SHERLOCK_GPU_PROCESS_TRUST_ROOTS_FILE": filepath.Join(directory, "roots"), "SHERLOCK_GPU_PROCESS_RUNNER_VERSION": "1.0.0", "SHERLOCK_GPU_PROCESS_SSH_EXECUTABLE": "/usr/bin/ssh",
		"SHERLOCK_GPU_PROCESS_SSH_SHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "SHERLOCK_GPU_PROCESS_KNOWN_HOSTS_FILE": filepath.Join(directory, "known"),
		"SHERLOCK_GPU_PROCESS_TARGET_AUTH_FILE": filepath.Join(directory, "auth"), "SHERLOCK_GPU_PROCESS_POLICY_FILE": filepath.Join(directory, "policy"), "SHERLOCK_GPU_PROCESS_NODE_MAP": "node-1=comp001",
		"SHERLOCK_GPU_PROCESS_INVENTORY_FILE": inventory,
	} {
		t.Setenv(key, value)
	}
	cfg, err := loadGPUProcessObservation("pilot-cluster")
	if err != nil || len(cfg.GPUs[domain.StableNodeID("node-1")]) != 1 {
		t.Fatalf("GPU observation config = %+v, err=%v", cfg, err)
	}
	if cfg.GPUs["node-1"][0].PhysicalGPUUUID != "GPU-11111111-2222-3333-4444-555555555555" {
		t.Fatalf("GPU mapping = %+v", cfg.GPUs)
	}
}

func TestLoadGPUProcessInventoryRejectsTrailingDocuments(t *testing.T) {
	directory := t.TempDir()
	for _, trailing := range []string{"{}", "garbage"} {
		path := filepath.Join(directory, "inventory-"+string(rune('a'+len(trailing)))+".json")
		if err := os.WriteFile(path, []byte(`{"nodes":[]} `+trailing), 0o600); err != nil {
			t.Fatal(err)
		}
		err := loadGPUProcessInventory(path, "cluster", map[domain.StableNodeID]string{"node-1": "comp001"}, map[domain.StableNodeID][]domain.EntityIdentity{})
		if err == nil {
			t.Fatalf("trailing %q accepted", trailing)
		}
	}
}
