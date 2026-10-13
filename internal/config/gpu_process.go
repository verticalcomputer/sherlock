package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// GPUProcessObservationConfig is a separate, default-off authority for the
// recurring read-only NVIDIA observation source. It deliberately has no
// credential, command, or diagnostic-runner field.
type GPUProcessObservationConfig struct {
	Enabled                   bool
	SourceID                  string
	CommandPackFile           string
	TrustRootsFile            string
	RunnerVersion             string
	SSHExecutable             string
	SSHExecutableSHA256       string
	SSHKnownHostsFile         string
	SSHTargetAuthentication   string
	SSHPolicyFile             string
	InventoryFile             string
	Nodes                     map[domain.StableNodeID]string
	GPUs                      map[domain.StableNodeID][]domain.EntityIdentity
	CompleteComputeVisibility bool
	PhysicalOnly              bool
}

func loadGPUProcessObservation(clusterID string) (GPUProcessObservationConfig, error) {
	enabled, err := boolEnv("SHERLOCK_GPU_PROCESS_OBSERVATIONS_ENABLED", false)
	if err != nil {
		return GPUProcessObservationConfig{}, err
	}
	cfg := GPUProcessObservationConfig{
		Enabled:                 enabled,
		SourceID:                valueOrDefault("SHERLOCK_GPU_PROCESS_SOURCE_ID", "local-gpu-process"),
		CommandPackFile:         strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_COMMAND_PACK_FILE")),
		TrustRootsFile:          strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_TRUST_ROOTS_FILE")),
		RunnerVersion:           strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_RUNNER_VERSION")),
		SSHExecutable:           strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_SSH_EXECUTABLE")),
		SSHExecutableSHA256:     strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_SSH_SHA256")),
		SSHKnownHostsFile:       strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_KNOWN_HOSTS_FILE")),
		SSHTargetAuthentication: strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_TARGET_AUTH_FILE")),
		SSHPolicyFile:           strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_POLICY_FILE")),
		InventoryFile:           strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_INVENTORY_FILE")),
		Nodes:                   make(map[domain.StableNodeID]string),
		GPUs:                    make(map[domain.StableNodeID][]domain.EntityIdentity),
	}
	if !enabled {
		return cfg, nil
	}
	if cfg.CompleteComputeVisibility, err = boolEnv("SHERLOCK_GPU_PROCESS_COMPLETE_VISIBILITY", false); err != nil {
		return GPUProcessObservationConfig{}, err
	}
	if cfg.PhysicalOnly, err = boolEnv("SHERLOCK_GPU_PROCESS_PHYSICAL_ONLY", false); err != nil {
		return GPUProcessObservationConfig{}, err
	}
	if strings.TrimSpace(clusterID) == "" || cfg.SourceID == "" {
		return GPUProcessObservationConfig{}, fmt.Errorf("GPU process observations require cluster and source identifiers")
	}
	for name, value := range map[string]string{
		"SHERLOCK_GPU_PROCESS_COMMAND_PACK_FILE": cfg.CommandPackFile,
		"SHERLOCK_GPU_PROCESS_TRUST_ROOTS_FILE":  cfg.TrustRootsFile,
		"SHERLOCK_GPU_PROCESS_RUNNER_VERSION":    cfg.RunnerVersion,
		"SHERLOCK_GPU_PROCESS_SSH_EXECUTABLE":    cfg.SSHExecutable,
		"SHERLOCK_GPU_PROCESS_SSH_SHA256":        cfg.SSHExecutableSHA256,
		"SHERLOCK_GPU_PROCESS_KNOWN_HOSTS_FILE":  cfg.SSHKnownHostsFile,
		"SHERLOCK_GPU_PROCESS_TARGET_AUTH_FILE":  cfg.SSHTargetAuthentication,
		"SHERLOCK_GPU_PROCESS_POLICY_FILE":       cfg.SSHPolicyFile,
		"SHERLOCK_GPU_PROCESS_INVENTORY_FILE":    cfg.InventoryFile,
	} {
		if value == "" {
			return GPUProcessObservationConfig{}, fmt.Errorf("%s is required when GPU process observations are enabled", name)
		}
	}
	rawNodes := strings.TrimSpace(os.Getenv("SHERLOCK_GPU_PROCESS_NODE_MAP"))
	if rawNodes == "" {
		return GPUProcessObservationConfig{}, fmt.Errorf("SHERLOCK_GPU_PROCESS_NODE_MAP is required when GPU process observations are enabled")
	}
	seenNames := map[string]bool{}
	for _, raw := range strings.Split(rawNodes, ",") {
		stable, target, ok := strings.Cut(strings.TrimSpace(raw), "=")
		stable, target = strings.TrimSpace(stable), strings.TrimSpace(target)
		if !ok || stable == "" || target == "" || cfg.Nodes[domain.StableNodeID(stable)] != "" || seenNames[target] {
			return GPUProcessObservationConfig{}, fmt.Errorf("SHERLOCK_GPU_PROCESS_NODE_MAP requires unique stable_id=target entries")
		}
		cfg.Nodes[domain.StableNodeID(stable)] = target
		seenNames[target] = true
	}
	if len(cfg.Nodes) == 0 || len(cfg.Nodes) > 16 {
		return GPUProcessObservationConfig{}, fmt.Errorf("SHERLOCK_GPU_PROCESS_NODE_MAP must contain between one and sixteen nodes")
	}
	if err := loadGPUProcessInventory(cfg.InventoryFile, domain.ClusterID(clusterID), cfg.Nodes, cfg.GPUs); err != nil {
		return GPUProcessObservationConfig{}, err
	}
	return cfg, nil
}

type gpuProcessInventoryDocument struct {
	Nodes []struct {
		StableID string `json:"stable_id"`
		GPUs     []struct {
			UUID string `json:"uuid"`
		} `json:"gpus"`
	} `json:"nodes"`
}

func loadGPUProcessInventory(path string, clusterID domain.ClusterID, targets map[domain.StableNodeID]string, destination map[domain.StableNodeID][]domain.EntityIdentity) error {
	payload, err := commandpack.ReadProtectedFile(path, 1<<20)
	if err != nil {
		return fmt.Errorf("load GPU process inventory: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var document gpuProcessInventoryDocument
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode GPU process inventory")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("GPU process inventory carries trailing data")
	}
	if len(document.Nodes) != len(targets) {
		return fmt.Errorf("GPU process inventory must cover every configured node")
	}
	seenNodes := map[domain.StableNodeID]bool{}
	for _, node := range document.Nodes {
		stable := domain.StableNodeID(strings.TrimSpace(node.StableID))
		if stable == "" || seenNodes[stable] || targets[stable] == "" || len(node.GPUs) == 0 || len(node.GPUs) > 256 {
			return fmt.Errorf("GPU process inventory has an invalid or duplicate node")
		}
		seenNodes[stable] = true
		seen := map[domain.PhysicalGPUUUID]bool{}
		for _, gpu := range node.GPUs {
			uuid := domain.PhysicalGPUUUID(strings.TrimSpace(gpu.UUID))
			identity := domain.EntityIdentity{ClusterID: clusterID, Kind: domain.EntityGPU, NodeID: stable, PhysicalGPUUUID: uuid}
			if seen[uuid] || uuid == "" {
				return fmt.Errorf("GPU process inventory has an invalid or duplicate GPU")
			}
			if _, err := domain.CreateEntityIdentity(identity); err != nil {
				return fmt.Errorf("GPU process inventory has an invalid GPU identity")
			}
			seen[uuid] = true
			destination[stable] = append(destination[stable], identity)
		}
	}
	return nil
}
