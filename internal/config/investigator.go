package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Investigator struct {
	DatabaseURL     string
	WorkerID        string
	PollInterval    time.Duration
	LeaseDuration   time.Duration
	MaxConcurrent   int
	MaxGlobal       int
	MaxPerCluster   int
	Model           Model
	AllowedClusters []string
	// DiagnosticClusters may execute reviewed diagnostics under AI direction.
	// It is empty by default and is a separate decision from AllowedClusters:
	// a cluster the model may reason about is not thereby a cluster it may run
	// commands on. Every entry must also appear in AllowedClusters.
	DiagnosticClusters []string
	// CommandPackFile, TrustRootsFile, and RunnerVersion are required only when
	// a diagnostic cluster is configured: without them the investigator cannot
	// verify the pack, and it must refuse to start rather than execute anything
	// it has not verified.
	CommandPackFile  string
	TrustRootsFile   string
	RunnerVersion    string
	ArtifactStorage  ArtifactStorage
	ArtifactMaxBytes int64
	MemoryMode       string
	ContextMaxTokens int64
	MemoryMaxTokens  int64
	MemoryMaxEntries int
}

func LoadInvestigator() (Investigator, error) {
	if err := loadLocalEnv(); err != nil {
		return Investigator{}, err
	}
	model, err := LoadModel()
	if err != nil {
		return Investigator{}, err
	}
	storage, err := LoadArtifactStorage()
	if err != nil {
		return Investigator{}, err
	}
	cfg := Investigator{
		DatabaseURL: os.Getenv("SHERLOCK_DATABASE_URL"), WorkerID: strings.TrimSpace(os.Getenv("SHERLOCK_INVESTIGATOR_ID")),
		PollInterval: 500 * time.Millisecond, LeaseDuration: 30 * time.Second, MaxConcurrent: 4, MaxGlobal: 16, MaxPerCluster: 4,
		Model: model, ArtifactStorage: storage, ArtifactMaxBytes: 1 << 20,
		MemoryMode: "DISABLED", ContextMaxTokens: 20_000, MemoryMaxTokens: 1_000, MemoryMaxEntries: 12,
	}
	if value := strings.ToUpper(strings.TrimSpace(os.Getenv("SHERLOCK_CLUSTER_MEMORY_MODE"))); value != "" {
		cfg.MemoryMode = value
	}
	if value, parseErr := intEnv("SHERLOCK_MODEL_CONTEXT_MAX_TOKENS", int(cfg.ContextMaxTokens)); parseErr != nil {
		return Investigator{}, parseErr
	} else {
		cfg.ContextMaxTokens = int64(value)
	}
	if value, parseErr := intEnv("SHERLOCK_MODEL_MEMORY_MAX_TOKENS", int(cfg.MemoryMaxTokens)); parseErr != nil {
		return Investigator{}, parseErr
	} else {
		cfg.MemoryMaxTokens = int64(value)
	}
	if cfg.MemoryMaxEntries, err = intEnv("SHERLOCK_MODEL_MEMORY_MAX_ENTRIES", cfg.MemoryMaxEntries); err != nil {
		return Investigator{}, err
	}
	if cfg.PollInterval, err = durationEnv("SHERLOCK_INVESTIGATOR_POLL_INTERVAL", cfg.PollInterval); err != nil {
		return Investigator{}, err
	}
	if cfg.LeaseDuration, err = durationEnv("SHERLOCK_INVESTIGATOR_LEASE_DURATION", cfg.LeaseDuration); err != nil {
		return Investigator{}, err
	}
	if cfg.MaxConcurrent, err = intEnv("SHERLOCK_INVESTIGATOR_MAX_CONCURRENT", cfg.MaxConcurrent); err != nil {
		return Investigator{}, err
	}
	if cfg.MaxGlobal, err = intEnv("SHERLOCK_INVESTIGATOR_MAX_GLOBAL", cfg.MaxGlobal); err != nil {
		return Investigator{}, err
	}
	if cfg.MaxPerCluster, err = intEnv("SHERLOCK_INVESTIGATOR_MAX_PER_CLUSTER", cfg.MaxPerCluster); err != nil {
		return Investigator{}, err
	}
	if bytes, parseErr := intEnv("SHERLOCK_MODEL_AUDIT_ARTIFACT_MAX_BYTES", int(cfg.ArtifactMaxBytes)); parseErr != nil {
		return Investigator{}, parseErr
	} else {
		cfg.ArtifactMaxBytes = int64(bytes)
	}
	seen := map[string]struct{}{}
	for _, value := range strings.Split(strings.TrimSpace(os.Getenv("SHERLOCK_MODEL_ALLOWED_CLUSTERS")), ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, " \t\r\n") {
			return Investigator{}, fmt.Errorf("SHERLOCK_MODEL_ALLOWED_CLUSTERS must be a comma-separated list of cluster IDs")
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			cfg.AllowedClusters = append(cfg.AllowedClusters, value)
		}
	}
	// Diagnostic execution is opt-in per cluster, and only for a cluster the
	// model is already allowed to reason about. That is one decision per cluster
	// onboarding rather than one per host, and it is the decision that carries
	// the risk.
	allowed := seen
	diagnosticSeen := map[string]struct{}{}
	for _, value := range strings.Split(strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_EXECUTION_CLUSTERS")), ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, " \t\r\n") {
			return Investigator{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_EXECUTION_CLUSTERS must be a comma-separated list of cluster IDs")
		}
		if _, ok := allowed[value]; !ok {
			return Investigator{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_EXECUTION_CLUSTERS contains a cluster that is not in SHERLOCK_MODEL_ALLOWED_CLUSTERS")
		}
		if _, ok := diagnosticSeen[value]; !ok {
			diagnosticSeen[value] = struct{}{}
			cfg.DiagnosticClusters = append(cfg.DiagnosticClusters, value)
		}
	}
	if len(cfg.DiagnosticClusters) > 0 {
		cfg.CommandPackFile = strings.TrimSpace(os.Getenv("SHERLOCK_COMMAND_PACK_FILE"))
		cfg.TrustRootsFile = strings.TrimSpace(os.Getenv("SHERLOCK_COMMAND_TRUST_ROOTS_FILE"))
		cfg.RunnerVersion = strings.TrimSpace(os.Getenv("SHERLOCK_RUNNER_VERSION"))
		if cfg.CommandPackFile == "" || cfg.TrustRootsFile == "" || cfg.RunnerVersion == "" {
			return Investigator{}, fmt.Errorf("diagnostic execution requires SHERLOCK_COMMAND_PACK_FILE, SHERLOCK_COMMAND_TRUST_ROOTS_FILE, and SHERLOCK_RUNNER_VERSION")
		}
	}
	if cfg.DatabaseURL == "" || cfg.WorkerID == "" {
		return Investigator{}, fmt.Errorf("SHERLOCK_DATABASE_URL and SHERLOCK_INVESTIGATOR_ID are required")
	}
	if cfg.Model.Provider == "" || len(cfg.AllowedClusters) == 0 || !cfg.ArtifactStorage.Configured() {
		return Investigator{}, fmt.Errorf("investigator requires a complete model configuration, allowed clusters, and artifact backend")
	}
	if cfg.PollInterval < 50*time.Millisecond || cfg.LeaseDuration < 3*cfg.PollInterval || cfg.LeaseDuration > 10*time.Minute || cfg.MaxConcurrent < 1 || cfg.MaxConcurrent > 128 || cfg.MaxGlobal < cfg.MaxConcurrent || cfg.MaxGlobal > 1024 || cfg.MaxPerCluster < 1 || cfg.MaxPerCluster > cfg.MaxGlobal {
		return Investigator{}, fmt.Errorf("investigator polling, lease, or concurrency setting is outside safety bounds")
	}
	if cfg.ArtifactMaxBytes < 1 || cfg.ArtifactMaxBytes > 4<<20 {
		return Investigator{}, fmt.Errorf("SHERLOCK_MODEL_AUDIT_ARTIFACT_MAX_BYTES must be between 1 byte and 4 MiB")
	}
	if (cfg.MemoryMode != "DISABLED" && cfg.MemoryMode != "SHADOW" && cfg.MemoryMode != "ENABLED") || cfg.ContextMaxTokens < 1024 || cfg.ContextMaxTokens > 1_000_000 || cfg.MemoryMaxTokens < 0 || cfg.MemoryMaxTokens > cfg.ContextMaxTokens || cfg.MemoryMaxEntries < 0 || cfg.MemoryMaxEntries > 12 {
		return Investigator{}, fmt.Errorf("cluster memory or context budget setting is outside safety bounds")
	}
	return cfg, nil
}
