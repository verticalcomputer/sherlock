package config

import (
	"encoding/base64"
	"path/filepath"
	"testing"
)

func TestLoadInvestigatorRequiresDedicatedIdentityAndBoundedConcurrency(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
	t.Setenv("SHERLOCK_AZURE_OPENAI_ENDPOINT", "https://fixture.openai.azure.com/openai/v1")
	t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "secret")
	t.Setenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "gpt")
	t.Setenv("SHERLOCK_MODEL_CONFIGURATION_ID", "config-v1")
	t.Setenv("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "1")
	t.Setenv("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", "1")
	t.Setenv("SHERLOCK_MODEL_ALLOWED_CLUSTERS", "cluster-a")
	t.Setenv("SHERLOCK_ARTIFACT_BACKEND", "local")
	t.Setenv("SHERLOCK_MODEL_AUDIT_ARTIFACT_ROOT", filepath.Join(t.TempDir(), "audit"))
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if _, err := LoadInvestigator(); err == nil {
		t.Fatal("missing investigator identity accepted")
	}
	t.Setenv("SHERLOCK_INVESTIGATOR_ID", "investigator-a")
	cfg, err := LoadInvestigator()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConcurrent != 4 || len(cfg.AllowedClusters) != 1 {
		t.Fatalf("config=%+v", cfg)
	}
	if cfg.MemoryMode != "DISABLED" || cfg.ContextMaxTokens != 20_000 || cfg.MemoryMaxTokens != 1_000 || cfg.MemoryMaxEntries != 12 {
		t.Fatalf("unsafe M11 defaults: %+v", cfg)
	}
	t.Setenv("SHERLOCK_CLUSTER_MEMORY_MODE", "true")
	if _, err := LoadInvestigator(); err == nil {
		t.Fatal("ambiguous memory enablement accepted")
	}
	t.Setenv("SHERLOCK_CLUSTER_MEMORY_MODE", "SHADOW")
	t.Setenv("SHERLOCK_INVESTIGATOR_MAX_CONCURRENT", "129")
	if _, err := LoadInvestigator(); err == nil {
		t.Fatal("unsafe concurrency accepted")
	}
}

// Diagnostic execution is a separate decision from letting the model reason
// about a cluster, and it cannot start without the means to verify the pack
// whose argv it will run.
func TestDiagnosticExecutionClustersAreOptInAndRequireAVerifiablePack(t *testing.T) {
	base := func(t *testing.T) {
		t.Helper()
		t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
		t.Setenv("SHERLOCK_INVESTIGATOR_ID", "investigator-a")
		t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
		t.Setenv("SHERLOCK_AZURE_OPENAI_ENDPOINT", "https://fixture.openai.azure.com/openai/v1")
		t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "secret")
		t.Setenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "gpt")
		t.Setenv("SHERLOCK_MODEL_CONFIGURATION_ID", "config-v1")
		t.Setenv("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "1")
		t.Setenv("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", "1")
		t.Setenv("SHERLOCK_MODEL_ALLOWED_CLUSTERS", "cluster-a")
		t.Setenv("SHERLOCK_ARTIFACT_BACKEND", "local")
		t.Setenv("SHERLOCK_MODEL_AUDIT_ARTIFACT_ROOT", filepath.Join(t.TempDir(), "audit"))
		t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		t.Setenv("SHERLOCK_DIAGNOSTIC_EXECUTION_CLUSTERS", "")
		t.Setenv("SHERLOCK_COMMAND_PACK_FILE", "")
		t.Setenv("SHERLOCK_COMMAND_TRUST_ROOTS_FILE", "")
		t.Setenv("SHERLOCK_RUNNER_VERSION", "")
	}

	t.Run("absent by default", func(t *testing.T) {
		base(t)
		cfg, err := LoadInvestigator()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.DiagnosticClusters) != 0 {
			t.Fatalf("diagnostic execution was enabled without being asked for: %v", cfg.DiagnosticClusters)
		}
	})

	t.Run("must be an allowed cluster", func(t *testing.T) {
		base(t)
		t.Setenv("SHERLOCK_DIAGNOSTIC_EXECUTION_CLUSTERS", "cluster-b")
		if _, err := LoadInvestigator(); err == nil {
			t.Fatal("a cluster the model may not reason about was granted execution")
		}
	})

	t.Run("requires a verifiable pack", func(t *testing.T) {
		base(t)
		t.Setenv("SHERLOCK_DIAGNOSTIC_EXECUTION_CLUSTERS", "cluster-a")
		if _, err := LoadInvestigator(); err == nil {
			t.Fatal("diagnostic execution started with no pack, trust roots, or runner version")
		}
		t.Setenv("SHERLOCK_COMMAND_PACK_FILE", "/etc/sherlock/pack.json")
		t.Setenv("SHERLOCK_COMMAND_TRUST_ROOTS_FILE", "/etc/sherlock/roots.json")
		if _, err := LoadInvestigator(); err == nil {
			t.Fatal("diagnostic execution started with no runner version")
		}
		t.Setenv("SHERLOCK_RUNNER_VERSION", "1.4.0")
		cfg, err := LoadInvestigator()
		if err != nil {
			t.Fatalf("a complete diagnostic configuration must load: %v", err)
		}
		if len(cfg.DiagnosticClusters) != 1 || cfg.DiagnosticClusters[0] != "cluster-a" {
			t.Fatalf("diagnostic clusters = %v", cfg.DiagnosticClusters)
		}
		if cfg.CommandPackFile == "" || cfg.TrustRootsFile == "" || cfg.RunnerVersion == "" {
			t.Fatalf("pack verification inputs were not captured: %+v", cfg)
		}
	})
}
