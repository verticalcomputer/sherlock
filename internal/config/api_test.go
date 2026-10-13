package config

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestLoadAPIRequiresKeyedHashSecretAndRejectsWildcardCORS(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", "")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "HASH_KEY") {
		t.Fatalf("expected hash-key error, got %v", err)
	}
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_API_ALLOWED_ORIGINS", "*")
	if _, err := LoadAPI(); err == nil {
		t.Fatal("expected wildcard CORS error")
	}
}

func TestLoadAPIAcceptsExplicitOriginsAndPairedTLS(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_API_ALLOWED_ORIGINS", "https://app.example, http://localhost:3000,https://app.example")
	t.Setenv("SHERLOCK_API_CERT_FILE", "server.crt")
	t.Setenv("SHERLOCK_API_KEY_FILE", "server.key")
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedOrigins) != 2 || cfg.TLSPrivateKey != "server.key" {
		t.Fatalf("unexpected API config: %+v", cfg)
	}
}

func TestLoadAPIPrivateAdminListenerIsDisabledWithLoopbackDefault(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_ADMIN_API_ENABLED", "")
	t.Setenv("SHERLOCK_ADMIN_API_ADDRESS", "")
	t.Setenv("SHERLOCK_ADMIN_API_CERT_FILE", "")
	t.Setenv("SHERLOCK_ADMIN_API_KEY_FILE", "")
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", "")
	t.Setenv("SHERLOCK_ADMIN_HUMAN_SESSION_REQUIRED", "")
	t.Setenv("SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED", "")
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminAPIEnabled || cfg.AdminHumanSessionRequired || cfg.AdminHumanAuthorizationRequired || cfg.AdminAPIListenAddress != defaultAdminAPIAddress || cfg.AdminAPIServiceToken.Configured() {
		t.Fatalf("unexpected private admin API defaults: %+v", cfg)
	}
}

func TestLoadAPIHumanSessionGateIsExplicitAndNeedsPrivateAPI(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_ADMIN_API_ENABLED", "")
	t.Setenv("SHERLOCK_ADMIN_HUMAN_SESSION_REQUIRED", "true")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "requires the private admin API") {
		t.Fatalf("enabled without API: %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_API_ENABLED", "true")
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", strings.Repeat("t", minimumServiceTokenLength))
	cfg, err := LoadAPI()
	if err != nil || !cfg.AdminHumanSessionRequired {
		t.Fatalf("enabled gate=%+v err=%v", cfg, err)
	}
	t.Setenv("SHERLOCK_ADMIN_HUMAN_SESSION_REQUIRED", "")
	t.Setenv("SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED", "true")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "requires human sessions") {
		t.Fatalf("authorization without session: %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_HUMAN_SESSION_REQUIRED", "true")
	cfg, err = LoadAPI()
	if err != nil || !cfg.AdminHumanAuthorizationRequired {
		t.Fatalf("authorization gate=%+v err=%v", cfg, err)
	}
}

func TestLoadAPIPrivateAdminListenerRequiresServiceToken(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_ADMIN_API_ENABLED", "true")
	t.Setenv("SHERLOCK_ADMIN_API_ADDRESS", "127.0.0.1:8082")
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", "too-short")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "ADMIN_API_TOKEN") {
		t.Fatalf("short private admin API token error = %v", err)
	}

	serviceToken := strings.Repeat("private-service-token-", 2)
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", serviceToken)
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AdminAPIEnabled || cfg.AdminAPIServiceToken.Reveal() != serviceToken {
		t.Fatal("private admin API service token was not loaded")
	}
	if rendered := fmt.Sprintf("%+v", cfg); strings.Contains(rendered, serviceToken) {
		t.Fatalf("private admin API token rendered in config: %q", rendered)
	}
}

func TestLoadAPIPrivateAdminListenerRequiresTLSOffLoopback(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_ADMIN_API_ENABLED", "true")
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", strings.Repeat("t", minimumServiceTokenLength))
	t.Setenv("SHERLOCK_ADMIN_API_ADDRESS", "0.0.0.0:8082")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "requires private admin API TLS") {
		t.Fatalf("non-TLS private admin listener error = %v", err)
	}

	t.Setenv("SHERLOCK_ADMIN_API_CERT_FILE", "admin-api.crt")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial private admin TLS error = %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_API_KEY_FILE", "admin-api.key")
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatalf("safe private admin listener rejected: %v", err)
	}
	if cfg.AdminAPITLSCertificate != "admin-api.crt" || cfg.AdminAPITLSPrivateKey != "admin-api.key" {
		t.Fatalf("private admin API TLS files not loaded: %+v", cfg)
	}
}

func TestLoadAPIRequiresCompleteDiagnosticTrustConfiguration(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_COMMAND_PACK_FILE", "/etc/sherlock/pack.json")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial diagnostic config error = %v", err)
	}
	t.Setenv("SHERLOCK_COMMAND_TRUST_ROOTS_FILE", "/etc/sherlock/roots.json")
	t.Setenv("SHERLOCK_DIAGNOSTIC_INVENTORY_FILE", "/etc/sherlock/inventory.json")
	t.Setenv("SHERLOCK_RUNNER_VERSION", "1.0.0")
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RunnerVersion != "1.0.0" {
		t.Fatalf("runner version = %q", cfg.RunnerVersion)
	}
}

func TestLoadAPIDoesNotOwnModelProviderConfiguration(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
	t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "runtime-model-secret")
	if _, err := LoadAPI(); err != nil {
		t.Fatalf("API coupled to investigator model configuration: %v", err)
	}
}

func TestLoadAPIArtifactBackendIsBoundedWhenConfigured(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
	t.Setenv("SHERLOCK_AZURE_OPENAI_ENDPOINT", "https://fixture.openai.azure.com/openai/v1/")
	t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "runtime-model-secret")
	t.Setenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "deployment-a")
	t.Setenv("SHERLOCK_MODEL_CONFIGURATION_ID", "config-v1")
	t.Setenv("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "1250000")
	t.Setenv("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", "5000000")
	t.Setenv("SHERLOCK_MODEL_ALLOWED_CLUSTERS", "cluster-a")
	t.Setenv("SHERLOCK_MODEL_AUDIT_ARTIFACT_ROOT", "")
	if _, err := LoadAPI(); err != nil {
		t.Fatalf("optional artifact backend: %v", err)
	}
	t.Setenv("SHERLOCK_MODEL_AUDIT_ARTIFACT_ROOT", "relative/path")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative model audit artifact root error = %v", err)
	}
	t.Setenv("SHERLOCK_MODEL_AUDIT_ARTIFACT_ROOT", t.TempDir())
	t.Setenv("SHERLOCK_MODEL_AUDIT_ARTIFACT_MAX_BYTES", "4194305")
	if _, err := LoadAPI(); err == nil || !strings.Contains(err.Error(), "MODEL_AUDIT_ARTIFACT_MAX_BYTES") {
		t.Fatalf("oversized model audit payload limit error = %v", err)
	}
}

func TestLoadAPIAzureModelAcceptsR2ArtifactBackendWithoutLocalRoot(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://test")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
	t.Setenv("SHERLOCK_AZURE_OPENAI_ENDPOINT", "https://fixture.openai.azure.com/openai/v1/")
	t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "runtime-model-secret")
	t.Setenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "deployment-a")
	t.Setenv("SHERLOCK_MODEL_CONFIGURATION_ID", "config-v1")
	t.Setenv("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "1")
	t.Setenv("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", "1")
	t.Setenv("SHERLOCK_MODEL_ALLOWED_CLUSTERS", "cluster-a")
	t.Setenv("SHERLOCK_MODEL_AUDIT_ARTIFACT_ROOT", "")
	t.Setenv("SHERLOCK_ARTIFACT_BACKEND", "r2")
	t.Setenv("SHERLOCK_R2_ENDPOINT", "https://account.r2.cloudflarestorage.com")
	t.Setenv("SHERLOCK_R2_BUCKET", "sherlock-audit")
	t.Setenv("SHERLOCK_R2_ACCESS_KEY_ID", "access-id")
	t.Setenv("SHERLOCK_R2_SECRET_ACCESS_KEY", "secret-value")
	t.Setenv("SHERLOCK_R2_PREFIX", "sherlock/model-audit")
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ArtifactStorage.Backend != ArtifactBackendR2 || cfg.ArtifactStorage.LocalRoot != "" {
		t.Fatalf("R2 artifact configuration=%+v", cfg.ArtifactStorage)
	}
	if rendered := fmt.Sprintf("%+v", cfg.ArtifactStorage); strings.Contains(rendered, "secret-value") {
		t.Fatalf("R2 secret rendered in configuration: %q", rendered)
	}
}
