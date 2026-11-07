package config

import (
	"path/filepath"
	"testing"
)

func TestRenewalDoesNotLoadCollectionOrDiagnostics(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.invalid")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "existing-collector")
	t.Setenv("SHERLOCK_COLLECTOR_IDENTITY_DIR", filepath.Join(t.TempDir(), "identity"))
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "/public/control.pem")
	t.Setenv("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE", "direct_mtls")
	t.Setenv("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE", "")
	t.Setenv("SHERLOCK_GPU_PROCESS_OBSERVATIONS_ENABLED", "true")
	t.Setenv("SHERLOCK_COLLECTION_OPERATIONS", "not-an-operation")
	t.Setenv("SHERLOCK_SLURM_NODE_MAP", "malformed")
	t.Setenv("SHERLOCK_COMMAND_PACK_FILE", "/missing/expired-pack")
	cfg, err := LoadCollectorRenewal()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CollectorID != "existing-collector" || cfg.CertificateFile != cfg.IdentityDir+"/current/cert.pem" {
		t.Fatalf("identity not preserved: %#v", cfg)
	}
	if _, err := LoadCollector(); err == nil {
		t.Fatal("ordinary collection unexpectedly ignored invalid config")
	}
}
