package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBCMAccessTestConfigurationIsOptInAndBounded(t *testing.T) {
	t.Setenv("SHERLOCK_BCM_ACCESS_TEST_ENABLED", "")
	t.Setenv("SHERLOCK_BCM_ACCESS_TEST_EXTERNAL_WORKER", "")
	t.Setenv("SHERLOCK_BCM_ACCESS_TEST_HOST", "")
	cfg, err := loadBCMAccessTest()
	if err != nil || cfg.Enabled {
		t.Fatalf("default must be disabled: %+v %v", cfg, err)
	}
	t.Setenv("SHERLOCK_BCM_ACCESS_TEST_ENABLED", "true")
	if _, err := loadBCMAccessTest(); err == nil {
		t.Fatal("enabled without host must fail")
	}
	t.Setenv("SHERLOCK_BCM_ACCESS_TEST_HOST", "fixture1-zone1-headnode")
	cfg, err = loadBCMAccessTest()
	if err != nil || !cfg.Enabled || cfg.SudoPath != "/usr/bin/sudo" || cfg.CmshPath != "/cm/local/apps/cmd/bin/cmsh" || cfg.ReleaseFile != "/etc/cm-release" || cfg.ExpectedHost != "fixture1-zone1-headnode" {
		t.Fatalf("enabled defaults: %+v %v", cfg, err)
	}
	t.Setenv("SHERLOCK_BCM_CMSH_EXECUTABLE", "cmsh")
	if _, err := loadBCMAccessTest(); err == nil {
		t.Fatal("relative executable accepted")
	}
	t.Setenv("SHERLOCK_BCM_CMSH_EXECUTABLE", "/opt/cmsh -c 'device list'")
	if _, err := loadBCMAccessTest(); err == nil {
		t.Fatal("executable with shell text accepted")
	}
	t.Setenv("SHERLOCK_BCM_CMSH_EXECUTABLE", "/cm/local/apps/cmd/bin/cmsh")
	t.Setenv("SHERLOCK_BCM_RELEASE_FILE", "cm-release")
	if _, err := loadBCMAccessTest(); err == nil {
		t.Fatal("relative release file accepted")
	}
	t.Setenv("SHERLOCK_BCM_RELEASE_FILE", "/etc/cm-release-staging")
	cfg, err = loadBCMAccessTest()
	if err != nil || cfg.ReleaseFile != "/etc/cm-release-staging" {
		t.Fatalf("custom release file: %+v %v", cfg, err)
	}
	t.Setenv("SHERLOCK_BCM_ACCESS_TEST_ENABLED", "false")
	t.Setenv("SHERLOCK_BCM_ACCESS_TEST_EXTERNAL_WORKER", "true")
	cfg, err = loadBCMAccessTest()
	if err != nil || cfg.Enabled || !cfg.ExternalWorker || cfg.ExpectedHost != "fixture1-zone1-headnode" {
		t.Fatalf("external worker configuration: %+v %v", cfg, err)
	}
	t.Setenv("SHERLOCK_BCM_ACCESS_TEST_ENABLED", "true")
	if _, err := loadBCMAccessTest(); err == nil {
		t.Fatal("embedded and external BCM workers accepted together")
	}
}

func TestControlLoadsOptionalCredentialKeyring(t *testing.T) {
	dir := t.TempDir()
	for name, value := range map[string]string{
		"SHERLOCK_DATABASE_URL": "postgres://example", "SHERLOCK_CONTROL_CERT_FILE": "cert", "SHERLOCK_CONTROL_KEY_FILE": "key",
		"SHERLOCK_COLLECTOR_CA_FILE": "ca", "SHERLOCK_COLLECTOR_CA_KEY_FILE": "cakey", "SHERLOCK_CONTROL_COLLECTOR_AUTH_MODE": "direct_mtls",
		"SHERLOCK_CREDENTIAL_KEYRING_FILE": "",
	} {
		t.Setenv(name, value)
	}
	cfg, err := LoadControl()
	if err != nil || cfg.CredentialKeyring.ActiveVersion != "" {
		t.Fatalf("control without keyring: %v %+v", err, cfg.CredentialKeyring.ActiveVersion)
	}
	path := filepath.Join(dir, "keyring.json")
	if err := os.WriteFile(path, []byte(`{"active_version":"v1","keys":{"v1":"`+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHERLOCK_CREDENTIAL_KEYRING_FILE", path)
	cfg, err = LoadControl()
	if err != nil || cfg.CredentialKeyring.ActiveVersion != "v1" || len(cfg.CredentialKeyring.Keys["v1"]) != 32 {
		t.Fatalf("control with keyring: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControl(); err == nil {
		t.Fatal("permissive keyring accepted by control")
	}
}
