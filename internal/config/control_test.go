package config

import (
	"strings"
	"testing"
	"time"
)

func setControlRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://control.test/sherlock")
	t.Setenv("SHERLOCK_CONTROL_CERT_FILE", "server.crt")
	t.Setenv("SHERLOCK_CONTROL_KEY_FILE", "server.key")
	t.Setenv("SHERLOCK_COLLECTOR_CA_FILE", "collector-ca.crt")
	t.Setenv("SHERLOCK_COLLECTOR_CA_KEY_FILE", "collector-ca.key")
}

func TestLoadControlSafeDefaults(t *testing.T) {
	setControlRequiredEnv(t)
	cfg, err := LoadControl()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "127.0.0.1:8443" || cfg.IdentityTTL != 12*time.Hour || cfg.WriteTimeout < 31*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadControlRequiresAllKeyMaterialPaths(t *testing.T) {
	setControlRequiredEnv(t)
	t.Setenv("SHERLOCK_COLLECTOR_CA_KEY_FILE", "")
	if _, err := LoadControl(); err == nil || !strings.Contains(err.Error(), "CA key") {
		t.Fatalf("expected missing CA key error, got %v", err)
	}
}

func TestLoadControlRejectsWriteTimeoutBelowLongPoll(t *testing.T) {
	setControlRequiredEnv(t)
	t.Setenv("SHERLOCK_CONTROL_WRITE_TIMEOUT", "30s")
	if _, err := LoadControl(); err == nil {
		t.Fatal("LoadControl accepted a write timeout that truncates maximum long polling")
	}
}

func TestLoadControlAdminBoundsBootstrapTTL(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://control.test/sherlock")
	t.Setenv("SHERLOCK_BOOTSTRAP_TTL", "25h")
	if _, err := LoadControlAdmin(); err == nil {
		t.Fatal("LoadControlAdmin accepted a bootstrap lifetime over 24 hours")
	}
}

// Execution is opt-in per collector, and the default must leave the control
// plane with no execution surface at all.
func TestLoadControlLeavesDiagnosticExecutionOffByDefault(t *testing.T) {
	setControlRequiredEnv(t)
	cfg, err := LoadControl()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DiagnosticExecutionCollectors) != 0 {
		t.Fatalf("diagnostic execution was enabled without configuration: %v", cfg.DiagnosticExecutionCollectors)
	}
	t.Setenv("SHERLOCK_DIAGNOSTIC_EXECUTION_COLLECTORS", " collector-head , collector-head-2 ,")
	cfg, err = LoadControl()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DiagnosticExecutionCollectors) != 2 || cfg.DiagnosticExecutionCollectors[0] != "collector-head" || cfg.DiagnosticExecutionCollectors[1] != "collector-head-2" {
		t.Fatalf("allow-list = %v", cfg.DiagnosticExecutionCollectors)
	}
}

func setCloudflareControlEnv(t *testing.T) {
	t.Helper()
	setControlRequiredEnv(t)
	t.Setenv("SHERLOCK_CONTROL_COLLECTOR_AUTH_MODE", "cloudflare_access_service_token_pop")
	t.Setenv("SHERLOCK_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "https://team.cloudflareaccess.com")
	t.Setenv("SHERLOCK_CLOUDFLARE_ACCESS_AUDIENCE", "audience-1")
	t.Setenv("SHERLOCK_CONTROL_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
	t.Setenv("SHERLOCK_CONTROL_COLLECTOR_HOST", "collector.example.com")
	t.Setenv("SHERLOCK_CONTROL_ENROLLMENT_HOST", "collector-enroll.example.com")
}

func TestLoadControlCloudflareModeRequiresClosedLoopbackConfiguration(t *testing.T) {
	setCloudflareControlEnv(t)
	cfg, err := LoadControl()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CollectorAuthMode != CollectorAuthCloudflareAccessServiceTokenPoP || len(cfg.TrustedProxyPrefixes) != 2 {
		t.Fatalf("unexpected proxy configuration: %+v", cfg)
	}

	tests := map[string]func(*testing.T){
		"unknown mode":    func(t *testing.T) { t.Setenv("SHERLOCK_CONTROL_COLLECTOR_AUTH_MODE", "auto") },
		"public listener": func(t *testing.T) { t.Setenv("SHERLOCK_CONTROL_ADDRESS", "0.0.0.0:8443") },
		"http issuer": func(t *testing.T) {
			t.Setenv("SHERLOCK_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "http://team.cloudflareaccess.com")
		},
		"multiple audiences":   func(t *testing.T) { t.Setenv("SHERLOCK_CLOUDFLARE_ACCESS_AUDIENCE", "one,two") },
		"public proxy":         func(t *testing.T) { t.Setenv("SHERLOCK_CONTROL_TRUSTED_PROXY_CIDRS", "10.0.0.0/8") },
		"same enrollment host": func(t *testing.T) { t.Setenv("SHERLOCK_CONTROL_ENROLLMENT_HOST", "collector.example.com") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			setCloudflareControlEnv(t)
			mutate(t)
			if _, err := LoadControl(); err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
		})
	}
}

func TestLoadControlDirectModeIgnoresProxySettings(t *testing.T) {
	setControlRequiredEnv(t)
	t.Setenv("SHERLOCK_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "not a URL")
	cfg, err := LoadControl()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CollectorAuthMode != CollectorAuthDirectMTLS {
		t.Fatalf("mode = %q", cfg.CollectorAuthMode)
	}
}

func TestNodeIssuerOptionalButRequiresBothPaths(t *testing.T) {
	setControlRequiredEnv(t)
	t.Setenv("SHERLOCK_NODE_CA_FILE", "")
	t.Setenv("SHERLOCK_NODE_CA_KEY_FILE", "")
	cfg, e := LoadControl()
	if e != nil || cfg.NodeCA != "" || cfg.NodeCAPrivateKey != "" {
		t.Fatal("default issuer", e)
	}
	t.Setenv("SHERLOCK_NODE_CA_FILE", "/protected/node-ca.pem")
	if _, e = LoadControl(); e == nil {
		t.Fatal("unpaired node issuer accepted")
	}
	t.Setenv("SHERLOCK_NODE_CA_KEY_FILE", "/protected/node-ca-key.pem")
	if _, e = LoadControl(); e != nil {
		t.Fatal(e)
	}
}
