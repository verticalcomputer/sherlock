package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var adminEnvironment = []string{
	"SHERLOCK_ADMIN_ENABLED",
	"SHERLOCK_ADMIN_API_URL",
	"SHERLOCK_ADMIN_API_TOKEN",
	"SHERLOCK_ADMIN_API_TIMEOUT",
	"SHERLOCK_ADMIN_ADDRESS",
	"SHERLOCK_ADMIN_CERT_FILE",
	"SHERLOCK_ADMIN_KEY_FILE",
	"SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_TEAM_DOMAIN",
	"SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_AUDIENCE",
	"SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED",
	"SHERLOCK_ADMIN_READ_HEADER_TIMEOUT",
	"SHERLOCK_ADMIN_READ_TIMEOUT",
	"SHERLOCK_ADMIN_WRITE_TIMEOUT",
	"SHERLOCK_ADMIN_IDLE_TIMEOUT",
	"SHERLOCK_ADMIN_SHUTDOWN_TIMEOUT",
}

func clearAdminEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range adminEnvironment {
		t.Setenv(name, "")
	}
}

func setEnabledAdminEnvironment(t *testing.T) {
	t.Helper()
	clearAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_ENABLED", "true")
	t.Setenv("SHERLOCK_ADMIN_API_URL", "http://127.0.0.1:8082")
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", strings.Repeat("t", minimumServiceTokenLength))
	t.Setenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "https://team.cloudflareaccess.com")
	t.Setenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_AUDIENCE", "admin-audience")
}

func TestLoadAdminIsDisabledWithLoopbackSafeDefaults(t *testing.T) {
	clearAdminEnvironment(t)
	cfg, err := LoadAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled || cfg.HumanAuthorizationRequired || cfg.ListenAddress != defaultAdminAddress || cfg.APIURL != "" || cfg.APIToken.Configured() {
		t.Fatalf("unexpected disabled config: %+v", cfg)
	}
	if cfg.APIClientTimeout != defaultAdminAPITimeout || cfg.ReadHeaderTimeout != 5*time.Second || cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("unexpected security or timeout defaults: %+v", cfg)
	}
}

func TestLoadAdminHumanAuthorizationIsExplicit(t *testing.T) {
	clearAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED", "true")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "requires the admin dashboard") {
		t.Fatalf("unauthorized disabled dashboard flag: %v", err)
	}
	setEnabledAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED", "true")
	cfg, err := LoadAdmin()
	if err != nil || !cfg.HumanAuthorizationRequired {
		t.Fatalf("human authorization=%+v err=%v", cfg, err)
	}
}

func TestLoadAdminEnabledConfigurationUsesCloudflareAccess(t *testing.T) {
	setEnabledAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_ADDRESS", "[::1]:9090")
	apiToken := strings.Repeat("runtime-api-token-", 2)
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", apiToken)
	cfg, err := LoadAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.AccessTeamDomain != "https://team.cloudflareaccess.com" || cfg.AccessAudience != "admin-audience" {
		t.Fatal("enabled admin Cloudflare Access configuration was not loaded")
	}
	if !cfg.APIToken.Configured() || cfg.APIToken.Reveal() != apiToken {
		t.Fatal("enabled admin API token was not loaded")
	}
	if rendered := fmt.Sprintf("%+v", cfg); strings.Contains(rendered, apiToken) {
		t.Fatalf("admin API token rendered in config: %q", rendered)
	}
}

func TestLoadAdminRequiresEnabledRuntimeInputs(t *testing.T) {
	setEnabledAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_API_URL", "")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "ADMIN_API_URL") {
		t.Fatalf("missing API URL error = %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_API_URL", "http://127.0.0.1:8082")
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", "too-short")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "ADMIN_API_TOKEN") {
		t.Fatalf("short API token error = %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_API_TOKEN", strings.Repeat("t", minimumServiceTokenLength))
	t.Setenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "ACCESS_TEAM_DOMAIN") {
		t.Fatalf("missing Access team domain error = %v", err)
	}
	setEnabledAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_AUDIENCE", "")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "ACCESS_AUDIENCE") {
		t.Fatalf("missing Access audience error = %v", err)
	}
}

func TestLoadAdminRejectsUnsafeServiceTokenShape(t *testing.T) {
	for _, token := range []string{strings.Repeat("x", 513), strings.Repeat("x", 31) + " ", strings.Repeat("x", 31) + ","} {
		setEnabledAdminEnvironment(t)
		t.Setenv("SHERLOCK_ADMIN_API_TOKEN", token)
		if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "ADMIN_API_TOKEN") {
			t.Fatalf("unsafe token accepted: length=%d error=%v", len(token), err)
		}
	}
}

func TestLoadAdminRejectsInvalidCloudflareAccessBoundary(t *testing.T) {
	for name, configure := range map[string]func(*testing.T){
		"plaintext issuer": func(t *testing.T) {
			t.Setenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "http://team.cloudflareaccess.com")
		},
		"issuer path": func(t *testing.T) {
			t.Setenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "https://team.cloudflareaccess.com/path")
		},
		"multiple audiences": func(t *testing.T) { t.Setenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_AUDIENCE", "one,two") },
	} {
		t.Run(name, func(t *testing.T) {
			setEnabledAdminEnvironment(t)
			configure(t)
			if _, err := LoadAdmin(); err == nil {
				t.Fatal("invalid Cloudflare Access boundary was accepted")
			}
		})
	}
}

func TestLoadAdminValidatesPrivateAPIURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "remote plaintext", url: "http://api.internal.example", want: "requires HTTPS"},
		{name: "userinfo", url: "https://token@api.internal.example", want: "userinfo"},
		{name: "query", url: "https://api.internal.example?scope=all", want: "query"},
		{name: "fragment", url: "https://api.internal.example#admin", want: "fragment"},
		{name: "path", url: "https://api.internal.example/private", want: "root path"},
		{name: "wrong scheme", url: "file://api.internal.example/", want: "HTTP or HTTPS"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnabledAdminEnvironment(t)
			t.Setenv("SHERLOCK_ADMIN_API_URL", test.url)
			if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadAdmin() error = %v, want substring %q", err, test.want)
			}
		})
	}

	for _, validURL := range []string{"http://localhost:8082", "http://[::1]:8082/", "https://api.internal.example"} {
		t.Run("accept "+validURL, func(t *testing.T) {
			setEnabledAdminEnvironment(t)
			t.Setenv("SHERLOCK_ADMIN_API_URL", validURL)
			if _, err := LoadAdmin(); err != nil {
				t.Fatalf("LoadAdmin() rejected %q: %v", validURL, err)
			}
		})
	}
}

func TestLoadAdminRejectsInvalidConfiguredAPIURLEvenWhenDisabled(t *testing.T) {
	clearAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_API_URL", "http://api.internal.example")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
		t.Fatalf("invalid disabled API URL error = %v", err)
	}
}

func TestLoadAdminRejectsUnsafeNonLoopbackListener(t *testing.T) {
	setEnabledAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_ADDRESS", "0.0.0.0:8081")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "requires admin TLS") {
		t.Fatalf("non-TLS remote listener error = %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_CERT_FILE", "admin.crt")
	t.Setenv("SHERLOCK_ADMIN_KEY_FILE", "admin.key")
	if _, err := LoadAdmin(); err != nil {
		t.Fatalf("safe remote listener rejected: %v", err)
	}
}

func TestLoadAdminRejectsInvalidTLSAddressAndDurationConfiguration(t *testing.T) {
	setEnabledAdminEnvironment(t)
	t.Setenv("SHERLOCK_ADMIN_CERT_FILE", "admin.crt")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial TLS error = %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_CERT_FILE", "")
	t.Setenv("SHERLOCK_ADMIN_ADDRESS", "127.0.0.1:http")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "numeric port") {
		t.Fatalf("invalid address error = %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_ADDRESS", defaultAdminAddress)
	t.Setenv("SHERLOCK_ADMIN_READ_HEADER_TIMEOUT", "0s")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "timeouts") {
		t.Fatalf("invalid timeout error = %v", err)
	}
	t.Setenv("SHERLOCK_ADMIN_READ_HEADER_TIMEOUT", "5s")
	t.Setenv("SHERLOCK_ADMIN_API_TIMEOUT", "61s")
	if _, err := LoadAdmin(); err == nil || !strings.Contains(err.Error(), "ADMIN_API_TIMEOUT") {
		t.Fatalf("invalid API timeout error = %v", err)
	}
}
