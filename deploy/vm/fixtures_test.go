package vmdeployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostgresComposeStaysLoopbackAndFileSecretBacked(t *testing.T) {
	compose := readFixture(t, "compose.yaml")
	for _, required := range []string{
		"${SHERLOCK_POSTGRES_BIND_ADDRESS:-127.0.0.1}:${SHERLOCK_POSTGRES_PORT:-5432}:5432",
		"POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password",
		"file: ${SHERLOCK_POSTGRES_PASSWORD_FILE:-/etc/sherlock/secrets/postgres_password}",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("compose.yaml is missing safety invariant %q", required)
		}
	}
	for _, forbidden := range []string{"POSTGRES_PASSWORD:", "0.0.0.0:5432", "sherlock:sherlock"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("compose.yaml contains forbidden database configuration %q", forbidden)
		}
	}
}

func TestNetworkListenerExamplesStayOnLoopback(t *testing.T) {
	cases := map[string][]string{
		filepath.Join("env", "api.env.example"): {
			"SHERLOCK_API_ADDRESS=127.0.0.1:8080",
			"SHERLOCK_ADMIN_API_ADDRESS=127.0.0.1:8082",
		},
		filepath.Join("env", "admin-ui.env.example"): {
			"SHERLOCK_ADMIN_ADDRESS=127.0.0.1:8081",
			"SHERLOCK_ADMIN_API_URL=http://127.0.0.1:8082",
			"SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_TEAM_DOMAIN=https://REPLACE_WITH_TEAM.cloudflareaccess.com",
			"SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_AUDIENCE=REPLACE_WITH_ADMIN_APPLICATION_AUD",
		},
		filepath.Join("env", "control.env.example"): {
			"SHERLOCK_CONTROL_ADDRESS=127.0.0.1:8443",
		},
		filepath.Join("env", "worker.env.example"): {
			"SHERLOCK_METRICS_ADDRESS=127.0.0.1:9091",
		},
	}
	for name, requiredValues := range cases {
		contents := readFixture(t, name)
		for _, required := range requiredValues {
			if !strings.Contains(contents, required) {
				t.Errorf("%s is missing loopback invariant %q", name, required)
			}
		}
	}
	adminUI := readFixture(t, filepath.Join("env", "admin-ui.env.example"))
	for _, forbidden := range []string{"SHERLOCK_ADMIN_BOOTSTRAP_SECRET", "SHERLOCK_ADMIN_SESSION_TTL", "SHERLOCK_ADMIN_COOKIE_SECURE"} {
		if strings.Contains(adminUI, forbidden) {
			t.Errorf("admin UI fixture still contains removed setting %q", forbidden)
		}
	}
}

func TestSystemdOrderingAndBaselineHardening(t *testing.T) {
	migrate := readFixture(t, filepath.Join("systemd", "sherlock-migrate.service"))
	if !strings.Contains(migrate, "Requires=sherlock-postgres.service") ||
		!strings.Contains(migrate, "After=sherlock-postgres.service") {
		t.Fatal("migration unit must require and start after PostgreSQL")
	}

	applicationUnits := []string{
		"sherlock-api.service",
		"sherlock-control.service",
		"sherlock-investigator.service",
		"sherlock-worker.service",
	}
	for _, name := range applicationUnits {
		contents := readFixture(t, filepath.Join("systemd", name))
		for _, required := range []string{
			"Requires=sherlock-migrate.service",
			"After=network-online.target sherlock-migrate.service",
			"NoNewPrivileges=true",
			"ProtectSystem=strict",
			"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		} {
			if !strings.Contains(contents, required) {
				t.Errorf("%s is missing service invariant %q", name, required)
			}
		}
	}

	admin := readFixture(t, filepath.Join("systemd", "sherlock-admin-ui.service"))
	if !strings.Contains(admin, "Requires=sherlock-api.service") ||
		!strings.Contains(admin, "After=network-online.target sherlock-api.service") {
		t.Fatal("admin UI must require and start after the API private listener")
	}
}

func TestControlAuthenticationModesAreExplicitAndSafe(t *testing.T) {
	control := readFixture(t, filepath.Join("env", "control.env.example"))
	for _, required := range []string{
		"SHERLOCK_CONTROL_COLLECTOR_AUTH_MODE=direct_mtls",
		"SHERLOCK_CONTROL_COLLECTOR_AUTH_MODE=cloudflare_access_service_token_pop",
		"SHERLOCK_CONTROL_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128",
		"SHERLOCK_CONTROL_COLLECTOR_HOST=collector-control.vertical.computer",
		"SHERLOCK_CONTROL_ENROLLMENT_HOST=collector-enroll.vertical.computer",
	} {
		if !strings.Contains(control, required) {
			t.Errorf("control template is missing %q", required)
		}
	}
	for _, forbidden := range []string{"0.0.0.0:8443", "noTLSVerify", "BYPASS_TOKEN", "TUNNEL_TOKEN=", "CF-Access-Client-Secret"} {
		if strings.Contains(control, forbidden) {
			t.Errorf("control template contains forbidden setting %q", forbidden)
		}
	}
	unit := readFixture(t, filepath.Join("systemd", "sherlock-control.service"))
	if !strings.Contains(unit, "ReadOnlyPaths=/etc/sherlock/pki") {
		t.Fatal("control unit does not make PKI paths read-only")
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}
