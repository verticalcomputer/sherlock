package config

import (
	"strings"
	"testing"
	"time"
)

func diagnosticEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_CLUSTER_ID", "pilot-cluster")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "/etc/sherlock/collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "/etc/sherlock/collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "/etc/sherlock/ca.crt")
	t.Setenv("SHERLOCK_COMMAND_PACK_FILE", "/etc/sherlock/pack.json")
	t.Setenv("SHERLOCK_COMMAND_TRUST_ROOTS_FILE", "/etc/sherlock/trust-roots.json")
	t.Setenv("SHERLOCK_RUNNER_VERSION", "1.4.0")
	t.Setenv("SHERLOCK_DIAGNOSTIC_INVENTORY_FILE", "/etc/sherlock/inventory.json")
	t.Setenv("SHERLOCK_DIAGNOSTIC_LOCAL_TARGET", "head01")
}

func TestLoadCollectorDiagnosticsDefaults(t *testing.T) {
	diagnosticEnvironment(t)
	cfg, err := LoadCollectorDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PollWait != 25*time.Second || cfg.Transport.RequestTimeout < cfg.PollWait {
		t.Fatalf("unsafe polling defaults: %+v", cfg)
	}
	if cfg.FailureBackoffMinimum <= 0 || cfg.FailureBackoffMaximum < cfg.FailureBackoffMinimum || cfg.IdleBackoff <= 0 {
		t.Fatalf("unsafe backoff defaults: %+v", cfg)
	}
	// A head node that was not given its own identity is still attributable:
	// the collector identity is the machine the control plane authenticated.
	if cfg.RunnerID != "collector-1" {
		t.Fatalf("runner identity = %q", cfg.RunnerID)
	}
	if cfg.JournalPath != "./diagnostic-result-journal.json" {
		t.Fatalf("diagnostic journal = %q", cfg.JournalPath)
	}
}

// The pack turns a definition reference into an argv and the inventory decides
// which machines are reachable. Missing either is a startup failure, not work
// claimed and then refused.
func TestLoadCollectorDiagnosticsRequiresTheExecutionInputs(t *testing.T) {
	for _, missing := range []string{
		"SHERLOCK_COMMAND_PACK_FILE",
		"SHERLOCK_COMMAND_TRUST_ROOTS_FILE",
		"SHERLOCK_RUNNER_VERSION",
		"SHERLOCK_DIAGNOSTIC_INVENTORY_FILE",
		"SHERLOCK_CLUSTER_ID",
	} {
		t.Run(missing, func(t *testing.T) {
			diagnosticEnvironment(t)
			t.Setenv(missing, "")
			if _, err := LoadCollectorDiagnostics(); err == nil {
				t.Fatalf("a head node started without %s", missing)
			}
		})
	}
}

func TestLoadCollectorDiagnosticsRequiresMutuallyAuthenticatedTransport(t *testing.T) {
	diagnosticEnvironment(t)
	t.Setenv("SHERLOCK_CONTROL_URL", "http://control.test")
	if _, err := LoadCollectorDiagnostics(); err == nil {
		t.Fatal("a plaintext control URL was accepted")
	}
	diagnosticEnvironment(t)
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "")
	if _, err := LoadCollectorDiagnostics(); err == nil {
		t.Fatal("a head node started without a client identity")
	}
}

func TestLoadCollectorDiagnosticsRequiresServiceTokenFileInPoPMode(t *testing.T) {
	diagnosticEnvironment(t)
	t.Setenv("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE", "cloudflare_access_service_token_pop")
	if _, err := LoadCollectorDiagnostics(); err == nil {
		t.Fatal("diagnostics accepted proof-of-possession mode without an Access Service Token file")
	}
	t.Setenv("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE", "/run/sherlock/access-token.json")
	if _, err := LoadCollectorDiagnostics(); err != nil {
		t.Fatal(err)
	}
}

// The control plane caps the long poll at thirty seconds and the request must
// outlast it, so a configuration that cannot complete one poll is refused
// rather than timing out on every claim.
func TestLoadCollectorDiagnosticsBoundsThePollWait(t *testing.T) {
	diagnosticEnvironment(t)
	t.Setenv("SHERLOCK_DIAGNOSTIC_POLL_WAIT", "45s")
	if _, err := LoadCollectorDiagnostics(); err == nil {
		t.Fatal("a poll wait beyond the protocol maximum was accepted")
	}
	diagnosticEnvironment(t)
	t.Setenv("SHERLOCK_DIAGNOSTIC_POLL_WAIT", "25s")
	t.Setenv("SHERLOCK_CONTROL_TIMEOUT", "10s")
	if _, err := LoadCollectorDiagnostics(); err == nil || !strings.Contains(err.Error(), "poll wait") {
		t.Fatalf("a request timeout shorter than the poll wait was accepted: %v", err)
	}
}

func TestLoadCollectorDiagnosticsBindsRunnerToAuthenticatedCollector(t *testing.T) {
	diagnosticEnvironment(t)
	t.Setenv("SHERLOCK_DIAGNOSTIC_RUNNER_ID", "head-node-1")
	if _, err := LoadCollectorDiagnostics(); err == nil {
		t.Fatal("an independently asserted runner identity was accepted")
	}
	diagnosticEnvironment(t)
	t.Setenv("SHERLOCK_DIAGNOSTIC_RUNNER_ID", "collector-1")
	cfg, err := LoadCollectorDiagnostics()
	if err != nil || cfg.RunnerID != "collector-1" || cfg.LocalTarget != "head01" {
		t.Fatalf("authenticated identity = %+v err=%v", cfg, err)
	}
}

// Local execution is the default, so an existing head-node deployment keeps its
// behavior when this configuration gains a mode.
func TestLoadCollectorDiagnosticsDefaultsToLocalExecution(t *testing.T) {
	diagnosticEnvironment(t)
	cfg, err := LoadCollectorDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExecutionMode != DiagnosticExecutionLocal {
		t.Fatalf("execution mode = %q, want local", cfg.ExecutionMode)
	}
}

func TestLoadCollectorDiagnosticsRefusesAnUnknownExecutionMode(t *testing.T) {
	diagnosticEnvironment(t)
	t.Setenv("SHERLOCK_DIAGNOSTIC_EXECUTION_MODE", "push")
	if _, err := LoadCollectorDiagnostics(); err == nil {
		t.Fatal("an unknown execution mode was accepted")
	}
}

// Each SSH input is load-bearing: the digest names the transport binary, the
// known-hosts file makes the remote host the intended one, and the alias
// inventory is where a target name becomes a machine to connect to.
func TestLoadCollectorDiagnosticsRequiresEverySSHInput(t *testing.T) {
	sshEnvironment := func(t *testing.T) {
		t.Helper()
		diagnosticEnvironment(t)
		t.Setenv("SHERLOCK_DIAGNOSTIC_EXECUTION_MODE", "ssh")
		t.Setenv("SHERLOCK_DIAGNOSTIC_SSH_EXECUTABLE", "/usr/bin/ssh")
		t.Setenv("SHERLOCK_DIAGNOSTIC_SSH_SHA256", strings.Repeat("a", 64))
		t.Setenv("SHERLOCK_DIAGNOSTIC_SSH_KNOWN_HOSTS_FILE", "/etc/sherlock/known_hosts")
		t.Setenv("SHERLOCK_DIAGNOSTIC_SSH_TARGET_AUTH_FILE", "/etc/sherlock/ssh-target-auth.v1.json")
	}
	sshEnvironment(t)
	cfg, err := LoadCollectorDiagnostics()
	if err != nil {
		t.Fatalf("a complete ssh configuration was refused: %v", err)
	}
	if cfg.ExecutionMode != DiagnosticExecutionSSH || cfg.SSHExecutable != "/usr/bin/ssh" {
		t.Fatalf("ssh configuration = %+v", cfg)
	}
	for _, missing := range []string{
		"SHERLOCK_DIAGNOSTIC_SSH_EXECUTABLE",
		"SHERLOCK_DIAGNOSTIC_SSH_SHA256",
		"SHERLOCK_DIAGNOSTIC_SSH_KNOWN_HOSTS_FILE",
		"SHERLOCK_DIAGNOSTIC_SSH_TARGET_AUTH_FILE",
	} {
		t.Run(missing, func(t *testing.T) {
			sshEnvironment(t)
			t.Setenv(missing, "")
			if _, err := LoadCollectorDiagnostics(); err == nil {
				t.Fatalf("ssh mode started without %s", missing)
			}
		})
	}
}

func TestLoadCollectorDiagnosticsRequiresSeparateAgentlessOptIn(t *testing.T) {
	agentlessEnvironment := func(t *testing.T) {
		t.Helper()
		diagnosticEnvironment(t)
		t.Setenv("SHERLOCK_DIAGNOSTIC_EXECUTION_MODE", "agentless_ssh")
		t.Setenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_EXECUTABLE", "/usr/bin/ssh")
		t.Setenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_SHA256", strings.Repeat("a", 64))
		t.Setenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_KNOWN_HOSTS_FILE", "/etc/sherlock/agentless_known_hosts")
		t.Setenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_TARGET_AUTH_FILE", "/etc/sherlock/agentless-target-auth.v1.json")
		t.Setenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_POLICY_FILE", "/etc/sherlock/agentless-policy.v1.json")
	}
	agentlessEnvironment(t)
	cfg, err := LoadCollectorDiagnostics()
	if err != nil {
		t.Fatalf("complete agentless configuration was refused: %v", err)
	}
	if cfg.ExecutionMode != DiagnosticExecutionAgentlessSSH || cfg.AgentlessSSHPolicyFile == "" || cfg.SSHExecutable != "" {
		t.Fatalf("agentless configuration = %+v", cfg)
	}
	for _, missing := range []string{
		"SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_EXECUTABLE",
		"SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_SHA256",
		"SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_KNOWN_HOSTS_FILE",
		"SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_TARGET_AUTH_FILE",
		"SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_POLICY_FILE",
	} {
		t.Run(missing, func(t *testing.T) {
			agentlessEnvironment(t)
			t.Setenv(missing, "")
			if _, err := LoadCollectorDiagnostics(); err == nil {
				t.Fatalf("agentless mode started without %s", missing)
			}
		})
	}
}
