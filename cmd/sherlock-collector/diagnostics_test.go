package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func writeDiagnosticFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func sshDiagnosticConfig(t *testing.T) config.CollectorDiagnostics {
	t.Helper()
	directory := t.TempDir()
	return config.CollectorDiagnostics{
		ClusterID: "pilot-cluster", RunnerID: "head-1", LocalTarget: "head01",
		ExecutionMode:       config.DiagnosticExecutionSSH,
		SSHExecutable:       "/usr/bin/ssh",
		SSHExecutableSHA256: strings.Repeat("a", 64),
		SSHKnownHostsFile:   writeDiagnosticFile(t, directory, "known_hosts", "@cert-authority *.pilot.internal ssh-ed25519 AAAA\n"),
		SSHTargetAuthenticationFile: writeDiagnosticFile(t, directory, "ssh-target-auth.v1.json", `{
  "schema_version":"sherlock.ssh-target-auth.v1",
  "authentication_profiles":[{"id":"pilot-key","method":"public_key","credential_source":"head_local_persistent","credential_reference":"openssh-default-identity"}],
  "targets":[{"id":"comp001","address":"comp001.pilot.internal","port":22,"username":"sherlock-runner","authentication_profile":"pilot-key","principal_constraint":"authorized_key_force_command"}]
}`),
		InventoryFile: writeDiagnosticFile(t, directory, "inventory.json", `{"pilot-cluster":{"comp001":"COMPUTE","head01":"HEAD"}}`),
	}
}

// The two modes differ in the only way that matters at this boundary: which
// machine an invocation is carried to.
func TestExecutionAdapterSelectsTheConfiguredTransport(t *testing.T) {
	ssh := sshDiagnosticConfig(t)
	adapter, err := newExecutionAdapter(ssh)
	if err != nil {
		t.Fatalf("ssh mode did not build: %v", err)
	}
	if _, isSSH := adapter.invoker.(*diagnosticrunner.RestrictedSSH); !isSSH {
		t.Fatalf("ssh mode built %T", adapter.invoker)
	}
	if adapter.targets["comp001"].Address != "comp001.pilot.internal" {
		t.Fatalf("targets = %v", adapter.targets)
	}

	local := ssh
	local.ExecutionMode = config.DiagnosticExecutionLocal
	adapter, err = newExecutionAdapter(local)
	if err != nil {
		t.Fatalf("local mode did not build: %v", err)
	}
	if _, isHost := adapter.invoker.(*diagnosticrunner.HostInvoker); !isHost {
		t.Fatalf("local mode built %T", adapter.invoker)
	}
	if adapter.targets != nil {
		t.Fatalf("local mode carried ssh targets: %v", adapter.targets)
	}

	agentless := agentlessDiagnosticConfig(t)
	adapter, err = newExecutionAdapter(agentless)
	if err != nil {
		t.Fatalf("agentless mode did not build: %v", err)
	}
	if _, isAgentless := adapter.invoker.(*diagnosticrunner.AgentlessSSH); !isAgentless {
		t.Fatalf("agentless mode built %T", adapter.invoker)
	}
}

func agentlessDiagnosticConfig(t *testing.T) config.CollectorDiagnostics {
	t.Helper()
	directory := t.TempDir()
	return config.CollectorDiagnostics{
		ClusterID: "pilot-cluster", RunnerID: "collector-head", ExecutionMode: config.DiagnosticExecutionAgentlessSSH,
		AgentlessSSHExecutable:       "/usr/bin/ssh",
		AgentlessSSHExecutableSHA256: strings.Repeat("a", 64),
		AgentlessSSHKnownHostsFile:   writeDiagnosticFile(t, directory, "agentless_known_hosts", "192.0.2.250 ssh-ed25519 AAAATestOnly\n"),
		AgentlessSSHTargetAuthenticationFile: writeDiagnosticFile(t, directory, "agentless-target-auth.v1.json", `{
  "schema_version":"sherlock.ssh-target-auth.v1",
  "authentication_profiles":[{"id":"pilot-key","method":"public_key","credential_source":"head_local_persistent","credential_reference":"openssh-default-identity"}],
  "targets":[{"id":"fixture1-zone1-comp001","address":"192.0.2.250","port":22,"username":"fixture_user_1","authentication_profile":"pilot-key","principal_constraint":"shared_shell_reduced_trust"}]
}`),
		AgentlessSSHPolicyFile: writeDiagnosticFile(t, directory, "agentless-policy.v1.json", `{
  "schema_version":"sherlock.agentless-ssh-policy.v1",
  "acknowledgement":"shared_shell_reduced_trust",
  "allow_list":[{"cluster_id":"pilot-cluster","target_id":"fixture1-zone1-comp001","definition_id":"gpu.ecc_counters","definition_version":"1.0.0"}]
}`),
		InventoryFile: writeDiagnosticFile(t, directory, "inventory.json", `{"pilot-cluster":{"fixture1-zone1-comp001":"COMPUTE"}}`),
	}
}

func TestAgentlessExecutionAdapterRejectsPasswordAndDoesNotChangeSealedSSH(t *testing.T) {
	agentless := agentlessDiagnosticConfig(t)
	payload, err := os.ReadFile(agentless.AgentlessSSHTargetAuthenticationFile)
	if err != nil {
		t.Fatal(err)
	}
	password := strings.Replace(string(payload), `"method":"public_key"`, `"method":"password"`, 1)
	if err := os.WriteFile(agentless.AgentlessSSHTargetAuthenticationFile, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newExecutionAdapter(agentless); err == nil {
		t.Fatal("agentless mode accepted a password profile")
	}

	sealed := sshDiagnosticConfig(t)
	adapter, err := newExecutionAdapter(sealed)
	if err != nil {
		t.Fatalf("sealed SSH behavior regressed: %v", err)
	}
	if _, ok := adapter.invoker.(*diagnosticrunner.RestrictedSSH); !ok {
		t.Fatalf("sealed SSH mode built %T", adapter.invoker)
	}
}

func TestAgentlessStartupEvidenceNamesReducedTrustWithoutSensitiveMaterial(t *testing.T) {
	cfg := config.CollectorDiagnostics{
		Transport: config.CollectorTransport{CollectorID: "collector-head"}, ClusterID: "pilot-cluster", RunnerID: "collector-head",
		ExecutionMode:                        config.DiagnosticExecutionAgentlessSSH,
		AgentlessSSHTargetAuthenticationFile: "/sensitive/path/target-auth.json",
	}
	attributes := diagnosticStartupAttributes(cfg, "pilot-pack", "1.0.0", 1)
	joined := strings.Join(anyStrings(attributes), "\x00")
	for _, required := range []string{"agentless_ssh", "shared_shell_reduced_trust", "login_shell_reduced_trust", "pilot-cluster"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("startup evidence lacks %q: %#v", required, attributes)
		}
	}
	if strings.Contains(joined, "target-auth") || strings.Contains(joined, "sensitive") {
		t.Fatalf("configuration material leaked into startup evidence: %#v", attributes)
	}

	sealed := cfg
	sealed.ExecutionMode = config.DiagnosticExecutionSSH
	if joined := strings.Join(anyStrings(diagnosticStartupAttributes(sealed, "pilot-pack", "1.0.0", 1)), "\x00"); strings.Contains(joined, "reduced_trust") {
		t.Fatal("sealed SSH startup was reclassified as reduced trust")
	}
}

func anyStrings(values []any) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = fmt.Sprint(value)
	}
	return result
}

func TestExecutionAdapterComposesHeadLocalPasswordProvider(t *testing.T) {
	cfg := sshDiagnosticConfig(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SSHKnownHostsFile = writeDiagnosticFile(t, t.TempDir(), "known_hosts", knownhosts.Line([]string{"comp001.pilot.internal"}, signer.PublicKey())+"\n")
	passwordDirectory := t.TempDir()
	if err := os.Chmod(passwordDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.SSHCredentialDirectory = passwordDirectory
	payload := `{
  "schema_version":"sherlock.ssh-target-auth.v1",
  "authentication_profiles":[{"id":"pilot-password","method":"password","credential_source":"head_local_persistent","credential_reference":"pilot-password-v1"}],
  "targets":[{"id":"comp001","address":"comp001.pilot.internal","port":22,"username":"sherlock-runner","authentication_profile":"pilot-password","principal_constraint":"dedicated_sshd_force_command"}]
}`
	if err := os.WriteFile(cfg.SSHTargetAuthenticationFile, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := newExecutionAdapter(cfg)
	if err != nil {
		t.Fatalf("password profile did not compose: %v", err)
	}
	if _, isSSH := adapter.invoker.(*diagnosticrunner.RestrictedSSH); !isSSH {
		t.Fatalf("password mode built %T", adapter.invoker)
	}

	missing := cfg
	missing.SSHCredentialDirectory = filepath.Join(t.TempDir(), "missing")
	if _, err := newExecutionAdapter(missing); err == nil {
		t.Fatal("password profile started without a protected provider")
	}
}

// Host identity is what makes the machine reached the intended one, so a
// missing or writable known-hosts file must stop the head node starting rather
// than surface as a per-target failure mid-investigation.
func TestExecutionAdapterRefusesUnsafeSSHConfiguration(t *testing.T) {
	base := sshDiagnosticConfig(t)

	missingHosts := base
	missingHosts.SSHKnownHostsFile = filepath.Join(t.TempDir(), "absent")
	if _, err := newExecutionAdapter(missingHosts); err == nil {
		t.Fatal("a missing known-hosts file was accepted")
	}

	writableHosts := base
	if err := os.Chmod(writableHosts.SSHKnownHostsFile, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := newExecutionAdapter(writableHosts); err == nil {
		t.Fatal("a world-writable known-hosts file was accepted")
	}
	if err := os.Chmod(base.SSHKnownHostsFile, 0o600); err != nil {
		t.Fatal(err)
	}

	// The transport must be ssh itself, pinned to a digest. Anything else here
	// would be an arbitrary binary the head node runs for every diagnostic.
	notSSH := base
	notSSH.SSHExecutable = "/bin/sh"
	if _, err := newExecutionAdapter(notSSH); err == nil {
		t.Fatal("a shell was accepted as the transport")
	}
	unpinned := base
	unpinned.SSHExecutableSHA256 = "not-a-digest"
	if _, err := newExecutionAdapter(unpinned); err == nil {
		t.Fatal("an unpinned transport was accepted")
	}
}

func TestClusterTargetRolesRequiresALocalRoleOnlyInLocalMode(t *testing.T) {
	base := sshDiagnosticConfig(t)
	roles, targets, err := clusterTargetRoles(base)
	if err != nil {
		t.Fatalf("ssh mode did not resolve roles: %v", err)
	}
	if len(targets) != 2 || targets[0] != "comp001" || targets[1] != "head01" {
		t.Fatalf("targets = %v, want them sorted and complete", targets)
	}
	if role, eligible := roles("comp001"); !eligible || role != "COMPUTE" {
		t.Fatalf("comp001 role = %q eligible=%t", role, eligible)
	}
	if _, eligible := roles("comp999"); eligible {
		t.Fatal("a target with no confirmed role was reported eligible")
	}

	// In local mode this host is the only machine that will ever be reached, so
	// an inventory that gives it no role can never produce a result.
	local := base
	local.ExecutionMode = config.DiagnosticExecutionLocal
	local.LocalTarget = "head99"
	if _, _, err := clusterTargetRoles(local); err == nil {
		t.Fatal("local mode started with no role for this host")
	}

	otherCluster := base
	otherCluster.ClusterID = "other-cluster"
	if _, _, err := clusterTargetRoles(otherCluster); err == nil {
		t.Fatal("a cluster absent from the inventory was accepted")
	}
}

// A stale role entry must not stop the head node executing everything else, so
// this is reported rather than refused.
func TestUnreachableTargetsReportsRoleHoldersWithoutAnAlias(t *testing.T) {
	sshTargets := map[string]diagnosticrunner.SSHTarget{"comp001": {ID: "comp001"}}
	if got := unreachableTargets([]string{"comp001", "comp002", "head01"}, sshTargets); len(got) != 2 || got[0] != "comp002" || got[1] != "head01" {
		t.Fatalf("unreachable = %v", got)
	}
	if got := unreachableTargets([]string{"comp001"}, nil); got != nil {
		t.Fatalf("local mode reported %v", got)
	}
}
