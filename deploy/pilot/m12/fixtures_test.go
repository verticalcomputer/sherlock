package m12pilot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
)

func TestOneNodeInventoriesUseTheReviewedDedicatedTarget(t *testing.T) {
	directory, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	roles, err := commandpack.LoadTargetRoles(filepath.Join(directory, "target-roles.one-node.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || len(roles["pilot-cluster"]) != 1 || roles["pilot-cluster"]["fixture1-zone1-comp001"] != commandpack.TargetCompute {
		t.Fatalf("roles = %#v", roles)
	}
	authentication, err := diagnosticrunner.LoadSSHTargetAuthentication(filepath.Join(directory, "ssh-target-auth.one-node.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(authentication.Targets) != 1 {
		t.Fatalf("targets = %#v", authentication.Targets)
	}
	target := authentication.Targets["fixture1-zone1-comp001"]
	profile := authentication.AuthenticationProfiles[target.AuthenticationProfile]
	if target.Address != "192.0.2.250" || target.Port != 22 || target.Username != "sherlock-runner" || target.PrincipalConstraint != diagnosticrunner.SSHPrincipalDedicatedSSHDForceCommand {
		t.Fatalf("target = %#v", target)
	}
	if profile.Method != diagnosticrunner.SSHAuthenticationPublicKey || profile.CredentialReference != diagnosticrunner.SSHOpenSSHDefaultIdentityReference {
		t.Fatalf("profile = %#v", profile)
	}
}

func TestAgentlessFixturesFixReducedTrustScopeWithoutCredentials(t *testing.T) {
	directory, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := diagnosticrunner.LoadSSHTargetAuthentication(filepath.Join(directory, "ssh-target-auth.agentless-one-node.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := authentication.Targets["fixture1-zone1-comp001"]
	profile := authentication.AuthenticationProfiles[target.AuthenticationProfile]
	if target.Address != "192.0.2.250" || target.Port != 22 || target.Username != "fixture_user_1" || target.PrincipalConstraint != diagnosticrunner.SSHPrincipalSharedShellReducedTrust {
		t.Fatalf("agentless target = %#v", target)
	}
	if profile.Method != diagnosticrunner.SSHAuthenticationPublicKey || profile.CredentialReference != diagnosticrunner.SSHOpenSSHDefaultIdentityReference {
		t.Fatalf("agentless profile = %#v", profile)
	}
	policy, err := diagnosticrunner.LoadAgentlessSSHPolicy(filepath.Join(directory, "agentless-ssh-policy.one-node.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.AllowList) != 1 || policy.AllowList[0] != (diagnosticrunner.AgentlessSSHPermission{
		ClusterID: "pilot-cluster", TargetID: "fixture1-zone1-comp001", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0",
	}) {
		t.Fatalf("agentless policy = %#v", policy)
	}
	for _, name := range []string{"agentless-ssh-policy.one-node.json", "ssh-target-auth.agentless-one-node.json"} {
		contents := readFixture(t, name)
		for _, forbidden := range []string{"password", "private_key", "ProxyCommand", "command_text"} {
			if strings.Contains(contents, forbidden) {
				t.Fatalf("%s contains prohibited field or command %q", name, forbidden)
			}
		}
	}
}

func TestForceCommandFixturesFixCommandEnvironmentAndSSHPolicy(t *testing.T) {
	wrapper := readFixture(t, "sherlock-runner-force-command")
	for _, required := range []string{
		`SSH_ORIGINAL_COMMAND-}`, `!= "sherlock-runner"`, "exec /usr/bin/env -i",
		"SHERLOCK_RUNNER_COMMAND_PACK_FILE=/etc/sherlock/diagnostics/pack.json",
		"SHERLOCK_RUNNER_TRUST_ROOTS_FILE=/etc/sherlock/diagnostics/trust-roots.json",
		"SHERLOCK_RUNNER_VERSION=1.4.0", "SHERLOCK_RUNNER_TARGET_ID=fixture1-zone1-comp001",
		"SHERLOCK_RUNNER_TARGET_ROLE=COMPUTE", "/usr/local/bin/sherlock-runner",
	} {
		if !strings.Contains(wrapper, required) {
			t.Errorf("wrapper lacks %q", required)
		}
	}
	for _, forbidden := range []string{"$@", "eval ", "sh -c", "PASSWORD", "ProxyCommand", "sudo"} {
		if strings.Contains(wrapper, forbidden) {
			t.Errorf("wrapper contains prohibited text %q", forbidden)
		}
	}

	sshd := readFixture(t, "sshd-sherlock-runner.conf")
	for _, required := range []string{
		"Match User sherlock-runner", "AuthenticationMethods publickey", "PasswordAuthentication no",
		"KbdInteractiveAuthentication no", "PermitTTY no", "MaxSessions 1",
		"DisableForwarding yes", "AllowAgentForwarding no", "AllowTcpForwarding no", "X11Forwarding no",
		"ForceCommand /usr/local/libexec/sherlock-runner-force-command", "Match all",
	} {
		if !strings.Contains(sshd, required) {
			t.Errorf("sshd policy lacks %q", required)
		}
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	payload, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
