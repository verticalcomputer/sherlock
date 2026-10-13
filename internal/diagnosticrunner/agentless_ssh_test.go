package diagnosticrunner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestLoadAgentlessSSHPolicyRequiresProtectedExplicitAcknowledgement(t *testing.T) {
	valid := `{
  "schema_version":"sherlock.agentless-ssh-policy.v1",
  "acknowledgement":"shared_shell_reduced_trust",
  "allow_list":[{"cluster_id":"pilot-cluster","target_id":"node-1","definition_id":"test-command","definition_version":"1.0.0"}]
}`
	path := writeInventory(t, "agentless-policy.json", valid)
	policy, err := LoadAgentlessSSHPolicy(path)
	if err != nil || len(policy.AllowList) != 1 || policy.AllowList[0].ClusterID != "pilot-cluster" {
		t.Fatalf("LoadAgentlessSSHPolicy() = %#v, %v", policy, err)
	}
	for name, contents := range map[string]string{
		"missing acknowledgement": strings.Replace(valid, `"shared_shell_reduced_trust"`, `""`, 1),
		"wrong schema":            strings.Replace(valid, `"sherlock.agentless-ssh-policy.v1"`, `"sherlock.agentless-ssh-policy.v2"`, 1),
		"empty allow list":        strings.Replace(valid, `[{"cluster_id":"pilot-cluster","target_id":"node-1","definition_id":"test-command","definition_version":"1.0.0"}]`, `[]`, 1),
		"invalid target":          strings.Replace(valid, `"target_id":"node-1"`, `"target_id":"node 1"`, 1),
		"unknown field":           strings.Replace(valid, `"allow_list":`, `"credential":"must-not-load","allow_list":`, 1),
		"duplicate":               strings.Replace(valid, `]`, `,{"cluster_id":"pilot-cluster","target_id":"node-1","definition_id":"test-command","definition_version":"1.0.0"}]`, 1),
		"trailing":                valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadAgentlessSSHPolicy(writeInventory(t, "policy.json", contents)); err == nil {
				t.Fatalf("%s policy was accepted", name)
			}
		})
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentlessSSHPolicy(path); err == nil {
		t.Fatal("a writable policy was accepted")
	}
	link := filepath.Join(t.TempDir(), "agentless-policy-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentlessSSHPolicy(link); err == nil {
		t.Fatal("a symlink policy was accepted")
	}
}

func TestAgentlessSSHUsesExactHardenedArgvAndQuotedPackConstants(t *testing.T) {
	adapter := testAgentlessSSH(t, ExecutableIdentity{Path: "/usr/bin/ssh", SHA256: strings.Repeat("a", 64)})
	malicious := `value'; touch /tmp/escaped; printf '%s`
	catalog, invocation := testVerifiedCatalogAndInvocation(t,
		ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("b", 64)},
		[]string{"--query", malicious, "$(id)", "line one\nline two"}, []string{"node-1"})
	request, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Targets) != 1 || len(request.Targets[0].input) != 0 {
		t.Fatalf("agentless request carried unexpected targets or input: %#v", request.Targets)
	}
	args := request.Targets[0].Args
	wantArgs := []string{
		"-F", "/dev/null", "-n", "-T",
		"-oBatchMode=yes", "-oCanonicalizeHostname=no", "-oClearAllForwardings=yes",
		"-oControlMaster=no", "-oControlPath=none", "-oControlPersist=no",
		"-oEscapeChar=none", "-oExitOnForwardFailure=yes",
		"-oForwardAgent=no", "-oForwardX11=no", "-oGlobalKnownHostsFile=/dev/null",
		"-oHostbasedAuthentication=no", "-oIdentitiesOnly=yes", "-oIdentityAgent=none",
		"-oKbdInteractiveAuthentication=no", "-oKnownHostsCommand=none", "-oLocalCommand=none",
		"-oNumberOfPasswordPrompts=0", "-oPasswordAuthentication=no", "-oPermitLocalCommand=no",
		"-oPreferredAuthentications=publickey", "-oProxyCommand=none", "-oProxyJump=none",
		"-oProxyUseFdpass=no", "-oPubkeyAuthentication=yes", "-oRequestTTY=no", "-oSendEnv=-*",
		"-oStrictHostKeyChecking=yes", "-oTunnel=no", "-oUpdateHostKeys=no", "-oUserKnownHostsFile=" + adapter.knownHostsFile,
		"-oVerifyHostKeyDNS=no", "-p", "22", "--", "cloud-user@compute-one",
	}
	if !slices.Equal(args[:len(args)-1], wantArgs) {
		t.Fatalf("SSH argv before the fixed remote command = %#v, want %#v", args[:len(args)-1], wantArgs)
	}
	joined := strings.Join(args, "\x00")
	for _, required := range []string{
		"-F\x00/dev/null\x00-n\x00-T", "-oBatchMode=yes", "-oClearAllForwardings=yes",
		"-oControlMaster=no", "-oControlPath=none", "-oControlPersist=no", "-oForwardAgent=no",
		"-oIdentityAgent=none", "-oKnownHostsCommand=none", "-oPermitLocalCommand=no",
		"-oProxyCommand=none", "-oProxyJump=none", "-oRequestTTY=no", "-oSendEnv=-*",
		"-oStrictHostKeyChecking=yes", "-oUpdateHostKeys=no", "-oVerifyHostKeyDNS=no",
		"-p\x0022\x00--\x00cloud-user@compute-one",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("SSH argv lacks %q: %#v", required, args)
		}
	}
	command := args[len(args)-1]
	for _, quoted := range []string{
		posixShellQuote("/usr/bin/nvidia-smi"), posixShellQuote("--query"), posixShellQuote(malicious),
		posixShellQuote("$(id)"), posixShellQuote("line one\nline two"), posixShellQuote(strings.Repeat("b", 64)),
	} {
		if !strings.Contains(command, quoted) {
			t.Fatalf("remote command lacks quoted token %q: %s", quoted, command)
		}
	}
	if strings.Count(command, "exec ") != 1 || !strings.Contains(command, "exit 125") || strings.Contains(command, "attempt-1") || strings.Contains(command, "node-1") {
		t.Fatalf("remote command is not the deterministic guard plus argv: %s", command)
	}
}

func TestPOSIXShellQuotePreservesTokensWithoutExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "injection-marker")
	values := []string{
		"plain",
		"single'quote",
		"$(touch " + marker + ")",
		"value; touch " + marker,
		"line one\nline two",
		"wildcards * ? [abc] and $HOME",
	}
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = posixShellQuote(value)
	}
	command := "set -- " + strings.Join(quoted, " ") + `; printf '%s\036' "$@"`
	output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("quoted shell evaluation failed: %v: %q", err, output)
	}
	var expected bytes.Buffer
	for _, value := range values {
		expected.WriteString(value)
		expected.WriteByte(0x1e)
	}
	if !bytes.Equal(output, expected.Bytes()) {
		t.Fatalf("quoted values = %q, want %q", output, expected.Bytes())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("a quoted signed constant executed shell syntax")
	}
}

func TestAgentlessSSHRejectsArgumentsParametersPrivilegeSecretsAndForeignScope(t *testing.T) {
	adapter := testAgentlessSSH(t, ExecutableIdentity{Path: "/usr/bin/ssh", SHA256: strings.Repeat("a", 64)})
	catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("b", 64)}, []string{"safe"}, []string{"node-1"})
	value := "caller-value"
	withArgument := invocation
	withArgument.Arguments = []commandpack.ArgumentValue{{Name: "command", String: &value}}
	foreignTarget := invocation
	foreignTarget.Targets[0].Name = "node-2"
	foreignDefinition := invocation
	foreignDefinition.DefinitionID = "arbitrary-command"
	for name, candidate := range map[string]commandpack.Invocation{
		"caller argument": withArgument, "foreign target": foreignTarget, "arbitrary definition": foreignDefinition,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := adapter.requestFromInvocation(catalog, "attempt-1", candidate, nil); err == nil {
				t.Fatalf("%s was accepted", name)
			} else if strings.Contains(err.Error(), value) {
				t.Fatal("caller text leaked through an error")
			}
		})
	}
	secret := "credential-must-not-leak"
	if _, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, [][]byte{[]byte(secret)}); err == nil {
		t.Fatal("a credential-bearing invocation was accepted")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatal("credential leaked through an error")
	}
	if _, err := agentlessRemoteCommand("usr/bin/nvidia-smi", strings.Repeat("b", 64), nil); err == nil {
		t.Fatal("a relative executable was accepted")
	}

	parameterized := agentlessCatalog(t, commandpack.Definition{
		ID: "test-command", Version: "1.0.0", Owner: "tests", Purpose: "parameter denial",
		SupportedCapabilities: []string{"diagnostics.read"}, Risk: commandpack.RiskLow,
		ExecutablePath: "/usr/bin/nvidia-smi", ExecutableSHA256: strings.Repeat("b", 64),
		Arguments:  []commandpack.ArgumentToken{{Parameter: "value"}},
		Parameters: []commandpack.Parameter{{Name: "value", Type: commandpack.ParameterString, Required: true, Enum: []string{"safe"}, MaxLength: 4}},
		Targets:    commandpack.TargetConstraints{Roles: []commandpack.TargetRole{commandpack.TargetCompute}, NamePattern: `^node-[0-9]+$`, MaximumCount: 1},
		Limits:     commandpack.Limits{TimeoutSeconds: 1, MaximumOutputBytes: 1024, MaximumConcurrency: 1}, OutputSchema: "test-output",
	})
	if _, err := adapter.requestFromInvocation(parameterized, "attempt-1", invocation, nil); err == nil {
		t.Fatal("a definition declaring parameters was accepted")
	}

	privileged := agentlessCatalog(t, commandpack.Definition{
		ID: "test-command", Version: "1.0.0", Owner: "tests", Purpose: "privilege denial",
		SupportedCapabilities: []string{"diagnostics.read"}, Risk: commandpack.RiskPrivileged,
		ExecutablePath: "/usr/bin/nvidia-smi", ExecutableSHA256: strings.Repeat("b", 64), Arguments: []commandpack.ArgumentToken{{Literal: "safe"}},
		Targets:           commandpack.TargetConstraints{Roles: []commandpack.TargetRole{commandpack.TargetCompute}, NamePattern: `^node-[0-9]+$`, MaximumCount: 1},
		RequiresPrivilege: true, SudoRule: "sherlock ALL=(root) NOPASSWD: /usr/bin/nvidia-smi safe",
		Limits: commandpack.Limits{TimeoutSeconds: 1, MaximumOutputBytes: 1024, MaximumConcurrency: 1}, OutputSchema: "test-output",
	})
	if _, err := adapter.requestFromInvocation(privileged, "attempt-1", invocation, nil); err == nil {
		t.Fatal("a privileged definition was accepted")
	}

	for _, executable := range []string{"/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/sftp", "/usr/bin/sha256sum"} {
		t.Run("forbidden pack executable "+filepath.Base(executable), func(t *testing.T) {
			catalog := agentlessCatalog(t, commandpack.Definition{
				ID: "test-command", Version: "1.0.0", Owner: "tests", Purpose: "transport trampoline denial",
				SupportedCapabilities: []string{"diagnostics.read"}, Risk: commandpack.RiskLow,
				ExecutablePath: executable, ExecutableSHA256: strings.Repeat("b", 64), Arguments: []commandpack.ArgumentToken{{Literal: "safe"}},
				Targets: commandpack.TargetConstraints{Roles: []commandpack.TargetRole{commandpack.TargetCompute}, NamePattern: `^node-[0-9]+$`, MaximumCount: 1},
				Limits:  commandpack.Limits{TimeoutSeconds: 1, MaximumOutputBytes: 1024, MaximumConcurrency: 1}, OutputSchema: "test-output",
			})
			if _, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil); err == nil {
				t.Fatalf("pack executable %s was accepted", executable)
			}
		})
	}
}

func TestAgentlessSSHRequiresPublicKeyReducedTrustAndProtectedHostIdentity(t *testing.T) {
	identity := ExecutableIdentity{Path: "/usr/bin/ssh", SHA256: strings.Repeat("a", 64)}
	password := testAgentlessSSHConfig(t, identity)
	profile := password.Authentication.AuthenticationProfiles["pilot-key"]
	profile.Method = SSHAuthenticationPassword
	password.Authentication.AuthenticationProfiles["pilot-key"] = profile
	if _, err := NewAgentlessSSH(password); err == nil {
		t.Fatal("a password profile was accepted")
	}
	sealed := testAgentlessSSHConfig(t, identity)
	target := sealed.Authentication.Targets["node-1"]
	target.PrincipalConstraint = SSHPrincipalAuthorizedKeyForceCommand
	sealed.Authentication.Targets["node-1"] = target
	if _, err := NewAgentlessSSH(sealed); err == nil {
		t.Fatal("a non-acknowledged principal was accepted")
	}
	foreign := testAgentlessSSHConfig(t, identity)
	foreign.ClusterID = "foreign-cluster"
	if _, err := NewAgentlessSSH(foreign); err == nil {
		t.Fatal("a cluster outside the protected policy was accepted")
	}

	base := testAgentlessSSHConfig(t, identity)
	adapter, err := NewAgentlessSSH(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base.KnownHostsFile, []byte("compute-one ssh-ed25519 changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("b", 64)}, []string{"safe"}, []string{"node-1"})
	if _, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil); err == nil {
		t.Fatal("a changed host identity file was accepted")
	}
}

func TestAgentlessSSHProjectsRawBoundedOutputAndClassifiesFailures(t *testing.T) {
	for name, fixture := range map[string]struct {
		script   string
		wantCode string
		wantText string
	}{
		"underlying output": {script: "#!/bin/sh\nprintf 'ecc=0\\001\\n'\nprintf 'warning\\n' >&2\n", wantText: "ecc=0[CONTROL]\n"},
		"digest drift":      {script: "#!/bin/sh\nexit 125\n", wantCode: CodeRemoteExecutableDrift},
		"changed host key":  {script: "#!/bin/sh\nprintf 'REMOTE HOST IDENTIFICATION HAS CHANGED' >&2\nexit 255\n", wantCode: CodeExitNonZero},
		"authentication":    {script: "#!/bin/sh\nprintf 'Permission denied' >&2\nexit 255\n", wantCode: CodeExitNonZero},
		"truncated output":  {script: "#!/bin/sh\ni=0; while [ $i -lt 1200 ]; do printf x; i=$((i+1)); done\n", wantCode: CodeOutputTruncated},
		"oversized stderr":  {script: "#!/bin/sh\ni=0; while [ $i -lt 1200 ]; do printf x >&2; i=$((i+1)); done\n", wantCode: CodeOutputTruncated},
	} {
		t.Run(name, func(t *testing.T) {
			identity := writeFakeSSH(t, fixture.script)
			adapter := testAgentlessSSH(t, identity)
			catalog, invocation := testAgentlessSSHFixtureCatalogAndInvocation(t)
			// This fixture only exercises SSH exit classification. Give its
			// disposable process enough scheduling headroom for the full race
			// lane; TestAgentlessSSHTimeoutIsBounded covers the command deadline.
			result, err := adapter.ExecuteInvocation(context.Background(), testRunnerWithLimits(t, 2048, 2), catalog, "attempt-1", invocation, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Targets) != 1 || result.Targets[0].ErrorCode != fixture.wantCode {
				t.Fatalf("result = %#v", result)
			}
			if fixture.wantText != "" && string(result.Targets[0].Stdout) != fixture.wantText {
				t.Fatalf("raw screened stdout = %q", result.Targets[0].Stdout)
			}
			if fixture.wantText != "" {
				projected := attemptTargets([]domain.DiagnosticTarget{"node-1"}, result)
				if len(projected) != 1 || projected[0].StdoutExcerpt != fixture.wantText || strings.Contains(projected[0].StdoutExcerpt, RemoteResultSchemaV1) {
					t.Fatalf("underlying output projection = %#v", projected)
				}
			}
			if strings.Contains(string(result.Targets[0].Stdout), RemoteResultSchemaV1) {
				t.Fatal("agentless output was fabricated as a runner envelope")
			}
		})
	}
}

func testAgentlessSSHFixtureCatalogAndInvocation(t *testing.T) (*commandpack.Catalog, commandpack.Invocation) {
	t.Helper()
	catalog := agentlessCatalog(t, commandpack.Definition{
		ID: "test-command", Version: "1.0.0", Owner: "tests", Purpose: "agentless SSH fixture",
		SupportedCapabilities: []string{"diagnostics.read"}, Risk: commandpack.RiskLow,
		ExecutablePath: "/usr/bin/nvidia-smi", ExecutableSHA256: strings.Repeat("b", 64), Arguments: []commandpack.ArgumentToken{{Literal: "safe"}},
		Targets: commandpack.TargetConstraints{Roles: []commandpack.TargetRole{commandpack.TargetCompute}, NamePattern: `^node-[0-9]+$`, MaximumCount: 1},
		Limits:  commandpack.Limits{TimeoutSeconds: 10, MaximumOutputBytes: 1024, MaximumConcurrency: 1}, OutputSchema: "test-output",
	})
	return catalog, commandpack.Invocation{DefinitionID: "test-command", DefinitionVersion: "1.0.0", Targets: []commandpack.Target{{Name: "node-1", Role: commandpack.TargetCompute}}}
}

func TestAgentlessSSHTimeoutIsBounded(t *testing.T) {
	identity := writeFakeSSH(t, "#!/bin/sh\nsleep 2\n")
	adapter := testAgentlessSSH(t, identity)
	catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("b", 64)}, []string{"safe"}, []string{"node-1"})
	request, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Timeout = 20 * time.Millisecond
	started := time.Now()
	result, err := testRunner(t).execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second || !result.Targets[0].TimedOut || result.Targets[0].ErrorCode != CodeTimedOut {
		t.Fatalf("timeout result = %#v elapsed=%s", result.Targets[0], elapsed)
	}
}

func TestAgentlessSSHRefusesReplacedTransportAndInactiveDefinitionBeforeDispatch(t *testing.T) {
	t.Run("replaced transport", func(t *testing.T) {
		identity := writeFakeSSH(t, "#!/bin/sh\nprintf reached\n")
		adapter := testAgentlessSSH(t, identity)
		if err := os.WriteFile(identity.Path, []byte("#!/bin/sh\nprintf replaced\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("b", 64)}, []string{"safe"}, []string{"node-1"})
		result, err := adapter.ExecuteInvocation(context.Background(), testRunner(t), catalog, "attempt-1", invocation, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Targets) != 1 || result.Targets[0].Started || result.Targets[0].ErrorCode != CodeExecutableReplaced {
			t.Fatalf("replaced transport result = %#v", result)
		}
	})

	t.Run("inactive definition", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "dispatched")
		identity := writeFakeSSH(t, "#!/bin/sh\nprintf reached >"+posixShellQuote(marker)+"\n")
		adapter := testAgentlessSSH(t, identity)
		catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("b", 64)}, []string{"safe"}, []string{"node-1"})
		runner := testRunnerAt(t, fixedRunnerClock{now: runnerTestNow.Add(2 * time.Hour)})
		if _, err := adapter.ExecuteInvocation(context.Background(), runner, catalog, "attempt-1", invocation, nil); err == nil {
			t.Fatal("an inactive definition was accepted")
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("inactive definition reached the SSH transport")
		}
	})
}

func testAgentlessSSH(t *testing.T, executable ExecutableIdentity) *AgentlessSSH {
	t.Helper()
	adapter, err := NewAgentlessSSH(testAgentlessSSHConfig(t, executable))
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func testAgentlessSSHConfig(t *testing.T, executable ExecutableIdentity) AgentlessSSHConfig {
	t.Helper()
	knownHosts := writeInventory(t, "known_hosts", "compute-one ssh-ed25519 AAAATestOnly\n")
	return AgentlessSSHConfig{
		ClusterID: "pilot-cluster", Executable: executable, KnownHostsFile: knownHosts,
		Authentication: SSHTargetAuthentication{
			SchemaVersion: SSHTargetAuthenticationSchemaV1,
			AuthenticationProfiles: map[string]SSHAuthenticationProfile{"pilot-key": {
				ID: "pilot-key", Method: SSHAuthenticationPublicKey, CredentialSource: SSHCredentialHeadLocalPersistent, CredentialReference: SSHOpenSSHDefaultIdentityReference,
			}},
			Targets: map[string]SSHTarget{"node-1": {
				ID: "node-1", Address: "compute-one", Port: 22, Username: "cloud-user", AuthenticationProfile: "pilot-key", PrincipalConstraint: SSHPrincipalSharedShellReducedTrust,
			}},
		},
		Policy: AgentlessSSHPolicy{SchemaVersion: AgentlessSSHPolicySchemaV1, Acknowledgement: AgentlessSSHTrustAcknowledgement, AllowList: []AgentlessSSHPermission{{
			ClusterID: "pilot-cluster", TargetID: "node-1", DefinitionID: "test-command", DefinitionVersion: "1.0.0",
		}}},
	}
}

func writeFakeSSH(t *testing.T, contents string) ExecutableIdentity {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(contents))
	return ExecutableIdentity{Path: path, SHA256: hex.EncodeToString(digest[:])}
}

func agentlessCatalog(t *testing.T, definition commandpack.Definition) *commandpack.Catalog {
	t.Helper()
	now := runnerTestNow
	pack := commandpack.Pack{
		SchemaVersion: commandpack.SchemaVersion, ID: "agentless-tests", Version: "1.0.0", Issuer: "test-issuer",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MinimumRunner: "1.0.0", MaximumRunner: "2.0.0",
		Reviews:     []commandpack.Review{{ReviewerID: "reviewer-a", ReviewedAt: now.Add(-3 * time.Minute), Approved: true}, {ReviewerID: "reviewer-b", ReviewedAt: now.Add(-2 * time.Minute), Approved: true}},
		Definitions: []commandpack.Definition{definition},
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := commandpack.Sign(pack, "test-root", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := commandpack.NewTrustStore([]commandpack.TrustRoot{{ID: "test-root", Issuer: pack.Issuer, PublicKey: publicKey, ActivatesAt: now.Add(-time.Hour), RetiresAt: now.Add(2 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Verify(release, "1.0.0", now)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}
