package diagnosticrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestRestrictedSSHUsesSealedPlanFixedInventoryAndStructuredInput(t *testing.T) {
	adapter := testSSHAdapter(t)
	malicious := "node; sudo sh -c 'touch /tmp/pwned'"
	catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)}, []string{"--query", malicious}, []string{"node-1"})

	request, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil)
	if err != nil {
		t.Fatalf("requestFromInvocation() error = %v", err)
	}
	target := request.Targets[0]
	joined := strings.Join(target.Args, "\x00")
	for _, required := range []string{
		"-F\x00/dev/null", "-oProxyCommand=none", "-oProxyJump=none", "-oControlMaster=no",
		"-oPermitLocalCommand=no", "-oStrictHostKeyChecking=yes", "-oIdentitiesOnly=yes",
		"-oPasswordAuthentication=no", "-oUserKnownHostsFile=" + adapter.knownHostsFile,
		"-p\x0022\x00--\x00sherlock-runner@compute-one\x00" + forcedRemoteCommand,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("ssh argv lacks %q: %#v", required, target.Args)
		}
	}
	if strings.Contains(joined, malicious) {
		t.Fatal("remote argument escaped into ssh argv")
	}
	if bytes.Contains(target.input, []byte("/usr/bin/nvidia-smi")) || bytes.Contains(target.input, []byte(malicious)) {
		t.Fatal("wire envelope flattened executable or argv instead of carrying the typed invocation")
	}
	var envelope remoteEnvelope
	if err := json.Unmarshal(target.input, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Invocation.DefinitionID != "test-command" || len(envelope.Invocation.Targets) != 1 || envelope.Invocation.Targets[0].Name != "node-1" || !validSHA256(envelope.ExpectedDefinitionDigest) {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestRemoteExecutorReplansTypedInvocationAgainstVerifiedCatalog(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)
	catalog, invocation := testVerifiedCatalogAndInvocation(t, identity, helperArgs("echo", "remote-sealed"), []string{"node-1"})
	adapter := testSSHAdapter(t)
	request, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := NewRemoteExecutor(catalog, runner, commandpack.Target{Name: "node-1", Role: commandpack.TargetCompute}, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	result, err := remote.Execute(context.Background(), bytes.NewReader(request.Targets[0].input), nil)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(result.Targets) != 1 || result.Targets[0].ErrorCode != "" || string(result.Targets[0].Stdout) != "remote-sealed" {
		t.Fatalf("result = %#v", result)
	}
}

func TestRemoteExecutorRejectsTamperedEnvelope(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)
	catalog, invocation := testVerifiedCatalogAndInvocation(t, identity, helperArgs("echo", "must-not-run"), []string{"node-1"})
	adapter := testSSHAdapter(t)
	request, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := NewRemoteExecutor(catalog, runner, commandpack.Target{Name: "node-1", Role: commandpack.TargetCompute}, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	var original remoteEnvelope
	if err := json.Unmarshal(request.Targets[0].input, &original); err != nil {
		t.Fatal(err)
	}
	stringValue := "shell payload"
	tests := map[string]func(remoteEnvelope) []byte{
		"definition": func(envelope remoteEnvelope) []byte {
			envelope.Invocation.DefinitionID = "unapproved-command"
			payload, _ := json.Marshal(envelope)
			return payload
		},
		"argument": func(envelope remoteEnvelope) []byte {
			envelope.Invocation.Arguments = []commandpack.ArgumentValue{{Name: "command", String: &stringValue}}
			payload, _ := json.Marshal(envelope)
			return payload
		},
		"digest": func(envelope remoteEnvelope) []byte {
			envelope.ExpectedDefinitionDigest = strings.Repeat("0", 64)
			payload, _ := json.Marshal(envelope)
			return payload
		},
		"target": func(envelope remoteEnvelope) []byte {
			envelope.Invocation.Targets[0].Name = "node-2"
			payload, _ := json.Marshal(envelope)
			return payload
		},
		"flattened executable": func(envelope remoteEnvelope) []byte {
			payload, _ := json.Marshal(envelope)
			return append([]byte(`{"executable":"/bin/sh",`), payload[1:]...)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := original
			candidate.Invocation = cloneInvocation(original.Invocation)
			if _, err := remote.Execute(context.Background(), bytes.NewReader(mutate(candidate)), nil); err == nil {
				t.Fatal("tampered envelope was accepted")
			}
		})
	}
}

func TestRestrictedSSHDecodesUnderlyingRemoteResult(t *testing.T) {
	request := testRemoteResultRequest()
	remote := testRemoteResult([]byte("underlying diagnostic output\n"))
	payload := encodeTestRemoteResult(t, remote)
	transport := testTransportResult(request, payload)

	result, err := (&RestrictedSSH{}).decodeTransportResult(request, transport)
	if err != nil {
		t.Fatalf("decodeTransportResult() error = %v", err)
	}
	if len(result.Targets) != 1 || !bytes.Equal(result.Targets[0].Stdout, remote.Targets[0].Stdout) {
		t.Fatalf("decoded result = %#v", result)
	}
	if bytes.Equal(result.Targets[0].Stdout, payload) || bytes.Contains(result.Targets[0].Stdout, []byte(RemoteResultSchemaV1)) {
		t.Fatal("SSH JSON wrapper was returned as diagnostic output")
	}
	recorded := attemptTargets([]domain.DiagnosticTarget{"node-1"}, result)
	if len(recorded) != 1 || recorded[0].StdoutExcerpt != "underlying diagnostic output\n" {
		t.Fatalf("durable target projection = %#v", recorded)
	}
}

func TestRestrictedSSHRejectsMalformedDuplicateTruncatedAndTrailingRemoteJSON(t *testing.T) {
	request := testRemoteResultRequest()
	valid := encodeTestRemoteResult(t, testRemoteResult([]byte("safe")))
	duplicate := append([]byte(`{"schema_version":"sherlock.runner-result.v1",`), valid[1:]...)
	unknown := append([]byte(`{"unexpected":true,`), valid[1:]...)
	tests := map[string][]byte{
		"malformed":      []byte(`{"schema_version":`),
		"duplicate key":  duplicate,
		"unknown field":  unknown,
		"truncated JSON": valid[:len(valid)-3],
		"trailing JSON":  append(append([]byte(nil), valid...), []byte(` {}`)...),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRemoteResult(payload, request, "node-1"); err == nil {
				t.Fatal("invalid remote JSON was accepted")
			}
		})
	}
	t.Run("bounded", func(t *testing.T) {
		bounded := request
		bounded.MaxOutputBytes = int64(len(valid) - 1)
		if _, err := decodeRemoteResult(valid, bounded, "node-1"); err == nil {
			t.Fatal("oversized remote JSON was accepted")
		}
	})
	t.Run("transport truncation", func(t *testing.T) {
		transport := testTransportResult(request, valid)
		transport.Targets[0].StdoutTruncated = true
		if _, err := (&RestrictedSSH{}).decodeTransportResult(request, transport); err == nil {
			t.Fatal("truncated transport result was accepted")
		}
	})
}

func TestRestrictedSSHRejectsTamperedAndMismatchedRemoteResults(t *testing.T) {
	request := testRemoteResultRequest()
	base := testRemoteResult([]byte("safe"))
	tests := map[string]func(*Result){
		"attempt": func(result *Result) { result.AttemptID = "attempt-2" },
		"definition ID": func(result *Result) {
			result.DefinitionID = "other-command"
		},
		"definition version": func(result *Result) { result.DefinitionVersion = "v2" },
		"definition digest": func(result *Result) {
			result.DefinitionDigest = strings.Repeat("b", 64)
		},
		"target": func(result *Result) { result.Targets[0].TargetID = "node-2" },
		"empty cardinality": func(result *Result) {
			result.Targets = nil
		},
		"duplicate cardinality": func(result *Result) {
			result.Targets = append(result.Targets, result.Targets[0])
		},
		"invalid target state": func(result *Result) {
			result.Targets[0].ErrorCode = "CALLER_CONTROLLED"
		},
		"claimed output exceeds definition": func(result *Result) {
			result.Targets[0].StdoutBytes = 1<<10 + 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneTestResult(base)
			mutate(&candidate)
			document := remoteResultDocument{SchemaVersion: RemoteResultSchemaV1, Result: toRemoteWireResult(candidate)}
			payload, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeRemoteResult(payload, request, "node-1"); err == nil {
				t.Fatal("tampered remote result was accepted")
			}
		})
	}
}

func TestRestrictedSSHRejectsFailedAndMismatchedTransportResults(t *testing.T) {
	request := testRemoteResultRequest()
	payload := encodeTestRemoteResult(t, testRemoteResult([]byte("safe")))
	tests := map[string]func(*Result){
		"nonzero SSH exit": func(result *Result) {
			result.Targets[0].ExitCode = 255
			result.Targets[0].ErrorCode = CodeExitNonZero
		},
		"transport target":  func(result *Result) { result.Targets[0].TargetID = "node-2" },
		"transport attempt": func(result *Result) { result.AttemptID = "attempt-2" },
		"transport cardinality": func(result *Result) {
			result.Targets = append(result.Targets, result.Targets[0])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			transport := testTransportResult(request, payload)
			mutate(&transport)
			if _, err := (&RestrictedSSH{}).decodeTransportResult(request, transport); err == nil {
				t.Fatal("invalid transport result was accepted")
			}
		})
	}
}

func TestRemoteResultBudgetAccountsForBase64AndPerTargetEnvelope(t *testing.T) {
	budget, err := remoteResultBudget(4 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if budget <= 4<<20 || budget > RestrictedSSHMaxTransportOutputBytes {
		t.Fatalf("budget = %d", budget)
	}
	if _, err := remoteResultBudget(64 << 20); err != nil {
		t.Fatalf("command-pack maximum is not representable: %v", err)
	}
	if _, err := remoteResultBudget(64<<20 + 1); err == nil {
		t.Fatal("output above the command-pack maximum was accepted")
	}
}

func TestRestrictedSSHRejectsTargetOutsideInventory(t *testing.T) {
	adapter := testSSHAdapter(t)
	catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)}, []string{"--query-gpu=index"}, []string{"node-2"})
	if _, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil); err == nil {
		t.Fatal("requestFromInvocation() error = nil")
	}
}

func TestRestrictedSSHRejectsSudoShellAndNestedSSH(t *testing.T) {
	adapter := testSSHAdapter(t)
	for _, executable := range []string{"/usr/bin/sudo", "/bin/sh", "/usr/bin/ssh"} {
		t.Run(executable, func(t *testing.T) {
			catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: executable, SHA256: strings.Repeat("a", 64)}, []string{"safe"}, []string{"node-1"})
			if _, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil); err == nil {
				t.Fatal("requestFromInvocation() error = nil")
			}
		})
	}
}

func TestRestrictedSSHRequiresPinnedKnownHostsFile(t *testing.T) {
	identity := ExecutableIdentity{Path: "/usr/bin/ssh", SHA256: strings.Repeat("0", 64)}
	tests := map[string]func(*SSHConfig){
		"missing":  func(config *SSHConfig) { config.KnownHostsFile = filepath.Join(t.TempDir(), "missing") },
		"relative": func(config *SSHConfig) { config.KnownHostsFile = "known_hosts" },
		"writable": func(config *SSHConfig) {
			config.KnownHostsFile = testKnownHostsFile(t)
			if err := os.Chmod(config.KnownHostsFile, 0666); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(config *SSHConfig) {
			target := testKnownHostsFile(t)
			link := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			config.KnownHostsFile = link
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := SSHConfig{Executable: identity, Authentication: testSSHTargetAuthentication(), KnownHostsFile: testKnownHostsFile(t)}
			mutate(&config)
			if _, err := NewRestrictedSSH(config); err == nil {
				t.Fatal("NewRestrictedSSH() error = nil")
			}
		})
	}
}

func TestRestrictedSSHDetectsKnownHostsReplacement(t *testing.T) {
	adapter := testSSHAdapter(t)
	if err := os.WriteFile(adapter.knownHostsFile, []byte("compute-one ssh-ed25519 changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	catalog, invocation := testVerifiedCatalogAndInvocation(t, ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)}, []string{"safe"}, []string{"node-1"})
	if _, err := adapter.requestFromInvocation(catalog, "attempt-1", invocation, nil); err == nil {
		t.Fatal("known-hosts replacement was accepted")
	}
}

func TestRestrictedSSHRejectsReducedTrustAndPasswordProfilesUntilNativeTransport(t *testing.T) {
	digest := strings.Repeat("0", 64)
	for name, mutate := range map[string]func(*SSHTargetAuthentication){
		"reduced trust principal": func(contract *SSHTargetAuthentication) {
			target := contract.Targets["node-1"]
			target.PrincipalConstraint = SSHPrincipalSharedShellReducedTrust
			contract.Targets["node-1"] = target
		},
		"password before native transport": func(contract *SSHTargetAuthentication) {
			profile := contract.AuthenticationProfiles["pilot-auth"]
			profile.Method = SSHAuthenticationPassword
			contract.AuthenticationProfiles["pilot-auth"] = profile
		},
	} {
		t.Run(name, func(t *testing.T) {
			contract := testSSHTargetAuthentication()
			mutate(&contract)
			_, err := NewRestrictedSSH(SSHConfig{
				Executable:     ExecutableIdentity{Path: "/usr/bin/ssh", SHA256: digest},
				Authentication: contract, KnownHostsFile: testKnownHostsFile(t),
			})
			if err == nil {
				t.Fatal("NewRestrictedSSH() error = nil")
			}
		})
	}
}

func testSSHAdapter(t *testing.T) *RestrictedSSH {
	t.Helper()
	adapter, err := NewRestrictedSSH(SSHConfig{
		Executable:     ExecutableIdentity{Path: "/usr/bin/ssh", SHA256: strings.Repeat("0", 64)},
		Authentication: testSSHTargetAuthentication(), KnownHostsFile: testKnownHostsFile(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func testSSHTargetAuthentication() SSHTargetAuthentication {
	return SSHTargetAuthentication{
		SchemaVersion: SSHTargetAuthenticationSchemaV1,
		AuthenticationProfiles: map[string]SSHAuthenticationProfile{
			"pilot-auth": {
				ID: "pilot-auth", Method: SSHAuthenticationPublicKey,
				CredentialSource: SSHCredentialHeadLocalPersistent, CredentialReference: SSHOpenSSHDefaultIdentityReference,
			},
		},
		Targets: map[string]SSHTarget{
			"node-1": {
				ID: "node-1", Address: "compute-one", Port: 22, Username: "sherlock-runner",
				AuthenticationProfile: "pilot-auth", PrincipalConstraint: SSHPrincipalAuthorizedKeyForceCommand,
			},
		},
	}
}

func testKnownHostsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("compute-one ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testRemoteResultRequest() executionRequest {
	return executionRequest{
		DefinitionID: "test-command", DefinitionVersion: "v1", DefinitionDigest: strings.Repeat("a", 64),
		AttemptID: "attempt-1", Targets: []targetPlan{{TargetID: "node-1"}}, MaxOutputBytes: 1 << 20, RemoteResultMaxOutputBytes: 1 << 10,
	}
}

func testRemoteResult(stdout []byte) Result {
	stdoutDigest := sha256.Sum256(stdout)
	stderrDigest := sha256.Sum256(nil)
	return Result{
		DefinitionID: "test-command", DefinitionVersion: "v1", DefinitionDigest: strings.Repeat("a", 64), AttemptID: "attempt-1",
		Targets: []TargetResult{{
			TargetID: "node-1", Started: true, ExitCode: 0, Stdout: append([]byte(nil), stdout...),
			StdoutBytes: int64(len(stdout)), StdoutSHA256: fmt.Sprintf("%x", stdoutDigest[:]),
			StderrSHA256: fmt.Sprintf("%x", stderrDigest[:]), Duration: time.Millisecond,
		}},
	}
}

func TestRemoteTransformationProofFailsClosedAcrossVersions(t *testing.T) {
	request := testRemoteResultRequest()
	base := testRemoteResult([]byte("safe"))
	base.Targets[0].StdoutTransformationState = domain.StdoutTransformationUnmodified
	for _, fixture := range []struct {
		name, schema, state string
		want                domain.StdoutTransformationState
	}{
		{"v2 valid", RemoteResultSchemaV2, "UNMODIFIED", domain.StdoutTransformationUnmodified},
		{"v2 missing", RemoteResultSchemaV2, "", domain.StdoutTransformationUnknown},
		{"v2 malformed", RemoteResultSchemaV2, "unmodified", domain.StdoutTransformationUnknown},
		{"v1 cannot attest", RemoteResultSchemaV1, "UNMODIFIED", domain.StdoutTransformationUnknown},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			wire := toRemoteWireResult(base)
			wire.Targets[0].StdoutTransformationState = fixture.state
			payload, err := json.Marshal(remoteResultDocument{SchemaVersion: fixture.schema, Result: wire})
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeRemoteResult(payload, request, "node-1")
			if err != nil {
				t.Fatal(err)
			}
			if got.Targets[0].StdoutTransformationState != fixture.want {
				t.Fatalf("state = %s, want %s", got.Targets[0].StdoutTransformationState, fixture.want)
			}
		})
	}
}

func encodeTestRemoteResult(t *testing.T, result Result) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := EncodeRemoteResult(&output, result); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func testTransportResult(request executionRequest, payload []byte) Result {
	return Result{
		DefinitionID: request.DefinitionID, DefinitionVersion: request.DefinitionVersion,
		DefinitionDigest: request.DefinitionDigest, AttemptID: request.AttemptID,
		Targets: []TargetResult{{TargetID: "node-1", Started: true, ExitCode: 0, Stdout: append([]byte(nil), payload...)}},
	}
}

func cloneTestResult(result Result) Result {
	cloned := result
	cloned.Targets = append([]TargetResult(nil), result.Targets...)
	for index := range cloned.Targets {
		cloned.Targets[index].Stdout = append([]byte(nil), result.Targets[index].Stdout...)
		cloned.Targets[index].Stderr = append([]byte(nil), result.Targets[index].Stderr...)
	}
	return cloned
}
