package diagnosticrunner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type clearingCredentialProvider struct {
	password  []byte
	reference string
	exposed   []byte
}

func (provider *clearingCredentialProvider) WithPassword(ctx context.Context, reference string, consume func([]byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.reference = reference
	buffer := append([]byte(nil), provider.password...)
	provider.exposed = buffer
	defer clear(buffer)
	return consume(buffer)
}

type nativeSSHTestServer struct {
	listener  net.Listener
	signer    ssh.Signer
	password  []byte
	output    []byte
	rawResult []byte
	hang      bool
	mutex     sync.Mutex
	commands  []string
	unsafe    []string
}

func newNativeSSHTestServer(t *testing.T, password, output []byte) *nativeSSHTestServer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &nativeSSHTestServer{listener: listener, signer: signer, password: append([]byte(nil), password...), output: append([]byte(nil), output...)}
	go server.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func (server *nativeSSHTestServer) serve() {
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		go server.serveConnection(connection)
	}
}

func (server *nativeSSHTestServer) serveConnection(connection net.Conn) {
	configuration := &ssh.ServerConfig{PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if metadata.User() != "sherlock-runner" || !bytes.Equal(password, server.password) {
			return nil, fmt.Errorf("denied")
		}
		return nil, nil
	}}
	configuration.AddHostKey(server.signer)
	_, channels, requests, err := ssh.NewServerConn(connection, configuration)
	if err != nil {
		_ = connection.Close()
		return
	}
	go func() {
		for request := range requests {
			server.mutex.Lock()
			server.unsafe = append(server.unsafe, "global:"+request.Type)
			server.mutex.Unlock()
			_ = request.Reply(false, nil)
		}
	}()
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "prohibited")
			continue
		}
		channel, requests, err := channelRequest.Accept()
		if err != nil {
			continue
		}
		go server.serveSession(channel, requests)
	}
}

func (server *nativeSSHTestServer) serveSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	for request := range requests {
		if request.Type != "exec" {
			server.mutex.Lock()
			server.unsafe = append(server.unsafe, request.Type)
			server.mutex.Unlock()
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if ssh.Unmarshal(request.Payload, &payload) != nil {
			_ = request.Reply(false, nil)
			continue
		}
		server.mutex.Lock()
		server.commands = append(server.commands, payload.Command)
		server.mutex.Unlock()
		if payload.Command != forcedRemoteCommand {
			_ = request.Reply(false, nil)
			continue
		}
		_ = request.Reply(true, nil)
		if server.hang {
			return
		}
		input, err := io.ReadAll(channel)
		if err == nil {
			server.writeRemoteResult(channel, input)
		}
		return
	}
}

func (server *nativeSSHTestServer) writeRemoteResult(channel ssh.Channel, input []byte) {
	defer channel.Close()
	if server.rawResult != nil {
		_, _ = channel.Write(server.rawResult)
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
	var envelope remoteEnvelope
	if json.Unmarshal(input, &envelope) != nil || len(envelope.Invocation.Targets) != 1 {
		return
	}
	stdoutDigest := sha256.Sum256(server.output)
	emptyDigest := sha256.Sum256(nil)
	result := Result{
		DefinitionID: envelope.Invocation.DefinitionID, DefinitionVersion: envelope.Invocation.DefinitionVersion,
		DefinitionDigest: envelope.ExpectedDefinitionDigest, AttemptID: envelope.AttemptID,
		Targets: []TargetResult{{
			TargetID: envelope.Invocation.Targets[0].Name, Started: true, ExitCode: 0,
			Stdout: append([]byte(nil), server.output...), StdoutBytes: int64(len(server.output)),
			StdoutSHA256: fmt.Sprintf("%x", stdoutDigest[:]), StderrSHA256: fmt.Sprintf("%x", emptyDigest[:]), Duration: time.Millisecond,
			StdoutTransformationState: domain.StdoutTransformationUnmodified,
		}},
	}
	_ = EncodeRemoteResult(channel, result)
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
}

func (server *nativeSSHTestServer) adapter(t *testing.T, provider SSHCredentialProvider) *RestrictedSSH {
	t.Helper()
	host, portText, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{server.listener.Addr().String()}, server.signer.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	authentication := SSHTargetAuthentication{
		SchemaVersion: SSHTargetAuthenticationSchemaV1,
		AuthenticationProfiles: map[string]SSHAuthenticationProfile{"pilot-password": {
			ID: "pilot-password", Method: SSHAuthenticationPassword, CredentialSource: SSHCredentialHeadLocalPersistent, CredentialReference: "pilot-password-v1",
		}},
		Targets: map[string]SSHTarget{"node-1": {
			ID: "node-1", Address: host, Port: uint16(port), Username: "sherlock-runner",
			AuthenticationProfile: "pilot-password", PrincipalConstraint: SSHPrincipalDedicatedSSHDForceCommand,
		}},
	}
	adapter, err := NewCredentialedSSH(SSHConfig{
		Executable:     ExecutableIdentity{Path: "/usr/bin/ssh", SHA256: strings.Repeat("0", 64)},
		Authentication: authentication, KnownHostsFile: knownHostsPath,
	}, provider)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestCredentialedSSHExecutesOnlyFixedCommandAndRedactsPassword(t *testing.T) {
	password := []byte("native-password-fixture")
	server := newNativeSSHTestServer(t, password, password)
	provider := &clearingCredentialProvider{password: password}
	adapter := server.adapter(t, provider)
	runner := testRunnerWithLimits(t, RestrictedSSHMaxTransportOutputBytes, 64)
	catalog, invocation := testVerifiedCatalogAndInvocation(t, testExecutableIdentity(t), helperArgs("echo", "ignored"), []string{"node-1"})
	result, err := adapter.ExecuteInvocation(context.Background(), runner, catalog, "attempt-1", invocation, nil)
	if err != nil {
		t.Fatalf("ExecuteInvocation() error = %v", err)
	}
	if len(result.Targets) != 1 || string(result.Targets[0].Stdout) != redactedMarker {
		t.Fatalf("result = %#v", result)
	}
	if result.Targets[0].StdoutTransformationState != domain.StdoutTransformationTransformed {
		t.Fatalf("native SSH redaction state = %s", result.Targets[0].StdoutTransformationState)
	}
	if bytes.Contains(result.Targets[0].Stdout, password) || provider.reference != "pilot-password-v1" || !allZero(provider.exposed) {
		t.Fatal("credential escaped provider lifetime or output redaction")
	}
	passwordDigest := sha256.Sum256(password)
	if result.Targets[0].StdoutSHA256 == fmt.Sprintf("%x", passwordDigest[:]) {
		t.Fatal("credential-derived output hash escaped redaction")
	}
	server.mutex.Lock()
	defer server.mutex.Unlock()
	if len(server.commands) != 1 || server.commands[0] != forcedRemoteCommand || len(server.unsafe) != 0 {
		t.Fatalf("commands = %v unsafe requests = %v", server.commands, server.unsafe)
	}
}

func TestNativeSSHEqualByteScreeningDowngradesProducerProof(t *testing.T) {
	password := []byte(redactedMarker)
	digest := sha256.Sum256(password)
	empty := sha256.Sum256(nil)
	target := TargetResult{
		TargetID: "node-1", Started: true, ExitCode: 0,
		Stdout: append([]byte(nil), password...), StdoutBytes: int64(len(password)),
		StdoutSHA256: fmt.Sprintf("%x", digest[:]), StderrSHA256: fmt.Sprintf("%x", empty[:]),
		StdoutTransformationState: domain.StdoutTransformationUnmodified,
	}
	got := redactTargetSecrets(target, [][]byte{password})
	if string(got.Stdout) != redactedMarker || got.StdoutTransformationState != domain.StdoutTransformationTransformed {
		t.Fatalf("equal-byte screening was not attested: state=%s output=%q", got.StdoutTransformationState, got.Stdout)
	}
}

func TestNativeSSHDoesNotRetainDigestBeyondScreenedPrefix(t *testing.T) {
	password := []byte("synthetic-head-password")
	prefix := []byte("visible-prefix")
	full := append(append([]byte(nil), prefix...), password...)
	fullDigest := sha256.Sum256(full)
	empty := sha256.Sum256(nil)
	for _, truncated := range []bool{false, true} {
		t.Run(fmt.Sprintf("truncated=%t", truncated), func(t *testing.T) {
			target := TargetResult{
				TargetID: "node-1", Started: true, ExitCode: 0,
				Stdout: append([]byte(nil), prefix...), StdoutBytes: int64(len(full)), StdoutTruncated: truncated,
				StdoutSHA256: fmt.Sprintf("%x", fullDigest[:]), StderrSHA256: fmt.Sprintf("%x", empty[:]),
				StdoutTransformationState: domain.StdoutTransformationUnmodified,
			}
			got := redactTargetSecrets(target, [][]byte{password})
			if got.StdoutSHA256 != strings.Repeat("0", 64) || got.StdoutSHA256 == fmt.Sprintf("%x", fullDigest[:]) {
				t.Fatal("native result retained a digest of unscreened bytes")
			}
			projected := attemptTargets([]domain.DiagnosticTarget{"node-1"}, Result{Targets: []TargetResult{got}})
			if len(projected) != 1 || projected[0].StdoutSHA256 != (domain.SHA256{}) {
				t.Fatal("head-node result retained a digest of unscreened bytes")
			}
		})
	}
}

func TestNativeSSHInvalidRemoteDigestCannotBecomeExactProof(t *testing.T) {
	empty := sha256.Sum256(nil)
	target := TargetResult{
		TargetID: "node-1", Started: true, ExitCode: 0,
		Stdout: []byte("safe"), StdoutBytes: 4,
		StdoutSHA256: strings.Repeat("a", 64), StderrSHA256: fmt.Sprintf("%x", empty[:]),
		StdoutTransformationState: domain.StdoutTransformationUnmodified,
	}
	got := redactTargetSecrets(target, nil)
	if got.StdoutTransformationState != domain.StdoutTransformationUnknown || got.StdoutSHA256 != strings.Repeat("0", 64) {
		t.Fatalf("invalid remote digest acquired exact proof: state=%s digest=%s", got.StdoutTransformationState, got.StdoutSHA256)
	}
}

func TestCredentialedSSHRejectsWrongPasswordWithoutLeakage(t *testing.T) {
	server := newNativeSSHTestServer(t, []byte("correct-password"), []byte("unused"))
	wrong := []byte("wrong-password-fixture")
	provider := &clearingCredentialProvider{password: wrong}
	adapter := server.adapter(t, provider)
	runner := testRunnerWithLimits(t, RestrictedSSHMaxTransportOutputBytes, 64)
	catalog, invocation := testVerifiedCatalogAndInvocation(t, testExecutableIdentity(t), helperArgs("echo", "ignored"), []string{"node-1"})
	_, err := adapter.ExecuteInvocation(context.Background(), runner, catalog, "attempt-1", invocation, nil)
	if err == nil || strings.Contains(err.Error(), string(wrong)) || !allZero(provider.exposed) {
		t.Fatalf("wrong-password failure = %v", err)
	}
}

func TestCredentialedSSHRejectsChangedPinnedHostIdentity(t *testing.T) {
	password := []byte("native-password-fixture")
	server := newNativeSSHTestServer(t, password, []byte("unused"))
	provider := &clearingCredentialProvider{password: password}
	adapter := server.adapter(t, provider)
	if err := os.WriteFile(adapter.knownHostsFile, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := testRunnerWithLimits(t, RestrictedSSHMaxTransportOutputBytes, 64)
	catalog, invocation := testVerifiedCatalogAndInvocation(t, testExecutableIdentity(t), helperArgs("echo", "ignored"), []string{"node-1"})
	if _, err := adapter.ExecuteInvocation(context.Background(), runner, catalog, "attempt-1", invocation, nil); err == nil {
		t.Fatal("changed host identity was accepted")
	}
}

func TestCredentialedSSHRejectsMalformedRunnerResult(t *testing.T) {
	password := []byte("native-password-fixture")
	server := newNativeSSHTestServer(t, password, nil)
	server.rawResult = []byte(`{"schema_version":`)
	provider := &clearingCredentialProvider{password: password}
	adapter := server.adapter(t, provider)
	runner := testRunnerWithLimits(t, RestrictedSSHMaxTransportOutputBytes, 64)
	catalog, invocation := testVerifiedCatalogAndInvocation(t, testExecutableIdentity(t), helperArgs("echo", "ignored"), []string{"node-1"})
	if _, err := adapter.ExecuteInvocation(context.Background(), runner, catalog, "attempt-1", invocation, nil); err == nil || !allZero(provider.exposed) {
		t.Fatalf("malformed result failure = %v", err)
	}
}

func TestCredentialedSSHBoundsRemoteCommandTime(t *testing.T) {
	password := []byte("native-password-fixture")
	server := newNativeSSHTestServer(t, password, nil)
	server.hang = true
	provider := &clearingCredentialProvider{password: password}
	adapter := server.adapter(t, provider)
	request := testRemoteResultRequest()
	request.Timeout = 50 * time.Millisecond
	request.Targets[0].input = []byte(`{}`)
	started := time.Now()
	_, err := adapter.runNativeSSH(context.Background(), request, request.Targets[0], adapter.targets["node-1"], password)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("bounded execution error = %v duration = %s", err, time.Since(started))
	}
}

func testRunnerWithLimits(t *testing.T, maxOutput int64, maxTargets int) *Runner {
	t.Helper()
	runner, err := New(Config{
		MaxTimeout: time.Minute, MaxOutputBytes: maxOutput, MaxInputBytes: 1 << 20,
		MaxTargets: maxTargets, MaxConcurrency: 8, MaxSuppliedSecrets: 8, MaxSecretBytes: maxSSHPasswordBytes,
		Clock: fixedRunnerClock{now: runnerTestNow},
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}
