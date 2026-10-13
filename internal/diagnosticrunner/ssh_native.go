package diagnosticrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"golang.org/x/crypto/ssh"
)

func (adapter *RestrictedSSH) executePasswordTarget(parent context.Context, request executionRequest, plan targetPlan) (TargetResult, error) {
	if adapter.credentials == nil || adapter.hostKeyCallback == nil {
		return TargetResult{}, errors.New("restricted ssh: password transport is unavailable")
	}
	if _, err := verifyKnownHostsFile(adapter.knownHostsFile, adapter.knownHostsSHA256); err != nil {
		return TargetResult{}, err
	}
	target := adapter.targets[plan.TargetID]
	profile := adapter.profiles[target.AuthenticationProfile]
	if profile.Method != SSHAuthenticationPassword || target.PrincipalConstraint != SSHPrincipalDedicatedSSHDForceCommand {
		return TargetResult{}, errors.New("restricted ssh: password target is not force-command constrained")
	}
	var result TargetResult
	err := adapter.credentials.WithPassword(parent, profile.CredentialReference, func(provided []byte) error {
		if len(provided) == 0 || len(provided) > maxSSHPasswordBytes {
			return errors.New("restricted ssh: password credential exceeds policy")
		}
		password := append([]byte(nil), provided...)
		defer clear(password)
		remote, err := adapter.runNativeSSH(parent, request, plan, target, password)
		if err != nil {
			return err
		}
		redactionSecrets := cloneSecrets(request.SuppliedSecrets)
		redactionSecrets = append(redactionSecrets, append([]byte(nil), password...))
		defer clearSecrets(redactionSecrets)
		result = redactTargetSecrets(remote, redactionSecrets)
		return nil
	})
	if err != nil {
		return TargetResult{}, errors.New("restricted ssh: password transport failed")
	}
	return result, nil
}

func (adapter *RestrictedSSH) runNativeSSH(parent context.Context, request executionRequest, plan targetPlan, target SSHTarget, password []byte) (TargetResult, error) {
	ctx, cancel := context.WithTimeout(parent, request.Timeout)
	defer cancel()
	address := net.JoinHostPort(target.Address, strconv.FormatUint(uint64(target.Port), 10))
	dialer := net.Dialer{Timeout: request.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return TargetResult{}, errors.New("restricted ssh: native connection failed")
	}
	defer connection.Close()
	if deadline, exists := ctx.Deadline(); exists {
		if err := connection.SetDeadline(deadline); err != nil {
			return TargetResult{}, errors.New("restricted ssh: native deadline failed")
		}
	}
	configuration := &ssh.ClientConfig{
		User: target.Username,
		Auth: []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) {
			// x/crypto/ssh requires a string at the protocol boundary. Create it
			// only when authentication asks, while the mutable source remains
			// owned and cleared by this call.
			return string(password), nil
		})},
		HostKeyCallback: adapter.hostKeyCallback,
		Timeout:         request.Timeout,
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, configuration)
	if err != nil {
		return TargetResult{}, errors.New("restricted ssh: native handshake failed")
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return TargetResult{}, errors.New("restricted ssh: native session failed")
	}
	defer session.Close()
	budget := &outputBudget{remaining: request.MaxOutputBytes}
	secrets := append(cloneSecrets(request.SuppliedSecrets), append([]byte(nil), password...))
	defer clearSecrets(secrets)
	stdout := newSafeCapture(budget, secrets)
	stderr := newSafeCapture(budget, secrets)
	defer stdout.destroy()
	defer stderr.destroy()
	session.Stdin = bytes.NewReader(plan.input)
	session.Stdout = stdout
	session.Stderr = stderr
	if err := session.Start(forcedRemoteCommand); err != nil {
		stdout.finish()
		stderr.finish()
		return TargetResult{}, errors.New("restricted ssh: fixed remote command failed to start")
	}
	waited := make(chan error, 1)
	go func() { waited <- session.Wait() }()
	select {
	case err = <-waited:
	case <-ctx.Done():
		_ = session.Close()
		_ = client.Close()
		<-waited
		stdout.finish()
		stderr.finish()
		return TargetResult{}, errors.New("restricted ssh: native command timed out or was cancelled")
	}
	stdout.finish()
	stderr.finish()
	payload, _, truncated, _, _ := stdout.result()
	defer clear(payload)
	if err != nil || truncated {
		return TargetResult{}, errors.New("restricted ssh: fixed remote command failed")
	}
	remote, err := decodeRemoteResult(payload, request, plan.TargetID)
	if err != nil {
		return TargetResult{}, err
	}
	return remote.Targets[0], nil
}

func redactTargetSecrets(target TargetResult, secrets [][]byte) TargetResult {
	stdoutBefore := target.Stdout
	stdoutComplete := !target.StdoutTruncated && target.StdoutBytes == int64(len(stdoutBefore))
	stdout, stdoutScreened, safeStdoutDigest := redactDiagnosticOutput(stdoutBefore, secrets)
	stdoutDigestMatches := safeStdoutDigest == target.StdoutSHA256
	if stdoutScreened {
		// Screening is a producer fact even when its replacement has the same bytes.
		target.StdoutTransformationState = domain.StdoutTransformationTransformed
	} else if stdoutComplete && !stdoutDigestMatches {
		target.StdoutTransformationState = domain.StdoutTransformationUnknown
	}
	if !bytes.Equal(stdout, target.Stdout) {
		clear(target.Stdout)
	}
	target.Stdout = stdout
	// A remote digest covers the entire emitted stream, which may contain a
	// head-local password beyond the saved prefix. Retain only a digest computed
	// from bytes screened here, or zero when those bytes are incomplete/unproven.
	target.StdoutSHA256 = safeNativeOutputDigest(safeStdoutDigest, stdoutComplete && (stdoutScreened || stdoutDigestMatches))
	stderrBefore := target.Stderr
	stderrComplete := !target.StderrTruncated && target.StderrBytes == int64(len(stderrBefore))
	stderr, stderrScreened, safeStderrDigest := redactDiagnosticOutput(stderrBefore, secrets)
	stderrDigestMatches := safeStderrDigest == target.StderrSHA256
	if !bytes.Equal(stderr, target.Stderr) {
		clear(target.Stderr)
	}
	target.Stderr = stderr
	target.StderrSHA256 = safeNativeOutputDigest(safeStderrDigest, stderrComplete && (stderrScreened || stderrDigestMatches))
	return target
}

func safeNativeOutputDigest(screenedDigest string, complete bool) string {
	if !complete {
		return strings.Repeat("0", sha256.Size*2)
	}
	return screenedDigest
}

func redactDiagnosticOutput(output []byte, secrets [][]byte) ([]byte, bool, string) {
	budget := &outputBudget{remaining: int64(len(output)) + int64(len(redactedMarker))*int64(len(output))}
	capture := newSafeCapture(budget, secrets)
	_, _ = capture.Write(output)
	capture.finish()
	redacted, _, _, digest, state := capture.result()
	return redacted, state == domain.StdoutTransformationTransformed, digest
}
