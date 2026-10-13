package diagnosticrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const forcedRemoteCommand = "sherlock-runner"
const maxKnownHostsBytes = 1 << 20
const maxSSHInventoryBytes = 1 << 20
const remoteResultTargetOverheadBytes = 64 << 10
const restrictedSSHMaxDiagnosticOutputBytes = 64 << 20

// RestrictedSSHMaxTransportOutputBytes accommodates the JSON/base64 expansion
// of the command-pack maximum while retaining a fixed head-side ceiling.
const RestrictedSSHMaxTransportOutputBytes = 4*((restrictedSSHMaxDiagnosticOutputBytes+2)/3) + remoteResultTargetOverheadBytes

const SSHTargetAuthenticationSchemaV1 = "sherlock.ssh-target-auth.v1"
const SSHOpenSSHDefaultIdentityReference = "openssh-default-identity"

type SSHAuthenticationMethod string

const (
	SSHAuthenticationPublicKey SSHAuthenticationMethod = "public_key"
	SSHAuthenticationPassword  SSHAuthenticationMethod = "password"
)

type SSHCredentialSource string

const (
	// SSHCredentialHeadLocalPersistent is an opaque, non-secret reference that
	// only the head-node credential provider may resolve. Interactive material
	// is deliberately absent from the v1 contract.
	SSHCredentialHeadLocalPersistent SSHCredentialSource = "head_local_persistent"
)

type SSHPrincipalConstraint string

const (
	SSHPrincipalAuthorizedKeyForceCommand SSHPrincipalConstraint = "authorized_key_force_command"
	SSHPrincipalDedicatedSSHDForceCommand SSHPrincipalConstraint = "dedicated_sshd_force_command"
	SSHPrincipalSharedShellReducedTrust   SSHPrincipalConstraint = "shared_shell_reduced_trust"
)

// SSHAuthenticationProfile contains only routing metadata for a head-local
// credential provider. CredentialReference is an opaque identifier, never a
// password, private key, environment-variable name, URL, or command argument.
type SSHAuthenticationProfile struct {
	ID                  string
	Method              SSHAuthenticationMethod
	CredentialSource    SSHCredentialSource
	CredentialReference string
}

// SSHTarget fixes the network and authentication identity for one Sherlock
// target. None of these values may be supplied by work, a model, or a caller.
type SSHTarget struct {
	ID                    string
	Address               string
	Port                  uint16
	Username              string
	AuthenticationProfile string
	PrincipalConstraint   SSHPrincipalConstraint
}

// SSHTargetAuthentication is the validated v1 target/profile contract.
type SSHTargetAuthentication struct {
	SchemaVersion          string
	AuthenticationProfiles map[string]SSHAuthenticationProfile
	Targets                map[string]SSHTarget
}

// SSHConfig names a fixed SSH executable and a protected, versioned target and
// authentication-profile contract.
type SSHConfig struct {
	Executable     ExecutableIdentity
	Authentication SSHTargetAuthentication
	KnownHostsFile string
}

type RestrictedSSH struct {
	executable       ExecutableIdentity
	targets          map[string]SSHTarget
	profiles         map[string]SSHAuthenticationProfile
	knownHostsFile   string
	knownHostsSHA256 string
	credentials      SSHCredentialProvider
	hostKeyCallback  ssh.HostKeyCallback
}

type remoteEnvelope struct {
	AttemptID                string                 `json:"attempt_id"`
	ExpectedDefinitionDigest string                 `json:"expected_definition_digest"`
	Invocation               commandpack.Invocation `json:"invocation"`
}

// RemoteExecutor is the server-side forced-command boundary. It trusts only its
// configured verified catalog and fixed local target, never flattened wire
// executable or argv values.
type RemoteExecutor struct {
	catalog          *commandpack.Catalog
	runner           *Runner
	target           commandpack.Target
	maxEnvelopeBytes int64
}

func NewRemoteExecutor(catalog *commandpack.Catalog, runner *Runner, target commandpack.Target, maxEnvelopeBytes int64) (*RemoteExecutor, error) {
	if catalog == nil || runner == nil || !safeIdentifier(target.Name) || maxEnvelopeBytes <= 0 || maxEnvelopeBytes > 1<<20 {
		return nil, errors.New("remote diagnostic runner: invalid configuration")
	}
	if target.Role != commandpack.TargetHead && target.Role != commandpack.TargetCompute && target.Role != commandpack.TargetBMCGateway {
		return nil, errors.New("remote diagnostic runner: invalid target role")
	}
	return &RemoteExecutor{catalog: catalog, runner: runner, target: target, maxEnvelopeBytes: maxEnvelopeBytes}, nil
}

func NewRestrictedSSH(config SSHConfig) (*RestrictedSSH, error) {
	return newRestrictedSSH(config, nil)
}

// NewCredentialedSSH preserves the pinned OpenSSH public-key path and enables
// native password authentication only for profiles that reference the supplied
// head-local provider.
func NewCredentialedSSH(config SSHConfig, credentials SSHCredentialProvider) (*RestrictedSSH, error) {
	if credentials == nil {
		return nil, errors.New("restricted ssh: credential provider is required")
	}
	return newRestrictedSSH(config, credentials)
}

func newRestrictedSSH(config SSHConfig, credentials SSHCredentialProvider) (*RestrictedSSH, error) {
	if err := validateExecutable(config.Executable); err != nil {
		return nil, fmt.Errorf("restricted ssh: %w", err)
	}
	if filepath.Base(config.Executable.Path) != "ssh" {
		return nil, errors.New("restricted ssh: executable must be ssh")
	}
	if config.Authentication.SchemaVersion != SSHTargetAuthenticationSchemaV1 || len(config.Authentication.Targets) == 0 {
		return nil, errors.New("restricted ssh: inventory is empty")
	}
	targets := make(map[string]SSHTarget, len(config.Authentication.Targets))
	profiles := make(map[string]SSHAuthenticationProfile, len(config.Authentication.AuthenticationProfiles))
	passwordProfiles := false
	for targetID, target := range config.Authentication.Targets {
		profile, exists := config.Authentication.AuthenticationProfiles[target.AuthenticationProfile]
		if !exists || targetID != target.ID || !validSSHTarget(target) || !validSSHAuthenticationProfile(profile) || !validPrincipalConstraint(profile.Method, target.PrincipalConstraint) {
			return nil, errors.New("restricted ssh: invalid inventory entry")
		}
		if target.PrincipalConstraint == SSHPrincipalSharedShellReducedTrust {
			return nil, errors.New("restricted ssh: shared shell-capable principals are reduced-trust and not production-accepted")
		}
		if profile.Method == SSHAuthenticationPassword {
			passwordProfiles = true
			if credentials == nil {
				return nil, errors.New("restricted ssh: password profiles require the bounded native transport")
			}
		} else if profile.CredentialReference != SSHOpenSSHDefaultIdentityReference {
			return nil, errors.New("restricted ssh: public-key profile requires the fixed OpenSSH default identity")
		}
		targets[targetID] = target
		profiles[profile.ID] = profile
	}
	knownHostsDigest, err := verifyKnownHostsFile(config.KnownHostsFile, "")
	if err != nil {
		return nil, err
	}
	adapter := &RestrictedSSH{
		executable: config.Executable, targets: targets,
		profiles: profiles, credentials: credentials,
		knownHostsFile: config.KnownHostsFile, knownHostsSHA256: knownHostsDigest,
	}
	if passwordProfiles {
		callback, err := knownhosts.New(config.KnownHostsFile)
		if err != nil {
			return nil, errors.New("restricted ssh: load pinned host identities")
		}
		adapter.hostKeyCallback = callback
	}
	return adapter, nil
}

// ExecuteInvocation verifies the typed invocation locally, then transports the
// invocation to a fixed remote runner which independently verifies it again.
func (adapter *RestrictedSSH) ExecuteInvocation(ctx context.Context, runner *Runner, catalog *commandpack.Catalog, attemptID string, invocation commandpack.Invocation, suppliedSecrets [][]byte) (Result, error) {
	if runner == nil {
		return Result{}, errors.New("restricted ssh: runner is required")
	}
	if err := runner.validateSuppliedSecrets(suppliedSecrets); err != nil {
		return Result{}, err
	}
	request, err := adapter.requestFromInvocation(catalog, attemptID, invocation, suppliedSecrets)
	if err != nil {
		return Result{}, err
	}
	defer clearSecrets(request.SuppliedSecrets)
	if err := runner.validate(request); err != nil {
		return Result{}, err
	}
	return adapter.executeRequest(ctx, runner, request)
}

func (adapter *RestrictedSSH) executeRequest(ctx context.Context, runner *Runner, request executionRequest) (Result, error) {
	combined := Result{
		DefinitionID: request.DefinitionID, DefinitionVersion: request.DefinitionVersion,
		DefinitionDigest: request.DefinitionDigest, AttemptID: request.AttemptID,
		Targets: make([]TargetResult, len(request.Targets)),
	}
	keyIndexes := make([]int, 0, len(request.Targets))
	passwordIndexes := make([]int, 0, len(request.Targets))
	for index, plan := range request.Targets {
		target := adapter.targets[plan.TargetID]
		profile := adapter.profiles[target.AuthenticationProfile]
		if profile.Method == SSHAuthenticationPassword {
			passwordIndexes = append(passwordIndexes, index)
		} else {
			keyIndexes = append(keyIndexes, index)
		}
	}
	if len(keyIndexes) > 0 {
		keyRequest := subsetExecutionRequest(request, keyIndexes)
		transport, err := runner.execute(ctx, keyRequest)
		if err != nil {
			return Result{}, err
		}
		decoded, err := adapter.decodeTransportResult(keyRequest, transport)
		if err != nil {
			return Result{}, err
		}
		for index, original := range keyIndexes {
			combined.Targets[original] = decoded.Targets[index]
		}
	}
	if len(passwordIndexes) > 0 {
		if err := adapter.executePasswordTargets(ctx, request, passwordIndexes, combined.Targets); err != nil {
			return Result{}, err
		}
	}
	return combined, nil
}

func subsetExecutionRequest(request executionRequest, indexes []int) executionRequest {
	subset := request
	subset.Targets = make([]targetPlan, len(indexes))
	for index, original := range indexes {
		subset.Targets[index] = request.Targets[original]
	}
	if subset.Concurrency > len(subset.Targets) {
		subset.Concurrency = len(subset.Targets)
	}
	return subset
}

func (adapter *RestrictedSSH) executePasswordTargets(ctx context.Context, request executionRequest, indexes []int, results []TargetResult) error {
	jobs := make(chan int, len(indexes))
	for _, index := range indexes {
		jobs <- index
	}
	close(jobs)
	workers := request.Concurrency
	if workers > len(indexes) {
		workers = len(indexes)
	}
	var group sync.WaitGroup
	var firstErr error
	var errorMutex sync.Mutex
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				result, err := adapter.executePasswordTarget(ctx, request, request.Targets[index])
				if err != nil {
					errorMutex.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errorMutex.Unlock()
					continue
				}
				results[index] = result
			}
		}()
	}
	group.Wait()
	return firstErr
}

func (adapter *RestrictedSSH) requestFromInvocation(catalog *commandpack.Catalog, attemptID string, invocation commandpack.Invocation, suppliedSecrets [][]byte) (executionRequest, error) {
	if _, err := verifyKnownHostsFile(adapter.knownHostsFile, adapter.knownHostsSHA256); err != nil {
		return executionRequest{}, err
	}
	if catalog == nil {
		return executionRequest{}, errors.New("restricted ssh: verified catalog is required")
	}
	invocation = cloneInvocation(invocation)
	plan, err := catalog.Plan(invocation)
	if err != nil {
		return executionRequest{}, errors.New("restricted ssh: invocation is not approved")
	}
	definitionID, definitionVersion, definitionDigest := plan.DefinitionIdentity()
	remotePath, remoteSHA256 := plan.ExecutableIdentity()
	argv := plan.Argv()
	limits := plan.Limits()
	validNotBefore, validBefore := plan.Validity()
	if len(argv) == 0 || argv[0] != remotePath || plan.RequiresPrivilege() || plan.SudoRule() != "" {
		return executionRequest{}, errors.New("restricted ssh: verified plan is not safe for unprivileged remote execution")
	}
	if err := validateExecutable(ExecutableIdentity{Path: remotePath, SHA256: remoteSHA256}); err != nil {
		return executionRequest{}, fmt.Errorf("restricted ssh: unsafe remote executable: %w", err)
	}
	base := filepath.Base(remotePath)
	if base == "ssh" || base == "scp" || base == "sftp" {
		return executionRequest{}, errors.New("restricted ssh: nested remote transport is prohibited")
	}
	planTargets := plan.Targets()
	if len(planTargets) == 0 {
		return executionRequest{}, errors.New("restricted ssh: no targets")
	}
	targets := make([]targetPlan, 0, len(planTargets))
	seen := make(map[string]struct{}, len(planTargets))
	for _, planTarget := range planTargets {
		targetID := planTarget.Name
		target, exists := adapter.targets[targetID]
		if !exists {
			return executionRequest{}, errors.New("restricted ssh: target is not in inventory")
		}
		if _, duplicate := seen[targetID]; duplicate {
			return executionRequest{}, errors.New("restricted ssh: duplicate target")
		}
		seen[targetID] = struct{}{}
		remoteInvocation := cloneInvocation(invocation)
		remoteInvocation.Targets = []commandpack.Target{{Name: targetID, Role: planTarget.Role}}
		envelope := remoteEnvelope{AttemptID: attemptID, ExpectedDefinitionDigest: definitionDigest, Invocation: remoteInvocation}
		payload, err := json.Marshal(envelope)
		if err != nil {
			return executionRequest{}, errors.New("restricted ssh: encode remote request")
		}
		plan := targetPlan{TargetID: targetID, input: payload}
		profile := adapter.profiles[target.AuthenticationProfile]
		if profile.Method == SSHAuthenticationPublicKey {
			port := strconv.FormatUint(uint64(target.Port), 10)
			plan.Args = []string{
				"-F", "/dev/null", "-T", "-oBatchMode=yes", "-oCanonicalizeHostname=no",
				"-oClearAllForwardings=yes", "-oControlMaster=no", "-oControlPath=none",
				"-oForwardAgent=no", "-oForwardX11=no", "-oGlobalKnownHostsFile=/dev/null", "-oIdentitiesOnly=yes",
				"-oKbdInteractiveAuthentication=no", "-oPasswordAuthentication=no",
				"-oLocalCommand=none", "-oPermitLocalCommand=no", "-oProxyCommand=none", "-oProxyJump=none",
				"-oRequestTTY=no", "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + adapter.knownHostsFile,
				"-oUpdateHostKeys=no", "-oVerifyHostKeyDNS=no",
				"-p", port, "--", target.Username + "@" + target.Address, forcedRemoteCommand,
			}
		}
		targets = append(targets, plan)
	}
	resultBudget, err := remoteResultBudget(int64(limits.MaximumOutputBytes))
	if err != nil {
		return executionRequest{}, err
	}
	return executionRequest{
		DefinitionID: definitionID, DefinitionVersion: definitionVersion, DefinitionDigest: definitionDigest,
		AttemptID: attemptID, Executable: adapter.executable, Targets: targets,
		Timeout:        time.Duration(limits.TimeoutSeconds) * time.Second,
		MaxOutputBytes: resultBudget, RemoteResultMaxOutputBytes: int64(limits.MaximumOutputBytes), Concurrency: limits.MaximumConcurrency,
		SuppliedSecrets: cloneSecrets(suppliedSecrets), ValidNotBefore: validNotBefore, ValidBefore: validBefore,
	}, nil
}

func (adapter *RestrictedSSH) decodeTransportResult(request executionRequest, transport Result) (Result, error) {
	if transport.AttemptID != request.AttemptID || transport.DefinitionID != request.DefinitionID || transport.DefinitionVersion != request.DefinitionVersion || transport.DefinitionDigest != request.DefinitionDigest || len(transport.Targets) != len(request.Targets) {
		return Result{}, errors.New("restricted ssh: transport result attribution is invalid")
	}
	combined := Result{
		DefinitionID: request.DefinitionID, DefinitionVersion: request.DefinitionVersion,
		DefinitionDigest: request.DefinitionDigest, AttemptID: request.AttemptID,
		Targets: make([]TargetResult, 0, len(request.Targets)),
	}
	seen := make(map[string]struct{}, len(request.Targets))
	for index, transportTarget := range transport.Targets {
		expectedTarget := request.Targets[index].TargetID
		if transportTarget.TargetID != expectedTarget || !transportTarget.Started || transportTarget.ExitCode != 0 || transportTarget.Signal != "" || transportTarget.TimedOut || transportTarget.Cancelled || transportTarget.ErrorCode != "" || transportTarget.StdoutTruncated {
			return Result{}, errors.New("restricted ssh: remote transport failed")
		}
		if _, duplicate := seen[expectedTarget]; duplicate {
			return Result{}, errors.New("restricted ssh: duplicate transport result")
		}
		seen[expectedTarget] = struct{}{}
		remote, err := decodeRemoteResult(transportTarget.Stdout, request, expectedTarget)
		if err != nil {
			return Result{}, err
		}
		combined.Targets = append(combined.Targets, remote.Targets[0])
	}
	return combined, nil
}

func remoteResultBudget(maximumDiagnosticOutput int64) (int64, error) {
	if maximumDiagnosticOutput <= 0 {
		return 0, errors.New("restricted ssh: invalid remote result budget")
	}
	if maximumDiagnosticOutput > restrictedSSHMaxDiagnosticOutputBytes {
		return 0, errors.New("restricted ssh: remote result exceeds transport policy")
	}
	encodedOutput := 4 * ((maximumDiagnosticOutput + 2) / 3)
	overhead := int64(remoteResultTargetOverheadBytes)
	if encodedOutput > RestrictedSSHMaxTransportOutputBytes-overhead {
		return 0, errors.New("restricted ssh: remote result exceeds transport policy")
	}
	return encodedOutput + overhead, nil
}

// Execute decodes a bounded forced-command payload, reconstructs a sealed plan
// from the configured verified catalog, fixes execution to this host's target,
// and only then invokes the no-shell runner.
func (executor *RemoteExecutor) Execute(ctx context.Context, input io.Reader, suppliedSecrets [][]byte) (Result, error) {
	if ctx == nil || input == nil {
		return Result{}, errors.New("remote diagnostic runner: context and input are required")
	}
	payload, err := io.ReadAll(io.LimitReader(input, executor.maxEnvelopeBytes+1))
	if err != nil || int64(len(payload)) > executor.maxEnvelopeBytes {
		return Result{}, errors.New("remote diagnostic runner: envelope exceeds policy")
	}
	var envelope remoteEnvelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Result{}, errors.New("remote diagnostic runner: invalid envelope")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Result{}, errors.New("remote diagnostic runner: trailing envelope data")
	}
	if !safeIdentifier(envelope.AttemptID) || !validSHA256(envelope.ExpectedDefinitionDigest) || len(envelope.Invocation.Targets) != 1 || envelope.Invocation.Targets[0] != executor.target {
		return Result{}, errors.New("remote diagnostic runner: envelope attribution is invalid")
	}
	plan, err := executor.catalog.Plan(cloneInvocation(envelope.Invocation))
	if err != nil {
		return Result{}, errors.New("remote diagnostic runner: invocation is not approved")
	}
	_, _, digest := plan.DefinitionIdentity()
	if digest != envelope.ExpectedDefinitionDigest {
		return Result{}, errors.New("remote diagnostic runner: definition catalog mismatch")
	}
	return executor.runner.ExecuteVerified(ctx, envelope.AttemptID, plan, suppliedSecrets)
}

func cloneInvocation(invocation commandpack.Invocation) commandpack.Invocation {
	cloned := invocation
	cloned.Targets = append([]commandpack.Target(nil), invocation.Targets...)
	cloned.Arguments = make([]commandpack.ArgumentValue, len(invocation.Arguments))
	for index, argument := range invocation.Arguments {
		cloned.Arguments[index] = argument
		if argument.String != nil {
			value := *argument.String
			cloned.Arguments[index].String = &value
		}
		if argument.Integer != nil {
			value := *argument.Integer
			cloned.Arguments[index].Integer = &value
		}
		if argument.Boolean != nil {
			value := *argument.Boolean
			cloned.Arguments[index].Boolean = &value
		}
	}
	return cloned
}

func validSSHAuthenticationProfile(profile SSHAuthenticationProfile) bool {
	return safeIdentifier(profile.ID) &&
		(profile.Method == SSHAuthenticationPublicKey || profile.Method == SSHAuthenticationPassword) &&
		profile.CredentialSource == SSHCredentialHeadLocalPersistent &&
		safeIdentifier(profile.CredentialReference)
}

func validSSHTarget(target SSHTarget) bool {
	return safeIdentifier(target.ID) && validSSHAddress(target.Address) && target.Port > 0 &&
		safeIdentifier(target.Username) && safeIdentifier(target.AuthenticationProfile) &&
		(target.PrincipalConstraint == SSHPrincipalAuthorizedKeyForceCommand || target.PrincipalConstraint == SSHPrincipalDedicatedSSHDForceCommand || target.PrincipalConstraint == SSHPrincipalSharedShellReducedTrust)
}

func validPrincipalConstraint(method SSHAuthenticationMethod, constraint SSHPrincipalConstraint) bool {
	if constraint == SSHPrincipalSharedShellReducedTrust {
		return true
	}
	if method == SSHAuthenticationPassword {
		return constraint == SSHPrincipalDedicatedSSHDForceCommand
	}
	return constraint == SSHPrincipalAuthorizedKeyForceCommand || constraint == SSHPrincipalDedicatedSSHDForceCommand
}

func validSSHAddress(address string) bool {
	if ip := net.ParseIP(address); ip != nil {
		return ip.To4() != nil
	}
	if len(address) == 0 || len(address) > 253 || strings.HasPrefix(address, "-") || strings.HasSuffix(address, "-") || strings.Contains(address, "..") {
		return false
	}
	for _, label := range strings.Split(address, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func verifyKnownHostsFile(path, expectedSHA256 string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return "", errors.New("restricted ssh: known-hosts path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&022 != 0 || info.Size() <= 0 || info.Size() > maxKnownHostsBytes {
		return "", errors.New("restricted ssh: known-hosts file must be a non-writable regular file")
	}
	payload, err := os.ReadFile(path)
	if err != nil || len(payload) == 0 || len(payload) > maxKnownHostsBytes {
		return "", errors.New("restricted ssh: known-hosts file is unavailable or empty")
	}
	digest := sha256.Sum256(payload)
	encoded := fmt.Sprintf("%x", digest[:])
	if expectedSHA256 != "" && encoded != expectedSHA256 {
		return "", errors.New("restricted ssh: known-hosts file identity changed")
	}
	return encoded, nil
}

func cloneSecrets(secrets [][]byte) [][]byte {
	cloned := make([][]byte, len(secrets))
	for index := range secrets {
		cloned[index] = append([]byte(nil), secrets[index]...)
	}
	return cloned
}

func clearSecrets(secrets [][]byte) {
	for index := range secrets {
		clear(secrets[index])
		secrets[index] = nil
	}
}

// LoadSSHTargetAuthentication reads the protected v1 target/profile contract.
// Password bytes have no representable field: profiles carry only an opaque
// provider reference that is resolved on the head node at execution time.
func LoadSSHTargetAuthentication(path string) (SSHTargetAuthentication, error) {
	payload, err := commandpack.ReadProtectedFile(path, maxSSHInventoryBytes)
	if err != nil {
		return SSHTargetAuthentication{}, fmt.Errorf("load ssh target authentication: %w", err)
	}
	var document struct {
		SchemaVersion          string `json:"schema_version"`
		AuthenticationProfiles []struct {
			ID                  string                  `json:"id"`
			Method              SSHAuthenticationMethod `json:"method"`
			CredentialSource    SSHCredentialSource     `json:"credential_source"`
			CredentialReference string                  `json:"credential_reference"`
		} `json:"authentication_profiles"`
		Targets []struct {
			ID                    string                 `json:"id"`
			Address               string                 `json:"address"`
			Port                  uint16                 `json:"port"`
			Username              string                 `json:"username"`
			AuthenticationProfile string                 `json:"authentication_profile"`
			PrincipalConstraint   SSHPrincipalConstraint `json:"principal_constraint"`
		} `json:"targets"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return SSHTargetAuthentication{}, errors.New("decode ssh target authentication")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return SSHTargetAuthentication{}, errors.New("ssh target authentication carries trailing data")
	}
	if document.SchemaVersion != SSHTargetAuthenticationSchemaV1 || len(document.AuthenticationProfiles) == 0 || len(document.Targets) == 0 {
		return SSHTargetAuthentication{}, errors.New("ssh target authentication schema is unsupported or empty")
	}
	result := SSHTargetAuthentication{
		SchemaVersion:          document.SchemaVersion,
		AuthenticationProfiles: make(map[string]SSHAuthenticationProfile, len(document.AuthenticationProfiles)),
		Targets:                make(map[string]SSHTarget, len(document.Targets)),
	}
	for _, encoded := range document.AuthenticationProfiles {
		profile := SSHAuthenticationProfile(encoded)
		if !validSSHAuthenticationProfile(profile) {
			return SSHTargetAuthentication{}, errors.New("ssh target authentication contains an invalid profile")
		}
		if _, duplicate := result.AuthenticationProfiles[profile.ID]; duplicate {
			return SSHTargetAuthentication{}, errors.New("ssh target authentication contains a duplicate profile")
		}
		result.AuthenticationProfiles[profile.ID] = profile
	}
	for _, encoded := range document.Targets {
		target := SSHTarget(encoded)
		if !validSSHTarget(target) {
			return SSHTargetAuthentication{}, errors.New("ssh target authentication contains an invalid target")
		}
		if _, duplicate := result.Targets[target.ID]; duplicate {
			return SSHTargetAuthentication{}, errors.New("ssh target authentication contains a duplicate target")
		}
		if _, exists := result.AuthenticationProfiles[target.AuthenticationProfile]; !exists {
			return SSHTargetAuthentication{}, errors.New("ssh target authentication references an unknown profile")
		}
		if !validPrincipalConstraint(result.AuthenticationProfiles[target.AuthenticationProfile].Method, target.PrincipalConstraint) {
			return SSHTargetAuthentication{}, errors.New("ssh target authentication principal constraint does not protect its authentication method")
		}
		result.Targets[target.ID] = target
	}
	return result, nil
}
