package diagnosticrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
)

const (
	AgentlessSSHPolicySchemaV1 = "sherlock.agentless-ssh-policy.v1"
	// AgentlessSSHTrustAcknowledgement is intentionally the same explicit value
	// used by the target-authentication contract. It is an acknowledgement of a
	// weaker boundary, never a production principal constraint.
	AgentlessSSHTrustAcknowledgement = SSHPrincipalSharedShellReducedTrust

	agentlessDigestExecutable = "/usr/bin/sha256sum"
	agentlessDigestDriftExit  = 125
	maxAgentlessPolicyBytes   = 1 << 20

	CodeRemoteExecutableDrift = "REMOTE_EXECUTABLE_DRIFT"
	CodeOutputTruncated       = "OUTPUT_TRUNCATED"
)

// AgentlessSSHPermission is one exact reduced-trust exception. Definitions are
// listed as well as cluster/target pairs so enabling the pilot cannot silently
// make every future parameter-free pack entry remotely executable.
type AgentlessSSHPermission struct {
	ClusterID         string
	TargetID          string
	DefinitionID      string
	DefinitionVersion string
}

// AgentlessSSHPolicy is loaded from a protected file and is separate from the
// production RestrictedSSH authentication contract. It contains no secret or
// command field.
type AgentlessSSHPolicy struct {
	SchemaVersion   string
	Acknowledgement SSHPrincipalConstraint
	AllowList       []AgentlessSSHPermission
}

type AgentlessSSHConfig struct {
	ClusterID      string
	Executable     ExecutableIdentity
	Authentication SSHTargetAuthentication
	KnownHostsFile string
	Policy         AgentlessSSHPolicy
}

// AgentlessSSH executes a fixed pack-derived command through an ordinary login
// shell. Unlike RestrictedSSH it neither sends nor accepts a runner envelope,
// and the remote host does not independently verify the command pack.
type AgentlessSSH struct {
	clusterID        string
	executable       ExecutableIdentity
	targets          map[string]SSHTarget
	profiles         map[string]SSHAuthenticationProfile
	permissions      map[string]struct{}
	knownHostsFile   string
	knownHostsSHA256 string
}

// AllowedTargets returns only targets reachable through the protected
// cluster/definition policy, for startup reachability reporting.
func (adapter *AgentlessSSH) AllowedTargets() map[string]SSHTarget {
	result := make(map[string]SSHTarget, len(adapter.targets))
	for id, target := range adapter.targets {
		result[id] = target
	}
	return result
}

func NewAgentlessSSH(config AgentlessSSHConfig) (*AgentlessSSH, error) {
	if !safeIdentifier(config.ClusterID) {
		return nil, errors.New("agentless ssh: cluster is invalid")
	}
	if err := validateExecutable(config.Executable); err != nil {
		return nil, fmt.Errorf("agentless ssh: %w", err)
	}
	if filepath.Base(config.Executable.Path) != "ssh" {
		return nil, errors.New("agentless ssh: executable must be ssh")
	}
	if err := validateAgentlessSSHPolicy(config.Policy); err != nil {
		return nil, err
	}
	if config.Authentication.SchemaVersion != SSHTargetAuthenticationSchemaV1 {
		return nil, errors.New("agentless ssh: target authentication contract is invalid")
	}

	targets := make(map[string]SSHTarget)
	profiles := make(map[string]SSHAuthenticationProfile)
	permissions := make(map[string]struct{})
	for _, permission := range config.Policy.AllowList {
		if permission.ClusterID != config.ClusterID {
			continue
		}
		target, exists := config.Authentication.Targets[permission.TargetID]
		if !exists || !validSSHTarget(target) {
			return nil, errors.New("agentless ssh: allow-listed target is absent from protected authentication inventory")
		}
		profile, exists := config.Authentication.AuthenticationProfiles[target.AuthenticationProfile]
		if !exists || !validSSHAuthenticationProfile(profile) {
			return nil, errors.New("agentless ssh: allow-listed target has an invalid authentication profile")
		}
		if profile.Method != SSHAuthenticationPublicKey || profile.CredentialReference != SSHOpenSSHDefaultIdentityReference {
			return nil, errors.New("agentless ssh: only the fixed OpenSSH public-key identity is permitted")
		}
		if target.PrincipalConstraint != SSHPrincipalSharedShellReducedTrust {
			return nil, errors.New("agentless ssh: target does not carry the reduced-trust acknowledgement")
		}
		targets[target.ID] = target
		profiles[profile.ID] = profile
		permissions[agentlessPermissionKey(permission.TargetID, permission.DefinitionID, permission.DefinitionVersion)] = struct{}{}
	}
	if len(permissions) == 0 {
		return nil, errors.New("agentless ssh: cluster is not explicitly allow-listed")
	}
	knownHostsDigest, err := verifyKnownHostsFile(config.KnownHostsFile, "")
	if err != nil {
		return nil, fmt.Errorf("agentless ssh: %w", err)
	}
	return &AgentlessSSH{
		clusterID: config.ClusterID, executable: config.Executable, targets: targets, profiles: profiles,
		permissions: permissions, knownHostsFile: config.KnownHostsFile, knownHostsSHA256: knownHostsDigest,
	}, nil
}

func (adapter *AgentlessSSH) ExecuteInvocation(ctx context.Context, runner *Runner, catalog *commandpack.Catalog, attemptID string, invocation commandpack.Invocation, suppliedSecrets [][]byte) (Result, error) {
	if runner == nil {
		return Result{}, errors.New("agentless ssh: runner is required")
	}
	request, err := adapter.requestFromInvocation(catalog, attemptID, invocation, suppliedSecrets)
	if err != nil {
		return Result{}, err
	}
	if err := runner.validate(request); err != nil {
		return Result{}, err
	}
	result, err := runner.execute(ctx, request)
	if err != nil {
		return Result{}, err
	}
	// Exit 125 is reserved by the generated guard and is never reported as a
	// successful probe. SSH authentication and host-key failures use SSH's 255.
	for index := range result.Targets {
		target := &result.Targets[index]
		if target.Started && !target.TimedOut && !target.Cancelled && target.ExitCode == agentlessDigestDriftExit {
			target.ErrorCode = CodeRemoteExecutableDrift
		}
		if target.StdoutTruncated || target.StderrTruncated {
			target.ErrorCode = CodeOutputTruncated
		}
	}
	return result, nil
}

func (adapter *AgentlessSSH) requestFromInvocation(catalog *commandpack.Catalog, attemptID string, invocation commandpack.Invocation, suppliedSecrets [][]byte) (executionRequest, error) {
	if len(suppliedSecrets) != 0 {
		return executionRequest{}, errors.New("agentless ssh: supplied secrets are prohibited")
	}
	if _, err := verifyKnownHostsFile(adapter.knownHostsFile, adapter.knownHostsSHA256); err != nil {
		return executionRequest{}, fmt.Errorf("agentless ssh: %w", err)
	}
	if catalog == nil {
		return executionRequest{}, errors.New("agentless ssh: verified catalog is required")
	}
	invocation = cloneInvocation(invocation)
	if len(invocation.Arguments) != 0 || len(invocation.Targets) != 1 {
		return executionRequest{}, errors.New("agentless ssh: arguments and multi-target invocations are prohibited")
	}
	definition, _, exists := catalog.Lookup(invocation.DefinitionID, invocation.DefinitionVersion)
	if !exists {
		return executionRequest{}, errors.New("agentless ssh: invocation is not approved")
	}
	if len(definition.Parameters) != 0 {
		return executionRequest{}, errors.New("agentless ssh: parameterized definitions are prohibited")
	}
	plan, err := catalog.Plan(invocation)
	if err != nil {
		return executionRequest{}, errors.New("agentless ssh: invocation is not approved")
	}
	definitionID, definitionVersion, definitionDigest := plan.DefinitionIdentity()
	planTargets := plan.Targets()
	if len(planTargets) != 1 {
		return executionRequest{}, errors.New("agentless ssh: exactly one target is required")
	}
	targetID := planTargets[0].Name
	if _, permitted := adapter.permissions[agentlessPermissionKey(targetID, definitionID, definitionVersion)]; !permitted {
		return executionRequest{}, errors.New("agentless ssh: cluster, target, or definition is outside the protected allow-list")
	}
	target, exists := adapter.targets[targetID]
	if !exists {
		return executionRequest{}, errors.New("agentless ssh: target is outside the protected allow-list")
	}
	profile := adapter.profiles[target.AuthenticationProfile]
	if profile.Method != SSHAuthenticationPublicKey || target.PrincipalConstraint != SSHPrincipalSharedShellReducedTrust {
		return executionRequest{}, errors.New("agentless ssh: target authentication is not the acknowledged public-key route")
	}

	remotePath, remoteSHA256 := plan.ExecutableIdentity()
	argv := plan.Argv()
	if len(argv) == 0 || argv[0] != remotePath || plan.RequiresPrivilege() || plan.SudoRule() != "" {
		return executionRequest{}, errors.New("agentless ssh: verified plan is not safe for unprivileged execution")
	}
	if err := validateExecutable(ExecutableIdentity{Path: remotePath, SHA256: remoteSHA256}); err != nil {
		return executionRequest{}, fmt.Errorf("agentless ssh: unsafe remote executable: %w", err)
	}
	switch filepath.Base(remotePath) {
	case "ssh", "scp", "sftp", "sha256sum":
		return executionRequest{}, errors.New("agentless ssh: transport or digest utilities cannot be pack executables")
	}
	remoteCommand, err := agentlessRemoteCommand(remotePath, remoteSHA256, argv[1:])
	if err != nil {
		return executionRequest{}, err
	}
	port := strconv.FormatUint(uint64(target.Port), 10)
	sshArgs := []string{
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
		"-oVerifyHostKeyDNS=no", "-p", port, "--", target.Username + "@" + target.Address, remoteCommand,
	}
	limits := plan.Limits()
	validNotBefore, validBefore := plan.Validity()
	return executionRequest{
		DefinitionID: definitionID, DefinitionVersion: definitionVersion, DefinitionDigest: definitionDigest,
		AttemptID: attemptID, Executable: adapter.executable,
		Targets:        []targetPlan{{TargetID: targetID, Args: sshArgs}},
		Timeout:        time.Duration(limits.TimeoutSeconds) * time.Second,
		MaxOutputBytes: int64(limits.MaximumOutputBytes), Concurrency: 1,
		ValidNotBefore: validNotBefore, ValidBefore: validBefore,
	}, nil
}

func agentlessRemoteCommand(executablePath, executableSHA256 string, arguments []string) (string, error) {
	identity := ExecutableIdentity{Path: executablePath, SHA256: executableSHA256}
	if err := validateExecutable(identity); err != nil {
		return "", fmt.Errorf("agentless ssh: unsafe remote executable: %w", err)
	}
	quotedArgv := make([]string, 0, len(arguments)+1)
	quotedArgv = append(quotedArgv, posixShellQuote(executablePath))
	for _, argument := range arguments {
		if strings.ContainsRune(argument, '\x00') {
			return "", errors.New("agentless ssh: remote argument contains NUL")
		}
		quotedArgv = append(quotedArgv, posixShellQuote(argument))
	}
	// The pack-derived executable and argv are each quoted as shell words. The
	// only syntax is repository-owned and constant. The digest is checked in the
	// same exec request immediately before replacing the login shell process.
	return "actual=$(" + posixShellQuote(agentlessDigestExecutable) + " " + posixShellQuote("--") + " " + posixShellQuote(executablePath) + ") || exit " + strconv.Itoa(agentlessDigestDriftExit) +
		"; [ \"${actual%% *}\" = " + posixShellQuote(executableSHA256) + " ] || exit " + strconv.Itoa(agentlessDigestDriftExit) +
		"; exec " + strings.Join(quotedArgv, " "), nil
}

func posixShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func agentlessPermissionKey(targetID, definitionID, definitionVersion string) string {
	return targetID + "\x00" + definitionID + "\x00" + definitionVersion
}

func validateAgentlessSSHPolicy(policy AgentlessSSHPolicy) error {
	if policy.SchemaVersion != AgentlessSSHPolicySchemaV1 || policy.Acknowledgement != AgentlessSSHTrustAcknowledgement || len(policy.AllowList) == 0 || len(policy.AllowList) > 64 {
		return errors.New("agentless ssh: policy is unsupported, empty, or lacks the reduced-trust acknowledgement")
	}
	seen := make(map[string]struct{}, len(policy.AllowList))
	for _, permission := range policy.AllowList {
		if !safeIdentifier(permission.ClusterID) || !safeIdentifier(permission.TargetID) || !safeIdentifier(permission.DefinitionID) || !safeIdentifier(permission.DefinitionVersion) {
			return errors.New("agentless ssh: policy contains an invalid permission")
		}
		key := permission.ClusterID + "\x00" + agentlessPermissionKey(permission.TargetID, permission.DefinitionID, permission.DefinitionVersion)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("agentless ssh: policy contains a duplicate permission")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func LoadAgentlessSSHPolicy(path string) (AgentlessSSHPolicy, error) {
	payload, err := commandpack.ReadProtectedFile(path, maxAgentlessPolicyBytes)
	if err != nil {
		return AgentlessSSHPolicy{}, fmt.Errorf("load agentless ssh policy: %w", err)
	}
	var document struct {
		SchemaVersion   string                 `json:"schema_version"`
		Acknowledgement SSHPrincipalConstraint `json:"acknowledgement"`
		AllowList       []struct {
			ClusterID         string `json:"cluster_id"`
			TargetID          string `json:"target_id"`
			DefinitionID      string `json:"definition_id"`
			DefinitionVersion string `json:"definition_version"`
		} `json:"allow_list"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return AgentlessSSHPolicy{}, errors.New("decode agentless ssh policy")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return AgentlessSSHPolicy{}, errors.New("agentless ssh policy carries trailing data")
	}
	policy := AgentlessSSHPolicy{SchemaVersion: document.SchemaVersion, Acknowledgement: document.Acknowledgement, AllowList: make([]AgentlessSSHPermission, len(document.AllowList))}
	for index, encoded := range document.AllowList {
		policy.AllowList[index] = AgentlessSSHPermission(encoded)
	}
	if err := validateAgentlessSSHPolicy(policy); err != nil {
		return AgentlessSSHPolicy{}, err
	}
	return policy, nil
}
