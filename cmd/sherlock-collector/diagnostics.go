package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// Process-local execution ceilings. Each reviewed definition carries its own
// timeout, output, and concurrency limits, and the runner refuses a plan that
// exceeds these; they are an outer bound on what any definition may ask for,
// not a tuning knob, so they are constants rather than configuration.
const (
	diagnosticMaxTimeout        = 5 * time.Minute
	diagnosticMaxOutputBytes    = 64 << 20
	diagnosticMaxInputBytes     = 1 << 20
	diagnosticMaxConcurrency    = 8
	diagnosticMaxSecrets        = 16
	diagnosticMaxSecretBytes    = 4 << 10
	diagnosticControlRenewAfter = 2 * time.Minute
	// A local invocation answers for one machine, so more than one target is
	// refused twice over: here, and by the host invoker itself. Over SSH each
	// target is a separate connection carrying its own sealed envelope, so the
	// ceiling is the widest target set a reviewed definition may declare.
	diagnosticMaxLocalTargets  = 1
	diagnosticMaxRemoteTargets = 64
)

// runDiagnostics claims reviewed diagnostic work and executes it until the
// context ends.
//
// This is the pull side of remote execution. The investigator enqueues an
// invocation and parks the investigation in AWAITING_EVIDENCE; a cluster denies
// inbound traffic, so nothing outside can execute it, and it stays queued until
// a process inside the perimeter claims it. That process is this one.
func runDiagnostics(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.LoadCollectorDiagnostics()
	if err != nil {
		return fmt.Errorf("diagnostic configuration is invalid: %w", err)
	}
	httpClient, err := controlHTTPClient(cfg.Transport)
	if err != nil {
		return err
	}
	control, err := collectorruntime.NewHTTPClient(cfg.Transport.ControlURL, httpClient, diagnosticControlRenewAfter)
	if err != nil {
		return err
	}
	source, err := collectorruntime.NewDiagnosticWorkClient(control, cfg.RunnerID, cfg.PollWait)
	if err != nil {
		return err
	}
	// Verified here for every execution mode. Restricted SSH verifies the pack
	// again independently in the sealed runner; reduced-trust agentless SSH does
	// not. The control plane transmits a definition reference; this pack is what
	// turns it into an argv.
	catalog, err := commandpack.LoadVerifiedCatalog(cfg.CommandPackFile, cfg.TrustRootsFile, cfg.RunnerVersion, time.Now().UTC())
	if err != nil {
		return err
	}
	adapter, err := newExecutionAdapter(cfg)
	if err != nil {
		return err
	}
	roles, targets, err := clusterTargetRoles(cfg)
	if err != nil {
		return err
	}
	journal, err := diagnosticrunner.OpenDiagnosticJournal(cfg.JournalPath, func() time.Time { return time.Now().UTC() })
	if err != nil {
		return err
	}
	head, err := diagnosticrunner.NewHeadNode(source, adapter.invoker, adapter.runner, catalog, roles, func() time.Time { return time.Now().UTC() },
		journal, diagnosticrunner.HeadNodeConfig{ClusterID: domain.ClusterID(cfg.ClusterID), RunnerID: cfg.RunnerID, PollWait: cfg.PollWait})
	if err != nil {
		return err
	}
	loop, err := diagnosticrunner.NewClaimLoop(head, diagnosticrunner.ClaimLoopConfig{
		IdleBackoff: cfg.IdleBackoff, FailureBackoffMinimum: cfg.FailureBackoffMinimum, FailureBackoffMaximum: cfg.FailureBackoffMaximum,
	}, logger)
	if err != nil {
		return err
	}
	packID, packVersion := catalog.PackIdentity()
	logger.Info("collector.diagnostics_started", diagnosticStartupAttributes(cfg, packID, packVersion, len(targets))...)
	if unreachable := unreachableTargets(targets, adapter.targets); len(unreachable) > 0 {
		// Not fatal: one stale entry must not stop a head node executing
		// everything else. It is reported at startup because the alternative is
		// discovering it as a per-target dispatch failure inside a live
		// investigation.
		logger.Warn("collector.diagnostic_targets_unreachable", "targets", unreachable)
	}
	return loop.Run(ctx)
}

func diagnosticStartupAttributes(cfg config.CollectorDiagnostics, packID, packVersion string, reachableTargets int) []any {
	attributes := []any{
		"collector_id", cfg.Transport.CollectorID, "runner_id", cfg.RunnerID, "cluster_id", cfg.ClusterID,
		"execution_mode", string(cfg.ExecutionMode), "reachable_targets", reachableTargets,
		"command_pack", packID, "command_pack_version", packVersion,
	}
	if cfg.ExecutionMode == config.DiagnosticExecutionAgentlessSSH {
		attributes = append(attributes,
			"trust_classification", string(diagnosticrunner.AgentlessSSHTrustAcknowledgement),
			"remote_execution_boundary", "login_shell_reduced_trust")
	}
	return attributes
}

// executionAdapter pairs the invoker that carries an invocation to its targets
// with the runner ceilings that suit it.
type executionAdapter struct {
	invoker diagnosticrunner.LocalInvoker
	runner  *diagnosticrunner.Runner
	// targets is the versioned SSH inventory, and is nil in local mode.
	targets map[string]diagnosticrunner.SSHTarget
}

func newExecutionAdapter(cfg config.CollectorDiagnostics) (executionAdapter, error) {
	maxTargets := diagnosticMaxLocalTargets
	maxOutputBytes := int64(diagnosticMaxOutputBytes)
	if cfg.ExecutionMode == config.DiagnosticExecutionSSH {
		maxTargets = diagnosticMaxRemoteTargets
		// The compute runner still applies the signed definition's raw-output
		// limit. This larger head-only capture bound accommodates the fixed JSON
		// envelope and base64 expansion without weakening that command limit.
		maxOutputBytes = diagnosticrunner.RestrictedSSHMaxTransportOutputBytes
	} else if cfg.ExecutionMode == config.DiagnosticExecutionAgentlessSSH {
		// The reduced-trust pilot is intentionally one target at a time. Its raw
		// SSH output is bounded directly by the signed definition.
		maxTargets = diagnosticMaxLocalTargets
	}
	runner, err := diagnosticrunner.New(diagnosticrunner.Config{
		MaxTimeout: diagnosticMaxTimeout, MaxOutputBytes: maxOutputBytes, MaxInputBytes: diagnosticMaxInputBytes,
		MaxTargets: maxTargets, MaxConcurrency: diagnosticMaxConcurrency,
		MaxSuppliedSecrets: diagnosticMaxSecrets, MaxSecretBytes: diagnosticMaxSecretBytes,
	})
	if err != nil {
		return executionAdapter{}, err
	}
	switch cfg.ExecutionMode {
	case config.DiagnosticExecutionSSH:
		authentication, err := diagnosticrunner.LoadSSHTargetAuthentication(cfg.SSHTargetAuthenticationFile)
		if err != nil {
			return executionAdapter{}, err
		}
		// The known-hosts file is validated now and its digest re-checked before
		// every dispatch, so a file swapped underneath a running head node stops
		// execution instead of silently trusting a new host key.
		sshConfig := diagnosticrunner.SSHConfig{
			Executable:     diagnosticrunner.ExecutableIdentity{Path: cfg.SSHExecutable, SHA256: cfg.SSHExecutableSHA256},
			Authentication: authentication,
			KnownHostsFile: cfg.SSHKnownHostsFile,
		}
		var invoker *diagnosticrunner.RestrictedSSH
		if hasPasswordProfile(authentication) {
			provider, providerErr := diagnosticrunner.NewFileSSHCredentialProvider(cfg.SSHCredentialDirectory)
			if providerErr != nil {
				return executionAdapter{}, providerErr
			}
			invoker, err = diagnosticrunner.NewCredentialedSSH(sshConfig, provider)
		} else {
			invoker, err = diagnosticrunner.NewRestrictedSSH(sshConfig)
		}
		if err != nil {
			return executionAdapter{}, err
		}
		return executionAdapter{invoker: invoker, runner: runner, targets: authentication.Targets}, nil
	case config.DiagnosticExecutionAgentlessSSH:
		authentication, err := diagnosticrunner.LoadSSHTargetAuthentication(cfg.AgentlessSSHTargetAuthenticationFile)
		if err != nil {
			return executionAdapter{}, err
		}
		policy, err := diagnosticrunner.LoadAgentlessSSHPolicy(cfg.AgentlessSSHPolicyFile)
		if err != nil {
			return executionAdapter{}, err
		}
		invoker, err := diagnosticrunner.NewAgentlessSSH(diagnosticrunner.AgentlessSSHConfig{
			ClusterID: cfg.ClusterID,
			Executable: diagnosticrunner.ExecutableIdentity{
				Path: cfg.AgentlessSSHExecutable, SHA256: cfg.AgentlessSSHExecutableSHA256,
			},
			Authentication: authentication,
			KnownHostsFile: cfg.AgentlessSSHKnownHostsFile,
			Policy:         policy,
		})
		if err != nil {
			return executionAdapter{}, err
		}
		return executionAdapter{invoker: invoker, runner: runner, targets: invoker.AllowedTargets()}, nil
	default:
		invoker, err := diagnosticrunner.NewHostInvoker(cfg.LocalTarget)
		if err != nil {
			return executionAdapter{}, err
		}
		return executionAdapter{invoker: invoker, runner: runner}, nil
	}
}

func hasPasswordProfile(authentication diagnosticrunner.SSHTargetAuthentication) bool {
	for _, profile := range authentication.AuthenticationProfiles {
		if profile.Method == diagnosticrunner.SSHAuthenticationPassword {
			return true
		}
	}
	return false
}

// clusterTargetRoles resolves this cluster's target roles from the reviewed
// inventory, and reports the target names it covers.
//
// A target with no currently confirmed role is not reached, so an inventory
// that says nothing about this cluster would leave the loop claiming work it
// can only refuse. That is a startup failure instead: an operator who forgot
// the entry finds out immediately rather than through an investigation that
// parked for its whole deadline. In local mode this host must itself hold a
// role, because it is the only machine that will ever be reached.
func clusterTargetRoles(cfg config.CollectorDiagnostics) (func(domain.DiagnosticTarget) (commandpack.TargetRole, bool), []string, error) {
	inventory, err := commandpack.LoadTargetRoles(cfg.InventoryFile)
	if err != nil {
		return nil, nil, err
	}
	targets, known := inventory[cfg.ClusterID]
	if !known || len(targets) == 0 {
		return nil, nil, fmt.Errorf("the diagnostic inventory has no entry for this cluster")
	}
	if cfg.ExecutionMode == config.DiagnosticExecutionLocal {
		if _, eligible := targets[cfg.LocalTarget]; !eligible {
			return nil, nil, fmt.Errorf("the diagnostic inventory gives this host no role in this cluster")
		}
	}
	roles := make(map[domain.DiagnosticTarget]commandpack.TargetRole, len(targets))
	names := make([]string, 0, len(targets))
	for target, role := range targets {
		roles[domain.DiagnosticTarget(target)] = role
		names = append(names, target)
	}
	slices.Sort(names)
	return func(target domain.DiagnosticTarget) (commandpack.TargetRole, bool) {
		role, eligible := roles[target]
		return role, eligible
	}, names, nil
}

// unreachableTargets reports role-holding targets that restricted SSH has no
// target/authentication entry for. In local mode there is nothing to compare.
func unreachableTargets(targets []string, sshTargets map[string]diagnosticrunner.SSHTarget) []string {
	if sshTargets == nil {
		return nil
	}
	unreachable := make([]string, 0)
	for _, target := range targets {
		if _, reachable := sshTargets[target]; !reachable {
			unreachable = append(unreachable, target)
		}
	}
	return unreachable
}
