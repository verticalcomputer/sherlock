package gpuprocess

import (
	"context"
	"fmt"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/gpuprocess"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	processDefinitionID      = "gpu.compute_processes"
	hostDefinitionID         = "gpu.host_stats"
	processDefinitionVersion = "1.1.0"
	hostDefinitionVersion    = "1.0.0"
)

// AgentlessSource is the observation-only AgentlessSSH composition. It has a
// distinct policy and protected files from diagnostics, never accepts a lease
// command or supplied secret, and invokes exactly two fixed definitions for
// each configured node.
type AgentlessSource struct {
	adapter                   *diagnosticrunner.AgentlessSSH
	runner                    *diagnosticrunner.Runner
	catalog                   *commandpack.Catalog
	targets                   map[domain.StableNodeID]string
	gpus                      map[domain.StableNodeID][]domain.EntityIdentity
	completeComputeVisibility bool
	physicalOnly              bool
	clusterID                 domain.ClusterID
	sourceID                  domain.SourceID
}

type AgentlessSourceConfig struct {
	ClusterID                 domain.ClusterID
	SourceID                  domain.SourceID
	CommandPackFile           string
	TrustRootsFile            string
	RunnerVersion             string
	SSHExecutable             diagnosticrunner.ExecutableIdentity
	KnownHostsFile            string
	TargetAuthentication      string
	PolicyFile                string
	Nodes                     map[domain.StableNodeID]string
	GPUs                      map[domain.StableNodeID][]domain.EntityIdentity
	CompleteComputeVisibility bool
	PhysicalOnly              bool
}

func NewAgentlessSource(cfg AgentlessSourceConfig) (*AgentlessSource, error) {
	if cfg.ClusterID == "" || cfg.SourceID == "" || len(cfg.Nodes) == 0 || len(cfg.Nodes) > 16 {
		return nil, fmt.Errorf("GPU process observation requires bounded cluster, source and node scope")
	}
	authentication, err := diagnosticrunner.LoadSSHTargetAuthentication(cfg.TargetAuthentication)
	if err != nil {
		return nil, fmt.Errorf("load GPU observation target authentication: %w", err)
	}
	policy, err := diagnosticrunner.LoadAgentlessSSHPolicy(cfg.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("load GPU observation SSH policy: %w", err)
	}
	for node, target := range cfg.Nodes {
		if node == "" || target == "" {
			return nil, fmt.Errorf("GPU observation node targets are invalid")
		}
		for _, definition := range []struct{ id, version string }{{processDefinitionID, processDefinitionVersion}, {hostDefinitionID, hostDefinitionVersion}} {
			permitted := false
			for _, permission := range policy.AllowList {
				if permission.ClusterID == string(cfg.ClusterID) && permission.TargetID == target && permission.DefinitionID == definition.id && permission.DefinitionVersion == definition.version {
					permitted = true
					break
				}
			}
			if !permitted {
				return nil, fmt.Errorf("GPU observation policy lacks %s@%s for node %q", definition.id, definition.version, node)
			}
		}
	}
	sshAdapter, err := diagnosticrunner.NewAgentlessSSH(diagnosticrunner.AgentlessSSHConfig{
		ClusterID: string(cfg.ClusterID), Executable: cfg.SSHExecutable, Authentication: authentication,
		KnownHostsFile: cfg.KnownHostsFile, Policy: policy,
	})
	if err != nil {
		return nil, fmt.Errorf("configure GPU observation SSH: %w", err)
	}
	catalog, err := commandpack.LoadVerifiedCatalog(cfg.CommandPackFile, cfg.TrustRootsFile, cfg.RunnerVersion, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("load GPU observation command pack: %w", err)
	}
	for _, definition := range []struct{ id, version string }{{processDefinitionID, processDefinitionVersion}, {hostDefinitionID, hostDefinitionVersion}} {
		if _, _, ok := catalog.Lookup(definition.id, definition.version); !ok {
			return nil, fmt.Errorf("GPU observation command pack lacks %s@%s", definition.id, definition.version)
		}
	}
	runner, err := diagnosticrunner.New(diagnosticrunner.Config{
		MaxTimeout: 15 * time.Second, MaxOutputBytes: 1 << 20, MaxInputBytes: 0,
		MaxTargets: 1, MaxConcurrency: 1, MaxSuppliedSecrets: 1, MaxSecretBytes: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("configure GPU observation runner: %w", err)
	}
	targets := make(map[domain.StableNodeID]string, len(cfg.Nodes))
	gpus := make(map[domain.StableNodeID][]domain.EntityIdentity, len(cfg.Nodes))
	seen := map[string]bool{}
	for node, target := range cfg.Nodes {
		if node == "" || target == "" || seen[target] {
			return nil, fmt.Errorf("GPU observation node targets are invalid or duplicated")
		}
		if _, exists := sshAdapter.AllowedTargets()[target]; !exists {
			return nil, fmt.Errorf("GPU observation target %q is outside the protected policy", target)
		}
		targets[node] = target
		if len(cfg.GPUs[node]) == 0 {
			return nil, fmt.Errorf("GPU observation node %q has no reviewed GPU inventory", node)
		}
		gpus[node] = append([]domain.EntityIdentity(nil), cfg.GPUs[node]...)
		seen[target] = true
	}
	return &AgentlessSource{adapter: sshAdapter, runner: runner, catalog: catalog, targets: targets, gpus: gpus, completeComputeVisibility: cfg.CompleteComputeVisibility, physicalOnly: cfg.PhysicalOnly, clusterID: cfg.ClusterID, sourceID: cfg.SourceID}, nil
}

func (s *AgentlessSource) Observe(ctx context.Context, node domain.StableNodeID) (adapter.Result, []adapter.HostStat, []adapter.Gap, error) {
	if s == nil || ctx == nil {
		return adapter.Result{}, nil, nil, fmt.Errorf("GPU observation source is unavailable")
	}
	target, ok := s.targets[node]
	if !ok {
		return adapter.Result{}, nil, []adapter.Gap{adapter.NodeUnknown}, fmt.Errorf("GPU observation node is not configured")
	}
	processResult, processGaps := s.invoke(ctx, processDefinitionID, target, node)
	// The two fixed observations are intentionally independent: a failure in
	// process attribution must not suppress host GPU fields, and vice versa.
	hostResult, hostGaps := s.invoke(ctx, hostDefinitionID, target, node)

	started, finished := processResult.started, processResult.finished
	if started.IsZero() {
		started = time.Now().UTC()
	}
	if finished.IsZero() || finished.Before(started) {
		finished = started
	}
	input := adapter.Input{Format: adapter.FormatV2, CSV: processResult.stdout, QuerySucceeded: processResult.ok,
		StartedAt: started, FinishedAt: finished, ObservedAt: finished, Failure: processResult.failure}
	result, err := adapter.Normalize(adapter.Config{ClusterID: s.clusterID, SourceID: s.sourceID,
		Node:                      &domain.EntityIdentity{ClusterID: s.clusterID, Kind: domain.EntityNode, NodeID: node},
		GPUs:                      s.gpus[node],
		CompleteComputeVisibility: s.completeComputeVisibility, PhysicalOnly: s.physicalOnly}, input)
	if err != nil {
		return adapter.Result{}, nil, append(processGaps, hostGaps...), fmt.Errorf("normalize GPU observation: %w", err)
	}
	stats := []adapter.HostStat(nil)
	if hostResult.ok {
		var parseErr error
		stats, hostGaps, parseErr = adapter.ParseHostStats(hostResult.stdout, adapter.MaxRecords)
		if parseErr != nil {
			hostGaps = append(hostGaps, adapter.OutputLimit)
		}
		stats, hostGaps = filterHostStats(stats, s.gpus[node], hostGaps)
	}
	return result, stats, append(processGaps, hostGaps...), nil
}

func filterHostStats(stats []adapter.HostStat, inventory []domain.EntityIdentity, gaps []adapter.Gap) ([]adapter.HostStat, []adapter.Gap) {
	known := make(map[domain.PhysicalGPUUUID]struct{}, len(inventory))
	for _, gpu := range inventory {
		known[gpu.PhysicalGPUUUID] = struct{}{}
	}
	filtered := stats[:0]
	for _, stat := range stats {
		if _, exists := known[stat.GPUUUID]; !exists {
			gaps = append(gaps, adapter.GPUUnknown)
			continue
		}
		filtered = append(filtered, stat)
	}
	return filtered, gaps
}

type invocationResult struct {
	stdout            string
	failure           adapter.Gap
	started, finished time.Time
	ok                bool
}

func (s *AgentlessSource) invoke(ctx context.Context, definitionID, target string, node domain.StableNodeID) (invocationResult, []adapter.Gap) {
	version := hostDefinitionVersion
	if definitionID == processDefinitionID {
		version = processDefinitionVersion
	}
	result, err := s.adapter.ExecuteInvocation(ctx, s.runner, s.catalog, "gpu-observation-"+string(node), commandpack.Invocation{
		DefinitionID: definitionID, DefinitionVersion: version,
		Targets: []commandpack.Target{{Name: target, Role: commandpack.TargetCompute}},
	}, nil)
	if err != nil || len(result.Targets) != 1 {
		return invocationResult{failure: adapter.Unsupported}, []adapter.Gap{adapter.Unsupported}
	}
	targetResult := result.Targets[0]
	value := invocationResult{stdout: string(targetResult.Stdout), started: time.Now().UTC().Add(-targetResult.Duration), finished: time.Now().UTC(), ok: targetResult.ErrorCode == "" && targetResult.ExitCode == 0 && !targetResult.StdoutTruncated && !targetResult.StderrTruncated}
	gap, ok := classifyTargetResult(targetResult)
	if ok {
		return value, nil
	}
	value.failure = gap
	return value, []adapter.Gap{gap}
}

func classifyTargetResult(target diagnosticrunner.TargetResult) (adapter.Gap, bool) {
	if target.ErrorCode == "" && target.ExitCode == 0 && !target.StdoutTruncated && !target.StderrTruncated {
		return "", true
	}
	switch target.ErrorCode {
	case diagnosticrunner.CodeTimedOut, diagnosticrunner.CodeCancelled:
		return adapter.Timeout, false
	case diagnosticrunner.CodeRemoteExecutableDrift, diagnosticrunner.CodeExecutableReplaced:
		return adapter.Unsupported, false
	case diagnosticrunner.CodeOutputTruncated:
		return adapter.OutputLimit, false
	case diagnosticrunner.CodeExitNonZero:
		if target.ExitCode == 255 {
			return adapter.AuthenticationUnavailable, false
		}
		return adapter.Unsupported, false
	default:
		return adapter.Unsupported, false
	}
}
