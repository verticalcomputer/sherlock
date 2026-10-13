package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"time"

	prometheusadapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	slurmadapter "github.com/verticalcomputer/sherlock/internal/adapters/slurm"
	"github.com/verticalcomputer/sherlock/internal/application"
	gpuprocessexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/gpuprocess"
	prometheusexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	slurmexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/slurm"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
)

// The optional runner is a local test seam; no collector request or environment
// setting can install a runner or provide an executable or command string.
func buildCollectionExecutors(cfg config.Collector, runner slurmadapter.Runner) (application.CollectionExecutor, *application.TypedCollectionRegistry, error) {
	clock := platform.SystemClock{}
	var legacyIDs, typedIDs, slurmIDs, gpuProcessIDs []domain.CollectionOperationID
	for _, id := range cfg.Operations {
		op, known := domain.ReviewedCollectionOperation(id)
		if !known {
			return nil, nil, fmt.Errorf("unreviewed local collection operation")
		}
		if op.Query != "" {
			legacyIDs = append(legacyIDs, id)
		} else if op.Source == domain.CollectionSourceSlurm {
			if id != domain.OperationSlurmInventory && id != domain.OperationSlurmSnapshot {
				return nil, nil, fmt.Errorf("slurm operation has no installed typed executor")
			}
			typedIDs = append(typedIDs, id)
			slurmIDs = append(slurmIDs, id)
		} else if op.Source == domain.CollectionSourceGPUProcess {
			typedIDs = append(typedIDs, id)
			gpuProcessIDs = append(gpuProcessIDs, id)
		} else {
			return nil, nil, fmt.Errorf("typed operation has no installed executor")
		}
	}
	expected, err := domain.LegacyCollectionCapabilities(legacyIDs)
	if err != nil || !slices.Equal(expected, cfg.Capabilities) {
		return nil, nil, fmt.Errorf("legacy capabilities do not match configured operations")
	}
	var legacy application.CollectionExecutor
	if len(legacyIDs) > 0 {
		source, err := prometheusadapter.NewClient(prometheusadapter.Config{BaseURL: cfg.PrometheusURL, Timeout: 10 * time.Second, MaxBytes: 10 << 20, MaxSeries: 10000,
			Auth: prometheusadapter.Auth{BearerToken: cfg.PrometheusBearer, Username: cfg.PrometheusUser, Password: cfg.PrometheusPassword}})
		if err != nil {
			return nil, nil, err
		}
		executor, err := prometheusexecution.New(source, clock, platform.RandomIDGenerator{})
		if err != nil {
			return nil, nil, err
		}
		legacy, err = application.NewCollectionOperationRegistry(legacyIDs, map[domain.CollectionSourceKind]application.CollectionExecutor{domain.CollectionSourcePrometheus: executor}, clock)
		if err != nil {
			return nil, nil, err
		}
	}
	var typed *application.TypedCollectionRegistry
	typedSources := make([]application.TypedCollectionSource, 0, 2)
	if len(slurmIDs) > 0 {
		if runner == nil {
			commands := []string{"scontrol"}
			if slices.Contains(slurmIDs, domain.OperationSlurmSnapshot) {
				commands = append(commands, "squeue", "sacct")
			}
			for _, command := range commands {
				if _, err := exec.LookPath(command); err != nil {
					return nil, nil, fmt.Errorf("slurm collection requires installed %s", command)
				}
			}
		}
		source, err := slurmadapter.NewClient(slurmadapter.Config{Timeout: 10 * time.Second, Runner: runner, SupportedDataParserVersions: []string{domain.SlurmSnapshotDataParserVersion, domain.SlurmSnapshotDataParserVersion2302}})
		if err != nil {
			return nil, nil, err
		}
		var executor *slurmexecution.Executor
		if slices.Contains(typedIDs, domain.OperationSlurmSnapshot) {
			executor, err = slurmexecution.NewSnapshot(source, clock, slurmexecution.SnapshotConfig{ClusterID: domain.ClusterID(cfg.SlurmClusterID), SourceID: domain.SourceID(cfg.SlurmSourceID), SchedulerNamespace: domain.SchedulerNamespace(cfg.SlurmSchedulerNamespace), SchedulerCluster: cfg.SlurmSchedulerCluster, Nodes: cfg.SlurmNodes, TrustedCurrentJobVisibility: cfg.SlurmCurrentJobsComplete, TrustedAccountingVisibility: cfg.SlurmAccountingComplete, AccountingOverlap: cfg.SlurmAccountingOverlap})
		} else {
			executor, err = slurmexecution.New(source, clock, cfg.SlurmNodes)
		}
		if err != nil {
			return nil, nil, err
		}
		typedSources = append(typedSources, application.TypedCollectionSource{ClusterID: domain.ClusterID(cfg.SlurmClusterID), SourceID: domain.SourceID(cfg.SlurmSourceID), Kind: domain.CollectionSourceSlurm, Operations: slurmIDs, Executor: executor})
	}
	if len(gpuProcessIDs) > 0 {
		gpuCfg := cfg.GPUProcessObservation
		nodes := make(map[domain.StableNodeID]gpuprocessexecution.NodeConfig, len(gpuCfg.Nodes))
		for stable := range gpuCfg.Nodes {
			nodes[stable] = gpuprocessexecution.NodeConfig{Node: &domain.EntityIdentity{ClusterID: domain.ClusterID(cfg.ClusterID), Kind: domain.EntityNode, NodeID: stable}, GPUs: gpuCfg.GPUs[stable], PhysicalOnly: gpuCfg.PhysicalOnly, CompleteComputeVisibility: gpuCfg.CompleteComputeVisibility}
		}
		source, sourceErr := gpuprocessexecution.NewAgentlessSource(gpuprocessexecution.AgentlessSourceConfig{
			ClusterID: domain.ClusterID(cfg.ClusterID), SourceID: domain.SourceID(gpuCfg.SourceID), CommandPackFile: gpuCfg.CommandPackFile,
			TrustRootsFile: gpuCfg.TrustRootsFile, RunnerVersion: gpuCfg.RunnerVersion,
			SSHExecutable: diagnosticrunner.ExecutableIdentity{Path: gpuCfg.SSHExecutable, SHA256: gpuCfg.SSHExecutableSHA256}, KnownHostsFile: gpuCfg.SSHKnownHostsFile,
			TargetAuthentication: gpuCfg.SSHTargetAuthentication, PolicyFile: gpuCfg.SSHPolicyFile, Nodes: gpuCfg.Nodes, GPUs: gpuCfg.GPUs,
			CompleteComputeVisibility: gpuCfg.CompleteComputeVisibility, PhysicalOnly: gpuCfg.PhysicalOnly,
		})
		if sourceErr != nil {
			return nil, nil, sourceErr
		}
		executor, execErr := gpuprocessexecution.New(source, clock, gpuprocessexecution.Config{ClusterID: domain.ClusterID(cfg.ClusterID), SourceID: domain.SourceID(gpuCfg.SourceID), Nodes: nodes})
		if execErr != nil {
			return nil, nil, execErr
		}
		typedSources = append(typedSources, application.TypedCollectionSource{ClusterID: domain.ClusterID(cfg.ClusterID), SourceID: domain.SourceID(gpuCfg.SourceID), Kind: domain.CollectionSourceGPUProcess, Operations: gpuProcessIDs, Executor: executor})
	}
	if len(typedSources) > 0 {
		typed, err = application.NewTypedCollectionRegistry(domain.CollectionProtocolVersion, typedSources, clock)
		if err != nil {
			return nil, nil, err
		}
	}
	if legacy == nil && typed == nil {
		return nil, nil, fmt.Errorf("no local collection operation is enabled")
	}
	return legacy, typed, nil
}

// Readiness is local configuration readiness, not live source acceptance. It
// constructs adapters without querying a source or opening the control channel.
func writeCollectionReadiness(w io.Writer, cfg config.Collector, runner slurmadapter.Runner) error {
	_, typed, err := buildCollectionExecutors(cfg, runner)
	if err != nil {
		return err
	}
	maximum := 1
	if typed != nil {
		maximum = domain.CollectionProtocolVersion
	}
	operations := slices.Clone(cfg.Operations)
	slices.Sort(operations)
	return json.NewEncoder(w).Encode(struct {
		Ready       bool                           `json:"ready"`
		ProtocolMin int                            `json:"protocol_min"`
		ProtocolMax int                            `json:"protocol_max"`
		Operations  []domain.CollectionOperationID `json:"operations"`
	}{true, 1, maximum, operations})
}
