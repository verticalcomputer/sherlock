package gpuprocess

import (
	"testing"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/gpuprocess"
	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestClassifyTargetResultMapsFixedSourceOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		target diagnosticrunner.TargetResult
		gap    adapter.Gap
		ok     bool
	}{
		{name: "success", target: diagnosticrunner.TargetResult{ExitCode: 0}, ok: true},
		{name: "ssh authentication", target: diagnosticrunner.TargetResult{ExitCode: 255, ErrorCode: diagnosticrunner.CodeExitNonZero}, gap: adapter.AuthenticationUnavailable},
		{name: "timeout", target: diagnosticrunner.TargetResult{ErrorCode: diagnosticrunner.CodeTimedOut}, gap: adapter.Timeout},
		{name: "cancelled", target: diagnosticrunner.TargetResult{ErrorCode: diagnosticrunner.CodeCancelled}, gap: adapter.Timeout},
		{name: "output limit", target: diagnosticrunner.TargetResult{ErrorCode: diagnosticrunner.CodeOutputTruncated}, gap: adapter.OutputLimit},
		{name: "remote drift", target: diagnosticrunner.TargetResult{ErrorCode: diagnosticrunner.CodeRemoteExecutableDrift}, gap: adapter.Unsupported},
		{name: "nonzero source", target: diagnosticrunner.TargetResult{ExitCode: 1, ErrorCode: diagnosticrunner.CodeExitNonZero}, gap: adapter.Unsupported},
		{name: "unexpected runner", target: diagnosticrunner.TargetResult{ErrorCode: diagnosticrunner.CodeStartFailed}, gap: adapter.Unsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gap, ok := classifyTargetResult(test.target)
			if gap != test.gap || ok != test.ok {
				t.Fatalf("classification = (%q,%v), want (%q,%v)", gap, ok, test.gap, test.ok)
			}
		})
	}
}

func TestNewAgentlessSourceRefusesMissingProtectedInputs(t *testing.T) {
	_, err := NewAgentlessSource(AgentlessSourceConfig{ClusterID: "cluster", SourceID: "source", Nodes: map[domain.StableNodeID]string{"node-1": "comp001"}})
	if err == nil {
		t.Fatal("source accepted missing signed pack, policy and authentication inputs")
	}
}

func TestFilterHostStatsUsesTrustedGPUInventory(t *testing.T) {
	known := []domain.EntityIdentity{{ClusterID: "cluster", Kind: domain.EntityGPU, NodeID: "node-1", PhysicalGPUUUID: "GPU-11111111-2222-3333-4444-555555555555"}}
	value := 1.0
	stats, gaps := filterHostStats([]adapter.HostStat{{GPUUUID: known[0].PhysicalGPUUUID, TemperatureC: &value}, {GPUUUID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", TemperatureC: &value}}, known, nil)
	if len(stats) != 1 || stats[0].GPUUUID != known[0].PhysicalGPUUUID || len(gaps) != 1 || gaps[0] != adapter.GPUUnknown {
		t.Fatalf("filtered host stats=%+v gaps=%v", stats, gaps)
	}
}
