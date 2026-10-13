package commandpack

import (
	"strings"
	"testing"
)

func TestGPUProcessDefinitionBoundedRead(t *testing.T) {
	id := ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)}
	definition, err := GPUProcessDefinition(id)
	if err != nil {
		t.Fatal(err)
	}
	if definition.RequiresPrivilege || definition.SudoRule != "" || len(definition.Parameters) != 0 || definition.Limits.MaximumOutputBytes != 1<<20 || definition.Limits.TimeoutSeconds != 15 || definition.Targets.MaximumCount != 1 || definition.ExecutableSHA256 != id.SHA256 {
		t.Fatal("query exceeded reviewed bounds")
	}
	if definition.Version != "1.1.0" || definition.OutputSchema != "nvidia.compute_processes.v2" || len(definition.Arguments) != 2 || definition.Arguments[0].Literal != "--query-compute-apps=gpu_uuid,pid" || definition.Arguments[1].Literal != "--format=csv,noheader,nounits" {
		t.Fatal("query changed")
	}
	pilot, err := PilotDefinitions(PilotIdentities{NvidiaSMI: id, Journalctl: id, Scontrol: id})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, installed := range pilot {
		if installed.ID == definition.ID && installed.Version == definition.Version {
			found = true
		}
	}
	if !found {
		t.Fatal("GPU process query missing from signed pilot definitions")
	}
	for _, bad := range []ExecutableIdentity{{}, {Path: "nvidia-smi", SHA256: id.SHA256}, {Path: id.Path, SHA256: "unknown"}} {
		if _, err := GPUProcessDefinition(bad); err == nil {
			t.Fatal("unverified executable accepted")
		}
	}
}

func TestGPUHostStatsDefinitionIsNarrowAndFixed(t *testing.T) {
	id := ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("b", 64)}
	definition, err := GPUHostStatsDefinition(id)
	if err != nil {
		t.Fatal(err)
	}
	if definition.ID != "gpu.host_stats" || definition.OutputSchema != "nvidia.host_stats.v1" || definition.RequiresPrivilege || len(definition.Parameters) != 0 || definition.Limits.TimeoutSeconds != 15 || definition.Limits.MaximumOutputBytes != 1<<20 || len(definition.Arguments) != 2 || definition.Arguments[0].Literal != "--query-gpu=uuid,temperature.gpu,power.draw,memory.used" {
		t.Fatalf("host-stats definition exceeded its reviewed boundary: %#v", definition)
	}
}
