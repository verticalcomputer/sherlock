package commandpack

// GPUProcessDefinition is the reviewed compute-process query included in the
// signed pilot pack. Callers supply verified executable identity; constructing
// this definition grants no execution rights.
// NVIDIA does not expose process start identity here: separate bounded proc
// evidence must bracket the query before a PID can identify an incarnation.
func GPUProcessDefinition(nvidiaSMI ExecutableIdentity) (Definition, error) {
	definition := Definition{
		ID: "gpu.compute_processes", Version: "1.1.0", Owner: "gpu-operations",
		Purpose:               "Read bounded NVIDIA compute-process GPU UUID, PID and MIG instance fields",
		SupportedCapabilities: []string{"gpu.process.read"}, Risk: RiskLow,
		ExecutablePath: nvidiaSMI.Path, ExecutableSHA256: nvidiaSMI.SHA256,
		Arguments: []ArgumentToken{
			{Literal: "--query-compute-apps=gpu_uuid,pid"},
			{Literal: "--format=csv,noheader,nounits"},
		},
		Targets:      TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 1},
		Limits:       Limits{TimeoutSeconds: 15, MaximumOutputBytes: 1 << 20, MaximumConcurrency: 1},
		OutputSchema: "nvidia.compute_processes.v2",
	}
	return definition, ValidateDefinition(definition)
}

// GPUHostStatsDefinition is the companion fixed query for GP-06e. “Host
// stats” here means only driver-reported GPU UUID, temperature, power draw and
// framebuffer use; it does not read processes, hostnames, filesystems, or
// general host telemetry. It is enabled only by the separate GP-06e
// observation configuration.
func GPUHostStatsDefinition(nvidiaSMI ExecutableIdentity) (Definition, error) {
	definition := Definition{
		ID: "gpu.host_stats", Version: "1.0.0", Owner: "gpu-operations",
		Purpose:               "Read bounded NVIDIA GPU UUID, temperature, power draw and framebuffer use",
		SupportedCapabilities: []string{"gpu.process.observe"}, Risk: RiskLow,
		ExecutablePath: nvidiaSMI.Path, ExecutableSHA256: nvidiaSMI.SHA256,
		Arguments: []ArgumentToken{
			{Literal: "--query-gpu=uuid,temperature.gpu,power.draw,memory.used"},
			{Literal: "--format=csv,noheader,nounits"},
		},
		Targets: TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 1},
		Limits:  Limits{TimeoutSeconds: 15, MaximumOutputBytes: 1 << 20, MaximumConcurrency: 1}, OutputSchema: "nvidia.host_stats.v1",
	}
	return definition, ValidateDefinition(definition)
}
