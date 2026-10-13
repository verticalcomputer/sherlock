package commandpack

import "fmt"

// ExecutableIdentity is supplied from pilot deployment inventory. Source code
// deliberately does not guess or pin a host-specific executable digest.
type ExecutableIdentity struct{ Path, SHA256 string }

type PilotIdentities struct{ NvidiaSMI, Journalctl, Scontrol ExecutableIdentity }

// PilotDefinitions builds the reviewed read-only definition set for the first
// Slurm/NVIDIA pilot. The caller embeds these definitions in a signed pack.
func PilotDefinitions(ids PilotIdentities) ([]Definition, error) {
	processDefinition, err := GPUProcessDefinition(ids.NvidiaSMI)
	if err != nil {
		return nil, err
	}
	hostStatsDefinition, err := GPUHostStatsDefinition(ids.NvidiaSMI)
	if err != nil {
		return nil, err
	}
	definitions := []Definition{
		processDefinition,
		// M12 closes the gap the investigation loop identified: it could observe
		// that an ECC counter was non-zero but not distinguish a transient
		// contained fault from a degrading device. All three additions read live
		// device state through the same pinned binary, take no parameters, and
		// require no privilege, so no sudo rule and no privilege adapter is
		// involved. The distinction they answer is the difference between an
		// alert and an RMA.
		//
		// Volatile counters reset with the driver; aggregate counters persist for
		// the device's life. A high aggregate count beside a low volatile one is a
		// device with a history; the reverse is a fault happening now.
		{ID: "gpu.ecc_counters", Version: "1.0.0", Owner: "gpu-operations", Purpose: "Read current (volatile) and lifetime (aggregate) GPU ECC error counters", SupportedCapabilities: []string{"gpu.read"}, Risk: RiskLow, ExecutablePath: ids.NvidiaSMI.Path, ExecutableSHA256: ids.NvidiaSMI.SHA256,
			Arguments: []ArgumentToken{{Literal: "--query-gpu=index,uuid,ecc.errors.corrected.volatile.total,ecc.errors.uncorrected.volatile.total,ecc.errors.corrected.aggregate.total,ecc.errors.uncorrected.aggregate.total"}, {Literal: "--format=csv,noheader,nounits"}},
			Targets:   TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 64}, Limits: Limits{TimeoutSeconds: 30, MaximumOutputBytes: 4 << 20, MaximumConcurrency: 8}, OutputSchema: "nvidia.ecc_counters.v1"},
		hostStatsDefinition,
		{ID: "gpu.inventory", Version: "1.0.0", Owner: "gpu-operations", Purpose: "Read bounded NVIDIA GPU identity and health fields", SupportedCapabilities: []string{"gpu.read"}, Risk: RiskLow, ExecutablePath: ids.NvidiaSMI.Path, ExecutableSHA256: ids.NvidiaSMI.SHA256,
			Arguments: []ArgumentToken{{Literal: "--query-gpu=index,uuid,name,pci.bus_id,temperature.gpu,power.draw,memory.used,ecc.errors.uncorrected.volatile.total"}, {Literal: "--format=csv,noheader,nounits"}},
			Targets:   TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 64}, Limits: Limits{TimeoutSeconds: 30, MaximumOutputBytes: 4 << 20, MaximumConcurrency: 8}, OutputSchema: "nvidia.inventory.v1"},
		// Retired pages are the pre-Ampere containment mechanism. The counts are
		// split by cause because that is the distinction that matters: single-bit
		// retirements are routine, double-bit retirements are not, and a non-zero
		// pending count means containment has not completed.
		{ID: "gpu.retired_pages", Version: "1.0.0", Owner: "gpu-operations", Purpose: "Read GPU retired page counts by cause and any pending retirement", SupportedCapabilities: []string{"gpu.read"}, Risk: RiskLow, ExecutablePath: ids.NvidiaSMI.Path, ExecutableSHA256: ids.NvidiaSMI.SHA256,
			Arguments: []ArgumentToken{{Literal: "--query-gpu=index,uuid,retired_pages.single_bit_ecc.count,retired_pages.double_bit.count,retired_pages.pending"}, {Literal: "--format=csv,noheader,nounits"}},
			Targets:   TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 64}, Limits: Limits{TimeoutSeconds: 30, MaximumOutputBytes: 4 << 20, MaximumConcurrency: 8}, OutputSchema: "nvidia.retired_pages.v1"},
		// Row remapping is the Ampere and later mechanism. Pending means a remap
		// is queued and needs a reset to take effect; failure means remapping
		// itself failed, which is the unambiguous RMA signal.
		// --query-remapped-rows accepts only remapped_rows.* fields. Target
		// identity is already carried by the signed plan and per-target result,
		// so asking this query family for index or uuid is both redundant and
		// rejected by nvidia-smi. Version 1.1.0 freezes the corrected four-column
		// output separately from the invalid 1.0.0 argv.
		{ID: "gpu.row_remap", Version: "1.1.0", Owner: "gpu-operations", Purpose: "Read GPU row-remap pending and failure state with correctable and uncorrectable remap counts", SupportedCapabilities: []string{"gpu.read"}, Risk: RiskLow, ExecutablePath: ids.NvidiaSMI.Path, ExecutableSHA256: ids.NvidiaSMI.SHA256,
			Arguments: []ArgumentToken{{Literal: "--query-remapped-rows=remapped_rows.pending,remapped_rows.failure,remapped_rows.correctable,remapped_rows.uncorrectable"}, {Literal: "--format=csv,noheader,nounits"}},
			Targets:   TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 64}, Limits: Limits{TimeoutSeconds: 30, MaximumOutputBytes: 4 << 20, MaximumConcurrency: 8}, OutputSchema: "nvidia.row_remap.v2"},
		{ID: "node.kernel_xid", Version: "1.0.0", Owner: "gpu-operations", Purpose: "Read a bounded kernel journal window for NVIDIA XID events", SupportedCapabilities: []string{"kernel.read", "sudo.journalctl"}, Risk: RiskPrivileged, ExecutablePath: ids.Journalctl.Path, ExecutableSHA256: ids.Journalctl.SHA256,
			Arguments: []ArgumentToken{{Literal: "--dmesg"}, {Literal: "--utc"}, {Literal: "--no-pager"}, {Literal: "--output=short-iso"}, {Literal: "--grep=NVRM: Xid"}, {Literal: "--since=-1 hour"}, {Literal: "--lines=2000"}},
			Targets:   TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 32}, RequiresPrivilege: true,
			SudoRule: fmt.Sprintf("sherlock ALL=(root) NOPASSWD: %s --dmesg --utc --no-pager --output=short-iso --grep=NVRM\\: Xid --since=-1\\ hour --lines=2000", ids.Journalctl.Path),
			Limits:   Limits{TimeoutSeconds: 30, MaximumOutputBytes: 4 << 20, MaximumConcurrency: 8}, OutputSchema: "kernel.xid.v1"},
		// Version 2.0.0 reads the same journal without privilege. Journal access
		// is a group membership on the reading account, not a sudo rule, so an
		// account in systemd-journal needs no elevation and the reduced-trust
		// agentless route can run it; 1.0.0 refuses to plan there because a
		// privileged definition demands an adapter that route does not have.
		// 1.0.0 is retained for a forced-command deployment whose runner does.
		//
		// The window is seven days rather than one hour because a sticky DCGM
		// gauge still reports an XID long after the kernel stopped logging it,
		// and a one-hour window returns empty for exactly the events that
		// prompted the investigation. Both bounds stay literal: the argv is
		// closed, and a supplied window would be a parameter on a journal read.
		{ID: "node.kernel_xid", Version: "2.0.0", Owner: "gpu-operations", Purpose: "Read a bounded kernel journal window for NVIDIA XID events without privilege", SupportedCapabilities: []string{"kernel.read"}, Risk: RiskLow, ExecutablePath: ids.Journalctl.Path, ExecutableSHA256: ids.Journalctl.SHA256,
			Arguments: []ArgumentToken{{Literal: "--dmesg"}, {Literal: "--utc"}, {Literal: "--no-pager"}, {Literal: "--output=short-iso"}, {Literal: "--grep=NVRM: Xid"}, {Literal: "--since=-7 days"}, {Literal: "--lines=2000"}},
			Targets:   TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 32},
			Limits:    Limits{TimeoutSeconds: 30, MaximumOutputBytes: 4 << 20, MaximumConcurrency: 8}, OutputSchema: "kernel.xid.v1"},
		{ID: "slurm.node_detail", Version: "1.0.0", Owner: "cluster-operations", Purpose: "Read detailed Slurm state for one validated node", SupportedCapabilities: []string{"slurm.read"}, Risk: RiskLow, ExecutablePath: ids.Scontrol.Path, ExecutableSHA256: ids.Scontrol.SHA256,
			Arguments: []ArgumentToken{{Literal: "show"}, {Literal: "node"}, {Parameter: "node"}, {Literal: "--json"}}, Parameters: []Parameter{{Name: "node", Type: ParameterString, Required: true, Pattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaxLength: 128}},
			Targets: TargetConstraints{Roles: []TargetRole{TargetHead}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 1}, Limits: Limits{TimeoutSeconds: 15, MaximumOutputBytes: 2 << 20, MaximumConcurrency: 1}, OutputSchema: "slurm.node.v1"},
	}
	previous := ""
	for _, definition := range definitions {
		if err := ValidateDefinition(definition); err != nil {
			return nil, fmt.Errorf("pilot definition %q: %w", definition.ID, err)
		}
		// ValidatePack requires canonical ordering. Catching it here means a
		// misplaced addition fails where it was written, not at signing time.
		if key := definition.ID + "@" + definition.Version; key <= previous {
			return nil, fmt.Errorf("pilot definition %q is out of canonical order", definition.ID)
		} else {
			previous = key
		}
	}
	return definitions, nil
}
