package investigationtools

import "slices"

const KernelXIDCorrelationToolID ToolID = "node.kernel_events.v1"

// XIDDisposition is the operational outcome of the reviewed XID playbook.
// It is intentionally smaller than a model-generated finding: every value has
// one owner and one bounded next action.
type XIDDisposition string

const (
	XIDGatherEvidence     XIDDisposition = "GATHER_EVIDENCE"
	XIDEscalateDatacenter XIDDisposition = "ESCALATE_DATACENTER"
	XIDResetAtMaintenance XIDDisposition = "RESET_AT_MAINTENANCE"
	XIDRestartWorkload    XIDDisposition = "RESTART_WORKLOAD"
	XIDRepairTelemetry    XIDDisposition = "REPAIR_TELEMETRY"
	XIDRepairDiagnostics  XIDDisposition = "REPAIR_DIAGNOSTICS"
	XIDEngineeringTriage  XIDDisposition = "ENGINEERING_TRIAGE"
)

// XIDDecisionFacts contains only facts whose meaning can be checked without a
// model. AttemptedTools records terminal action outcomes such as SUCCEEDED,
// NO_EVIDENCE, or FAILED. The diagnostic boolean/counter facts are projections
// from their cited evidence, not guesses based on a DCGM gauge.
type XIDDecisionFacts struct {
	AttemptedTools         map[ToolID]string
	XIDCodes               []int
	KernelXIDObserved      bool
	RowRemapFailure        bool
	RowRemapPending        bool
	UncorrectableECCBefore uint64
	UncorrectableECCAfter  uint64
	GPUIsMissing           bool
}

type XIDDecision struct {
	Disposition XIDDisposition
	Owner       string
	Action      string
	NextToolID  ToolID
	Reason      string
}

// The fourth step reads the node's kernel journal directly rather than looking
// up committed kernel evidence. The lookup form could never resolve: no
// collector, diagnostic or log pipeline in this deployment writes an evidence
// envelope for a kernel operation, so the step returned empty for exactly the
// events that prompted the run. Reading the journal spends a diagnostic call
// and touches the node, which the first three steps already do.
var xidEvidencePass = []ToolID{
	DiagnosticECCCountersToolID,
	DiagnosticRowRemapToolID,
	DiagnosticRetiredPagesToolID,
	DiagnosticKernelXIDToolID,
}

func XIDRequiredEvidenceTools() []ToolID { return slices.Clone(xidEvidencePass) }

// DecideXIDAction applies the reviewed XID decision tree. It requests each
// decision-changing diagnostic at most once before making a disposition and
// never responds to a sticky gauge by slicing the same metrics window again.
func DecideXIDAction(facts XIDDecisionFacts) XIDDecision {
	if facts.GPUIsMissing {
		return xidDatacenterEscalation("GPU is missing from the current inventory")
	}
	if slices.Contains(facts.XIDCodes, 95) || slices.Contains(facts.XIDCodes, 64) {
		return xidDatacenterEscalation("an XID 95 or XID 64 was confirmed")
	}
	if facts.RowRemapFailure {
		return xidDatacenterEscalation("row remapping reported a failure")
	}
	if facts.UncorrectableECCAfter > facts.UncorrectableECCBefore {
		return xidDatacenterEscalation("uncorrectable ECC errors increased during the investigation")
	}

	for _, toolID := range xidEvidencePass {
		if _, attempted := facts.AttemptedTools[toolID]; !attempted {
			return XIDDecision{
				Disposition: XIDGatherEvidence,
				Owner:       "Sherlock diagnostics",
				Action:      "Run the next reviewed XID diagnostic and attach its evidence.",
				NextToolID:  toolID,
				Reason:      "the XID decision record is missing a required evidence class",
			}
		}
	}

	for _, toolID := range xidEvidencePass {
		if outcome := facts.AttemptedTools[toolID]; outcome == "FAILED" || outcome == "REJECTED" || outcome == "OUTCOME_UNKNOWN" || outcome == "UNAVAILABLE" {
			return XIDDecision{
				Disposition: XIDRepairDiagnostics,
				Owner:       "Sherlock engineering",
				Action:      "Restore the failed reviewed diagnostic path, then start a new XID investigation.",
				Reason:      "required XID evidence could not be collected by " + string(toolID),
			}
		}
	}

	if facts.RowRemapPending {
		return XIDDecision{
			Disposition: XIDResetAtMaintenance,
			Owner:       "Cluster operations",
			Action:      "Schedule a maintenance reset of the affected GPU and verify row-remap state after it returns.",
			Reason:      "row remapping is pending but has not failed",
		}
	}
	if onlyXIDCode(facts.XIDCodes, 94) {
		if facts.KernelXIDObserved {
			return XIDDecision{
				Disposition: XIDRestartWorkload,
				Owner:       "Workload operations",
				Action:      "Restart the affected workload and schedule a convenient GPU reset if the contained XID recurs.",
				Reason:      "kernel evidence confirmed contained XID 94 without ECC or row-remap escalation signals",
			}
		}
		return XIDDecision{
			Disposition: XIDRepairTelemetry,
			Owner:       "Sherlock observability",
			Action:      "Correct the sticky DCGM XID gauge handling and monitor for a new kernel-correlated edge.",
			Reason:      "only XID 94 remained in metrics and no matching kernel event was found",
		}
	}
	return XIDDecision{
		Disposition: XIDEngineeringTriage,
		Owner:       "Sherlock engineering",
		Action:      "Review the cited XID code and diagnostic outputs, then extend the reviewed decision rule before escalation.",
		Reason:      "the collected XID evidence does not match a reviewed deterministic disposition",
	}
}

func xidDatacenterEscalation(reason string) XIDDecision {
	return XIDDecision{
		Disposition: XIDEscalateDatacenter,
		Owner:       "Datacenter operations",
		Action:      "Drain the affected GPU or node and open a datacenter or vendor ticket with the cited XID, ECC, row-remap, and kernel evidence.",
		Reason:      reason,
	}
}

func onlyXIDCode(values []int, want int) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value != want {
			return false
		}
	}
	return true
}
