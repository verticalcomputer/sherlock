package investigation

import (
	"context"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
)

// One reviewed read of the source-bound frozen correlation precedes synthesis.
// Targets[0] is the scheduler source bound by admission, not a model selector.
// No native diagnostic or repair is authorized by this monitoring playbook.
func (o *Orchestrator) deterministicSlurmPlan(ctx context.Context, s application.InvestigationSnapshot) (application.InvestigationDecision, error) {
	const tool investigationtools.ToolID = "cluster.slurm_failure_evidence.v1"
	for _, a := range s.PriorActions {
		if a.ToolID == string(tool) {
			return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopNoUsefulAction}, nil
		}
	}
	r := s.Investigation.Request()
	filter, err := o.resolveAuthorityFilter(ctx, s)
	if err != nil {
		return application.InvestigationDecision{}, err
	}
	bounds, ok := o.catalog.ToolBounds(filter, tool)
	if !ok {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopPolicyExhausted}, nil
	}
	if len(r.Scope.EntityIDs) == 0 || r.Budget.MaxToolCalls <= s.Investigation.Usage().ToolCalls || r.Budget.MaxFanOut < 1 || r.Scope.End.Sub(r.Scope.Start) > bounds.MaxWindow {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopBudgetExceeded}, nil
	}
	call := investigationtools.Call{ToolID: tool, EntityKind: r.Scope.EntityKind, Targets: []string{r.Scope.EntityIDs[0]}, Start: r.Scope.Start, End: r.Scope.End}
	canonical, err := o.catalog.CanonicalCallKey(filter, call)
	if err != nil {
		return application.InvestigationDecision{}, fmt.Errorf("build Slurm evidence action: %w", err)
	}
	id, err := o.ids.NewID()
	if err != nil {
		return application.InvestigationDecision{}, err
	}
	return application.InvestigationDecision{Action: &domain.InvestigationAction{ID: domain.InvestigationActionID(id), ToolID: string(tool), Digest: domain.ChecksumSHA256([]byte(canonical)), FanOut: 1, Targets: call.Targets, Start: call.Start, End: call.End}}, nil
}
