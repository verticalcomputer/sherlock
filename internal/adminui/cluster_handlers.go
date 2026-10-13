package adminui

import (
	"net/http"
	"strings"
	"time"
)

// clusterDetailTab serves one cluster view. Summary, recovery gates,
// investigations, and health signals are separate pages that share one load.
func (server *Server) clusterDetailTab(tab string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		server.clusterDetailPage(writer, request, tab)
	}
}

func (server *Server) clusterDetailPage(writer http.ResponseWriter, request *http.Request, tab string) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	id := strings.TrimSpace(request.PathValue("id"))
	record, err := server.provider.GetCluster(request.Context(), id)
	if err != nil || id == "" {
		http.Error(writer, "cluster not found", http.StatusNotFound)
		return
	}
	summary, summaryErr := server.provider.GetClusterSummary(request.Context(), id)
	operations, operationsErr := server.provider.LoadClusterOperations(request.Context(), id)
	page := clusterDetailPageData{
		pageBase: pageBase{Page: "clusters", CSRFToken: csrfToken},
		Access:   clusterAccess(request.Context(), id),
		Record:   record, Cluster: summary, SummaryAvailable: summaryErr == nil,
	}
	if summaryErr != nil {
		page.Error = "Operational resource data is temporarily unavailable. Missing data is not interpreted as healthy."
		page.Cluster = Cluster{ID: record.ID, Name: record.DisplayName, State: StateUnavailable}
	}
	if operationsErr != nil {
		if page.Error != "" {
			page.Error += " "
		}
		page.Error += "Current issues and investigations are temporarily unavailable."
	} else {
		page.OperationsAvailable = true
		operations.Tickets, page.HistoricalXID = splitHistoricalXIDTickets(operations.Tickets, server.clock.Now())
		page.Issues = consolidateTickets(operations.Tickets)
		page.Investigations = operations.Investigations
		page.GeneratedAt = operations.GeneratedAt
	}
	page.Glance = buildClusterGlance(page.Cluster, page.Issues, page.Investigations)
	page.Recovery = buildRecoveryPlan(page.Glance, page.Cluster.ExpectedCollectorNames, page.Cluster.MissingCollectorLabels, page.Cluster.ExcludedCollectorLabels, page.Cluster.SourceGapLabels, page.Cluster.OnDemandSourceLabels, page.Cluster.EvidenceStreams, page.Cluster.EvidenceHistory)
	if operationsErr != nil {
		for _, index := range []int{2, 3} {
			page.Recovery[index].NotApplicable = false
			page.Recovery[index].State = StateUnavailable
			page.Recovery[index].Current = "Incident status unavailable"
		}
	}
	page.GatesMet, page.ApplicableGates = openFirstUnmetGate(page.Recovery)
	page.Blockers = groupEvidenceBlockers(page.Cluster.EvidenceStreams)
	page.BlockerStreamCount = blockerStreamCount(page.Blockers)
	page.Rerun = buildInvestigationForm(page.Glance, "admin-"+request.Context().Value(requestKey{}).(string))
	page.NextAction = buildNextAction(page.Glance, page.Blockers, page.Rerun, page.Investigations, server.clock.Now().UTC())
	if !page.Access.CanInvestigate {
		page.Rerun.Available = false
		if page.NextAction.Kind == "repair-plan" || page.NextAction.Kind == "rerun" {
			page.NextAction = clusterAction{Kind: "none", Title: "Administrator action required", Detail: "A cluster administrator can start a bounded investigation. You can follow existing runs and shared reports."}
		}
	}
	if page.Cluster.Network.Enrolled && page.Cluster.Network.State != "HEALTHY" {
		page.NextAction = clusterAction{Kind: "none", Title: "Review network monitoring", Detail: "Inspect the per-node read errors and port states below. Missing source evidence does not prove a rail failure."}
	}
	if operationsErr != nil {
		page.NextAction = clusterAction{Kind: "none", Title: "Incident status unavailable", Detail: "The private incident projection could not be loaded. Retry before drawing an incident conclusion."}
	}
	page.RecentInvestigations, page.EarlierInvestigations = splitRecentInvestigations(page.Investigations, recentInvestigationLimit)
	if started := strings.TrimSpace(request.URL.Query().Get("investigation_started")); validAdminToken(started) {
		page.StartedInvestigationID = started
	}
	if started := strings.TrimSpace(request.URL.Query().Get("repair_proposal_started")); validAdminToken(started) {
		page.StartedRepairProposalID = started
	}
	page.StartFailed = request.URL.Query().Get("start_failed") == "1"
	page.RepairProposalFailed = request.URL.Query().Get("repair_proposal_failed") == "1"
	if page.RepairProposalFailed && page.Glance.PrimaryIssue != nil {
		if existing := latestEvidenceRepairInvestigation(page.Investigations, page.Glance.PrimaryIssue.ID, server.clock.Now().UTC(), 24*time.Hour); existing != nil {
			page.ExistingRepairProposalID = existing.ID
		}
	}
	page.RepairProposalCleared = request.URL.Query().Get("repair_proposal_cleared") == "1"
	page.RepairProposalNoIncident = request.URL.Query().Get("repair_proposal_no_incident") == "1"
	page.presentTab(tab, server.clock.Now().UTC())
	if !server.auditView(writer, request, key, "cluster_detail") {
		return
	}
	server.renderTemplate(writer, server.detailTemplate, "cluster-detail.html", page)
}
