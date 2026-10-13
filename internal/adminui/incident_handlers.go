package adminui

import (
	"net/http"
	"strings"
)

func (server *Server) operationsPage(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	operations, err := server.provider.LoadOperations(request.Context())
	var historicalXID []Ticket
	operations.Tickets, historicalXID = splitHistoricalXIDTickets(operations.Tickets, server.clock.Now())
	operations.Tickets = consolidateTickets(operations.Tickets)
	section := strings.TrimPrefix(request.URL.Path, "/admin/")
	page := operationsPageData{pageBase: pageBase{Page: section, CSRFToken: csrfToken}, Operations: operations, HistoricalXID: historicalXID}
	page.Title = map[string]string{"operations": "Overview", "incidents": "Incidents", "investigations": "Investigations", "repairs": "Autonomous repairs"}[section]
	if err != nil {
		page.Error = "Live tickets and investigations are temporarily unavailable."
		page.Operations = Operations{GeneratedAt: server.clock.Now().UTC()}
	}
	page.RecentInvestigations, page.EarlierInvestigations = splitRecentInvestigations(page.Operations.Investigations, operationsInvestigationLimit)
	if section == "operations" && err == nil {
		now := page.Operations.GeneratedAt
		if now.IsZero() {
			now = server.clock.Now()
		}
		page.Overview = server.buildOverview(request.Context(), page.Operations, now)
	}
	if !server.auditView(writer, request, key, "operations") {
		return
	}
	server.renderTemplate(writer, server.operationsTemplate, "operations.html", page)
}

// XID is a retained last-code gauge. An old edge is history, even when the
// exporter still reports the same nonzero value. Keep the durable OPEN record
// accessible for review; this presentation split does not assert recovery.
