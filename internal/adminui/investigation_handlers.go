package adminui

import (
	"errors"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func investigationPending(status string) bool {
	state := domain.InvestigationStatus(status)
	return state.Validate() == nil && !state.Terminal()
}

func (server *Server) cancelInvestigation(w http.ResponseWriter, r *http.Request) {
	key, csrf, ok := server.requireAccess(w, r)
	if !ok {
		return
	}
	if !server.parseAndVerifyCSRF(w, r, csrf) {
		return
	}
	id := r.PathValue("id")
	report, err := server.provider.LoadInvestigationReport(r.Context(), id)
	if err != nil {
		http.Error(w, "investigation not found", http.StatusNotFound)
		return
	}
	if !clusterAccess(r.Context(), report.ClusterID).CanInvestigate {
		http.Error(w, "cluster administrator required", http.StatusForbidden)
		return
	}
	version, err := strconv.Atoi(r.PostForm.Get("expected_version"))
	if err != nil || version < 1 || version != report.Version || !investigationPending(report.Status) {
		http.Error(w, "investigation advanced; refresh before cancelling", http.StatusConflict)
		return
	}
	provider, ok := server.provider.(InvestigationCanceller)
	if !ok {
		http.Error(w, "investigation cancellation unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := provider.CancelInvestigation(r.Context(), id, version, "Cancelled by cluster administrator", server.mutationContext(r, key)); err != nil {
		http.Error(w, "cancellation was not confirmed; refresh durable progress", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/admin/investigations/"+url.PathEscape(strings.TrimSpace(id)), http.StatusSeeOther)
}

func (server *Server) startInvestigation(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	clusterID := strings.TrimSpace(request.PathValue("id"))
	input, err := parseInvestigationForm(request.PostForm, server.clock.Now().UTC())
	if err != nil || !validAdminToken(clusterID) {
		http.Error(writer, "invalid investigation limits, scope, or question", http.StatusBadRequest)
		return
	}
	result, err := server.provider.StartInvestigation(request.Context(), clusterID, input, server.mutationContext(request, key))
	if err != nil {
		http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"?start_failed=1", http.StatusSeeOther)
		return
	}
	http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"?investigation_started="+url.QueryEscape(result.ID), http.StatusSeeOther)
}

func (server *Server) investigationReportPage(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	id := strings.TrimSpace(request.PathValue("id"))
	if id == "" {
		http.Error(writer, "investigation not found", http.StatusNotFound)
		return
	}
	report, err := server.provider.LoadInvestigationReport(request.Context(), id)
	if err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			http.Error(writer, "investigation report not found", http.StatusNotFound)
			return
		}
		http.Error(writer, "investigation report is temporarily unavailable; verify that the private API is current and reachable", http.StatusBadGateway)
		return
	}
	if !server.auditView(writer, request, key, "investigation_report") {
		return
	}
	server.renderTemplate(writer, server.reportTemplate, "investigation-report.html", investigationReportPageData{
		pageBase: pageBase{Page: "investigations", CSRFToken: csrfToken}, Report: report,
		CanCancel: clusterAccess(request.Context(), report.ClusterID).CanInvestigate && report.Version > 0 && investigationPending(report.Status),
	})
}
