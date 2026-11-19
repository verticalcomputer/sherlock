package adminui

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
)

type AssessmentHistoryProvider interface {
	GetAssessmentHistory(context.Context, string, string, string, int64, int64) (alertdelivery.ProductionNotificationHistory, error)
}

var assessmentTemplate = template.Must(template.New("assessment").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Cooling investigation history</title><link rel="stylesheet" href="/admin/assets/dashboard.css"></head><body><main><h1>Cooling investigation history</h1><p>Cluster {{.History.Occurrence.ClusterID}} · Asset {{.History.Occurrence.Asset}}</p><p>Incident {{.History.Occurrence.IncidentID}} · Occurrence {{.History.Occurrence.ID}}</p><p>Opened {{.History.Occurrence.OpenedAt}} · {{if .History.Occurrence.ClosedAt}}Measured recovery {{.History.Occurrence.ClosedAt}}{{else}}No measured recovery recorded. Current condition requires fresh evidence.{{end}}</p><p>Acknowledged by: {{.History.Occurrence.AcknowledgedBy}}. Acknowledgment does not mute notifications.</p><p>Maintenance until: {{.History.Occurrence.MaintenanceUntil}}. Reason: {{.History.Occurrence.MaintenanceReason}}</p><h2>Events and supporting evidence</h2>{{range .History.Events}}<article><h3>{{.Kind}} · {{.At}}</h3><p>{{.Summary}}</p><p>Event {{.ID}} · Evidence {{.EvidenceID}}</p><details><summary>Retained evidence</summary><pre>{{printf "%s" .Evidence}}</pre></details></article>{{else}}<p>No events on this page.</p>{{end}}{{if .NextEvents}}<p><a href="{{.NextEvents}}">Next events</a></p>{{end}}<h2>Delivery history</h2><pre>{{.Delivery}}</pre><h2>Operator audit</h2><pre>{{.Audit}}</pre>{{if .NextAudit}}<p><a href="{{.NextAudit}}">Next operator actions</a></p>{{end}}<p>All times include their time zone. Slack acceptance does not establish human receipt.</p></main></body></html>`))

func (server *Server) assessmentPage(w http.ResponseWriter, r *http.Request) {
	key, _, ok := server.requireAccess(w, r)
	if !ok {
		return
	}
	if _, enforced := r.Context().Value(humanAccessKey{}).(map[string]ClusterAccess); !enforced {
		http.Error(w, "verified cluster membership is required", http.StatusForbidden)
		return
	}
	provider, ok := server.provider.(AssessmentHistoryProvider)
	if !ok {
		http.Error(w, "assessment history unavailable", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	var after, audit int64
	for k, v := range q {
		if (k != "after" && k != "after_audit") || len(v) != 1 {
			http.Error(w, "invalid history cursor", http.StatusBadRequest)
			return
		}
		n, e := strconv.ParseInt(v[0], 10, 64)
		if e != nil || n < 0 {
			http.Error(w, "invalid history cursor", http.StatusBadRequest)
			return
		}
		if k == "after" {
			after = n
		} else {
			audit = n
		}
	}
	h, err := provider.GetAssessmentHistory(r.Context(), r.PathValue("id"), r.PathValue("enrollment"), r.PathValue("occurrence"), after, audit)
	if err != nil {
		http.Error(w, "assessment history unavailable", http.StatusServiceUnavailable)
		return
	}
	if h.Occurrence.ClusterID != r.PathValue("id") || h.Occurrence.EnrollmentID != r.PathValue("enrollment") || h.Occurrence.ID != r.PathValue("occurrence") {
		http.Error(w, "assessment occurrence not found", http.StatusNotFound)
		return
	}
	data := struct {
		History                                alertdelivery.ProductionNotificationHistory
		Delivery, Audit, NextEvents, NextAudit string
	}{History: h, Delivery: prettyAssessmentJSON(h.Delivery), Audit: prettyAssessmentJSON(h.Audit)}
	next := func(e, a int64) string {
		return r.URL.Path + "?" + url.Values{"after": {strconv.FormatInt(e, 10)}, "after_audit": {strconv.FormatInt(a, 10)}}.Encode()
	}
	if h.More {
		data.NextEvents = next(h.NextAfter, audit)
	}
	if h.MoreAudit {
		data.NextAudit = next(after, h.NextAuditAfter)
	}
	var b bytes.Buffer
	if err = assessmentTemplate.Execute(&b, data); err != nil || b.Len() > 24<<20 {
		http.Error(w, "assessment history unavailable", http.StatusServiceUnavailable)
		return
	}
	if !server.auditView(w, r, key, "assessment_history") {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b.Bytes())
}
func prettyAssessmentJSON(raw json.RawMessage) string {
	var b bytes.Buffer
	if json.Indent(&b, raw, "", "  ") != nil {
		return "Unavailable"
	}
	return b.String()
}
