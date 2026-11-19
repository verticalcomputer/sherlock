package adminapi

import (
	"context"
	"encoding/json"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"net/http"
	"strconv"
)

type AssessmentHistoryProvider interface {
	HistoryPageWithAudit(context.Context, string, string, string, int64, int64) (alertdelivery.ProductionNotificationHistory, error)
}

func (server *Server) assessmentHistory(w http.ResponseWriter, r *http.Request) {
	// Evidence includes original retained samples. Never fall back to the older
	// service-token-only compatibility mode for this new human-facing route.
	if !server.requireHumanAuthorization || server.assessmentHistoryProvider == nil {
		writeProblem(w, http.StatusServiceUnavailable, "ASSESSMENT_DISABLED", "assessment evidence requires verified cluster authorization")
		return
	}
	cluster, enrollment, occurrence := r.PathValue("cluster_id"), r.PathValue("enrollment_id"), r.PathValue("occurrence_id")
	if !validClusterIDPath(cluster) || !validClusterIDPath(enrollment) || !validClusterIDPath(occurrence) {
		writeProblem(w, 400, "INVALID_ARGUMENT", "exact assessment scope is required")
		return
	}
	q := r.URL.Query()
	var after, audit int64
	for k, v := range q {
		if (k != "after" && k != "after_audit") || len(v) != 1 {
			writeProblem(w, 400, "INVALID_ARGUMENT", "invalid history cursor")
			return
		}
		n, e := strconv.ParseInt(v[0], 10, 64)
		if e != nil || n < 0 {
			writeProblem(w, 400, "INVALID_ARGUMENT", "invalid history cursor")
			return
		}
		if k == "after" {
			after = n
		} else {
			audit = n
		}
	}
	h, err := server.assessmentHistoryProvider.HistoryPageWithAudit(r.Context(), cluster, enrollment, occurrence, after, audit)
	if err != nil {
		writeProblem(w, 503, "SERVICE_UNAVAILABLE", "assessment history is unavailable")
		return
	}
	if h.Occurrence.ClusterID != cluster || h.Occurrence.EnrollmentID != enrollment || h.Occurrence.ID != occurrence {
		writeProblem(w, 404, "NOT_FOUND", "assessment occurrence not found")
		return
	}
	b, err := json.Marshal(h)
	if err != nil || len(b) > 20<<20 {
		writeProblem(w, 503, "SERVICE_UNAVAILABLE", "assessment history exceeds page bounds")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(b)
}
