package collectorcontrol

import (
	"context"
	"fmt"
	"net/http"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type PrometheusReportStore interface {
	// True means the exact payload was committed or had already been committed.
	RecordPrometheusReport(context.Context, domain.PrometheusReport) (bool, error)
}

// NewPrometheusUploadHandler mounts only the scheduled reporting endpoint.
func NewPrometheusUploadHandler(identity IdentityAuthenticator, auth RequestAuthenticator, store PrometheusReportStore,
	clock Clock, collector domain.CollectorID, cluster domain.ClusterID, source domain.SourceID) (http.Handler, error) {
	if identity == nil || auth == nil || store == nil || clock == nil || collector == "" || cluster == "" || source == "" {
		return nil, fmt.Errorf("scheduled Prometheus upload requires identity, storage, and an explicit collector, cluster, and source")
	}
	t := &Transport{authenticator: identity, requestAuth: auth, mux: http.NewServeMux()}
	t.mux.HandleFunc("POST "+domain.PrometheusUploadPath, func(w http.ResponseWriter, r *http.Request) {
		correlation, ok := validateProtocol(w, r)
		if !ok {
			return
		}
		if r.ContentLength > domain.PrometheusUploadMaxBytes {
			writeProblem(w, http.StatusRequestEntityTooLarge, "RESULT_LIMIT_EXCEEDED", "scheduled report exceeds upload limit", correlation)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, domain.PrometheusUploadMaxBytes)
		caller, ok := t.authenticate(w, r, correlation)
		if !ok {
			return
		}
		if caller.CollectorID != collector || caller.ClusterID != cluster {
			writeProblem(w, http.StatusForbidden, "FORBIDDEN", "collector is outside the scheduled report scope", correlation)
			return
		}
		var report domain.PrometheusReport
		if !decodeJSON(w, r, &report) || report.Validate(cluster, source, clock.Now()) != nil {
			writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "scheduled report is invalid", correlation)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		accepted, err := store.RecordPrometheusReport(ctx, report)
		switch {
		case err != nil:
			writeProblem(w, http.StatusServiceUnavailable, "UNAVAILABLE", "scheduled report could not be stored", correlation)
		case !accepted:
			writeProblem(w, http.StatusConflict, "CONFLICT", "different report already exists for the slot", correlation)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	return t, nil
}
