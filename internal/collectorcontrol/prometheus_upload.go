package collectorcontrol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type PrometheusReportStore interface {
	// True means the exact payload was committed or had already been committed.
	RecordPrometheusReport(context.Context, domain.PrometheusReport) (bool, error)
}

// PrometheusUploadBinding grants one authenticated collector access to one source.
// The collector's cluster is obtained from its registered certificate identity.
type PrometheusUploadBinding struct {
	CollectorID domain.CollectorID
	SourceID    domain.SourceID
}

type SharedPrometheusReportStore interface {
	PrometheusReportStore
	PrometheusUploadSourceAllowed(context.Context, domain.ClusterID, domain.SourceID) (bool, error)
}

var errPrometheusUploadScope = errors.New("collector is outside the scheduled report scope")

// NewSharedPrometheusUploadHandler resolves scope using operator bindings and
// database source ownership after authenticating each collector.
func NewSharedPrometheusUploadHandler(identity IdentityAuthenticator, auth RequestAuthenticator, store SharedPrometheusReportStore,
	clock Clock, bindings []PrometheusUploadBinding) (http.Handler, error) {
	if store == nil || len(bindings) == 0 || len(bindings) > 256 {
		return nil, fmt.Errorf("shared scheduled upload requires storage and between one and 256 collector bindings")
	}
	sources := make(map[domain.CollectorID]domain.SourceID, len(bindings))
	for _, binding := range bindings {
		if !validPrometheusUploadIdentifier(string(binding.CollectorID)) || !validPrometheusUploadIdentifier(string(binding.SourceID)) {
			return nil, fmt.Errorf("shared scheduled upload binding has an invalid collector or source")
		}
		if _, exists := sources[binding.CollectorID]; exists {
			return nil, fmt.Errorf("shared scheduled upload repeats a collector binding")
		}
		sources[binding.CollectorID] = binding.SourceID
	}
	return newPrometheusUploadHandler(identity, auth, store, clock, func(ctx context.Context, caller AuthenticatedIdentity) (domain.SourceID, error) {
		source, found := sources[caller.CollectorID]
		if !found || caller.ClusterID == "" {
			return "", errPrometheusUploadScope
		}
		allowed, err := store.PrometheusUploadSourceAllowed(ctx, caller.ClusterID, source)
		if err != nil {
			return "", err
		}
		if !allowed {
			return "", errPrometheusUploadScope
		}
		return source, nil
	})
}

func validPrometheusUploadIdentifier(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n\x00")
}

// NewPrometheusUploadHandler mounts only the scheduled reporting endpoint.
func NewPrometheusUploadHandler(identity IdentityAuthenticator, auth RequestAuthenticator, store PrometheusReportStore,
	clock Clock, collector domain.CollectorID, cluster domain.ClusterID, source domain.SourceID) (http.Handler, error) {
	if identity == nil || auth == nil || store == nil || clock == nil || collector == "" || cluster == "" || source == "" {
		return nil, fmt.Errorf("scheduled Prometheus upload requires identity, storage, and an explicit collector, cluster, and source")
	}
	return newPrometheusUploadHandler(identity, auth, store, clock, func(_ context.Context, caller AuthenticatedIdentity) (domain.SourceID, error) {
		if caller.CollectorID != collector || caller.ClusterID != cluster {
			return "", errPrometheusUploadScope
		}
		return source, nil
	})
}

func newPrometheusUploadHandler(identity IdentityAuthenticator, auth RequestAuthenticator, store PrometheusReportStore, clock Clock,
	resolve func(context.Context, AuthenticatedIdentity) (domain.SourceID, error)) (http.Handler, error) {
	if identity == nil || auth == nil || store == nil || clock == nil {
		return nil, fmt.Errorf("scheduled Prometheus upload requires identity, authentication, storage and clock")
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
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		source, err := resolve(ctx, caller)
		if errors.Is(err, errPrometheusUploadScope) {
			writeProblem(w, http.StatusForbidden, "FORBIDDEN", "collector is outside the scheduled report scope", correlation)
			return
		}
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "UNAVAILABLE", "scheduled report scope could not be resolved", correlation)
			return
		}
		var report domain.PrometheusReport
		if !decodeJSON(w, r, &report) || report.Validate(caller.ClusterID, source, clock.Now()) != nil {
			writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "scheduled report is invalid", correlation)
			return
		}
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
