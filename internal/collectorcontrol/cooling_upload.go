package collectorcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ErrCoolingUploadRejected identifies a report denied by durable upload authority.
var ErrCoolingUploadRejected = errors.New("cooling upload is outside enrolled authority")

type CoolingUploadStore interface {
	// True means the exact payload is committed. False with no error is a slot conflict.
	RecordCoolingUpload(context.Context, domain.CollectorID, domain.ClusterID, domain.CoolingUploadReport) (bool, error)
}

// NewCoolingUploadHandler mounts only the opt-in scheduled cooling report path.
func NewCoolingUploadHandler(identity IdentityAuthenticator, auth RequestAuthenticator, store CoolingUploadStore,
	clock Clock, profile domain.CoolingUploadProfile, hash string) (http.Handler, error) {
	if identity == nil || auth == nil || store == nil || clock == nil {
		return nil, fmt.Errorf("cooling upload requires identity, authentication, storage and clock")
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if digest, err := domain.ParseSHA256(hash); err != nil || digest.String() != hash {
		return nil, fmt.Errorf("invalid cooling upload profile hash")
	}
	profile.Assets = slices.Clone(profile.Assets)
	t := &Transport{authenticator: identity, requestAuth: auth, mux: http.NewServeMux()}
	t.mux.HandleFunc("POST "+domain.CoolingUploadPath, func(w http.ResponseWriter, r *http.Request) {
		correlation, ok := validateProtocolVersion(w, r, domain.CoolingUploadVersion)
		if !ok {
			return
		}
		if r.ContentLength > domain.CoolingUploadMaxBytes {
			writeProblem(w, http.StatusRequestEntityTooLarge, "RESULT_LIMIT_EXCEEDED", "cooling report exceeds upload limit", correlation)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, domain.CoolingUploadMaxBytes)
		caller, ok := t.authenticate(w, r, correlation)
		if !ok {
			return
		}
		if caller.CollectorID != profile.CollectorID || caller.ClusterID != profile.ClusterID {
			writeProblem(w, http.StatusForbidden, "FORBIDDEN", "collector is outside the cooling upload scope", correlation)
			return
		}
		var report domain.CoolingUploadReport
		encoded, err := io.ReadAll(r.Body)
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			writeProblem(w, http.StatusRequestEntityTooLarge, "RESULT_LIMIT_EXCEEDED", "cooling report exceeds upload limit", correlation)
			return
		}
		if err != nil || !decodeCoolingUploadReport(w, r, encoded, &report) || report.Validate(profile, hash, clock.Now()) != nil {
			writeProblem(w, http.StatusBadRequest, "INVALID_ARGUMENT", "cooling report is invalid", correlation)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		accepted, err := store.RecordCoolingUpload(ctx, caller.CollectorID, caller.ClusterID, report)
		switch {
		case errors.Is(err, ErrCoolingUploadRejected):
			writeProblem(w, http.StatusForbidden, "FORBIDDEN", "cooling report lacks active enrollment", correlation)
		case err != nil:
			writeProblem(w, http.StatusServiceUnavailable, "UNAVAILABLE", "cooling report could not be stored", correlation)
		case !accepted:
			writeProblem(w, http.StatusConflict, "CONFLICT", "different cooling report already exists for the slot", correlation)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	return t, nil
}

func decodeCoolingUploadReport(w http.ResponseWriter, r *http.Request, encoded []byte, report *domain.CoolingUploadReport) bool {
	r.Body = io.NopCloser(bytes.NewReader(encoded))
	if !decodeJSONLimit(w, r, report, domain.CoolingUploadMaxBytes) {
		return false
	}
	// The canonical encoding lets storage bind the exact signed wire bytes
	// using the typed report, including when a retry uses a fresh nonce.
	canonical, err := json.Marshal(report)
	return err == nil && bytes.Equal(encoded, canonical)
}
