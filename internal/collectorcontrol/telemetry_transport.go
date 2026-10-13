package collectorcontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// TelemetryIntake is separate from collector work/leases/results. A valid
// gateway collector certificate alone never grants authority over node data.
type TelemetryIntake interface {
	Grant(context.Context, domain.ClusterID, domain.CollectorID, string) (telemetry.Grant, error)
	RegisterSession(context.Context, domain.ClusterID, domain.CollectorID, telemetry.SessionMessage) (telemetry.SessionReceipt, error)
	AcceptBatch(context.Context, domain.ClusterID, domain.CollectorID, telemetry.NodeBatch, string) (telemetry.CloudReceipt, error)
	Status(context.Context, domain.ClusterID, domain.CollectorID, string) (telemetry.EnrollmentStatus, error)
}

// ConfigureTelemetry is called before serving. Existing v1/v2 routes retain
// their version contract and use no telemetry state or enrollment authority.
func (t *Transport) ConfigureTelemetry(store TelemetryIntake) error {
	if store == nil {
		return fmt.Errorf("telemetry intake is required")
	}
	t.mux.HandleFunc("GET /collector/telemetry/v1/enrollments/{enrollment_id}/grant", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.telemetryRequest(w, r)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		grant, err := store.Grant(ctx, identity.ClusterID, identity.CollectorID, r.PathValue("enrollment_id"))
		if err != nil {
			writeTelemetryError(w, err, id)
			return
		}
		writeJSON(w, 200, grant)
	})
	t.mux.HandleFunc("GET /collector/telemetry/v1/enrollments/{enrollment_id}/status", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.telemetryRequest(w, r)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		status, err := store.Status(ctx, identity.ClusterID, identity.CollectorID, r.PathValue("enrollment_id"))
		if err != nil {
			writeTelemetryError(w, err, id)
			return
		}
		writeJSON(w, 200, status)
	})
	t.mux.HandleFunc("POST /collector/telemetry/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.telemetryRequest(w, r)
		if !ok {
			return
		}
		body, ok := readTelemetryBody(w, r, id)
		if !ok {
			return
		}
		session, err := telemetry.DecodeSessionMessage(body, "")
		if err != nil {
			writeProblem(w, 400, "TELEMETRY_INVALID", "invalid telemetry session", id)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		receipt, err := store.RegisterSession(ctx, identity.ClusterID, identity.CollectorID, session)
		if err != nil {
			writeTelemetryError(w, err, id)
			return
		}
		writeJSON(w, 200, receipt)
	})
	t.mux.HandleFunc("POST /collector/telemetry/v1/batches", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.telemetryRequest(w, r)
		if !ok {
			return
		}
		body, ok := readTelemetryBody(w, r, id)
		if !ok {
			return
		}
		var envelope struct {
			Batch            telemetry.NodeBatch `json:"batch"`
			GatewayReceiptID string              `json:"gateway_receipt_id"`
		}
		if telemetry.DecodeStrictJSON(body, "", &envelope) != nil || envelope.GatewayReceiptID == "" || len(envelope.GatewayReceiptID) > 128 || strings.TrimSpace(envelope.GatewayReceiptID) != envelope.GatewayReceiptID {
			writeProblem(w, 400, "TELEMETRY_INVALID", "invalid telemetry envelope", id)
			return
		}
		batch := envelope.Batch
		if err := telemetry.ValidateNodeBatch(batch); err != nil {
			writeProblem(w, 400, "TELEMETRY_INVALID", "invalid telemetry batch", id)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		receipt, err := store.AcceptBatch(ctx, identity.ClusterID, identity.CollectorID, batch, envelope.GatewayReceiptID)
		if err != nil {
			writeTelemetryError(w, err, id)
			return
		}
		writeJSON(w, 200, receipt)
	})
	if retirement, ok := store.(RetirementIntake); ok {
		t.configureRetirement(retirement)
	}
	return nil
}
func (t *Transport) telemetryRequest(w http.ResponseWriter, r *http.Request) (AuthenticatedIdentity, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	id, ok := validateProtocol(w, r)
	if !ok {
		return AuthenticatedIdentity{}, id, false
	}
	if r.Header.Get("X-Sherlock-Telemetry-Version") != "1" {
		writeProblem(w, 426, "TELEMETRY_VERSION_UNSUPPORTED", "telemetry version 1 is required", id)
		return AuthenticatedIdentity{}, id, false
	}
	identity, ok := t.authenticate(w, r, id)
	if !ok {
		return identity, id, false
	}
	if r.URL.RawQuery != "" {
		writeProblem(w, 400, "TELEMETRY_INVALID", "query arguments are not supported", id)
		return identity, id, false
	}
	return identity, id, true
}
func readTelemetryBody(w http.ResponseWriter, r *http.Request, id string) ([]byte, bool) {
	encoding := r.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" {
		writeProblem(w, 415, "TELEMETRY_ENCODING_UNSUPPORTED", "identity encoding is required", id)
		return nil, false
	}
	if r.Header.Get("Content-Type") != "application/json" {
		writeProblem(w, 415, "TELEMETRY_MEDIA_UNSUPPORTED", "application/json is required", id)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, telemetry.MaxBatchBytes))
	if err != nil {
		writeProblem(w, 413, "TELEMETRY_BODY_LIMIT", "telemetry body unavailable or too large", id)
		return nil, false
	}
	return body, true
}

func writeTelemetryError(w http.ResponseWriter, err error, id string) {
	status, code := http.StatusServiceUnavailable, "TELEMETRY_UNAVAILABLE"
	switch {
	case errors.Is(err, telemetry.ErrInvalid):
		status, code = 400, "TELEMETRY_INVALID"
	case errors.Is(err, telemetry.ErrUnauthorized):
		status, code = 403, "TELEMETRY_UNAUTHORIZED"
	case errors.Is(err, telemetry.ErrConflict):
		status, code = 409, "TELEMETRY_CONFLICT"
	case errors.Is(err, telemetry.ErrBackpressure):
		status, code = 429, "TELEMETRY_BACKPRESSURE"
	case errors.Is(err, telemetry.ErrReplayExpired):
		status, code = 410, "TELEMETRY_REPLAY_EXPIRED"
	}
	writeProblem(w, status, code, "telemetry operation was not accepted", id)
}
