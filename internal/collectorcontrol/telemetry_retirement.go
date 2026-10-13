package collectorcontrol

import (
	"context"
	"io"
	"net/http"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// RetirementIntake is an additive ownership protocol. Older telemetry stores
// retain their existing routes and cannot advertise retirement capability.
type RetirementIntake interface {
	RetirementCapabilities(context.Context, domain.ClusterID, domain.CollectorID, string) (telemetry.RetirementCapabilities, error)
	PrepareRetirement(context.Context, domain.ClusterID, domain.CollectorID, telemetry.ReleaseRequest, telemetry.ReleaseManifest, telemetry.ReleaseAdmissionReceipt) (telemetry.CloudRetirementReceipt, error)
	CommitRetirement(context.Context, domain.ClusterID, domain.CollectorID, telemetry.ReleaseRequest, telemetry.GatewayReleaseCommit) (telemetry.CloudRetirementReceipt, error)
	CompleteRetirement(context.Context, domain.ClusterID, domain.CollectorID, telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error)
}

func (t *Transport) configureRetirement(store RetirementIntake) {
	t.mux.HandleFunc("GET /collector/telemetry/v1/enrollments/{enrollment_id}/retirement-capabilities", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.retirementRequest(w, r)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		capability, err := store.RetirementCapabilities(ctx, identity.ClusterID, identity.CollectorID, r.PathValue("enrollment_id"))
		if err != nil {
			writeTelemetryError(w, err, id)
			return
		}
		if telemetry.ValidateRetirementCapabilities(capability) != nil {
			writeTelemetryError(w, telemetry.ErrUnavailable, id)
			return
		}
		writeJSON(w, 200, capability)
	})
	t.mux.HandleFunc("POST /collector/telemetry/v1/retirement/prepare", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.retirementRequest(w, r)
		if !ok {
			return
		}
		body, ok := readRetirementBody(w, r, id)
		if !ok {
			return
		}
		var e telemetry.ReleasePrepareEnvelope
		if telemetry.DecodeStrictJSON(body, "", &e) != nil || telemetry.ValidateReleaseEnvelope(e.Release) != nil || telemetry.ValidateReleaseAdmissionReceipt(e.Admission) != nil || e.Admission.Binding != e.Release.Request.Binding() {
			writeTelemetryError(w, telemetry.ErrInvalid, id)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		receipt, err := store.PrepareRetirement(ctx, identity.ClusterID, identity.CollectorID, e.Release.Request, e.Release.Manifest, e.Admission)
		if err != nil {
			writeTelemetryError(w, err, id)
			return
		}
		if telemetry.ValidateCloudRetirementReceipt(receipt) != nil || receipt.Phase != "PREPARED" || receipt.Binding != e.Release.Request.Binding() || receipt.GatewayAdmissionID != e.Admission.ID {
			writeTelemetryError(w, telemetry.ErrUnavailable, id)
			return
		}
		writeJSON(w, 200, receipt)
	})
	t.mux.HandleFunc("POST /collector/telemetry/v1/retirement/commit", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.retirementRequest(w, r)
		if !ok {
			return
		}
		body, ok := readRetirementBody(w, r, id)
		if !ok {
			return
		}
		var e telemetry.ReleaseCommitEnvelope
		if telemetry.DecodeStrictJSON(body, "", &e) != nil || telemetry.ValidateReleaseRequest(e.Request) != nil || telemetry.ValidateGatewayReleaseCommit(e.Commit) != nil || e.Request.Binding() != e.Commit.Binding {
			writeTelemetryError(w, telemetry.ErrInvalid, id)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		receipt, err := store.CommitRetirement(ctx, identity.ClusterID, identity.CollectorID, e.Request, e.Commit)
		if err != nil {
			writeTelemetryError(w, err, id)
			return
		}
		if telemetry.ValidateCloudRetirementReceipt(receipt) != nil || receipt.Phase != "FINAL" || receipt.Binding != e.Commit.Binding || receipt.GatewayAdmissionID != e.Commit.GatewayAdmissionID || receipt.PreparedReceiptID != e.Commit.PreparedReceiptID || receipt.GatewayCommitID != e.Commit.ID {
			writeTelemetryError(w, telemetry.ErrUnavailable, id)
			return
		}
		writeJSON(w, 200, receipt)
	})
	t.mux.HandleFunc("POST /collector/telemetry/v1/retirement/complete", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.retirementRequest(w, r)
		if !ok {
			return
		}
		body, ok := readRetirementBody(w, r, id)
		if !ok {
			return
		}
		var c telemetry.NodeReleaseCompletion
		if telemetry.DecodeStrictJSON(body, "", &c) != nil || telemetry.ValidateNodeReleaseCompletion(c) != nil {
			writeTelemetryError(w, telemetry.ErrInvalid, id)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		receipt, err := store.CompleteRetirement(ctx, identity.ClusterID, identity.CollectorID, c)
		if err != nil {
			writeTelemetryError(w, err, id)
			return
		}
		if telemetry.ValidateNodeCompletionReceipt(receipt) != nil || receipt.Binding != c.Binding || receipt.CompletionDigest != c.Digest || receipt.CloudFinalReceiptID != c.CloudFinalReceiptID || receipt.GatewayRetirementReceiptID != c.GatewayRetirementReceiptID {
			writeTelemetryError(w, telemetry.ErrUnavailable, id)
			return
		}
		writeJSON(w, 200, receipt)
	})
}

func (t *Transport) retirementRequest(w http.ResponseWriter, r *http.Request) (AuthenticatedIdentity, string, bool) {
	identity, id, ok := t.telemetryRequest(w, r)
	if !ok {
		return identity, id, false
	}
	if r.Header.Get("X-Sherlock-Release-Version") != "1" || len(r.Header.Values("X-Sherlock-Release-Version")) != 1 {
		writeProblem(w, 426, "RETIREMENT_VERSION_UNSUPPORTED", "retirement version 1 is required", id)
		return identity, id, false
	}
	return identity, id, true
}

func readRetirementBody(w http.ResponseWriter, r *http.Request, id string) ([]byte, bool) {
	encoding := r.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" || r.Header.Get("Content-Type") != "application/json" {
		writeProblem(w, 415, "TELEMETRY_MEDIA_UNSUPPORTED", "identity application/json is required", id)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, telemetry.MaxReleaseBytes))
	if err != nil {
		writeProblem(w, 413, "TELEMETRY_BODY_LIMIT", "retirement body unavailable or too large", id)
		return nil, false
	}
	return body, true
}
