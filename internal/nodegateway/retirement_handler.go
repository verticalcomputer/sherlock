package nodegateway

import (
	"context"
	"net/http"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// RetirementIngress advertises only durably supported local/cloud retirement.
// Pending admission returns backpressure; it cannot impersonate a final receipt.
type RetirementIngress interface {
	RetirementCapabilities(context.Context, string) (telemetry.RetirementCapabilities, error)
	ReleaseOwnership(context.Context, telemetry.ReleaseEnvelope) (telemetry.GatewayRetirementReceipt, error)
	CompleteNodeRelease(context.Context, telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error)
}

func (h *Handler) configureRetirement(ingress RetirementIngress) {
	h.mux.HandleFunc("POST /node-telemetry/v1/retirement/capabilities", func(w http.ResponseWriter, r *http.Request) {
		principal, _, body, release, ok := h.retirementRequest(w, r)
		if !ok {
			return
		}
		defer release()
		var empty struct{}
		if telemetry.DecodeStrictJSON(body, "", &empty) != nil {
			problem(w, 400, "INVALID_INPUT")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		capability, err := ingress.RetirementCapabilities(ctx, principal.EnrollmentID)
		if err != nil {
			operationProblem(w, err)
			return
		}
		if telemetry.ValidateRetirementCapabilities(capability) != nil {
			problem(w, 503, "OWNERSHIP_UNAVAILABLE")
			return
		}
		respond(w, capability)
	})
	h.mux.HandleFunc("POST /node-telemetry/v1/retirement/releases", func(w http.ResponseWriter, r *http.Request) {
		principal, grant, body, release, ok := h.retirementRequest(w, r)
		if !ok {
			return
		}
		defer release()
		e, err := telemetry.DecodeReleaseEnvelope(body, "")
		if err != nil {
			problem(w, 400, "INVALID_INPUT")
			return
		}
		request := e.Request
		if request.ClusterID != principal.ClusterID || request.NodeID != principal.NodeID || request.EnrollmentID != principal.EnrollmentID || telemetry.ValidateReleaseForGrant(request, grant, h.authority.now()) != nil {
			problem(w, 403, "IDENTITY_REJECTED")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		receipt, err := ingress.ReleaseOwnership(ctx, e)
		if err != nil {
			operationProblem(w, err)
			return
		}
		if telemetry.ValidateGatewayRetirementReceipt(receipt) != nil || receipt.Binding != request.Binding() {
			problem(w, 503, "OWNERSHIP_UNAVAILABLE")
			return
		}
		respond(w, receipt)
	})
	h.mux.HandleFunc("POST /node-telemetry/v1/retirement/completions", func(w http.ResponseWriter, r *http.Request) {
		principal, grant, body, release, ok := h.retirementRequest(w, r)
		if !ok {
			return
		}
		defer release()
		var c telemetry.NodeReleaseCompletion
		if telemetry.DecodeStrictJSON(body, "", &c) != nil || telemetry.ValidateNodeReleaseCompletion(c) != nil {
			problem(w, 400, "INVALID_INPUT")
			return
		}
		if c.Binding.ClusterID != principal.ClusterID || c.Binding.NodeID != principal.NodeID || c.Binding.EnrollmentID != principal.EnrollmentID || telemetry.ValidateNodeCompletionForGrant(c, grant, h.authority.now()) != nil {
			problem(w, 403, "IDENTITY_REJECTED")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		receipt, err := ingress.CompleteNodeRelease(ctx, c)
		if err != nil {
			operationProblem(w, err)
			return
		}
		if telemetry.ValidateNodeCompletionReceipt(receipt) != nil || receipt.Binding != c.Binding || receipt.CompletionDigest != c.Digest || receipt.CloudFinalReceiptID != c.CloudFinalReceiptID || receipt.GatewayRetirementReceiptID != c.GatewayRetirementReceiptID {
			problem(w, 503, "OWNERSHIP_UNAVAILABLE")
			return
		}
		respond(w, receipt)
	})
}

func (h *Handler) retirementRequest(w http.ResponseWriter, r *http.Request) (Principal, telemetry.Grant, []byte, func(), bool) {
	release, ok := h.acquire(w, r)
	if !ok {
		return Principal{}, telemetry.Grant{}, nil, nil, false
	}
	if r.Header.Get("X-Sherlock-Release-Version") != "1" || len(r.Header.Values("X-Sherlock-Release-Version")) != 1 {
		release()
		problem(w, 426, "RETIREMENT_VERSION_UNSUPPORTED")
		return Principal{}, telemetry.Grant{}, nil, nil, false
	}
	p, g, body, releaseNode, ok := h.request(w, r, telemetry.MaxReleaseBytes)
	if !ok {
		release()
		return p, g, nil, nil, false
	}
	return p, g, body, func() { releaseNode(); release() }, true
}
