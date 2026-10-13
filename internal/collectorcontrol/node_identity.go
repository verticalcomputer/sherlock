package collectorcontrol

import (
	"context"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"net/http"
)

type NodeIdentityIntake interface {
	ConsumeNodeBootstrap(context.Context, domain.ClusterID, domain.CollectorID, string, nodeidentity.Request, *nodeidentity.Issuer) (nodeidentity.CertificateBundle, error)
}

// ConfigureNodeIdentity adds only the authenticated head-relay route. A nil
// issuer denies new issuance while committed historical bundle retrieval may
// still succeed after current authority checks. No token mint route is exposed.
func (t *Transport) ConfigureNodeIdentity(store NodeIdentityIntake, issuer *nodeidentity.Issuer) error {
	if store == nil {
		return telemetry.ErrInvalid
	}
	t.mux.HandleFunc("POST /collector/telemetry/v1/node-certificates", func(w http.ResponseWriter, r *http.Request) {
		identity, id, ok := t.telemetryRequest(w, r)
		if !ok {
			return
		}
		body, ok := readTelemetryBody(w, r, id)
		if !ok {
			return
		}
		if len(body) > nodeidentity.MaxRequestBytes+512 {
			writeTelemetryError(w, telemetry.ErrInvalid, id)
			return
		}
		var envelope struct {
			Token   string               `json:"token"`
			Request nodeidentity.Request `json:"request"`
		}
		if telemetry.DecodeStrictJSON(body, "", &envelope) != nil {
			writeTelemetryError(w, telemetry.ErrInvalid, id)
			return
		}
		if _, e := nodeidentity.BootstrapTokenHash(envelope.Token); e != nil {
			writeTelemetryError(w, telemetry.ErrInvalid, id)
			return
		}
		if _, e := nodeidentity.ValidateRequest(envelope.Request); e != nil {
			writeTelemetryError(w, telemetry.ErrInvalid, id)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		bundle, e := store.ConsumeNodeBootstrap(ctx, identity.ClusterID, identity.CollectorID, envelope.Token, envelope.Request, issuer)
		if e != nil {
			writeTelemetryError(w, e, id)
			return
		}
		// Store implementations may not substitute a different committed binding.
		if bundle.ProtocolVersion != 1 || bundle.Scope != envelope.Request.Scope || bundle.CSRSHA256 != envelope.Request.CSRSHA256 || bundle.SPKISHA256 != envelope.Request.SPKISHA256 || bundle.IssuedAt.IsZero() || bundle.NotAfter.IsZero() {
			writeTelemetryError(w, telemetry.ErrUnavailable, id)
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	})
	return nil
}
