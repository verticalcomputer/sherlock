package collectorcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// TypedCollectionOperations extends the existing durable work authority.
// Implementations MUST claim the same work/attempt rows used by WorkLeaseOperations,
// authenticate cluster/collector/lease, bind the result to the stored plan with
// ValidateTypedResultForLease, and commit all facts and replay identity atomically.
// There is deliberately no in-memory fallback or v1 result translation.
type TypedCollectionOperations interface {
	ClaimTypedWork(context.Context, domain.ClusterID, domain.CollectorID, string, time.Duration, []domain.SourceID) (domain.TypedWorkLease, bool, error)
	SubmitTypedResult(context.Context, domain.ClusterID, domain.CollectorID, LeaseRef, domain.TypedCollectorResult, string) (FinalizeOutcome, error)
}

// ConfigureTypedCollection must run before serving requests. Persistence and
// collector capability selection are separate rollout gates (GP-03c/GP-03d).
func (t *Transport) ConfigureTypedCollection(operations TypedCollectionOperations) error {
	if t == nil || operations == nil || t.typedWork != nil {
		return fmt.Errorf("typed collection operations are missing or already configured")
	}
	t.typedWork = operations
	return nil
}

// TypedClaimResponse is shared by control and runtime to prevent wire drift.
type TypedClaimResponse struct {
	WorkID        domain.WorkID         `json:"work_id"`
	Attempt       int                   `json:"attempt"`
	LeaseToken    string                `json:"lease_token"`
	LeaseExpires  time.Time             `json:"lease_expires_at"`
	WorkExpiresAt time.Time             `json:"work_expires_at"`
	Plan          domain.CollectionPlan `json:"plan"`
}

type TypedResultRequest struct {
	LeaseToken string          `json:"lease_token"`
	Document   json.RawMessage `json:"document"`
	SHA256     string          `json:"sha256"`
}

func (t *Transport) typedAvailable(w http.ResponseWriter, correlationID string) bool {
	if t.typedWork == nil {
		writeProblem(w, http.StatusServiceUnavailable, "TYPED_COLLECTION_UNAVAILABLE", "typed collection is not configured", correlationID)
		return false
	}
	return true
}

func (t *Transport) claimTypedWork(w http.ResponseWriter, r *http.Request) {
	id, ok := validateProtocolVersion(w, r, domain.CollectionProtocolVersion)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, id)
	if !ok {
		return
	}
	if !t.typedAvailable(w, id) {
		return
	}
	sources := make([]domain.SourceID, 0, len(r.URL.Query()["source_id"]))
	for _, source := range r.URL.Query()["source_id"] {
		sources = append(sources, domain.SourceID(source))
	}
	if err := domain.ValidateCollectionClaimSources(sources); err != nil {
		writeProblem(w, 400, "INVALID_ARGUMENT", "typed claim requires bounded configured source identifiers", id)
		return
	}
	wait, err := parseWait(r.URL.Query().Get("wait_seconds"))
	if err != nil {
		writeProblem(w, 400, "INVALID_ARGUMENT", "wait_seconds is invalid", id)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wait+defaultRequestTimeout)
	defer cancel()
	deadline := t.clock.Now().Add(wait)
	for {
		token, err := t.randomToken()
		if err != nil {
			writeOperationError(w, err, id)
			return
		}
		lease, found, err := t.typedWork.ClaimTypedWork(ctx, identity.ClusterID, identity.CollectorID, token, defaultLeaseDuration, sources)
		if err != nil {
			writeOperationError(w, err, id)
			return
		}
		if found {
			if err := domain.ValidateTypedWorkLease(lease); err != nil || lease.Plan.ClusterID != identity.ClusterID || lease.Lease.CollectorID != identity.CollectorID || lease.Lease.LeaseToken != token || !slices.Contains(sources, lease.Plan.SourceID) {
				writeOperationError(w, ErrWorkLeaseInvalid, id)
				return
			}
			writeJSON(w, 200, TypedClaimResponse{WorkID: lease.Lease.Work.WorkID, Attempt: lease.Lease.Attempt, LeaseToken: token, LeaseExpires: lease.Lease.LeaseExpires.UTC(), WorkExpiresAt: lease.Lease.Work.WorkExpiresAt.UTC(), Plan: lease.Plan})
			return
		}
		remaining := deadline.Sub(t.clock.Now())
		if remaining <= 0 {
			w.WriteHeader(204)
			return
		}
		pause := min(remaining, longPollInterval)
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			writeOperationError(w, ctx.Err(), id)
			return
		case <-timer.C:
		}
	}
}

func (t *Transport) typedLease(renew bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.withLeaseVersion(w, r, renew, domain.CollectionProtocolVersion)
	}
}

func (t *Transport) submitTypedResult(w http.ResponseWriter, r *http.Request) {
	id, ok := validateProtocolVersion(w, r, domain.CollectionProtocolVersion)
	if !ok {
		return
	}
	identity, ok := t.authenticate(w, r, id)
	if !ok {
		return
	}
	if !t.typedAvailable(w, id) {
		return
	}
	ref, ok := resultPathReference(w, r, id)
	if !ok {
		return
	}
	var body TypedResultRequest
	if !decodeJSONLimit(w, r, &body, (10<<20)+4096) || len(body.LeaseToken) < 32 || len(body.LeaseToken) > 256 {
		writeProblem(w, 400, "INVALID_ARGUMENT", "typed result request is invalid", id)
		return
	}
	document, err := domain.DecodeTypedCollectorResult(body.Document)
	digest := sha256.Sum256(body.Document)
	if err != nil || body.SHA256 != hex.EncodeToString(digest[:]) || document.WorkID != ref.WorkID || document.Attempt != ref.Attempt || document.Plan.ClusterID != identity.ClusterID {
		writeProblem(w, 400, "INVALID_ARGUMENT", "typed result identity, schema, or checksum is invalid", id)
		return
	}
	ref.LeaseToken = body.LeaseToken
	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()
	outcome, err := t.typedWork.SubmitTypedResult(ctx, identity.ClusterID, identity.CollectorID, ref, document, body.SHA256)
	if err != nil {
		writeOperationError(w, err, id)
		return
	}
	writeJSON(w, 200, resultFinalizationResponseDTO{RunID: string(outcome.RunID), Status: string(outcome.Status), SHA256: outcome.SHA256, PreviouslyFinalized: outcome.PreviouslyFinalized})
}
