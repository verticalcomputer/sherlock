package collectorruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// These explicit methods leave the v1 runtime and its capability advertisement
// unchanged. Composition may adopt them only after durable typed ingestion and
// capability routing are enabled.
func (c *HTTPClient) ClaimTyped(ctx context.Context, claim ClaimRequest) (*domain.TypedWorkLease, error) {
	if err := domain.ValidateCollectionClaimSources(claim.SourceIDs); err != nil {
		return nil, err
	}
	query := url.Values{"wait_seconds": {strconv.Itoa(int(claim.Wait / time.Second))}}
	for _, source := range claim.SourceIDs {
		query.Add("source_id", string(source))
	}
	var wire collectorcontrol.TypedClaimResponse
	status, err := c.doV2(ctx, http.MethodGet, "/collector/v2/work/claim?"+query.Encode(), nil, &wire, 200, 204)
	if err != nil || status == 204 {
		return nil, err
	}
	p := wire.Plan
	if !slices.Contains(claim.SourceIDs, p.SourceID) {
		return nil, fmt.Errorf("typed claim source is not locally configured")
	}
	lease := domain.TypedWorkLease{Plan: p, Lease: domain.WorkLease{
		CollectorID: claim.CollectorID, Attempt: wire.Attempt, LeaseToken: wire.LeaseToken, LeaseExpires: wire.LeaseExpires,
		Work: domain.CollectorWork{WorkID: wire.WorkID, Status: domain.WorkLeased, AvailableAt: p.ScheduledFor, WorkExpiresAt: wire.WorkExpiresAt,
			Task: domain.CollectionTask{RunID: p.RunID, ClusterID: p.ClusterID, SourceID: p.SourceID, IdempotencyKey: p.IdempotencyKey}},
	}}
	if err := domain.ValidateTypedWorkLease(lease); err != nil {
		return nil, fmt.Errorf("invalid typed claim: %w", err)
	}
	return &lease, nil
}

func (c *HTTPClient) StartTyped(ctx context.Context, ref LeaseRef) error {
	_, err := c.doV2(ctx, http.MethodPost, typedLeasePath(ref, "/start"), leaseWire{LeaseToken: ref.LeaseToken}, nil, 204)
	return err
}

func (c *HTTPClient) RenewTyped(ctx context.Context, ref LeaseRef) (time.Time, error) {
	_, err := c.doV2(ctx, http.MethodPost, typedLeasePath(ref, "/renew"), leaseWire{LeaseToken: ref.LeaseToken, DurationSeconds: int(c.renewFor.Seconds())}, nil, 204)
	return time.Now().UTC().Add(c.renewFor), err
}

func (c *HTTPClient) SubmitTyped(ctx context.Context, ref LeaseRef, document domain.TypedCollectorResult) error {
	if document.WorkID != ref.WorkID || document.Attempt != ref.Attempt {
		return fmt.Errorf("typed result does not match request lease")
	}
	encoded, err := domain.EncodeTypedCollectorResult(document)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	body := collectorcontrol.TypedResultRequest{LeaseToken: ref.LeaseToken, Document: encoded, SHA256: hex.EncodeToString(digest[:])}
	_, err = c.doV2(ctx, http.MethodPost, typedLeasePath(ref, "/results"), body, nil, 200)
	return err
}

func typedLeasePath(ref LeaseRef, suffix string) string {
	return strings.Replace(leasePath(ref, suffix), "/collector/v1/", "/collector/v2/", 1)
}

func (c *HTTPClient) doV2(ctx context.Context, method, path string, body, output any, expected ...int) (int, error) {
	return c.doWithHeaders(ctx, method, path, body, output, map[string]string{protocolHeader: "2"}, expected...)
}
