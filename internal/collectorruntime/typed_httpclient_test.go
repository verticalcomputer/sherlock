package collectorruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestTypedHTTPClientClaimLeaseAndExactCanonicalSubmission(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	plan := domain.CollectionPlan{SchemaVersion: 2, RunID: "run-1", ClusterID: "cluster-1", SourceID: "slurm-1", SourceKind: domain.CollectionSourceSlurm, Operation: domain.OperationSlurmEvents, PayloadSchema: domain.CollectionEventsSchema, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}}, Cursor: "initial", ScheduledFor: now, Deadline: now.Add(time.Minute), Limits: domain.CollectionLimits{MaxRecords: 10, MaxBytes: 100000}, IdempotencyKey: "key-1"}
	claim := collectorcontrol.TypedClaimResponse{WorkID: "work-1", Attempt: 2, LeaseToken: strings.Repeat("a", 32), LeaseExpires: plan.Deadline, WorkExpiresAt: plan.Deadline, Plan: plan}
	result := domain.TypedCollectorResult{SchemaVersion: 2, WorkID: claim.WorkID, Attempt: claim.Attempt, Plan: plan, Status: domain.ResultNoData, StartedAt: now, CompletedAt: plan.Deadline,
		Coverage: domain.SourceCoverage{SchemaVersion: 1, ClusterID: plan.ClusterID, SourceID: plan.SourceID, Scope: domain.CoverageEvents, State: domain.SourceCoverageUnknown, SourceAt: now, EffectiveAt: now, ObservedAt: plan.Deadline}, Payload: domain.CollectionPayload{Kind: domain.CollectionPayloadEvents, Events: &domain.CollectionEventsPayload{Events: []domain.CollectionEvent{}}}, NextCursor: "next"}
	claims, submissions := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(protocolHeader) != "2" || r.Header.Get(correlationHeader) == "" {
			t.Error("missing v2 headers")
		}
		switch {
		case r.URL.Path == "/collector/v2/work/claim":
			if r.URL.Query().Get("source_id") != "slurm-1" {
				t.Error("configured source filter was not sent")
			}
			claims++
			if claims == 1 {
				w.WriteHeader(204)
				return
			}
			_ = json.NewEncoder(w).Encode(claim)
		case strings.HasSuffix(r.URL.Path, "/start"), strings.HasSuffix(r.URL.Path, "/renew"):
			if !strings.HasPrefix(r.URL.Path, "/collector/v2/work/work-1/attempts/2/") {
				t.Errorf("wrong lease path: %s", r.URL.Path)
			}
			w.WriteHeader(204)
		case r.URL.Path == "/collector/v2/work/work-1/attempts/2/results":
			var body collectorcontrol.TypedResultRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			digest := sha256.Sum256(body.Document)
			if body.SHA256 != hex.EncodeToString(digest[:]) || body.LeaseToken != claim.LeaseToken {
				t.Error("canonical checksum or lease token changed")
			}
			decoded, err := domain.DecodeTypedCollectorResult(body.Document)
			if err != nil || decoded.Payload.Kind != domain.CollectionPayloadEvents {
				t.Errorf("document: %v", err)
			}
			submissions++
			w.WriteHeader(200)
		default:
			t.Errorf("unexpected route: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := ClaimRequest{CollectorID: "collector-1", Wait: 0, SourceIDs: []domain.SourceID{"slurm-1"}}
	if lease, err := client.ClaimTyped(context.Background(), req); err != nil || lease != nil {
		t.Fatalf("no work: %v %v", lease, err)
	}
	lease, err := client.ClaimTyped(context.Background(), req)
	if err != nil || lease.Plan.Operation != plan.Operation {
		t.Fatalf("typed claim: %v", err)
	}
	ref := LeaseRef{WorkID: claim.WorkID, Attempt: claim.Attempt, LeaseToken: claim.LeaseToken}
	if err := client.StartTyped(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RenewTyped(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if err := client.SubmitTyped(context.Background(), ref, result); err != nil {
		t.Fatal(err)
	}
	if submissions != 1 {
		t.Fatal("result was not submitted")
	}
	result.Attempt++
	if err := client.SubmitTyped(context.Background(), ref, result); err == nil || submissions != 1 {
		t.Fatal("mismatched attempt reached transport")
	}
	claim.Plan.SchemaVersion = 99
	if _, err := client.ClaimTyped(context.Background(), req); err == nil {
		t.Fatal("unknown plan version accepted")
	}
}
