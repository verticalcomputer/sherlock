package collectorruntime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestHTTPClientUploadsExactResultWireContract(t *testing.T) {
	payload := []byte(`{"schema_version":1}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/collector/v1/work/work-1/attempts/2/results/chunks/3" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get(protocolHeader) != "1" || r.Header.Get(correlationHeader) == "" {
			t.Error("protocol or correlation header missing")
		}
		var body struct {
			LeaseToken string `json:"lease_token"`
			Payload    string `json:"payload_base64"`
			SHA256     string `json:"sha256"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.LeaseToken != "secret" || body.Payload != base64.StdEncoding.EncodeToString(payload) || body.SHA256 != "digest" {
			t.Errorf("body = %+v", body)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	err = client.UploadChunk(context.Background(), ResultChunk{
		LeaseRef: LeaseRef{WorkID: "work-1", Attempt: 2, LeaseToken: "secret"}, Index: 3, Payload: payload, SHA256: "digest",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHTTPClientMapsClaimAndNoContent(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("wait_seconds") != "5" {
			t.Errorf("wait_seconds = %q", r.URL.Query().Get("wait_seconds"))
		}
		if calls == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(claimWire{
			WorkID: "work-1", Attempt: 1, LeaseToken: "token", LeaseExpires: now.Add(time.Minute), WorkExpiresAt: now.Add(time.Hour),
			Task: taskWire{RunID: "run-1", ClusterID: "cluster-1", SourceID: "source-1", QueryKind: string(domain.QuerySourceHealth), ScheduledFor: now, Deadline: now.Add(time.Minute), MaxSeries: 10, MaxBytes: 1024, IdempotencyKey: "key"},
		})
	}))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claim := ClaimRequest{CollectorID: "collector-1", Wait: 5 * time.Second}
	lease, err := client.Claim(context.Background(), claim)
	if err != nil || lease != nil {
		t.Fatalf("empty claim = %+v, %v", lease, err)
	}
	lease, err = client.Claim(context.Background(), claim)
	if err != nil || lease == nil || lease.Work.Task.RunID != "run-1" || lease.CollectorID != "collector-1" {
		t.Fatalf("claim = %+v, %v", lease, err)
	}
}

func TestHTTPClientClassifiesLeaseConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusConflict) }))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Start(context.Background(), LeaseRef{WorkID: "work-1", Attempt: 1, LeaseToken: "token"})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Start error = %v, want lease lost", err)
	}
}

func TestHTTPClientPreservesNamespacedWorkPath(t *testing.T) {
	const workID = "repair-work-attempt-m1/head-prometheus/dcgm_gpu_utilization"
	mux := http.NewServeMux()
	mux.HandleFunc("POST /collector/v1/work/{work_id}/attempts/{attempt}/start", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("work_id") != workID {
			t.Errorf("work ID changed: %q", r.PathValue("work_id"))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background(), LeaseRef{WorkID: workID, Attempt: 1, LeaseToken: "test"}); err != nil {
		t.Fatal(err)
	}
}
