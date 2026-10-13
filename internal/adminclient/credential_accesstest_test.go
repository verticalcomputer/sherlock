package adminclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminui"
)

func TestClientCredentialAccessTestsPassActorAndDecodeStrictly(t *testing.T) {
	var seen []string
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.Method+" "+request.URL.Path+" subject="+request.Header.Get("X-Sherlock-Access-Subject"))
		if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 40) {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(request.Body)
		if len(raw) > 0 {
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			bodies = append(bodies, body)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet:
			_, _ = writer.Write([]byte(`{"tests":[{"test_id":"ctest_1","cluster_id":"cluster-1","credential_id":"cred_1","credential_version":2,"host":"head-1","purpose":"BCM_READ_ONLY","username":"fixture_user_1","status":"SUCCEEDED","requested_by":"access-a","requested_at":"2026-09-21T10:00:00Z","deadline":"2026-09-21T10:15:00Z","attempt":1,"collector_id":"head","outcome_code":"BCM_ACCESS_VERIFIED","outcome_summary":"ok","bcm_version":"10.24","devices_listed":3,"completed_at":"2026-09-21T10:01:00Z","credential_current":false,"credential_status":"REVOKED"}]}`))
		case strings.HasSuffix(request.URL.Path, "/cancel"):
			writer.WriteHeader(http.StatusNoContent)
		default:
			_, _ = writer.Write([]byte(`{"test_id":"ctest_2","cluster_id":"cluster-1","credential_id":"cred_1","credential_version":2,"host":"head-1","purpose":"BCM_READ_ONLY","username":"fixture_user_1","status":"REQUESTED","requested_by":"access-a","requested_at":"2026-09-21T10:00:00Z","deadline":"2026-09-21T10:15:00Z","attempt":0,"devices_listed":0,"credential_current":true,"credential_status":"ACTIVE"}`))
		}
	}))
	defer server.Close()
	client, err := New(server.URL, []byte(strings.Repeat("t", 40)), &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	mutation := adminui.MutationContext{SessionFingerprint: make([]byte, 32), RequestID: "request-1", OccurredAt: time.Now().UTC(), ActorSubject: "access-a"}
	tests, err := client.ListCredentialAccessTests(context.Background(), "cluster-1", "access-a")
	if err != nil || len(tests) != 1 || tests[0].Verified() || tests[0].Status != "SUCCEEDED" || tests[0].CredentialCurrent || tests[0].DevicesListed != 3 {
		t.Fatalf("list: %v %+v", err, tests)
	}
	requested, err := client.RequestCredentialAccessTest(context.Background(), "cluster-1", "access-a", "cred_1", 2, mutation)
	if err != nil || requested.ID != "ctest_2" || !requested.Pending() {
		t.Fatalf("request: %v %+v", err, requested)
	}
	if err := client.CancelCredentialAccessTest(context.Background(), "cluster-1", "access-a", "ctest_2", mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RequestCredentialAccessTest(context.Background(), "cluster-1", "access-a", "cred_1", 0, mutation); err == nil {
		t.Fatal("zero version must be rejected before any request")
	}
	if _, err := client.ListCredentialAccessTests(context.Background(), "cluster-1", ""); err == nil {
		t.Fatal("empty subject must be rejected before any request")
	}
	want := []string{
		"GET /internal/admin/v1/clusters/cluster-1/credential-access-tests subject=access-a",
		"POST /internal/admin/v1/clusters/cluster-1/credentials/cred_1/access-tests subject=",
		"POST /internal/admin/v1/clusters/cluster-1/credential-access-tests/ctest_2/cancel subject=",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s", strings.Join(seen, "\n"))
	}
	if len(bodies) != 2 || bodies[0]["actor_subject"] != "access-a" || bodies[0]["expected_version"] != float64(2) || bodies[1]["actor_subject"] != "access-a" {
		t.Fatalf("bodies: %+v", bodies)
	}
}

func TestClientCredentialInventoryDiscoveryRoutesAndNotFound(t *testing.T) {
	var seen []string
	missing := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.Method+" "+request.URL.Path+" subject="+request.Header.Get("X-Sherlock-Access-Subject"))
		if request.Method == http.MethodGet && missing {
			writer.Header().Set("Content-Type", "application/problem+json")
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte(`{"code":"NOT_FOUND"}`))
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet {
			_, _ = writer.Write([]byte(`{"test_id":"ctest_inv","cluster_id":"cluster-1","credential_id":"cred_1","credential_version":2,"host":"head-1","bcm_version":"10.24","completed_at":"2026-09-21T10:01:00Z","credential_current":true,"devices":[{"type":"headnode","hostname":"head-1","status":"UP"},{"type":"physicalnode","hostname":"node001","status":"DOWN"}]}`))
			return
		}
		_, _ = writer.Write([]byte(`{"test_id":"ctest_inv","cluster_id":"cluster-1","credential_id":"cred_1","credential_version":2,"host":"head-1","purpose":"BCM_READ_ONLY","username":"fixture_user_1","operation":"bcm.inventory_discovery.v1","status":"REQUESTED","requested_by":"access-a","requested_at":"2026-09-21T10:00:00Z","deadline":"2026-09-21T10:15:00Z","attempt":0,"devices_listed":0,"credential_current":true,"credential_status":"ACTIVE"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, []byte(strings.Repeat("t", 40)), &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	mutation := adminui.MutationContext{SessionFingerprint: make([]byte, 32), RequestID: "request-1", OccurredAt: time.Now().UTC(), ActorSubject: "access-a"}
	requested, err := client.RequestCredentialInventoryDiscovery(context.Background(), "cluster-1", "access-a", "cred_1", 2, mutation)
	if err != nil || requested.ID != "ctest_inv" || requested.Operation != adminui.CredentialInventoryDiscoveryOperation || !requested.Pending() {
		t.Fatalf("request: %v %+v", err, requested)
	}
	if _, err := client.RequestCredentialInventoryDiscovery(context.Background(), "cluster-1", "access-a", "cred_1", 0, mutation); err == nil {
		t.Fatal("zero version must be rejected before any request")
	}
	if _, err := client.RequestCredentialInventoryDiscovery(context.Background(), "cluster-1", "", "cred_1", 2, mutation); err == nil {
		t.Fatal("missing actor must be rejected before any request")
	}
	latest, found, err := client.LatestInventoryDiscovery(context.Background(), "cluster-1", "access-a")
	if err != nil || !found || latest.TestID != "ctest_inv" || len(latest.Devices) != 2 || latest.Devices[1].Hostname != "node001" || latest.Devices[1].Status != "DOWN" || !latest.CredentialCurrent {
		t.Fatalf("latest: %v found=%v %+v", err, found, latest)
	}
	missing = true
	if _, found, err := client.LatestInventoryDiscovery(context.Background(), "cluster-1", "access-a"); err != nil || found {
		t.Fatalf("absent discovery must be a clean miss: found=%v err=%v", found, err)
	}
	if _, _, err := client.LatestInventoryDiscovery(context.Background(), "cluster-1", ""); err == nil {
		t.Fatal("missing actor must be rejected before any request")
	}
	for _, want := range []string{
		"POST /internal/admin/v1/clusters/cluster-1/credentials/cred_1/inventory-discoveries subject=",
		"GET /internal/admin/v1/clusters/cluster-1/inventory-discovery/latest subject=access-a",
	} {
		if !strings.Contains(strings.Join(seen, "\n"), want) {
			t.Fatalf("missing request %q in %v", want, seen)
		}
	}
}
