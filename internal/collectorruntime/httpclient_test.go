package collectorruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/servicefailure"
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

func TestHTTPClientClassifiesAuthenticationWithoutRetrying(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) }))
		client, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Claim(context.Background(), ClaimRequest{CollectorID: "collector", Wait: time.Second})
		server.Close()
		if !errors.Is(err, ErrAuthentication) || calls != 1 {
			t.Fatalf("status=%d calls=%d err=%v", status, calls, err)
		}
	}
}

// A peer rejecting our client identity reports a remote alert rather than a
// local x509 verification error. Exercise actual handshakes in both TLS lanes,
// including the TLS1.3 post-handshake read where no exported AlertError exists.
func TestHTTPClientClassifiesRealPeerMTLSRejection(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("TLS%d/missing=%t", version, missing), func(t *testing.T) {
				caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-client-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
				caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
				if err != nil {
					t.Fatal(err)
				}
				issuer, err := x509.ParseCertificate(caDER)
				if err != nil {
					t.Fatal(err)
				}
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				// Valid dates and issuer, deliberately wrong EKU for client authentication.
				leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "wrong-client-purpose"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
				leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, public, caPrivate)
				if err != nil {
					t.Fatal(err)
				}
				pool := x509.NewCertPool()
				pool.AddCert(issuer)
				var requests, connections atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusNoContent) }))
				server.Config.ErrorLog = log.New(io.Discard, "", 0)
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				server.TLS = &tls.Config{MinVersion: version, MaxVersion: version, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
				server.StartTLS()
				defer server.Close()
				httpClient := server.Client()
				transport := httpClient.Transport.(*http.Transport).Clone()
				transport.TLSClientConfig = transport.TLSClientConfig.Clone()
				transport.TLSClientConfig.MinVersion = version
				transport.TLSClientConfig.MaxVersion = version
				if !missing {
					transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: private}}
				}
				httpClient.Transport = transport
				httpClient.Timeout = 3 * time.Second
				defer transport.CloseIdleConnections()
				client, err := NewHTTPClient(server.URL, httpClient, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				err = client.Heartbeat(context.Background(), Heartbeat{CollectorID: "fixture"})
				if missing && version == tls.VersionTLS12 {
					// TLS1.2 reports only the ambiguous handshake_failure alert for
					// no client cert. Do not classify every handshake failure as
					// authentication: it can also signal a transient peer issue.
					if err == nil || servicefailure.Permanent(err) {
						t.Fatalf("ambiguous TLS1.2 failure classified permanent: %v", err)
					}
					if requests.Load() != 0 || connections.Load() != 1 {
						t.Fatalf("unexpected retry/handler: %d/%d", connections.Load(), requests.Load())
					}
					return
				}
				if !errors.Is(err, ErrAuthentication) || !servicefailure.Permanent(err) {
					t.Fatalf("peer certificate rejection not permanent auth: %T %v", err, err)
				}
				if requests.Load() != 0 || connections.Load() != 1 {
					t.Fatalf("rejected identity reachedhandler/retried: requests=%d connections=%d", requests.Load(), connections.Load())
				}
			})
		}
	}
}
