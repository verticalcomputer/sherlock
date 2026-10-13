package nodegateway

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type retirementFlowIngress struct {
	*flowIngress
	pending, foreign bool
	retirementCalls  int
}

func (f *retirementFlowIngress) RetirementCapabilities(context.Context, string) (telemetry.RetirementCapabilities, error) {
	f.retirementCalls++
	return telemetry.SupportedRetirementCapabilities(), nil
}
func (f *retirementFlowIngress) ReleaseOwnership(_ context.Context, e telemetry.ReleaseEnvelope) (telemetry.GatewayRetirementReceipt, error) {
	f.retirementCalls++
	if f.pending {
		return telemetry.GatewayRetirementReceipt{}, telemetry.ErrBackpressure
	}
	b := e.Request.Binding()
	if f.foreign {
		b.SessionID = "foreign"
	}
	cloud := telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "cloud-final", Phase: "FINAL", Binding: b, GatewayAdmissionID: "admission", PreparedReceiptID: "prepared", GatewayCommitID: "commit", StoredAt: e.Request.CreatedAt, Durability: "CLOUD"}
	id, err := telemetry.GatewayRetirementReceiptID(cloud)
	if err != nil {
		return telemetry.GatewayRetirementReceipt{}, err
	}
	return telemetry.GatewayRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: id, Binding: b, GatewayAdmissionID: "admission", PreparedReceiptID: "prepared", GatewayCommitID: "commit", CloudFinalReceipt: cloud, StoredAt: e.Request.CreatedAt, Durability: "GATEWAY"}, nil
}
func (f *retirementFlowIngress) CompleteNodeRelease(_ context.Context, c telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error) {
	f.retirementCalls++
	if f.pending {
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrBackpressure
	}
	b := c.Binding
	if f.foreign {
		b.SessionID = "foreign"
	}
	return telemetry.NodeCompletionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "cloud-completion", Binding: b, CompletionDigest: c.Digest, CloudFinalReceiptID: c.CloudFinalReceiptID, GatewayRetirementReceiptID: c.GatewayRetirementReceiptID, StoredAt: c.CreatedAt, Durability: "CLOUD"}, nil
}
func retirementTLSFixture(t *testing.T) (*tlsFlow, *retirementFlowIngress, *Client, telemetry.ReleaseEnvelope) {
	t.Helper()
	f := newTLSFlow(t)
	f.server.Close()
	ingress := &retirementFlowIngress{flowIngress: f.ingress}
	a, err := NewAuthority(f.grant.ClusterID, f.grant.GatewayCollectorID, f.pin, []string{f.grant.EnrollmentID}, loaderFunc(func(context.Context, string) (telemetry.Grant, error) { return f.grant, nil }))
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(a, ingress)
	if err != nil {
		t.Fatal(err)
	}
	config, _, err := ServerTLSConfig(f.serverIdentity, f.nodeCA.pool)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.TLS = config
	server.StartTLS()
	t.Cleanup(server.Close)
	f.server = server
	client, err := NewClient(server.URL, f.identity, f.serverCA.pool, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	_, b, _ := f.signed(t)
	m := telemetry.ReleaseManifest{Batches: []telemetry.ReleaseBatchFact{{Sequence: "1", Digest: b.Digest, GatewayReceiptID: "batch-receipt"}}}
	d, err := telemetry.CanonicalReleaseManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	r := telemetry.ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: "release", ClusterID: b.Key.ClusterID, NodeID: b.Key.NodeID, EnrollmentID: b.Key.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: b.Key.SessionEpoch, SessionID: b.Key.SessionID, SigningKeyID: b.SigningKeyID, CreatedAt: time.Now().UTC(), FromSequence: "1", ThroughSequence: "1", ManifestDigest: hex.EncodeToString(d[:])}
	if err := telemetry.SignReleaseRequest(&r, f.nodeKey); err != nil {
		t.Fatal(err)
	}
	return f, ingress, client, telemetry.ReleaseEnvelope{Request: r, Manifest: m}
}
func TestTLSRetirementPendingIsNotFinalAndForeignProofCannotRelease(t *testing.T) {
	f, ingress, client, e := retirementTLSFixture(t)
	if _, err := client.RetirementCapabilities(context.Background()); err != nil {
		t.Fatal(err)
	}
	ingress.pending = true
	if _, err := client.ReleaseOwnership(context.Background(), e); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("pending returned ownership", err)
	}
	ingress.pending = false
	final, err := client.ReleaseOwnership(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	c := telemetry.NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: "completion", Binding: e.Request.Binding(), CloudFinalReceiptID: final.CloudFinalReceipt.ID, GatewayRetirementReceiptID: final.ID, SigningKeyID: e.Request.SigningKeyID, CreatedAt: e.Request.CreatedAt}
	if err := telemetry.SignNodeCompletion(&c, f.nodeKey); err != nil {
		t.Fatal(err)
	}
	ingress.pending = true
	if _, err := client.CompleteNodeRelease(context.Background(), c); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("pending completion acknowledged", err)
	}
	ingress.pending = false
	if _, err := client.CompleteNodeRelease(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	ingress.foreign = true
	if _, err := client.ReleaseOwnership(context.Background(), e); err == nil {
		t.Fatal("foreign gateway proof accepted")
	}
	if _, err := client.CompleteNodeRelease(context.Background(), c); err == nil {
		t.Fatal("foreign completion accepted")
	}
	prior := ingress.retirementCalls
	e.Request.Signature = strings.Repeat("A", 86)
	if _, err := client.ReleaseOwnership(context.Background(), e); err == nil || ingress.retirementCalls != prior {
		t.Fatal("bad signature reached ingress", err)
	}
}
func TestTLSRetirementVersionAndIdentityFencesPrecedeIngress(t *testing.T) {
	f, ingress, _, e := retirementTLSFixture(t)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.serverCA.pool, Certificates: []tls.Certificate{f.identity}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, tc := range []struct {
		name    string
		edit    func(*http.Request)
		foreign bool
		code    int
	}{
		{"missing-version", func(r *http.Request) { r.Header.Del("X-Sherlock-Release-Version") }, false, 426},
		{"duplicate-version", func(r *http.Request) { r.Header.Add("X-Sherlock-Release-Version", "1") }, false, 426},
		{"foreign-node", nil, true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := e
			if tc.foreign {
				value.Request.NodeID = "foreign"
				if err := telemetry.SignReleaseRequest(&value.Request, f.nodeKey); err != nil {
					t.Fatal(err)
				}
			}
			body, _ := json.Marshal(value)
			request, err := http.NewRequest("POST", f.server.URL+"/node-telemetry/v1/retirement/releases", strings.NewReader(string(body)))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Sherlock-Telemetry-Version", "1")
			request.Header.Set("X-Sherlock-Release-Version", "1")
			if tc.edit != nil {
				tc.edit(request)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.code || ingress.retirementCalls != 0 {
				t.Fatal("fence admitted request", response.StatusCode, ingress.retirementCalls)
			}
		})
	}
}
