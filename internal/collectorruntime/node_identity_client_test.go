package collectorruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNodeIdentityClientBindsProtectedRelayResponse(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	request, e := nodeidentity.NewRequest(nodeidentity.Scope{ClusterID: "cluster-a", NodeID: "node-a", EnrollmentID: "enrollment-a", KeyID: "key-a"}, key)
	if e != nil {
		t.Fatal(e)
	}
	token, _, _ := nodeidentity.NewBootstrapToken()
	good := nodeidentity.CertificateBundle{ProtocolVersion: 1, Scope: request.Scope, CSRSHA256: request.CSRSHA256, SPKISHA256: request.SPKISHA256, CertificatePEM: "public-fixture-certificate", NodeCAPEM: "public-fixture-ca", IssuedAt: time.Now().Add(-time.Second), NotAfter: time.Now().Add(time.Hour)}
	wire, _ := json.Marshal(good)
	for i, reply := range []string{string(wire), strings.Replace(string(wire), `"node-a"`, `"foreign"`, 1), string(wire) + `{}`, strings.Replace(string(wire), `"protocol_version":1`, `"protocol_version":1,"protocol_version":1`, 1)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/collector/telemetry/v1/node-certificates" || r.Header.Get("X-Sherlock-Telemetry-Version") != "1" {
				t.Error("relay path/header")
			}
			var got struct {
				Token   string               `json:"token"`
				Request nodeidentity.Request `json:"request"`
			}
			if json.NewDecoder(r.Body).Decode(&got) != nil || got.Token != token || got.Request.CSRSHA256 != request.CSRSHA256 {
				t.Error("relay request changed")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(reply))
		}))
		client := newTelemetryTestClient(t, server)
		_, e = client.IssueNodeCertificate(context.Background(), token, request)
		server.Close()
		if i == 0 && e != nil || i > 0 && e == nil {
			t.Fatal("relay response binding", i, e)
		}
	}
}
