package collectorcontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
)

type identityIntake struct {
	calls      int
	cluster    domain.ClusterID
	collector  domain.CollectorID
	err        error
	substitute bool
}

func (f *identityIntake) ConsumeNodeBootstrap(_ context.Context, c domain.ClusterID, g domain.CollectorID, _ string, r nodeidentity.Request, _ *nodeidentity.Issuer) (nodeidentity.CertificateBundle, error) {
	f.calls++
	f.cluster = c
	f.collector = g
	b := nodeidentity.CertificateBundle{ProtocolVersion: 1, Scope: r.Scope, CSRSHA256: r.CSRSHA256, SPKISHA256: r.SPKISHA256, IssuedAt: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	if f.substitute {
		b.Scope.NodeID = "foreign"
	}
	return b, f.err
}
func identityEnvelope(t *testing.T) string {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	r, e := nodeidentity.NewRequest(nodeidentity.Scope{ClusterID: "cluster-1", NodeID: "node-a", EnrollmentID: "enrollment-a", KeyID: "key-a"}, key)
	if e != nil {
		t.Fatal(e)
	}
	token, _, e := nodeidentity.NewBootstrapToken()
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(struct {
		Token   string               `json:"token"`
		Request nodeidentity.Request `json:"request"`
	}{token, r})
	return string(b)
}
func TestNodeIdentityRelayAuthenticatesAndRejectsAmbiguousInput(t *testing.T) {
	tr, _, _, _, _ := newTestTransport(t)
	store := &identityIntake{}
	if e := tr.ConfigureNodeIdentity(store, nil); e != nil {
		t.Fatal(e)
	}
	body := identityEnvelope(t)
	path := "/collector/telemetry/v1/node-certificates"
	w := telemetryRequest(t, tr, path, body, true, nil)
	if w.Code != 200 || store.calls != 1 || store.cluster != "cluster-1" || store.collector != "collector-1" {
		t.Fatal("principal binding", w.Code)
	}
	for _, check := range []struct {
		body   string
		auth   bool
		modify func(*http.Request)
	}{
		{body, false, nil},
		{strings.Replace(body, `"token":`, `"TOKEN":`, 1), true, nil},
		{body + `{}`, true, nil},
		{strings.Replace(body, `"protocol_version":1`, `"protocol_version":1,"protocol_version":1`, 1), true, nil},
		{body, true, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{body, true, func(r *http.Request) { r.Header.Set("X-Sherlock-Telemetry-Version", "2") }},
		{strings.Repeat(" ", nodeidentity.MaxRequestBytes+513), true, nil},
	} {
		before := store.calls
		w = telemetryRequest(t, tr, path, check.body, check.auth, check.modify)
		if w.Code < 400 || store.calls != before {
			t.Fatal("ambiguous or unauthenticated relay admitted", w.Code)
		}
	}
	store.err = errors.New("private-driver-token-detail")
	w = telemetryRequest(t, tr, path, body, true, nil)
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-driver") {
		t.Fatal("unsafe store error", w.Code)
	}
	store.err = nil
	store.substitute = true
	w = telemetryRequest(t, tr, path, body, true, nil)
	if w.Code != 503 {
		t.Fatal("substituted node identity returned", w.Code)
	}
}
