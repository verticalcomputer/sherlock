package nodegateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type loaderFunc func(context.Context, string) (telemetry.Grant, error)

func (f loaderFunc) Grant(ctx context.Context, id string) (telemetry.Grant, error) { return f(ctx, id) }
func authFixture(t *testing.T, at time.Time) (telemetry.Grant, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := telemetry.Grant{ProtocolVersion: 1, EnrollmentID: "enrollment-a", EnrollmentRevision: 1, ControlRevision: 1, Status: "ACTIVE", ClusterID: "cluster-a", NodeID: "node-a", InventoryRevisionID: "inventory-a", GatewayCollectorID: "gateway-a", Sources: []telemetry.SourceGrant{{SourceID: "source-a", SchemaVersion: 1, ProfileID: telemetry.FixtureProfile}}, AgentVersion: "fixture.v1", BuildSHA256: strings.Repeat("a", 64), GatewaySPKISHA256: strings.Repeat("b", 64), Keys: []telemetry.NodeKey{{ID: "key-a", Epoch: "1", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pub), State: "ACTIVE"}}, NotBefore: at.Add(-time.Second), NotAfter: at.Add(4 * time.Minute)}
	return g, pub
}
func identityRequest(t *testing.T, g telemetry.Grant, pub ed25519.PublicKey, at time.Time) *http.Request {
	t.Helper()
	uri, err := NodeIdentityURI(g.ClusterID, g.NodeID, g.EnrollmentID, g.Keys[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{Raw: []byte("synthetic-verified-certificate"), PublicKey: pub, URIs: []*url.URL{uri}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour)}
	r := httptest.NewRequest("POST", "https://gateway.invalid/node-telemetry/v1/batches", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return r
}
func TestAuthorityLeasesExpireAndRestartRequiresFreshPoll(t *testing.T) {
	now := time.Now()
	g, pub := authFixture(t, now)
	var calls atomic.Int32
	var revoked atomic.Bool
	loader := loaderFunc(func(context.Context, string) (telemetry.Grant, error) {
		calls.Add(1)
		if revoked.Load() {
			return telemetry.Grant{}, errors.New("private loader detail")
		}
		return g, nil
	})
	a, err := NewAuthority(g.ClusterID, g.GatewayCollectorID, g.GatewaySPKISHA256, []string{g.EnrollmentID}, loader)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return now }
	r := identityRequest(t, g, pub, now)
	if _, _, err := a.Authenticate(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	if _, _, err := a.Authenticate(context.Background(), r); err != nil {
		t.Fatal("approved running lease should remain bounded and valid", err)
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected repeated poll")
	}
	now = now.Add(5 * time.Minute)
	if _, _, err := a.Authenticate(context.Background(), r); !errors.Is(err, telemetry.ErrUnauthorized) || strings.Contains(err.Error(), "private") {
		t.Fatal("expired lease admitted or exposed detail", err)
	}
	restarted, err := NewAuthority(g.ClusterID, g.GatewayCollectorID, g.GatewaySPKISHA256, []string{g.EnrollmentID}, loader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.Authenticate(context.Background(), r); !errors.Is(err, telemetry.ErrUnauthorized) {
		t.Fatal("restart reused authority", err)
	}
}
func TestAuthorityRejectsForeignCertificateKeyScopeAndGatewayPin(t *testing.T) {
	at := time.Now()
	g, pub := authFixture(t, at)
	for _, name := range []string{"unverified", "foreign-node", "wrong-key", "multiple-uri", "expired-cert", "wrong-pin", "unknown-enrollment", "replay-revoked-key"} {
		t.Run(name, func(t *testing.T) {
			candidate := g
			candidate.Keys = append([]telemetry.NodeKey{}, g.Keys...)
			r := identityRequest(t, g, pub, at)
			switch name {
			case "unverified":
				r.TLS.VerifiedChains = nil
			case "foreign-node":
				r.TLS.PeerCertificates[0].URIs[0].Path = strings.ReplaceAll(r.TLS.PeerCertificates[0].URIs[0].Path, "node-a", "node-b")
			case "wrong-key":
				other, _, _ := ed25519.GenerateKey(rand.Reader)
				r.TLS.PeerCertificates[0].PublicKey = other
			case "multiple-uri":
				r.TLS.PeerCertificates[0].URIs = append(r.TLS.PeerCertificates[0].URIs, r.TLS.PeerCertificates[0].URIs[0])
			case "expired-cert":
				r.TLS.PeerCertificates[0].NotAfter = at.Add(-time.Second)
			case "wrong-pin":
				candidate.GatewaySPKISHA256 = strings.Repeat("c", 64)
			case "unknown-enrollment":
				r.TLS.PeerCertificates[0].URIs[0].Path = strings.ReplaceAll(r.TLS.PeerCertificates[0].URIs[0].Path, g.EnrollmentID, "foreign")
			case "replay-revoked-key":
				candidate.Keys[0].State = "REVOKED"
			}
			a, err := NewAuthority(g.ClusterID, g.GatewayCollectorID, g.GatewaySPKISHA256, []string{g.EnrollmentID}, loaderFunc(func(context.Context, string) (telemetry.Grant, error) { return candidate, nil }))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := a.Authenticate(context.Background(), r); !errors.Is(err, telemetry.ErrUnauthorized) {
				t.Fatal("foreign authority admitted", err)
			}
		})
	}
}
func TestAuthoritySlowEnrollmentCannotBlockOtherNodes(t *testing.T) {
	at := time.Now()
	g, _ := authFixture(t, at)
	other := g
	other.EnrollmentID = "enrollment-b"
	other.NodeID = "node-b"
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	a, err := NewAuthority(g.ClusterID, g.GatewayCollectorID, g.GatewaySPKISHA256, []string{g.EnrollmentID, other.EnrollmentID}, loaderFunc(func(ctx context.Context, id string) (telemetry.Grant, error) {
		if id == g.EnrollmentID {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return telemetry.Grant{}, ctx.Err()
			}
			return g, nil
		}
		return other, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	go func() { defer close(done); _, _ = a.grant(context.Background(), g.EnrollmentID) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := a.grant(ctx, other.EnrollmentID); err != nil {
		t.Fatal("unrelated enrollment blocked", err)
	}
	close(release)
	<-done
}
func TestNodeIdentityURIRejectsAliasedOrUnboundedIdentity(t *testing.T) {
	for _, id := range []string{"", "foreign/node", "%2F", "space name", "line\nbreak", strings.Repeat("x", 129)} {
		if _, err := NodeIdentityURI("cluster-a", id, "enrollment-a", "key-a"); err == nil {
			t.Fatal("invalid identity admitted", id)
		}
	}
}
