// Package nodegateway implements the compute-node authentication boundary. It
// has no command surface and cannot create an enrollment.
package nodegateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// GrantLoader must fetch over the authenticated pinned outbound collector TLS
// boundary. A file or caller-provided request grant cannot implement authority.
type GrantLoader interface {
	Grant(context.Context, string) (telemetry.Grant, error)
}
type cachedGrant struct {
	mu      sync.Mutex
	busy    atomic.Bool
	grant   telemetry.Grant
	expires time.Time
}
type Authority struct {
	cluster, collector, gatewayPin string
	cache                          map[string]*cachedGrant
	loader                         GrantLoader
	now                            func() time.Time
}

func NewAuthority(cluster, collector, gatewayPin string, enrollments []string, loader GrantLoader) (*Authority, error) {
	pin, pinErr := hex.DecodeString(gatewayPin)
	if !identityID(cluster) || !identityID(collector) || pinErr != nil || len(pin) != 32 || hex.EncodeToString(pin) != gatewayPin || loader == nil || len(enrollments) == 0 || len(enrollments) > 4096 {
		return nil, telemetry.ErrInvalid
	}
	entries := make(map[string]*cachedGrant, len(enrollments))
	for _, id := range enrollments {
		if !identityID(id) || entries[id] != nil {
			return nil, telemetry.ErrInvalid
		}
		entries[id] = &cachedGrant{}
	}
	return &Authority{cluster: cluster, collector: collector, gatewayPin: gatewayPin, cache: entries, loader: loader, now: time.Now}, nil
}

// No persisted cache is restored: startup always needs a fresh authority poll.
// A monotonic expires value survives wall-clock changes within this process.
func (a *Authority) grant(ctx context.Context, id string) (telemetry.Grant, error) {
	entry := a.cache[id]
	if entry == nil {
		return telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	now := a.now()
	if now.Before(entry.expires) {
		return entry.grant, nil
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	grant, err := a.loader.Grant(bounded, id)
	if err != nil {
		return telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	end := a.now()
	ttl := grant.NotAfter.Sub(grant.NotBefore)
	if telemetry.ValidateGrant(grant, end) != nil || grant.ProtocolVersion != 1 || grant.Status != "ACTIVE" || grant.EnrollmentID != id || grant.ClusterID != a.cluster || grant.GatewayCollectorID != a.collector || grant.GatewaySPKISHA256 != a.gatewayPin || ttl <= 0 || ttl > 5*time.Minute || grant.NotBefore.After(now.Add(30*time.Second)) || !grant.NotAfter.After(end) {
		return telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	// Response network time is subtracted from its remote lease duration; neither
	// client nor remote wall clocks can extend the five-minute local lease.
	ttl -= end.Sub(now)
	if ttl <= 0 {
		return telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	expires := end.Add(ttl)
	if remaining := grant.NotAfter.Sub(end); remaining < ttl {
		expires = end.Add(remaining)
	}
	entry.grant, entry.expires = grant, expires
	return grant, nil
}

type Principal struct{ ClusterID, NodeID, EnrollmentID, KeyID string }

func NodeIdentityURI(cluster, node, enrollment, key string) (*url.URL, error) {
	for _, id := range []string{cluster, node, enrollment, key} {
		if !identityID(id) {
			return nil, telemetry.ErrInvalid
		}
	}
	return &url.URL{Scheme: "spiffe", Host: "sherlock", Path: "/node/" + cluster + "/" + node + "/" + enrollment + "/" + key}, nil
}
func certificatePrincipal(cert *x509.Certificate) (Principal, error) {
	if cert == nil || len(cert.URIs) != 1 || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		return Principal{}, telemetry.ErrUnauthorized
	}
	uri := cert.URIs[0]
	if uri.Scheme != "spiffe" || uri.Host != "sherlock" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || uri.RawPath != "" {
		return Principal{}, telemetry.ErrUnauthorized
	}
	parts := strings.Split(uri.Path, "/")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "node" {
		return Principal{}, telemetry.ErrUnauthorized
	}
	expected, err := NodeIdentityURI(parts[2], parts[3], parts[4], parts[5])
	if err != nil || expected.String() != uri.String() {
		return Principal{}, telemetry.ErrUnauthorized
	}
	return Principal{ClusterID: parts[2], NodeID: parts[3], EnrollmentID: parts[4], KeyID: parts[5]}, nil
}
func (a *Authority) Authenticate(ctx context.Context, r *http.Request) (Principal, telemetry.Grant, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return Principal{}, telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	cert := r.TLS.PeerCertificates[0]
	// VerifiedChains originates in the node listener's RequireAndVerifyClientCert
	// TLS configuration; caller-supplied request headers are never identities.
	if len(r.TLS.VerifiedChains[0]) == 0 || !bytes.Equal(r.TLS.VerifiedChains[0][0].Raw, cert.Raw) {
		return Principal{}, telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	principal, err := certificatePrincipal(cert)
	if err != nil || principal.ClusterID != a.cluster {
		return Principal{}, telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	grant, err := a.grant(ctx, principal.EnrollmentID)
	if err != nil || grant.NodeID != principal.NodeID {
		return Principal{}, telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	key, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return Principal{}, telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	matched := false
	for _, authorized := range grant.Keys {
		if authorized.ID != principal.KeyID || (authorized.State != "ACTIVE" && authorized.State != "VERIFY_ONLY") {
			continue
		}
		decoded, err := telemetry.ParseNodePublicKey(authorized)
		if err == nil && bytes.Equal(decoded, key) {
			matched = true
		}
	}
	if !matched {
		return Principal{}, telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	if !a.now().Before(cert.NotAfter) || a.now().Before(cert.NotBefore) {
		return Principal{}, telemetry.Grant{}, telemetry.ErrUnauthorized
	}
	return principal, grant, nil
}

func identityID(v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}
