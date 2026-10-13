package collectorcontrol

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	accessAssertionHeader = "Cf-Access-Jwt-Assertion"
	forwardedDERHeader    = "Cf-Client-Cert-Der-Base64"
	forwardedSHAHeader    = "Cf-Client-Cert-Sha256"
	maxAssertionBytes     = 16 << 10
	maxForwardedDERBytes  = 10 << 10
	maxJWKSBytes          = 1 << 20
)

type AuthEventObserver interface {
	Rejected(reason string)
	JWKSRefresh(succeeded bool, lastSuccessfulAge time.Duration)
}

type discardAuthObserver struct{}

func (discardAuthObserver) Rejected(string)                 {}
func (discardAuthObserver) JWKSRefresh(bool, time.Duration) {}

type CloudflareAccessMTLSConfig struct {
	Issuer             string
	Audience           string
	TrustedProxies     []netip.Prefix
	CollectorHostname  string
	EnrollmentHostname string
	CollectorRoots     *x509.CertPool
	HTTPClient         *http.Client
	Clock              Clock
	Observer           AuthEventObserver
}

type CloudflareAccessMTLSAuthenticator struct {
	issuer, audience, collectorHostname, enrollmentHostname string
	trustedProxies                                          []netip.Prefix
	roots                                                   *x509.CertPool
	clock                                                   Clock
	observer                                                AuthEventObserver
	keys                                                    *boundedJWKS
}

func NewCloudflareAccessMTLSAuthenticator(ctx context.Context, cfg CloudflareAccessMTLSConfig) (*CloudflareAccessMTLSAuthenticator, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.CollectorHostname == "" || cfg.EnrollmentHostname == "" || cfg.CollectorRoots == nil || cfg.HTTPClient == nil || cfg.Clock == nil || len(cfg.TrustedProxies) == 0 {
		return nil, fmt.Errorf("cloudflare Access mTLS authentication configuration is incomplete")
	}
	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" || issuerURL.User != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" || (issuerURL.Path != "" && issuerURL.Path != "/") {
		return nil, fmt.Errorf("cloudflare Access issuer must be an absolute HTTPS origin")
	}
	if strings.ContainsAny(cfg.Audience, ", \t\r\n") || strings.EqualFold(cfg.CollectorHostname, cfg.EnrollmentHostname) {
		return nil, fmt.Errorf("cloudflare Access audience and host boundaries are invalid")
	}
	for _, prefix := range cfg.TrustedProxies {
		if !prefix.Addr().IsLoopback() {
			return nil, fmt.Errorf("cloudflare Access trusted proxies must be loopback")
		}
	}
	observer := cfg.Observer
	if observer == nil {
		observer = discardAuthObserver{}
	}
	keys := &boundedJWKS{url: strings.TrimSuffix(cfg.Issuer, "/") + "/cdn-cgi/access/certs", client: cfg.HTTPClient, clock: cfg.Clock, observer: observer}
	if err := keys.refresh(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap Cloudflare Access signing keys: %w", err)
	}
	return &CloudflareAccessMTLSAuthenticator{
		issuer: strings.TrimSuffix(cfg.Issuer, "/"), audience: cfg.Audience,
		collectorHostname: strings.ToLower(cfg.CollectorHostname), enrollmentHostname: strings.ToLower(cfg.EnrollmentHostname),
		trustedProxies: append([]netip.Prefix(nil), cfg.TrustedProxies...), roots: cfg.CollectorRoots,
		clock: cfg.Clock, observer: observer, keys: keys,
	}, nil
}

func (a *CloudflareAccessMTLSAuthenticator) AllowEnrollment(r *http.Request) bool {
	allowed := a.trustedProxy(r) && r.Method == http.MethodPost && r.URL.Path == "/collector/v1/enroll" && requestHostname(r) == a.enrollmentHostname
	if !allowed {
		a.observer.Rejected("enrollment_boundary")
	}
	return allowed
}

func (a *CloudflareAccessMTLSAuthenticator) Certificate(r *http.Request) (*x509.Certificate, error) {
	if !a.trustedProxy(r) {
		return a.reject("proxy_peer")
	}
	if requestHostname(r) != a.collectorHostname {
		return a.reject("collector_host")
	}
	if len(r.Header.Values(accessAssertionHeader)) == 0 {
		return a.reject("assertion_missing")
	}
	assertion, ok := oneBoundedHeader(r.Header, accessAssertionHeader, maxAssertionBytes)
	if !ok {
		return a.reject("assertion_header")
	}
	claims := &jwt.RegisteredClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(a.issuer), jwt.WithAudience(a.audience), jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return a.clock.Now().UTC() }))
	token, err := parser.ParseWithClaims(assertion, claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || len(kid) < 1 || len(kid) > 256 {
			return nil, ErrRequestAuthentication
		}
		return a.keys.key(r.Context(), kid)
	})
	if err != nil || !token.Valid || claims.NotBefore == nil {
		return a.reject(assertionReason(err, claims))
	}
	if len(r.Header.Values(forwardedDERHeader)) == 0 || len(r.Header.Values(forwardedSHAHeader)) == 0 {
		return a.reject("certificate_missing")
	}
	encodedDER, ok := oneBoundedHeader(r.Header, forwardedDERHeader, (maxForwardedDERBytes*4/3)+4)
	if !ok {
		return a.reject("certificate_header")
	}
	digestText, ok := oneBoundedHeader(r.Header, forwardedSHAHeader, 64)
	if !ok || len(digestText) != 64 {
		return a.reject("certificate_digest")
	}
	expectedDigest, err := hex.DecodeString(digestText)
	if err != nil || len(expectedDigest) != sha256.Size {
		return a.reject("certificate_digest")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encodedDER)
	if err != nil || len(der) < 1 || len(der) > maxForwardedDERBytes {
		return a.reject("certificate_malformed")
	}
	actualDigest := sha256.Sum256(der)
	if subtle.ConstantTimeCompare(actualDigest[:], expectedDigest) != 1 {
		return a.reject("certificate_digest")
	}
	certificates, err := x509.ParseCertificates(der)
	if err != nil || len(certificates) != 1 {
		return a.reject("certificate_malformed")
	}
	leaf := certificates[0]
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return a.reject("certificate_usage")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: a.roots, CurrentTime: a.clock.Now().UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return a.reject("certificate_chain")
	}
	return leaf, nil
}

func assertionReason(err error, claims *jwt.RegisteredClaims) string {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "assertion_expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return "assertion_not_before"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "assertion_issuer"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "assertion_audience"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "assertion_signature"
	case err == nil && claims.NotBefore == nil:
		return "assertion_not_before"
	default:
		return "assertion_invalid"
	}
}

func (a *CloudflareAccessMTLSAuthenticator) IdentityRejected(err error) {
	if errors.Is(err, ErrCollectorInactive) {
		a.observer.Rejected("collector_inactive")
		return
	}
	a.observer.Rejected("collector_lookup")
}

func (a *CloudflareAccessMTLSAuthenticator) reject(reason string) (*x509.Certificate, error) {
	a.observer.Rejected(reason)
	return nil, ErrRequestAuthentication
}

func (a *CloudflareAccessMTLSAuthenticator) trustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, prefix := range a.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func requestHostname(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func oneBoundedHeader(header http.Header, name string, limit int) (string, bool) {
	values := header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && len(returnValue) > 0 && len(returnValue) <= limit && !strings.ContainsAny(returnValue, "\r\n,")
}

type boundedJWKS struct {
	url                    string
	client                 *http.Client
	clock                  Clock
	observer               AuthEventObserver
	mu                     sync.RWMutex
	refreshMu              sync.Mutex
	keys                   map[string]*rsa.PublicKey
	expiresAt, lastRefresh time.Time
	lastUnknownRefresh     time.Time
}

func (j *boundedJWKS) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	now := j.clock.Now().UTC()
	j.mu.RLock()
	key := j.keys[kid]
	expires := j.expiresAt
	j.mu.RUnlock()
	if key != nil && now.Before(expires) {
		return key, nil
	}
	if key == nil && now.Before(expires) {
		j.mu.Lock()
		if !j.lastUnknownRefresh.IsZero() && now.Sub(j.lastUnknownRefresh) < 30*time.Second {
			j.mu.Unlock()
			return nil, ErrRequestAuthentication
		}
		j.lastUnknownRefresh = now
		j.mu.Unlock()
	}
	if err := j.refresh(ctx); err != nil {
		return nil, ErrRequestAuthentication
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	if !now.Before(j.expiresAt) || j.keys[kid] == nil {
		return nil, ErrRequestAuthentication
	}
	return j.keys[kid], nil
}

func (j *boundedJWKS) refresh(ctx context.Context) error {
	j.refreshMu.Lock()
	defer j.refreshMu.Unlock()
	now := j.clock.Now().UTC()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return err
	}
	response, err := j.client.Do(request)
	if err != nil {
		j.observeRefresh(false)
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		j.observeRefresh(false)
		return fmt.Errorf("JWKS returned non-success status")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(payload) > maxJWKSBytes {
		j.observeRefresh(false)
		return fmt.Errorf("JWKS document exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var document struct {
		Keys []struct{ Kty, Kid, Use, Alg, N, E string } `json:"keys"`
	}
	if err := decoder.Decode(&document); err != nil || len(document.Keys) < 1 || len(document.Keys) > 32 {
		j.observeRefresh(false)
		return fmt.Errorf("JWKS document is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		j.observeRefresh(false)
		return fmt.Errorf("JWKS document contains trailing data")
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, item := range document.Keys {
		if item.Kty != "RSA" || item.Alg != "RS256" || (item.Use != "" && item.Use != "sig") || len(item.Kid) < 1 || len(item.Kid) > 256 || keys[item.Kid] != nil {
			continue
		}
		nBytes, nErr := base64.RawURLEncoding.Strict().DecodeString(item.N)
		eBytes, eErr := base64.RawURLEncoding.Strict().DecodeString(item.E)
		if nErr != nil || eErr != nil || len(nBytes) < 256 || len(eBytes) < 1 || len(eBytes) > 4 {
			continue
		}
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		if e < 3 || e%2 == 0 {
			continue
		}
		keys[item.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		j.observeRefresh(false)
		return fmt.Errorf("JWKS contains no usable signing keys")
	}
	ttl := cacheMaxAge(response.Header.Get("Cache-Control"))
	j.mu.Lock()
	j.keys, j.lastRefresh, j.expiresAt = keys, now, now.Add(ttl)
	j.mu.Unlock()
	j.observeRefresh(true)
	return nil
}

func (j *boundedJWKS) observeRefresh(succeeded bool) {
	age := -time.Second
	j.mu.RLock()
	if !j.lastRefresh.IsZero() {
		age = j.clock.Now().UTC().Sub(j.lastRefresh)
	}
	j.mu.RUnlock()
	j.observer.JWKSRefresh(succeeded, age)
}

func cacheMaxAge(value string) time.Duration {
	const defaultTTL = 5 * time.Minute
	for _, directive := range strings.Split(value, ",") {
		if name := strings.TrimSpace(directive); strings.EqualFold(name, "no-store") || strings.EqualFold(name, "no-cache") {
			return 0
		}
		name, raw, found := strings.Cut(strings.TrimSpace(directive), "=")
		if found && strings.EqualFold(name, "max-age") {
			seconds, err := strconv.ParseInt(strings.Trim(raw, `"`), 10, 64)
			if err != nil || seconds < 0 {
				return defaultTTL
			}
			ttl := time.Duration(seconds) * time.Second
			if ttl > 24*time.Hour {
				return 24 * time.Hour
			}
			return ttl
		}
	}
	return defaultTTL
}
