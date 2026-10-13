package collectorcontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/verticalcomputer/sherlock/internal/collectorpop"
)

const (
	maxPoPCertificateBytes = 10 << 10
	maxPoPBodyBytes        = 12 << 20
	maximumPoPClockSkew    = 2 * time.Minute
	requestNonceLifetime   = 5 * time.Minute
)

type CloudflareAccessServiceTokenPoPConfig struct {
	Issuer             string
	Audience           string
	TrustedProxies     []netip.Prefix
	CollectorHostname  string
	EnrollmentHostname string
	CollectorRoots     *x509.CertPool
	ReplayStore        RequestReplayStore
	HTTPClient         *http.Client
	Clock              Clock
	Observer           AuthEventObserver
}

// CloudflareAccessServiceTokenPoPAuthenticator treats Cloudflare's Service
// Token assertion as an edge-admission gate, never as the collector identity.
// The collector identity remains its short-lived Sherlock certificate and a
// signature made by the corresponding private key over this exact request.
type CloudflareAccessServiceTokenPoPAuthenticator struct {
	issuer, audience, collectorHostname, enrollmentHostname string
	trustedProxies                                          []netip.Prefix
	roots                                                   *x509.CertPool
	replays                                                 RequestReplayStore
	clock                                                   Clock
	observer                                                AuthEventObserver
	keys                                                    *boundedJWKS
}

func NewCloudflareAccessServiceTokenPoPAuthenticator(ctx context.Context, cfg CloudflareAccessServiceTokenPoPConfig) (*CloudflareAccessServiceTokenPoPAuthenticator, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.CollectorHostname == "" || cfg.EnrollmentHostname == "" || cfg.CollectorRoots == nil || cfg.ReplayStore == nil || cfg.HTTPClient == nil || cfg.Clock == nil || len(cfg.TrustedProxies) == 0 {
		return nil, fmt.Errorf("cloudflare Access Service Token proof-of-possession configuration is incomplete")
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
	return &CloudflareAccessServiceTokenPoPAuthenticator{
		issuer: strings.TrimSuffix(cfg.Issuer, "/"), audience: cfg.Audience,
		collectorHostname: strings.ToLower(cfg.CollectorHostname), enrollmentHostname: strings.ToLower(cfg.EnrollmentHostname),
		trustedProxies: append([]netip.Prefix(nil), cfg.TrustedProxies...), roots: cfg.CollectorRoots,
		replays: cfg.ReplayStore, clock: cfg.Clock, observer: observer, keys: keys,
	}, nil
}

func (a *CloudflareAccessServiceTokenPoPAuthenticator) AllowEnrollment(r *http.Request) bool {
	if !a.trustedProxy(r) || r.Method != http.MethodPost || r.URL.Path != "/collector/v1/enroll" || requestHostname(r) != a.enrollmentHostname {
		a.observer.Rejected("enrollment_boundary")
		return false
	}
	if err := a.verifyAssertion(r); err != nil {
		return false
	}
	return true
}

func (a *CloudflareAccessServiceTokenPoPAuthenticator) Certificate(r *http.Request) (*x509.Certificate, error) {
	if !a.trustedProxy(r) {
		return a.rejectPoP("proxy_peer")
	}
	if requestHostname(r) != a.collectorHostname {
		return a.rejectPoP("collector_host")
	}
	if err := a.verifyAssertion(r); err != nil {
		return nil, err
	}
	encodedCertificate, ok := oneBoundedHeader(r.Header, collectorpop.CertificateHeader, (maxPoPCertificateBytes*4/3)+4)
	if !ok {
		return a.rejectPoP("certificate_header")
	}
	certificateDER, err := base64.StdEncoding.Strict().DecodeString(encodedCertificate)
	if err != nil || len(certificateDER) == 0 || len(certificateDER) > maxPoPCertificateBytes {
		return a.rejectPoP("certificate_malformed")
	}
	certificates, err := x509.ParseCertificates(certificateDER)
	if err != nil || len(certificates) != 1 {
		return a.rejectPoP("certificate_malformed")
	}
	leaf := certificates[0]
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve == nil || publicKey.Curve.Params().Name != "P-256" || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return a.rejectPoP("certificate_usage")
	}
	now := a.clock.Now().UTC()
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: a.roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return a.rejectPoP("certificate_chain")
	}
	timestampText, ok := oneBoundedHeader(r.Header, collectorpop.TimestampHeader, 64)
	if !ok {
		return a.rejectPoP("request_timestamp")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, timestampText)
	if err != nil || timestamp.Before(now.Add(-maximumPoPClockSkew)) || timestamp.After(now.Add(maximumPoPClockSkew)) {
		return a.rejectPoP("request_timestamp")
	}
	digestText, ok := oneBoundedHeader(r.Header, collectorpop.ContentHashHeader, 64)
	if !ok || len(digestText) != 64 {
		return a.rejectPoP("content_digest")
	}
	expectedDigest, err := hex.DecodeString(digestText)
	if err != nil || len(expectedDigest) != sha256.Size {
		return a.rejectPoP("content_digest")
	}
	body, err := readAndRestoreBody(r, maxPoPBodyBytes)
	if err != nil {
		return a.rejectPoP("content_size")
	}
	actualDigest := sha256.Sum256(body)
	if !bytes.Equal(expectedDigest, actualDigest[:]) {
		return a.rejectPoP("content_digest")
	}
	protocol, ok := oneBoundedHeader(r.Header, collectorpop.ProtocolHeader, 16)
	if !ok {
		return a.rejectPoP("protocol_header")
	}
	correlationID, ok := oneBoundedHeader(r.Header, collectorpop.CorrelationHeader, 128)
	if !ok || !validCorrelationID(correlationID) {
		return a.rejectPoP("correlation_header")
	}
	canonical, err := collectorpop.CanonicalRequest(r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Host, protocol, correlationID, timestampText, actualDigest)
	if err != nil {
		return a.rejectPoP("signature_input")
	}
	signatureText, ok := oneBoundedHeader(r.Header, collectorpop.SignatureHeader, 256)
	if !ok {
		return a.rejectPoP("signature_header")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	if err != nil || len(signature) == 0 || len(signature) > 128 {
		return a.rejectPoP("signature_header")
	}
	canonicalDigest := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(publicKey, canonicalDigest[:], signature) {
		return a.rejectPoP("signature_invalid")
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	if err := a.replays.ConsumeCollectorRequestNonce(r.Context(), fingerprint, correlationID, now.Add(requestNonceLifetime)); err != nil {
		if errors.Is(err, ErrRequestReplay) {
			return a.rejectPoP("request_replay")
		}
		return a.rejectPoP("replay_store")
	}
	return leaf, nil
}

func (a *CloudflareAccessServiceTokenPoPAuthenticator) verifyAssertion(r *http.Request) error {
	if len(r.Header.Values(accessAssertionHeader)) == 0 {
		_, err := a.rejectPoP("assertion_missing")
		return err
	}
	assertion, ok := oneBoundedHeader(r.Header, accessAssertionHeader, maxAssertionBytes)
	if !ok {
		_, err := a.rejectPoP("assertion_header")
		return err
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
	if err != nil || !token.Valid || claims.IssuedAt == nil || claims.IssuedAt.Time.After(a.clock.Now().UTC().Add(maximumPoPClockSkew)) {
		_, rejected := a.rejectPoP(assertionReason(err, claims))
		return rejected
	}
	return nil
}

func (a *CloudflareAccessServiceTokenPoPAuthenticator) IdentityRejected(err error) {
	if errors.Is(err, ErrCollectorInactive) {
		a.observer.Rejected("collector_inactive")
		return
	}
	a.observer.Rejected("collector_lookup")
}

func (a *CloudflareAccessServiceTokenPoPAuthenticator) rejectPoP(reason string) (*x509.Certificate, error) {
	a.observer.Rejected(reason)
	return nil, ErrRequestAuthentication
}

func (a *CloudflareAccessServiceTokenPoPAuthenticator) trustedProxy(r *http.Request) bool {
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

func readAndRestoreBody(r *http.Request, maximum int64) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, fmt.Errorf("request body exceeds proof-of-possession limit")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}
