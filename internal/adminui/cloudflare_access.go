package adminui

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	accessAssertionHeader = "Cf-Access-Jwt-Assertion"
	maxAccessAssertion    = 16 << 10
	maxAccessJWKS         = 1 << 20
)

var ErrCloudflareAccessDenied = errors.New("cloudflare Access authentication failed")

type AccessIdentity struct {
	Issuer  string
	Subject string
	Email   string
}

type AccessVerifier interface {
	Verify(context.Context, string) (AccessIdentity, error)
}

type CloudflareAccessConfig struct {
	Issuer     string
	Audience   string
	HTTPClient *http.Client
	Clock      Clock
}

type CloudflareAccessVerifier struct {
	issuer, audience string
	clock            Clock
	keys             *accessJWKS
}

type accessClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
	Type  string `json:"type"`
}

func NewCloudflareAccessVerifier(ctx context.Context, cfg CloudflareAccessConfig) (*CloudflareAccessVerifier, error) {
	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" || issuerURL.User != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" || (issuerURL.Path != "" && issuerURL.Path != "/") {
		return nil, fmt.Errorf("cloudflare Access issuer must be an absolute HTTPS origin")
	}
	if cfg.Audience == "" || strings.ContainsAny(cfg.Audience, ", \t\r\n") {
		return nil, fmt.Errorf("cloudflare Access audience must contain exactly one non-empty value")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("cloudflare Access HTTP client is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = wallClock{}
	}
	issuer := strings.TrimSuffix(cfg.Issuer, "/")
	keys := &accessJWKS{url: issuer + "/cdn-cgi/access/certs", client: cfg.HTTPClient, clock: cfg.Clock}
	if err := keys.refresh(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap Cloudflare Access signing keys: %w", err)
	}
	return &CloudflareAccessVerifier{issuer: issuer, audience: cfg.Audience, clock: cfg.Clock, keys: keys}, nil
}

func (verifier *CloudflareAccessVerifier) Verify(ctx context.Context, assertion string) (AccessIdentity, error) {
	if len(assertion) < 1 || len(assertion) > maxAccessAssertion || strings.ContainsAny(assertion, "\r\n,") {
		return AccessIdentity{}, ErrCloudflareAccessDenied
	}
	claims := &accessClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(verifier.issuer),
		jwt.WithAudience(verifier.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(func() time.Time { return verifier.clock.Now().UTC() }),
	)
	token, err := parser.ParseWithClaims(assertion, claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || len(kid) < 1 || len(kid) > 256 {
			return nil, ErrCloudflareAccessDenied
		}
		return verifier.keys.key(ctx, kid)
	})
	if err != nil || !token.Valid || claims.IssuedAt == nil || claims.NotBefore == nil || claims.Type != "app" || !validAccessIdentity(claims.Subject, claims.Email) {
		return AccessIdentity{}, ErrCloudflareAccessDenied
	}
	return AccessIdentity{Issuer: verifier.issuer, Subject: claims.Subject, Email: claims.Email}, nil
}

func validAccessIdentity(subject, email string) bool {
	if len(subject) < 1 || len(subject) > 256 || len(email) < 3 || len(email) > 320 || !strings.Contains(email, "@") {
		return false
	}
	return !strings.ContainsAny(subject+email, "\x00\r\n")
}

type accessJWKS struct {
	url                string
	client             *http.Client
	clock              Clock
	mu                 sync.RWMutex
	refreshMu          sync.Mutex
	keys               map[string]*rsa.PublicKey
	expiresAt          time.Time
	lastUnknownRefresh time.Time
}

func (keys *accessJWKS) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	now := keys.clock.Now().UTC()
	keys.mu.RLock()
	key, expiresAt := keys.keys[kid], keys.expiresAt
	keys.mu.RUnlock()
	if key != nil && now.Before(expiresAt) {
		return key, nil
	}
	if key == nil && now.Before(expiresAt) {
		keys.mu.Lock()
		if !keys.lastUnknownRefresh.IsZero() && now.Sub(keys.lastUnknownRefresh) < 30*time.Second {
			keys.mu.Unlock()
			return nil, ErrCloudflareAccessDenied
		}
		keys.lastUnknownRefresh = now
		keys.mu.Unlock()
	}
	if err := keys.refresh(ctx); err != nil {
		return nil, ErrCloudflareAccessDenied
	}
	keys.mu.RLock()
	defer keys.mu.RUnlock()
	if !now.Before(keys.expiresAt) || keys.keys[kid] == nil {
		return nil, ErrCloudflareAccessDenied
	}
	return keys.keys[kid], nil
}

func (keys *accessJWKS) refresh(ctx context.Context) error {
	keys.refreshMu.Lock()
	defer keys.refreshMu.Unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, keys.url, nil)
	if err != nil {
		return err
	}
	response, err := keys.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned non-success status")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxAccessJWKS+1))
	if err != nil || len(payload) > maxAccessJWKS {
		return fmt.Errorf("JWKS document exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var document struct {
		Keys []struct{ Kty, Kid, Use, Alg, N, E string } `json:"keys"`
	}
	if err := decoder.Decode(&document); err != nil || len(document.Keys) < 1 || len(document.Keys) > 32 {
		return fmt.Errorf("JWKS document is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("JWKS document contains trailing data")
	}
	parsed := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, item := range document.Keys {
		if item.Kty != "RSA" || item.Alg != "RS256" || (item.Use != "" && item.Use != "sig") || len(item.Kid) < 1 || len(item.Kid) > 256 || parsed[item.Kid] != nil {
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
		parsed[item.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(parsed) == 0 {
		return fmt.Errorf("JWKS contains no usable signing keys")
	}
	keys.mu.Lock()
	keys.keys = parsed
	keys.expiresAt = keys.clock.Now().UTC().Add(accessCacheMaxAge(response.Header.Get("Cache-Control")))
	keys.mu.Unlock()
	return nil
}

func accessCacheMaxAge(value string) time.Duration {
	const defaultTTL = 5 * time.Minute
	for _, directive := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(directive)
		if strings.EqualFold(trimmed, "no-store") || strings.EqualFold(trimmed, "no-cache") {
			return 0
		}
		name, raw, found := strings.Cut(trimmed, "=")
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
