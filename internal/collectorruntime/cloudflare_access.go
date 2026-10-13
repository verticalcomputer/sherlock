package collectorruntime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorpop"
)

const maximumAccessCredentialBytes = 4 << 10

type AccessServiceToken struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func ReadAccessServiceToken(path string) (AccessServiceToken, error) {
	info, err := os.Stat(path)
	if err != nil {
		return AccessServiceToken{}, fmt.Errorf("inspect cloudflare Access Service Token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > maximumAccessCredentialBytes {
		return AccessServiceToken{}, fmt.Errorf("cloudflare Access Service Token file must be a bounded owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return AccessServiceToken{}, fmt.Errorf("open cloudflare Access Service Token file: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumAccessCredentialBytes+1))
	decoder.DisallowUnknownFields()
	var token AccessServiceToken
	if err := decoder.Decode(&token); err != nil {
		return AccessServiceToken{}, fmt.Errorf("decode cloudflare Access Service Token file: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF || !boundedCredential(token.ClientID, 512) || !boundedCredential(token.ClientSecret, 512) {
		return AccessServiceToken{}, fmt.Errorf("cloudflare Access Service Token file is invalid")
	}
	return token, nil
}

func boundedCredential(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

type accessServiceTokenRoundTripper struct {
	next   http.RoundTripper
	token  AccessServiceToken
	leaf   *x509.Certificate
	signer *ecdsa.PrivateKey
	now    func() time.Time
	random io.Reader
}

func NewAccessServiceTokenRoundTripper(next http.RoundTripper, token AccessServiceToken) (http.RoundTripper, error) {
	return newAccessServiceTokenRoundTripper(next, token, tls.Certificate{}, nil, rand.Reader)
}

func NewAccessServiceTokenPoPRoundTripper(next http.RoundTripper, token AccessServiceToken, certificate tls.Certificate) (http.RoundTripper, error) {
	return newAccessServiceTokenRoundTripper(next, token, certificate, time.Now, rand.Reader)
}

func newAccessServiceTokenRoundTripper(next http.RoundTripper, token AccessServiceToken, certificate tls.Certificate, now func() time.Time, random io.Reader) (http.RoundTripper, error) {
	if next == nil || !boundedCredential(token.ClientID, 512) || !boundedCredential(token.ClientSecret, 512) {
		return nil, fmt.Errorf("cloudflare Access Service Token transport configuration is invalid")
	}
	transport := &accessServiceTokenRoundTripper{next: next, token: token, now: now, random: random}
	if now == nil {
		return transport, nil
	}
	if len(certificate.Certificate) != 1 || certificate.PrivateKey == nil || random == nil {
		return nil, fmt.Errorf("sherlock proof-of-possession requires one collector certificate and private key")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse proof-of-possession certificate: %w", err)
	}
	privateKey, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve == nil || privateKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("sherlock proof-of-possession requires a P-256 private key")
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&privateKey.PublicKey) {
		return nil, fmt.Errorf("proof-of-possession certificate and private key do not match")
	}
	transport.leaf, transport.signer = leaf, privateKey
	return transport, nil
}

func (t *accessServiceTokenRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("CF-Access-Client-Id", t.token.ClientID)
	clone.Header.Set("CF-Access-Client-Secret", t.token.ClientSecret)
	if t.signer == nil {
		return t.next.RoundTrip(clone)
	}
	body, err := readClientRequestBody(request)
	if err != nil {
		return nil, err
	}
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))
	bodyDigest := sha256.Sum256(body)
	timestamp := t.now().UTC().Format(time.RFC3339Nano)
	host := clone.Host
	if host == "" {
		host = clone.URL.Host
	}
	canonical, err := collectorpop.CanonicalRequest(
		clone.Method, clone.URL.EscapedPath(), clone.URL.RawQuery, host,
		clone.Header.Get(collectorpop.ProtocolHeader), clone.Header.Get(collectorpop.CorrelationHeader), timestamp, bodyDigest,
	)
	if err != nil {
		return nil, fmt.Errorf("canonicalize collector proof-of-possession request: %w", err)
	}
	canonicalDigest := sha256.Sum256(canonical)
	signature, err := ecdsa.SignASN1(t.random, t.signer, canonicalDigest[:])
	if err != nil {
		return nil, fmt.Errorf("sign collector proof-of-possession request: %w", err)
	}
	clone.Header.Set(collectorpop.CertificateHeader, base64.StdEncoding.EncodeToString(t.leaf.Raw))
	clone.Header.Set(collectorpop.TimestampHeader, timestamp)
	clone.Header.Set(collectorpop.ContentHashHeader, hex.EncodeToString(bodyDigest[:]))
	clone.Header.Set(collectorpop.SignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	return t.next.RoundTrip(clone)
}

func readClientRequestBody(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return []byte{}, nil
	}
	reader := request.Body
	if request.GetBody != nil {
		var err error
		reader, err = request.GetBody()
		if err != nil {
			return nil, fmt.Errorf("read collector request body for proof-of-possession: body is unavailable")
		}
		defer reader.Close()
	}
	body, err := io.ReadAll(io.LimitReader(reader, maximumBodyBytes+1))
	if err != nil || int64(len(body)) > maximumBodyBytes {
		return nil, fmt.Errorf("read collector request body for proof-of-possession: body is unavailable or oversized")
	}
	if request.GetBody == nil {
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	return body, nil
}
