// Package nodeidentity provides offline node CSR and dedicated client-CA helpers.
// It grants no enrollment, gateway, workload or repair authority.
package nodeidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

const (
	Version                = 1
	MaxPEMBytes            = 16 << 10
	MaxRequestBytes        = 24 << 10
	MaxBundleBytes         = 48 << 10
	MaxCertificateLifetime = 24 * time.Hour
	MaxBootstrapLifetime   = 10 * time.Minute
)

var (
	ErrInvalid      = errors.New("invalid node identity")
	ErrUnauthorized = errors.New("node identity is unauthorized")
	ErrUnavailable  = errors.New("node identity is unavailable")
	ErrInUse        = errors.New("node identity directory is in use")
)

type Scope struct {
	ClusterID    string `json:"cluster_id"`
	NodeID       string `json:"node_id"`
	EnrollmentID string `json:"enrollment_id"`
	KeyID        string `json:"key_id"`
}

type Request struct {
	ProtocolVersion int    `json:"protocol_version"`
	Scope           Scope  `json:"scope"`
	CSRPEM          string `json:"csr_pem"`
	CSRSHA256       string `json:"csr_sha256"`
	SPKISHA256      string `json:"spki_sha256"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

// CertificateBundle is public immutable issuance material. Neither its NodeCA
// nor its scope is an independent trust anchor or enrollment grant.
type CertificateBundle struct {
	ProtocolVersion int       `json:"protocol_version"`
	Scope           Scope     `json:"scope"`
	CSRSHA256       string    `json:"csr_sha256"`
	SPKISHA256      string    `json:"spki_sha256"`
	CertificatePEM  string    `json:"certificate_pem"`
	NodeCAPEM       string    `json:"node_ca_pem"`
	IssuedAt        time.Time `json:"issued_at"`
	NotAfter        time.Time `json:"not_after"`
}

func IdentityURI(scope Scope) (*url.URL, error) {
	for _, value := range []string{scope.ClusterID, scope.NodeID, scope.EnrollmentID, scope.KeyID} {
		if !telemetry.ValidIdentifier(value) {
			return nil, ErrInvalid
		}
	}
	return &url.URL{Scheme: "spiffe", Host: "sherlock", Path: "/node/" + scope.ClusterID + "/" + scope.NodeID + "/" + scope.EnrollmentID + "/" + scope.KeyID}, nil
}

func digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

// NewRequest receives a local key; it never returns or serializes that key.
func NewRequest(scope Scope, key ed25519.PrivateKey) (Request, error) {
	if _, err := IdentityURI(scope); err != nil || len(key) != ed25519.PrivateKeySize {
		return Request{}, ErrInvalid
	}
	if !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) {
		return Request{}, ErrInvalid
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}}, key)
	if err != nil {
		return Request{}, ErrUnavailable
	}
	public := key.Public().(ed25519.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return Request{}, ErrUnavailable
	}
	return Request{Version, scope, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), digest(der), digest(spki), base64.RawStdEncoding.EncodeToString(public)}, nil
}

func singlePEM(value, kind string) ([]byte, error) {
	if len(value) == 0 || len(value) > MaxPEMBytes {
		return nil, ErrInvalid
	}
	// Do not permit ignored preambles, additional objects, or PEM headers.
	if !strings.HasPrefix(value, "-----BEGIN "+kind+"-----") {
		return nil, ErrInvalid
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	return block.Bytes, nil
}

func ValidateRequest(request Request) (ed25519.PublicKey, error) {
	if request.ProtocolVersion != Version {
		return nil, ErrInvalid
	}
	if _, err := IdentityURI(request.Scope); err != nil {
		return nil, err
	}
	der, err := singlePEM(request.CSRPEM, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil || len(csr.Extensions) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 || !bytes.Equal(csr.RawSubject, []byte{0x30, 0}) {
		return nil, ErrInvalid
	}
	// Inspect the complete raw attribute set. The deprecated parsed Attributes
	// field can omit attributes whose values are outside its legacy shape.
	var info struct {
		Version            int
		Subject, PublicKey asn1.RawValue
		Attributes         []asn1.RawValue `asn1:"tag:0"`
	}
	rest, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &info)
	if err != nil || len(rest) != 0 || info.Version != 0 || len(info.Attributes) != 0 {
		return nil, ErrInvalid
	}
	public, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	if request.CSRSHA256 != digest(der) || request.SPKISHA256 != digest(csr.RawSubjectPublicKeyInfo) || len(request.PublicKeyBase64) != 43 || request.PublicKeyBase64 != base64.RawStdEncoding.EncodeToString(public) {
		return nil, ErrInvalid
	}
	return append(ed25519.PublicKey(nil), public...), nil
}

// ValidateRequestForGrant proves scope/key equality only. The caller must check
// current authenticated gateway, inventory and immutable enrollment authority
// transactionally. allowVerifyOnly is solely for committed historical retrieval.
func ValidateRequestForGrant(request Request, grant telemetry.Grant, at time.Time, allowVerifyOnly bool) error {
	public, err := ValidateRequest(request)
	if err != nil {
		return err
	}
	if telemetry.ValidateGrant(grant, at) != nil || request.Scope.ClusterID != grant.ClusterID || request.Scope.NodeID != grant.NodeID || request.Scope.EnrollmentID != grant.EnrollmentID {
		return ErrUnauthorized
	}
	for _, key := range grant.Keys {
		if key.ID == request.Scope.KeyID {
			if key.State != "ACTIVE" && !(allowVerifyOnly && key.State == "VERIFY_ONLY") {
				return ErrUnauthorized
			}
			expected, err := telemetry.ParseNodePublicKey(key)
			if err != nil || !bytes.Equal(public, expected) {
				return ErrUnauthorized
			}
			return nil
		}
	}
	return ErrUnauthorized
}

type Issuer struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	caPEM       string
}

func ParsePrivateKey(value string) (ed25519.PrivateKey, error) {
	der, err := singlePEM(value, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, ErrInvalid
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	return key, nil
}

func NewIssuer(caPEM, keyPEM string) (*Issuer, error) {
	der, err := singlePEM(caPEM, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || len(ca.UnhandledCriticalExtensions) != 0 || !bytes.Equal(ca.RawIssuer, ca.RawSubject) || ca.CheckSignatureFrom(ca) != nil {
		return nil, ErrInvalid
	}
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	public, ok := ca.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, key.Public().(ed25519.PublicKey)) {
		return nil, ErrInvalid
	}
	return &Issuer{ca, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))}, nil
}

func (issuer *Issuer) NodeCAFingerprint() string {
	if issuer == nil || issuer.certificate == nil {
		return ""
	}
	return digest(issuer.certificate.Raw)
}

// Issue signs a candidate only. Returning it before the atomic consume commits
// would violate the bootstrap protocol. This helper does not consume a token.
func (issuer *Issuer) Issue(request Request, at time.Time, lifetime time.Duration) (CertificateBundle, error) {
	public, err := ValidateRequest(request)
	if err != nil {
		return CertificateBundle{}, err
	}
	if issuer == nil || issuer.certificate == nil || at.IsZero() || lifetime <= 0 || lifetime > MaxCertificateLifetime || lifetime%time.Second != 0 {
		return CertificateBundle{}, ErrInvalid
	}
	at = at.Round(0).UTC().Truncate(time.Second)
	if at.Before(issuer.certificate.NotBefore) || !at.Before(issuer.certificate.NotAfter) || at.Add(lifetime).After(issuer.certificate.NotAfter) {
		return CertificateBundle{}, ErrUnavailable
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return CertificateBundle{}, ErrUnavailable
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	uri, _ := IdentityURI(request.Scope)
	before := at.Add(-time.Minute)
	if before.Before(issuer.certificate.NotBefore) {
		before = issuer.certificate.NotBefore
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{}, NotBefore: before, NotAfter: at.Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.certificate, public, issuer.key)
	if err != nil {
		return CertificateBundle{}, ErrUnavailable
	}
	return CertificateBundle{Version, request.Scope, request.CSRSHA256, request.SPKISHA256, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), issuer.caPEM, at, template.NotAfter}, nil
}

func VerifyImport(bundle CertificateBundle, request Request, key ed25519.PrivateKey, trustedNodeCAFingerprint string, at time.Time) error {
	public, err := ValidateRequest(request)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(public, key.Public().(ed25519.PublicKey)) || bundle.ProtocolVersion != Version || bundle.Scope != request.Scope || bundle.CSRSHA256 != request.CSRSHA256 || bundle.SPKISHA256 != request.SPKISHA256 || at.IsZero() {
		return ErrUnauthorized
	}
	caDER, err := singlePEM(bundle.NodeCAPEM, "CERTIFICATE")
	if err != nil {
		return err
	}
	if len(trustedNodeCAFingerprint) != 64 || digest(caDER) != trustedNodeCAFingerprint {
		return ErrUnauthorized
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || !bytes.Equal(ca.RawIssuer, ca.RawSubject) || ca.CheckSignatureFrom(ca) != nil {
		return ErrInvalid
	}
	der, err := singlePEM(bundle.CertificatePEM, "CERTIFICATE")
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ErrInvalid
	}
	certPublic, ok := cert.PublicKey.(ed25519.PublicKey)
	uri, _ := IdentityURI(request.Scope)
	if !ok || !bytes.Equal(public, certPublic) || cert.IsCA || !cert.BasicConstraintsValid || !bytes.Equal(cert.RawSubject, []byte{0x30, 0}) || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != uri.String() || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 || digest(cert.RawSubjectPublicKeyInfo) != bundle.SPKISHA256 {
		return ErrUnauthorized
	}
	if bundle.IssuedAt.IsZero() || !bundle.NotAfter.Equal(cert.NotAfter) || !bundle.IssuedAt.Before(cert.NotAfter) || cert.NotAfter.Sub(bundle.IssuedAt) > MaxCertificateLifetime || cert.NotBefore.After(bundle.IssuedAt) || bundle.IssuedAt.Sub(cert.NotBefore) > time.Minute || bundle.IssuedAt.After(at) || !at.Before(cert.NotAfter) {
		return ErrUnauthorized
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrUnauthorized
	}
	return nil
}
