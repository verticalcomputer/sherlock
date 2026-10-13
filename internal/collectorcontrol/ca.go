package collectorcontrol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type CAIssuer struct {
	certificate *x509.Certificate
	signer      crypto.Signer
	chainPEM    []byte
	random      io.Reader
}

func NewCAIssuer(certificatePEM, privateKeyPEM []byte, random io.Reader) (*CAIssuer, error) {
	if random == nil {
		return nil, fmt.Errorf("certificate random source is required")
	}
	certificateBlock, rest := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("exactly one CA certificate is required")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("certificate is not a signing CA")
	}
	keyBlock, rest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("exactly one CA private key is required")
	}
	privateKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	publicFromKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("encode CA public key: %w", err)
	}
	publicFromCertificate, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode CA certificate public key: %w", err)
	}
	if !bytes.Equal(publicFromKey, publicFromCertificate) {
		return nil, fmt.Errorf("CA certificate and private key do not match")
	}
	return &CAIssuer{certificate: certificate, signer: privateKey, chainPEM: append([]byte(nil), certificatePEM...), random: random}, nil
}

func (i *CAIssuer) Issue(clusterID domain.ClusterID, collectorID domain.CollectorID, csrPEM []byte, now time.Time, lifetime time.Duration) (IssuedIdentity, error) {
	if clusterID == "" || collectorID == "" {
		return IssuedIdentity{}, fmt.Errorf("cluster and collector identifiers are required")
	}
	if lifetime < 5*time.Minute || lifetime > 24*time.Hour {
		return IssuedIdentity{}, fmt.Errorf("certificate lifetime must be between five minutes and 24 hours")
	}
	csrBlock, rest := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return IssuedIdentity{}, fmt.Errorf("exactly one PEM certificate request is required")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return IssuedIdentity{}, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedIdentity{}, fmt.Errorf("verify certificate request: %w", err)
	}
	if err := validateCollectorPublicKey(csr.PublicKey); err != nil {
		return IssuedIdentity{}, err
	}
	if now.UTC().Before(i.certificate.NotBefore) || !now.UTC().Before(i.certificate.NotAfter) {
		return IssuedIdentity{}, fmt.Errorf("collector CA is not currently valid")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := randInt(i.random, serialLimit)
	if err != nil {
		return IssuedIdentity{}, fmt.Errorf("create certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notBefore := now.UTC().Add(-time.Minute)
	if notBefore.Before(i.certificate.NotBefore) {
		notBefore = i.certificate.NotBefore.UTC()
	}
	notAfter := now.UTC().Add(lifetime)
	if notAfter.After(i.certificate.NotAfter) {
		return IssuedIdentity{}, fmt.Errorf("collector certificate would outlive its CA")
	}
	identityPath := "/cluster/" + string(clusterID) + "/collector/" + string(collectorID)
	identityURI := &url.URL{
		Scheme: "spiffe", Host: "sherlock", Path: identityPath,
		RawPath: "/cluster/" + url.PathEscape(string(clusterID)) + "/collector/" + url.PathEscape(string(collectorID)),
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: string(collectorID), Organization: []string{"Sherlock collectors"}},
		NotBefore:    notBefore, NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{identityURI},
	}
	der, err := x509.CreateCertificate(i.random, template, i.certificate, csr.PublicKey, i.signer)
	if err != nil {
		return IssuedIdentity{}, fmt.Errorf("sign collector certificate: %w", err)
	}
	fingerprint := sha256.Sum256(der)
	return IssuedIdentity{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CAChainPEM:     append([]byte(nil), i.chainPEM...), Serial: hex.EncodeToString(serial.Bytes()),
		Fingerprint: fingerprint, NotBefore: notBefore, NotAfter: notAfter,
	}, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("parse CA private key")
}

func validateCollectorPublicKey(publicKey any) error {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return fmt.Errorf("collector ECDSA key must be at least P-256")
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("collector RSA key must be at least 2048 bits")
		}
	default:
		return fmt.Errorf("collector key algorithm is not supported")
	}
	return nil
}

func randInt(random io.Reader, max *big.Int) (*big.Int, error) {
	if max.Sign() <= 0 {
		return nil, fmt.Errorf("random upper bound must be positive")
	}
	bytesNeeded := (max.BitLen() + 7) / 8
	buffer := make([]byte, bytesNeeded)
	for {
		if _, err := io.ReadFull(random, buffer); err != nil {
			return nil, err
		}
		excess := uint(bytesNeeded*8 - max.BitLen())
		buffer[0] &= byte(0xff >> excess)
		value := new(big.Int).SetBytes(buffer)
		if value.Cmp(max) < 0 {
			return value, nil
		}
	}
}
