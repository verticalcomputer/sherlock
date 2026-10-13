package nodeidentity

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
)

const MaxSeparationCertificates = 16

// ParseCertificateChain accepts bounded certificate-only PEM chains. Parsing
// alone never makes a certificate a trust anchor or verifies current validity.
func ParseCertificateChain(body []byte) ([]*x509.Certificate, error) {
	if len(body) == 0 || len(body) > 64<<10 {
		return nil, ErrInvalid
	}
	var chain []*x509.Certificate
	for len(bytes.TrimSpace(body)) > 0 {
		if len(chain) >= MaxSeparationCertificates || !bytes.HasPrefix(bytes.TrimSpace(body), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalid
		}
		block, rest := pem.Decode(body)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalid
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, ErrInvalid
		}
		chain = append(chain, cert)
		body = rest
	}
	if len(chain) == 0 {
		return nil, ErrInvalid
	}
	return chain, nil
}

// ValidateCASeparation rejects authority shared with the dedicated node CA.
// Reissued/cross-signed certificates cannot hide a reused public key. Checking
// every presented/verified chain member catches intermediates, not just leaves.
// Normal TLS verification and pinning must still independently succeed.
func ValidateCASeparation(nodeCA *x509.Certificate, others []*x509.Certificate) error {
	if nodeCA == nil || !nodeCA.IsCA || !nodeCA.BasicConstraintsValid || nodeCA.KeyUsage&x509.KeyUsageCertSign == 0 || len(nodeCA.RawSubjectPublicKeyInfo) == 0 || len(others) == 0 || len(others) > MaxSeparationCertificates {
		return ErrInvalid
	}
	for _, other := range others {
		if other == nil || len(other.RawSubjectPublicKeyInfo) == 0 {
			return ErrInvalid
		}
		// Parsing/marshalling the actual key normalizes SPKI representation rather
		// than comparing certificate serials, names, encodings or file paths.
		nodeKey, e := x509.MarshalPKIXPublicKey(nodeCA.PublicKey)
		if e != nil {
			return ErrInvalid
		}
		otherKey, e := x509.MarshalPKIXPublicKey(other.PublicKey)
		if e != nil || bytes.Equal(nodeKey, otherKey) {
			return ErrInvalid
		}
		if other.CheckSignatureFrom(nodeCA) == nil || other.IsCA && nodeCA.CheckSignatureFrom(other) == nil {
			return ErrInvalid
		}
	}
	return nil
}
