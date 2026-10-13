package nodeidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func separationCertificate(t *testing.T, serial int64, ca bool, key ed25519.PrivateKey, parent *x509.Certificate, signer ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	at := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Synthetic separation"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = template
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func separationKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestCASeparationRejectsReissueAndIntermediateAuthority(t *testing.T) {
	nodeKey := separationKey(t)
	nodeCA := separationCertificate(t, 1, true, nodeKey, nil, nil)
	reissued := separationCertificate(t, 2, true, nodeKey, nil, nil)
	if bytes.Equal(nodeCA.Raw, reissued.Raw) {
		t.Fatal("fixture certificates should differ")
	}
	intermediateKey := separationKey(t)
	intermediate := separationCertificate(t, 3, true, intermediateKey, nodeCA, nodeKey)
	leaf := separationCertificate(t, 4, false, separationKey(t), intermediate, intermediateKey)
	independentKey := separationKey(t)
	independentCA := separationCertificate(t, 5, true, independentKey, nil, nil)
	independentLeaf := separationCertificate(t, 6, false, separationKey(t), independentCA, independentKey)
	crossSigned := separationCertificate(t, 7, true, nodeKey, independentCA, independentKey)
	for name, chain := range map[string][]*x509.Certificate{"reissued": {reissued}, "intermediate": {leaf, intermediate}, "crosssigned_same_key": {crossSigned}, "node_under_collector_root": {independentCA, crossSigned}} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(ValidateCASeparation(nodeCA, chain), ErrInvalid) {
				t.Fatal("shared node authority accepted")
			}
		})
	}
	if ValidateCASeparation(nodeCA, []*x509.Certificate{independentLeaf, independentCA}) != nil {
		t.Fatal("independent chain rejected")
	}
	// A node CA signed by a collector root also violates separation even when
	// the duplicate node key certificate is omitted from the other chain.
	if ValidateCASeparation(crossSigned, []*x509.Certificate{independentCA}) == nil {
		t.Fatal("collector authority over node CA accepted")
	}
}

func TestCertificateSeparationParserBounds(t *testing.T) {
	cert := separationCertificate(t, 1, true, separationKey(t), nil, nil)
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if chain, err := ParseCertificateChain(append(append([]byte(" \n"), body...), []byte("\n")...)); err != nil || len(chain) != 1 {
		t.Fatalf("valid chain: %v", err)
	}
	for _, bad := range [][]byte{nil, append([]byte("junk\n"), body...), append(append([]byte(nil), body...), []byte("junk")...), bytes.Repeat(body, 17), bytes.Repeat([]byte("x"), 64<<10+1), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cert.Raw})} {
		if _, err := ParseCertificateChain(bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed/unbounded chain accepted")
		}
	}
	if ValidateCASeparation(cert, make([]*x509.Certificate, 17)) == nil || ValidateCASeparation(cert, []*x509.Certificate{nil}) == nil {
		t.Fatal("invalid chain accepted")
	}
}

func TestCSRRejectsUnknownRawAttributes(t *testing.T) {
	f := newFixture(t)
	der, err := singlePEM(f.request.CSRPEM, "CERTIFICATE REQUEST")
	if err != nil {
		t.Fatal(err)
	}
	var csr struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err = asn1.Unmarshal(der, &csr); err != nil {
		t.Fatal(err)
	}
	var info struct {
		Version            int
		Subject, PublicKey asn1.RawValue
		Attributes         []asn1.RawValue `asn1:"tag:0"`
	}
	if _, err = asn1.Unmarshal(csr.Info.FullBytes, &info); err != nil {
		t.Fatal(err)
	}
	// A valid signed unknown attribute with an arbitrary SET value must be
	// rejected even if x509's legacy parsed Attributes would omit it.
	attribute, err := asn1.Marshal(struct {
		ID     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{asn1.ObjectIdentifier{1, 2, 3, 4}, []asn1.RawValue{{Tag: asn1.TagOctetString, Bytes: []byte("opaque")}}})
	if err != nil {
		t.Fatal(err)
	}
	info.Attributes = []asn1.RawValue{{FullBytes: attribute}}
	raw, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	csr.Info = asn1.RawValue{FullBytes: raw}
	signature := ed25519.Sign(f.key, raw)
	csr.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	der, err = asn1.Marshal(csr)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil || parsed.CheckSignature() != nil {
		t.Fatalf("fixture signed CSR invalid: %v", err)
	}
	request := f.request
	request.CSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	request.CSRSHA256 = digest(der)
	if _, err = ValidateRequest(request); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown CSR attribute accepted")
	}
}
