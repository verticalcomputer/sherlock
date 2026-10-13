package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func TestConfigureNodeIdentityRejectsSharedAuthorityAcrossFullChain(t *testing.T) {
	key := func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	cert := func(serial int64, ca bool, k ed25519.PrivateKey, parent *x509.Certificate, signer ed25519.PrivateKey) *x509.Certificate {
		now := time.Now()
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Synthetic control boundary"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			template.KeyUsage |= x509.KeyUsageCertSign
		}
		if parent == nil {
			parent = template
			signer = k
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, k.Public(), signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	nodeKey, otherKey, intermediateKey := key(), key(), key()
	node := cert(1, true, nodeKey, nil, nil)
	reissue := cert(2, true, nodeKey, nil, nil)
	other := cert(3, true, otherKey, nil, nil)
	intermediate := cert(4, true, intermediateKey, node, nodeKey)
	leaf := cert(5, false, key(), intermediate, intermediateKey)
	certPEM := func(c *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	private, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name              string
		collector, server []byte
	}{{"reissued collector CA", certPEM(reissue), certPEM(other)}, {"node-issued intermediate in server chain", certPEM(other), append(certPEM(leaf), certPEM(intermediate)...)}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name string, body []byte) string {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			cfg := config.Control{NodeCA: write("node.pem", certPEM(node)), NodeCAPrivateKey: write("node-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), CollectorCA: write("collector.pem", tc.collector), ServerCertificate: write("server.pem", tc.server)}
			// Nil transport deliberately proves admission fails before route wiring.
			if err := configureNodeIdentity(cfg, nil, nil); !errors.Is(err, telemetry.ErrInvalid) {
				t.Fatalf("shared authority not rejected: %v", err)
			}
		})
	}
}
