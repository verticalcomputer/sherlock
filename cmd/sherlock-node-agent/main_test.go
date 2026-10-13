package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/nodegateway"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/nodetelemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func protectedConfig(t *testing.T) (string, nodeConfig) {
	t.Helper()
	root := t.TempDir()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	identityURI, _ := nodegateway.NodeIdentityURI("cluster-a", "node-a", "enrollment-a", "key-a")
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, IsCA: true, URIs: []*url.URL{identityURI}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	c := nodeConfig{Root: filepath.Join(root, "queue"), Scope: nodetelemetry.LocalScope{ClusterID: "cluster-a", NodeID: "node-a", EnrollmentID: "enrollment-a", InventoryRevisionID: "inventory-a", SourceIDs: []string{"fixture-a"}, AgentVersion: "fixture-agent", BuildSHA256: strings.Repeat("a", 64), GatewaySPKISHA256: strings.Repeat("b", 64), Keys: []telemetry.NodeKey{{ID: "key-a", Epoch: "1", State: "ACTIVE", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(public)}}}, SigningKeyID: "key-a", GatewayURL: "https://gateway.invalid", CertificateFile: filepath.Join(root, "node.crt"), PrivateKeyFile: filepath.Join(root, "node.key"), GatewayCAFile: filepath.Join(root, "gateway-ca.crt")}
	for path, body := range map[string][]byte{c.CertificateFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.PrivateKeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), c.GatewayCAFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})} {
		if e = os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
	}
	body, _ := json.Marshal(c)
	path := filepath.Join(root, "config.json")
	if e = os.WriteFile(path, body, 0600); e != nil {
		t.Fatal(e)
	}
	return path, c
}

func TestFixtureOptInAndFixedSafeErrors(t *testing.T) {
	for _, args := range [][]string{{"--config", "private-path-secret"}, {"--fixture", "--config", "private-path-secret", "--unknown=private-token-secret"}, {"--fixture", "--config", "private-path-secret"}} {
		var out, errs bytes.Buffer
		if run(context.Background(), args, &out, &errs) == 0 {
			t.Fatal("invalid arguments accepted")
		}
		if strings.Contains(errs.String(), "private-") {
			t.Fatal("private argument leaked")
		}
	}
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &out, &errs); code != 0 || !strings.Contains(out.String(), "Synthetic fixture.v1 only") {
		t.Fatal("help contract")
	}
}

func TestProtectedStrictConfigurationAndKeyInputs(t *testing.T) {
	path, c := protectedConfig(t)
	if parsed, _, _, e := loadConfig(path); e != nil || parsed.Scope.EnrollmentID != c.Scope.EnrollmentID {
		t.Fatal("valid protected fixture", e)
	}
	for _, body := range []string{`{"root":"a","root":"b"}`, `{"unknown":"private-body-secret"}`, `{} {}`, `{"interval_seconds":9223372036854775807}`, `{"interval_seconds":1}`} {
		if e := os.WriteFile(path, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if _, _, _, e := loadConfig(path); e == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	body, _ := json.Marshal(c)
	_ = os.WriteFile(path, body, 0600)
	if e := os.Chmod(c.PrivateKeyFile, 0644); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := loadConfig(path); e == nil {
		t.Fatal("world-readable private key accepted")
	}
	_ = os.Chmod(c.PrivateKeyFile, 0600)
	link := filepath.Join(filepath.Dir(path), "config-link.json")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := loadConfig(link); e == nil {
		t.Fatal("symlink config accepted")
	}
}

func TestLocalIdentityCommandsAndImportedConfiguration(t *testing.T) {
	path, c := protectedConfig(t)
	directory := filepath.Join(filepath.Dir(path), "identity")
	args := []string{"identity-request", "--directory", directory, "--cluster", c.Scope.ClusterID, "--node", c.Scope.NodeID, "--enrollment", c.Scope.EnrollmentID, "--key", c.SigningKeyID}
	var out, errs bytes.Buffer
	if run(context.Background(), args, &out, &errs) != 0 {
		t.Fatal("local request", errs.String())
	}
	if strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatal("private key emitted")
	}
	var request nodeidentity.Request
	if telemetry.DecodeStrictJSON(out.Bytes(), "", &request) != nil {
		t.Fatal("public request JSON")
	}
	firstKey, e := os.ReadFile(filepath.Join(directory, nodeidentity.PrivateKeyFile))
	if e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if run(context.Background(), args, &out, &errs) != 0 {
		t.Fatal("request retry")
	}
	again, _ := os.ReadFile(filepath.Join(directory, nodeidentity.PrivateKeyFile))
	if !bytes.Equal(firstKey, again) {
		t.Fatal("request retry replaced private key")
	}
	caPEM, _ := os.ReadFile(c.GatewayCAFile)
	caKeyPEM, _ := os.ReadFile(c.PrivateKeyFile)
	issuer, e := nodeidentity.NewIssuer(string(caPEM), string(caKeyPEM))
	if e != nil {
		t.Fatal(e)
	}
	bundle, e := issuer.Issue(request, time.Now().Add(-time.Second), time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(bundle)
	bundlePath := filepath.Join(filepath.Dir(path), "bundle.json")
	if e = os.WriteFile(bundlePath, wire, 0600); e != nil {
		t.Fatal(e)
	}
	importArgs := []string{"identity-import", "--directory", directory, "--bundle", bundlePath, "--node-ca-sha256", issuer.NodeCAFingerprint()}
	out.Reset()
	if run(context.Background(), importArgs, &out, &errs) != 0 {
		t.Fatal("identity import", errs.String())
	}
	if strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatal("import emitted private key")
	}
	c.IdentityDir = directory
	c.NodeCASHA256 = issuer.NodeCAFingerprint()
	c.CertificateFile = ""
	c.PrivateKeyFile = ""
	c.Scope.Keys[0].PublicKeyBase64 = request.PublicKeyBase64
	c.FixtureBootID = "explicit-synthetic-boot"
	encoded, _ := json.Marshal(c)
	_ = os.WriteFile(path, encoded, 0600)
	if _, _, _, e = loadConfig(path); e != nil {
		t.Fatal("imported identity config", e)
	}
	c.CertificateFile = bundlePath
	encoded, _ = json.Marshal(c)
	_ = os.WriteFile(path, encoded, 0600)
	if _, _, _, e = loadConfig(path); e == nil {
		t.Fatal("mixed identity alternatives accepted")
	}
	c.CertificateFile = ""
	c.Scope.NodeID = "foreign-node"
	encoded, _ = json.Marshal(c)
	_ = os.WriteFile(path, encoded, 0600)
	if _, _, _, e = loadConfig(path); e == nil {
		t.Fatal("foreign imported scope accepted")
	}
	importArgs[len(importArgs)-1] = strings.Repeat("0", 64)
	out.Reset()
	errs.Reset()
	if run(context.Background(), importArgs, &out, &errs) == 0 || strings.Contains(errs.String(), directory) {
		t.Fatal("untrusted import accepted or path leaked")
	}
	if _, _, e = nodeidentity.LoadIdentity(directory, issuer.NodeCAFingerprint(), time.Now()); e != nil {
		t.Fatal("failed import replaced prior identity")
	}
}

func TestReleaseSourceBindingAndPublicVersion(t *testing.T) {
	oldVersion, oldSource := releaseVersion, releaseSourceSHA256
	t.Cleanup(func() { releaseVersion = oldVersion; releaseSourceSHA256 = oldSource })
	releaseVersion = ""
	releaseSourceSHA256 = ""
	var out, errs bytes.Buffer
	if run(context.Background(), []string{"version"}, &out, &errs) != 0 || !strings.Contains(out.String(), "DEVELOPMENT") || !strings.Contains(out.String(), "UNKNOWN") {
		t.Fatal("development version claim")
	}
	path, c := protectedConfig(t)
	releaseVersion = c.Scope.AgentVersion
	releaseSourceSHA256 = c.Scope.BuildSHA256
	if _, _, _, e := loadConfig(path); e != nil {
		t.Fatal("matching source candidate rejected", e)
	}
	out.Reset()
	if run(context.Background(), []string{"version"}, &out, &errs) != 0 || !strings.Contains(out.String(), releaseSourceSHA256) || strings.Contains(out.String(), "PRIVATE") {
		t.Fatal("candidate public version")
	}
	for _, field := range []string{"version", "digest"} {
		bad := c
		if field == "version" {
			bad.Scope.AgentVersion = "foreign-candidate"
		} else {
			bad.Scope.BuildSHA256 = strings.Repeat("0", 64)
		}
		body, _ := json.Marshal(bad)
		_ = os.WriteFile(path, body, 0600)
		if _, _, _, e := loadConfig(path); e == nil {
			t.Fatal("candidate mismatch admitted", field)
		}
	}
}
