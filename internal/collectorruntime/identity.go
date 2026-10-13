package collectorruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"
)

type BootstrapToken struct{ value []byte }

func (BootstrapToken) String() string   { return "[REDACTED]" }
func (BootstrapToken) GoString() string { return "[REDACTED]" }

func ReadBootstrapToken(reader io.Reader) (*BootstrapToken, error) {
	if reader == nil {
		return nil, fmt.Errorf("bootstrap token input is required")
	}
	limited := io.LimitReader(reader, 257)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap token: %w", err)
	}
	value := bytes.TrimSpace(raw)
	if len(value) < 32 || len(value) > 256 || bytes.ContainsAny(value, " \t\r\n") {
		clear(raw)
		return nil, fmt.Errorf("bootstrap token must contain 32 to 256 non-whitespace bytes")
	}
	token := &BootstrapToken{value: append([]byte(nil), value...)}
	clear(raw)
	return token, nil
}

func ReadBootstrapTokenFile(path string) (*BootstrapToken, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect bootstrap token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("bootstrap token file must be a regular owner-only file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open bootstrap token file: %w", err)
	}
	defer file.Close()
	return ReadBootstrapToken(file)
}

func (t *BootstrapToken) clear() {
	if t != nil {
		clear(t.value)
		t.value = nil
	}
}

func (t *BootstrapToken) Clear() { t.clear() }

type CollectorMetadata struct {
	DisplayName     string
	Version         string
	BuildCommit     string
	OperatingSystem string
	Architecture    string
}

type IssuedIdentity struct {
	CollectorID    string
	CertificatePEM []byte
	CAChainPEM     []byte
	NotBefore      time.Time
	NotAfter       time.Time
}

type metadataWire struct {
	DisplayName     string `json:"display_name"`
	Version         string `json:"version"`
	BuildCommit     string `json:"build_commit"`
	ProtocolMin     int    `json:"protocol_min"`
	ProtocolMax     int    `json:"protocol_max"`
	OperatingSystem string `json:"operating_system"`
	Architecture    string `json:"architecture"`
}
type enrollWire struct {
	CSRPEM   string       `json:"csr_pem"`
	Metadata metadataWire `json:"metadata"`
}
type renewIdentityWire struct {
	CSRPEM string `json:"csr_pem"`
}
type identityWire struct {
	CollectorID    string    `json:"collector_id,omitempty"`
	CertificatePEM string    `json:"certificate_pem"`
	CAChainPEM     string    `json:"ca_chain_pem"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}

func (c *HTTPClient) Enroll(ctx context.Context, token *BootstrapToken, csrPEM []byte, metadata CollectorMetadata) (IssuedIdentity, error) {
	if token == nil || len(token.value) == 0 {
		return IssuedIdentity{}, fmt.Errorf("bootstrap token is required")
	}
	body := enrollWire{CSRPEM: string(csrPEM), Metadata: metadataWire{
		DisplayName: metadata.DisplayName, Version: metadata.Version, BuildCommit: metadata.BuildCommit,
		ProtocolMin: ProtocolVersion, ProtocolMax: ProtocolVersion, OperatingSystem: metadata.OperatingSystem, Architecture: metadata.Architecture,
	}}
	var response identityWire
	_, err := c.doWithHeaders(ctx, "POST", "/collector/v1/enroll", body, &response, map[string]string{"Authorization": "Bearer " + string(token.value)}, 201)
	if err != nil {
		return IssuedIdentity{}, err
	}
	return identityFromWire(response), nil
}

func (c *HTTPClient) RenewIdentity(ctx context.Context, csrPEM []byte) (IssuedIdentity, error) {
	var response identityWire
	_, err := c.do(ctx, "POST", "/collector/v1/identity/renew", renewIdentityWire{CSRPEM: string(csrPEM)}, &response, 200)
	if err != nil {
		return IssuedIdentity{}, err
	}
	return identityFromWire(response), nil
}

func identityFromWire(wire identityWire) IssuedIdentity {
	return IssuedIdentity{CollectorID: wire.CollectorID, CertificatePEM: []byte(wire.CertificatePEM), CAChainPEM: []byte(wire.CAChainPEM), NotBefore: wire.NotBefore.UTC(), NotAfter: wire.NotAfter.UTC()}
}

func GenerateIdentityRequest() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate collector private key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode collector private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"Sherlock collectors"}}}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create collector certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func ValidateIssuedIdentity(identity IssuedIdentity, privateKeyPEM []byte, expectedCollectorID string, now time.Time) (*x509.Certificate, error) {
	keyBlock, rest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("collector private key is invalid")
	}
	privateAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse collector private key: %w", err)
	}
	privateKey, ok := privateAny.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("collector private key is not P-256")
	}
	certificateBlock, rest := pem.Decode(identity.CertificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("collector certificate response is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse collector certificate: %w", err)
	}
	certificatePublic, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certificatePublic.Equal(&privateKey.PublicKey) {
		return nil, fmt.Errorf("collector certificate does not match generated private key")
	}
	if expectedCollectorID != "" && certificate.Subject.CommonName != expectedCollectorID {
		return nil, fmt.Errorf("collector certificate identity does not match expected collector")
	}
	if len(certificate.URIs) != 1 || certificate.URIs[0].Scheme != "spiffe" || certificate.URIs[0].Host != "sherlock" || !strings.HasSuffix(certificate.URIs[0].Path, "/collector/"+expectedCollectorID) {
		return nil, fmt.Errorf("collector certificate SPIFFE identity is invalid")
	}
	if identity.NotBefore.IsZero() || identity.NotAfter.IsZero() || !identity.NotBefore.Truncate(time.Second).Equal(certificate.NotBefore) || !identity.NotAfter.Truncate(time.Second).Equal(certificate.NotAfter) {
		return nil, fmt.Errorf("collector certificate validity metadata does not match certificate")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(identity.CAChainPEM) {
		return nil, fmt.Errorf("collector CA chain response is invalid")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now.UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("verify issued collector certificate: %w", err)
	}
	return certificate, nil
}

func PersistIdentity(directory string, identity IssuedIdentity, privateKeyPEM []byte, expectedCollectorID string, now time.Time) error {
	collectorID := expectedCollectorID
	if collectorID == "" {
		collectorID = identity.CollectorID
	}
	if collectorID == "" || strings.ContainsAny(collectorID, "/\\\x00") {
		return fmt.Errorf("issued collector identifier is invalid")
	}
	certificate, err := ValidateIssuedIdentity(identity, privateKeyPEM, collectorID, now)
	if err != nil {
		return err
	}
	versions := filepath.Join(directory, "versions")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return fmt.Errorf("create collector identity directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("restrict collector identity directory: %w", err)
	}
	if err := os.Chmod(versions, 0o700); err != nil {
		return fmt.Errorf("restrict collector identity versions: %w", err)
	}
	versionName := certificate.SerialNumber.Text(16) + "-" + fmt.Sprint(certificate.NotAfter.Unix())
	staging, err := os.MkdirTemp(versions, ".identity-*")
	if err != nil {
		return fmt.Errorf("stage collector identity: %w", err)
	}
	defer os.RemoveAll(staging)
	for _, file := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"key.pem", privateKeyPEM, 0o600}, {"cert.pem", identity.CertificatePEM, 0o644}, {"ca.pem", identity.CAChainPEM, 0o644}, {"collector_id", []byte(collectorID + "\n"), 0o600}} {
		if err := writeSynced(filepath.Join(staging, file.name), file.data, file.mode); err != nil {
			return err
		}
	}
	finalDirectory := filepath.Join(versions, versionName)
	if err := os.Rename(staging, finalDirectory); err != nil {
		return fmt.Errorf("publish collector identity version: %w", err)
	}
	linkTemporary := filepath.Join(directory, ".current-"+versionName)
	if err := os.Symlink(filepath.Join("versions", versionName), linkTemporary); err != nil {
		return fmt.Errorf("stage collector identity pointer: %w", err)
	}
	if err := os.Rename(linkTemporary, filepath.Join(directory, "current")); err != nil {
		_ = os.Remove(linkTemporary)
		return fmt.Errorf("activate collector identity: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open collector identity directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync collector identity directory: %w", err)
	}
	return nil
}

func writeSynced(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create collector identity file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write collector identity file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync collector identity file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close collector identity file: %w", err)
	}
	return nil
}

func ReadTokenFromStdin(input *os.File, output io.Writer) (*BootstrapToken, error) {
	if input == nil {
		return nil, fmt.Errorf("standard input is unavailable")
	}
	if term.IsTerminal(int(input.Fd())) {
		if output != nil {
			_, _ = io.WriteString(output, "Bootstrap token: ")
		}
		raw, err := term.ReadPassword(int(input.Fd()))
		if output != nil {
			_, _ = io.WriteString(output, "\n")
		}
		if err != nil {
			return nil, fmt.Errorf("read bootstrap token: %w", err)
		}
		defer clear(raw)
		return ReadBootstrapToken(bytes.NewReader(raw))
	}
	return ReadBootstrapToken(bufio.NewReader(input))
}

func DefaultCollectorMetadata(displayName, version, commit string) CollectorMetadata {
	return CollectorMetadata{DisplayName: displayName, Version: version, BuildCommit: commit, OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH}
}
