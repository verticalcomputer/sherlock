package collectorruntime

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var uploadIdentityVersion = regexp.MustCompile("^[0-9a-f]{2,32}$")

// UploadIdentity is separate from the legacy collector identity directory.
type UploadIdentity struct {
	Directory, Cluster, Collector, CAPin string
}

func PinnedUploadCA(raw []byte, pin string) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("exactly one pinned collector CA is required")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	fingerprint := sha256.Sum256(block.Bytes)
	if err != nil || !ca.IsCA || hex.EncodeToString(fingerprint[:]) != pin {
		return nil, fmt.Errorf("collector CA pin mismatch")
	}
	return ca, nil
}

func PrivateUploadDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("identity directory must be an absolute clean path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return fmt.Errorf("identity directory cannot traverse symbolic links")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("identity directory must be private (0700)")
	}
	return nil
}

func (s UploadIdentity) Current() (string, error) {
	if err := PrivateUploadDirectory(s.Directory); err != nil {
		return "", err
	}
	link, err := os.Readlink(filepath.Join(s.Directory, "current"))
	version := filepath.Base(link)
	if err != nil || link != filepath.Join("versions", version) || !uploadIdentityVersion.MatchString(version) {
		return "", fmt.Errorf("invalid upload identity pointer")
	}
	return version, nil
}

func (s UploadIdentity) Load(version string, at time.Time) (tls.Certificate, error) {
	if !uploadIdentityVersion.MatchString(version) {
		return tls.Certificate{}, fmt.Errorf("invalid upload identity version")
	}
	dir := filepath.Join(s.Directory, "versions", version)
	for _, path := range []string{s.Directory, filepath.Dir(dir), dir} {
		if err := PrivateUploadDirectory(path); err != nil {
			return tls.Certificate{}, err
		}
	}
	cert, err := readUploadIdentityFile(filepath.Join(dir, "cert.pem"), false)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := readUploadIdentityFile(filepath.Join(dir, "key.pem"), true)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(key)
	ca, err := readUploadIdentityFile(filepath.Join(dir, "ca.pem"), false)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := ValidateUploadIdentity(cert, key, ca, s.Cluster, s.Collector, s.CAPin, at)
	if err != nil {
		return tls.Certificate{}, err
	}
	if UploadIdentitySerial(pair.Leaf) != version {
		return tls.Certificate{}, fmt.Errorf("upload identity serial differs from version")
	}
	return pair, nil
}

func UploadIdentitySerial(leaf *x509.Certificate) string {
	return hex.EncodeToString(leaf.SerialNumber.Bytes())
}

func ValidateUploadIdentity(cert, key, ca []byte, cluster, collector, pin string, at time.Time) (tls.Certificate, error) {
	root, err := PinnedUploadCA(ca, pin)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) != 1 {
		return tls.Certificate{}, fmt.Errorf("invalid upload identity key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	uri := "spiffe://sherlock/cluster/" + cluster + "/collector/" + collector
	if cluster == "" || collector == "" || leaf.Subject.CommonName != collector || len(leaf.URIs) != 1 || leaf.URIs[0].String() != uri || leaf.IsCA {
		return tls.Certificate{}, fmt.Errorf("upload identity scope mismatch")
	}
	// Enforce the exact algorithm and key matching required by PoP.
	if _, err := NewAccessServiceTokenPoPRoundTripper(http.DefaultTransport, AccessServiceToken{"validation", "validation"}, pair); err != nil {
		return tls.Certificate{}, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return tls.Certificate{}, fmt.Errorf("verify upload leaf: %w", err)
	}
	pair.Leaf = leaf
	return pair, nil
}

func readUploadIdentityFile(path string, secret bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<10 || (secret && info.Mode().Perm() != 0o600) {
		return nil, fmt.Errorf("invalid upload identity file %s", filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if err != nil || len(data) > 16<<10 {
		return nil, fmt.Errorf("oversized or unreadable upload identity file")
	}
	return data, nil
}

// Stage writes a new immutable version without changing the current pointer.
func (s UploadIdentity) Stage(cert, key, ca []byte, at time.Time) (string, error) {
	pair, err := ValidateUploadIdentity(cert, key, ca, s.Cluster, s.Collector, s.CAPin, at)
	if err != nil {
		return "", err
	}
	versions := filepath.Join(s.Directory, "versions")
	for _, path := range []string{s.Directory, versions} {
		if err := PrivateUploadDirectory(path); err != nil {
			return "", err
		}
	}
	version := UploadIdentitySerial(pair.Leaf)
	if !uploadIdentityVersion.MatchString(version) {
		return "", fmt.Errorf("invalid upload identity serial")
	}
	dest := filepath.Join(versions, version)
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		return "", fmt.Errorf("upload identity version already exists or cannot be inspected")
	}
	stage, err := os.MkdirTemp(versions, ".stage-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	for name, data := range map[string][]byte{"cert.pem": cert, "key.pem": key, "ca.pem": ca} {
		if err := writeSynced(filepath.Join(stage, name), data, 0o600); err != nil {
			return "", err
		}
	}
	if err := syncUploadDirectory(stage); err != nil {
		return "", err
	}
	if err := os.Rename(stage, dest); err != nil {
		return "", err
	}
	return version, syncUploadDirectory(versions)
}

// Switch atomically selects a validated version, including during rollback.
// The caller must serialize writes and probe the selected identity first.
func (s UploadIdentity) Switch(expected, target string, at time.Time) error {
	if _, err := s.Load(target, at); err != nil {
		return err
	}
	if expected == "absent" {
		if _, err := os.Lstat(filepath.Join(s.Directory, "current")); !os.IsNotExist(err) {
			return fmt.Errorf("upload identity pointer already exists or cannot be inspected")
		}
	} else if current, err := s.Current(); err != nil || current != expected {
		return fmt.Errorf("upload identity pointer changed since preflight")
	}
	tmp, err := os.MkdirTemp(s.Directory, ".switch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	link := filepath.Join(tmp, "current")
	if err := os.Symlink(filepath.Join("versions", target), link); err != nil {
		return err
	}
	if err := os.Rename(link, filepath.Join(s.Directory, "current")); err != nil {
		return err
	}
	return syncUploadDirectory(s.Directory)
}

func syncUploadDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
