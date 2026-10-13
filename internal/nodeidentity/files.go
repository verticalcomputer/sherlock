package nodeidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"golang.org/x/sys/unix"
)

const (
	PrivateKeyFile = "node-key.pem"
	RequestFile    = "identity-request.json"
	BundleFile     = "identity.json"
)

type directory struct {
	fd   int
	lock *os.File
}

func openDirectory(path string) (*directory, error) {
	fd, err := secureDirectory(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 {
		unix.Close(fd)
		return nil, ErrUnauthorized
	}
	d := &directory{fd: fd}
	lock, err := d.open("identity.lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		d.close()
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		d.close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrInUse
		}
		return nil, ErrUnavailable
	}
	d.lock = lock
	return d, nil
}

// secureDirectory retains the checked final descriptor. Every ancestor is
// traversed with NOFOLLOW before creation; writable non-root ancestors fail.
// Only Darwin's explicit root-owned /var and /tmp aliases are resolved.
func secureDirectory(path string) (int, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || absolute == "/" {
		return -1, ErrInvalid
	}
	if runtime.GOOS == "darwin" {
		for _, alias := range []string{"/var", "/tmp"} {
			if absolute == alias || strings.HasPrefix(absolute, alias+"/") {
				var st unix.Stat_t
				target, readErr := os.Readlink(alias)
				if unix.Lstat(alias, &st) != nil || readErr != nil || st.Uid != 0 || target != "private"+alias {
					return -1, ErrUnauthorized
				}
				absolute = "/private" + absolute
			}
		}
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), "/"), "/")
	for index, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if unix.Mkdirat(fd, part, 0o700) != nil || unix.Fsync(fd) != nil {
				unix.Close(fd)
				return -1, ErrUnavailable
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			unix.Close(fd)
			return -1, ErrUnauthorized
		}
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil {
			unix.Close(next)
			unix.Close(fd)
			return -1, ErrUnavailable
		}
		final := index == len(parts)-1
		trusted := st.Uid == uint32(os.Geteuid()) || !final && st.Uid == 0
		stickyRoot := !final && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if !trusted || st.Mode&0o022 != 0 && !stickyRoot || final && st.Mode&0o777 != 0o700 {
			unix.Close(next)
			unix.Close(fd)
			return -1, ErrUnauthorized
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func (d *directory) close() {
	if d.lock != nil {
		_ = d.lock.Close()
	}
	_ = unix.Close(d.fd)
}

func (d *directory) open(name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(d.fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, ErrUnavailable
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		unix.Close(fd)
		return nil, ErrUnauthorized
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (d *directory) read(name string, limit int) ([]byte, error) {
	file, err := d.open(name, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(data) > limit {
		return nil, ErrInvalid
	}
	return data, nil
}

// atomicWrite checks an existing destination before replacement. The private
// directory and process lock prevent another authorized process interleaving.
// Rename never follows a destination symlink, and directory fsync owns success.
func (d *directory) atomicWrite(name string, data []byte) error {
	if file, err := d.open(name, unix.O_RDONLY); err == nil {
		file.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrUnavailable
	}
	staging := ".identity-" + digest(random[:])[:32]
	file, err := d.open(staging, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(d.fd, staging, 0)
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	if unix.Renameat(d.fd, staging, d.fd, name) != nil || unix.Fsync(d.fd) != nil {
		return ErrUnavailable
	}
	return nil
}

func privatePEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// CreateIdentityRequest creates or resumes a durable local key/request pair.
// It never regenerates a corrupt key or silently changes an existing scope.
func CreateIdentityRequest(path string, scope Scope) (Request, error) {
	if _, err := IdentityURI(scope); err != nil {
		return Request{}, err
	}
	d, err := openDirectory(path)
	if err != nil {
		return Request{}, err
	}
	defer d.close()
	keyBytes, err := d.read(PrivateKeyFile, MaxPEMBytes)
	var key ed25519.PrivateKey
	if errors.Is(err, os.ErrNotExist) {
		// A request without its private key cannot be repaired by generating one.
		if _, requestErr := d.read(RequestFile, MaxRequestBytes); !errors.Is(requestErr, os.ErrNotExist) {
			return Request{}, ErrUnauthorized
		}
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Request{}, ErrUnavailable
		}
		keyBytes, err = privatePEM(key)
		if err != nil {
			return Request{}, err
		}
		if err = d.atomicWrite(PrivateKeyFile, keyBytes); err != nil {
			return Request{}, err
		}
	} else if err != nil {
		return Request{}, err
	}
	if key == nil {
		key, err = ParsePrivateKey(string(keyBytes))
		if err != nil {
			return Request{}, err
		}
	}
	old, err := d.read(RequestFile, MaxRequestBytes)
	if err == nil {
		var request Request
		if telemetry.DecodeStrictJSON(old, "", &request) != nil {
			return Request{}, ErrInvalid
		}
		public, err := ValidateRequest(request)
		if err != nil || request.Scope != scope || !public.Equal(key.Public()) {
			return Request{}, ErrUnauthorized
		}
		return request, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Request{}, err
	}
	request, err := NewRequest(scope, key)
	if err != nil {
		return Request{}, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return Request{}, ErrUnavailable
	}
	if err = d.atomicWrite(RequestFile, encoded); err != nil {
		return Request{}, err
	}
	return request, nil
}

// ImportIdentity verifies against independently approved trust and the durable
// original request/key before atomically replacing only the public bundle.
func ImportIdentity(path string, bundle CertificateBundle, trustedNodeCAFingerprint string, at time.Time) error {
	d, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer d.close()
	keyBytes, err := d.read(PrivateKeyFile, MaxPEMBytes)
	if err != nil {
		return err
	}
	key, err := ParsePrivateKey(string(keyBytes))
	if err != nil {
		return err
	}
	requestBytes, err := d.read(RequestFile, MaxRequestBytes)
	if err != nil {
		return err
	}
	var request Request
	if telemetry.DecodeStrictJSON(requestBytes, "", &request) != nil {
		return ErrInvalid
	}
	if err = VerifyImport(bundle, request, key, trustedNodeCAFingerprint, at); err != nil {
		return err
	}
	encoded, err := json.Marshal(bundle)
	if err != nil || len(encoded) > MaxBundleBytes {
		return ErrInvalid
	}
	return d.atomicWrite(BundleFile, encoded)
}

// LoadIdentity verifies the current public bundle on every load. It returns the
// private key only to the local TLS composition root; callers must not print it.
func LoadIdentity(path, trustedNodeCAFingerprint string, at time.Time) (CertificateBundle, ed25519.PrivateKey, error) {
	d, err := openDirectory(path)
	if err != nil {
		return CertificateBundle{}, nil, err
	}
	defer d.close()
	keyBytes, err := d.read(PrivateKeyFile, MaxPEMBytes)
	if err != nil {
		return CertificateBundle{}, nil, err
	}
	key, err := ParsePrivateKey(string(keyBytes))
	if err != nil {
		return CertificateBundle{}, nil, err
	}
	requestBytes, err := d.read(RequestFile, MaxRequestBytes)
	if err != nil {
		return CertificateBundle{}, nil, err
	}
	bundleBytes, err := d.read(BundleFile, MaxBundleBytes)
	if err != nil {
		return CertificateBundle{}, nil, err
	}
	var request Request
	var bundle CertificateBundle
	if telemetry.DecodeStrictJSON(requestBytes, "", &request) != nil || telemetry.DecodeStrictJSON(bundleBytes, "", &bundle) != nil {
		return CertificateBundle{}, nil, ErrInvalid
	}
	if err = VerifyImport(bundle, request, key, trustedNodeCAFingerprint, at); err != nil {
		return CertificateBundle{}, nil, err
	}
	return bundle, key, nil
}
