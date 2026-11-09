// sherlock-prometheus-identity rotates the scheduled upload identity offline.
// Only the issue command needs the bastion's CA key and issuer database role.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"golang.org/x/sys/unix"
)

func input(path string, private bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || (private && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("invalid identity input permissions or type")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		return nil, errors.New("identity input empty, unreadable or oversized")
	}
	return raw, nil
}

func output(path string, data []byte) error {
	if err := collectorruntime.PrivateUploadDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func lockIdentity(dir string) (func(), error) {
	if err := collectorruntime.PrivateUploadDirectory(dir); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(dir, ".rotation.lock"), unix.O_CREAT|unix.O_NOFOLLOW|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("another identity operation is in progress: %w", err)
	}
	return func() { _ = unix.Close(fd) }, nil
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("expected request, issue, status, stage or switch")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := fs.String("identity-dir", "", "private head identity directory")
	cluster := fs.String("cluster", "", "expected cluster")
	collector := fs.String("collector", "", "expected collector UUID")
	pin := fs.String("ca-sha256", "", "existing collector CA DER fingerprint")
	cert := fs.String("cert", "", "leaf input or issuance output")
	key := fs.String("key", "", "head leaf key input or request key output")
	ca := fs.String("ca", "", "collector CA public file")
	caKey := fs.String("ca-key", "", "bastion CA private key file")
	csr := fs.String("csr", "", "certificate request path")
	expected := fs.String("expect", "", "expected current serial (or absent for first head switch)")
	fingerprint := fs.String("expect-sha256", "", "expected current leaf DER fingerprint")
	target := fs.String("target", "", "head version to select")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if args[0] == "request" {
		private, request, err := collectorruntime.GenerateIdentityRequest()
		if err != nil {
			return err
		}
		defer clear(private)
		if err := output(*key, private); err != nil {
			return err
		}
		return output(*csr, request)
	}
	decoded, err := hex.DecodeString(*pin)
	if *collector == "" || *cluster == "" || err != nil || len(decoded) != 32 {
		return errors.New("collector, cluster and CA pin are required")
	}
	identity := collectorruntime.UploadIdentity{Directory: *dir, Cluster: *cluster, Collector: *collector, CAPin: *pin}
	now := time.Now()
	switch args[0] {
	case "status":
		return status(identity)
	case "issue":
		return issue(identity, *expected, *fingerprint, *csr, *ca, *caKey, *cert, now)
	case "stage":
		unlock, err := lockIdentity(*dir)
		if err != nil {
			return err
		}
		defer unlock()
		leaf, err := input(*cert, false)
		if err != nil {
			return err
		}
		private, err := input(*key, true)
		if err != nil {
			return err
		}
		defer clear(private)
		roots, err := input(*ca, false)
		if err != nil {
			return err
		}
		version, err := identity.Stage(leaf, private, roots, now)
		if err == nil {
			fmt.Println(version)
		}
		return err
	case "switch":
		unlock, err := lockIdentity(*dir)
		if err != nil {
			return err
		}
		defer unlock()
		return identity.Switch(*expected, *target, now)
	default:
		return errors.New("expected request, issue, status, stage or switch")
	}
}

func issue(scope collectorruntime.UploadIdentity, previous, fingerprint, csr, ca, caKey, cert string, now time.Time) error {
	if err := collectorruntime.PrivateUploadDirectory(filepath.Dir(cert)); err != nil {
		return err
	}
	if _, err := os.Lstat(cert); !os.IsNotExist(err) {
		return errors.New("issuance output must not exist")
	}
	raw, err := hex.DecodeString(fingerprint)
	if err != nil || len(raw) != 32 || previous == "" {
		return errors.New("expected previous serial and fingerprint are required")
	}
	request, err := input(csr, false)
	if err != nil {
		return err
	}
	roots, err := input(ca, false)
	if err != nil {
		return err
	}
	if _, err := collectorruntime.PinnedUploadCA(roots, scope.CAPin); err != nil {
		return err
	}
	private, err := input(caKey, true)
	if err != nil {
		return err
	}
	defer clear(private)
	issuer, err := collectorcontrol.NewCAIssuer(roots, private, rand.Reader)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	pool, err := issuerPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		return err
	}
	cluster, collector := domain.ClusterID(scope.Cluster), domain.CollectorID(scope.Collector)
	next, err := issuer.Issue(cluster, collector, request, now, 12*time.Hour)
	if err != nil {
		return err
	}
	// Preserve the leaf before committing its registration. If there is an
	// ambiguous commit, compare the database receipt before transferring it.
	if err := output(cert, next.CertificatePEM); err != nil {
		return err
	}
	if err := store.RegisterPrometheusRenewal(ctx, cluster, collector, previous, [32]byte(raw), next); err != nil {
		return fmt.Errorf("registration did not confirm; do not transfer %s: %w", filepath.Base(cert), err)
	}
	fmt.Printf("registered serial=%s not_after=%s ttl_seconds=%s\n", next.Serial, next.NotAfter.UTC().Format(time.RFC3339), strconv.Itoa(12*3600))
	return nil
}

func issuerPool(ctx context.Context) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(os.Getenv("SHERLOCK_PROMETHEUS_ISSUER_DATABASE_URL"))
	if err != nil {
		return nil, errors.New("invalid issuer DSN")
	}
	conn := config.ConnConfig
	if os.Getenv("SHERLOCK_PROMETHEUS_ISSUER_DATABASE_URL") == "" ||
		!(filepath.IsAbs(conn.Host) || net.ParseIP(conn.Host).IsLoopback()) ||
		len(conn.Fallbacks) != 0 || conn.User == "" || conn.Database == "" {
		return nil, errors.New("issuer database must be explicitly configured on loopback or a local socket")
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("could not configure issuer database")
	}
	return pool, nil
}

// status reads the current registered certificate so an automation retry can
// distinguish a committed issuance from a saved but unregistered certificate.
func status(scope collectorruntime.UploadIdentity) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := issuerPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	var serial, fingerprint string
	var expiry time.Time
	var valid bool
	err = pool.QueryRow(ctx, `
		SELECT i.certificate_serial, encode(i.certificate_sha256,'hex'), i.not_after,
		       i.not_before <= clock_timestamp() AND i.not_after > clock_timestamp()
		FROM public.collectors c JOIN public.collector_identities i
		  ON i.collector_id=c.collector_id AND i.certificate_serial=c.identity_serial
		WHERE c.collector_id=$1 AND c.cluster_id=$2 AND c.status='ACTIVE'
		  AND i.revoked_at IS NULL AND i.superseded_at IS NULL`, scope.Collector, scope.Cluster).
		Scan(&serial, &fingerprint, &expiry, &valid)
	if err != nil {
		return fmt.Errorf("read current registered upload identity: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Serial      string `json:"serial"`
		Fingerprint string `json:"fingerprint"`
		Expires     int64  `json:"expires"`
		Valid       bool   `json:"valid"`
	}{serial, fingerprint, expiry.Unix(), valid})
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
