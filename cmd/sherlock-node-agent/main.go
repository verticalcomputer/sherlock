// sherlock-node-agent runs an explicitly synthetic resident source over pinned
// node TLS. It neither installs itself nor has a command or cloud credential.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/verticalcomputer/sherlock/internal/nodegateway"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/nodetelemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetrylocal"
)

// Release tooling binds the reviewed source manifest, not a self-referential
// executable hash. Empty development values make no candidate provenance claim.
var releaseVersion string
var releaseSourceSHA256 string

type nodeConfig struct {
	Root            string                   `json:"root"`
	Scope           nodetelemetry.LocalScope `json:"scope"`
	SigningKeyID    string                   `json:"signing_key_id"`
	GatewayURL      string                   `json:"gateway_url"`
	CertificateFile string                   `json:"certificate_file"`
	PrivateKeyFile  string                   `json:"private_key_file"`
	IdentityDir     string                   `json:"identity_dir"`
	NodeCASHA256    string                   `json:"node_ca_sha256"`
	GatewayCAFile   string                   `json:"gateway_ca_file"`
	IntervalSeconds int64                    `json:"interval_seconds"`
	FixtureBootID   string                   `json:"fixture_boot_id"`
}

func loadConfig(path string) (nodeConfig, tls.Certificate, *x509.CertPool, error) {
	var c nodeConfig
	body, e := telemetrylocal.ReadProtected(path, 64<<10)
	if e != nil {
		return c, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
	}
	if telemetry.DecodeStrictJSON(body, "", &c) != nil || c.IntervalSeconds < 0 || c.IntervalSeconds > 86400 || c.IntervalSeconds > 0 && c.IntervalSeconds < 10 {
		return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
	}
	if c.FixtureBootID != "" && !telemetry.ValidIdentifier(c.FixtureBootID) {
		return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
	}
	if releaseSourceSHA256 != "" {
		digest, err := hex.DecodeString(releaseSourceSHA256)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != releaseSourceSHA256 || releaseVersion == "" || c.Scope.BuildSHA256 != releaseSourceSHA256 || c.Scope.AgentVersion != releaseVersion {
			return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
		}
	}
	var certPEM, keyPEM []byte
	if c.IdentityDir != "" {
		if c.CertificateFile != "" || c.PrivateKeyFile != "" || c.NodeCASHA256 == "" {
			return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
		}
		bundle, key, err := nodeidentity.LoadIdentity(c.IdentityDir, c.NodeCASHA256, time.Now())
		if err != nil || bundle.Scope != (nodeidentity.Scope{ClusterID: c.Scope.ClusterID, NodeID: c.Scope.NodeID, EnrollmentID: c.Scope.EnrollmentID, KeyID: c.SigningKeyID}) {
			return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
		}
		defer clear(der)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		certPEM = []byte(bundle.CertificatePEM + bundle.NodeCAPEM)
	} else {
		if c.NodeCASHA256 != "" {
			return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
		}
		certPEM, e = telemetrylocal.ReadProtected(c.CertificateFile, 64<<10)
		if e != nil {
			return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
		}
		keyPEM, e = telemetrylocal.ReadProtected(c.PrivateKeyFile, 64<<10)
		if e != nil {
			return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
		}
	}
	defer clear(keyPEM)
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
	}
	if _, ok := cert.PrivateKey.(ed25519.PrivateKey); !ok {
		return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	expected, uriErr := nodeidentity.IdentityURI(nodeidentity.Scope{ClusterID: c.Scope.ClusterID, NodeID: c.Scope.NodeID, EnrollmentID: c.Scope.EnrollmentID, KeyID: c.SigningKeyID})
	if err != nil || uriErr != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != expected.String() {
		return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
	}
	caPEM, e := telemetrylocal.ReadProtected(c.GatewayCAFile, 64<<10)
	if e != nil {
		return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(caPEM) {
		return nodeConfig{}, tls.Certificate{}, nil, nodetelemetry.ErrInvalid
	}
	return c, cert, ca, nil
}
func run(ctx context.Context, args []string, out, errs io.Writer) int {
	if len(args) > 0 && args[0] == "version" {
		if len(args) != 1 {
			fmt.Fprintln(errs, "node telemetry version arguments invalid")
			return 2
		}
		version, source := releaseVersion, releaseSourceSHA256
		if version == "" {
			version = "DEVELOPMENT"
		}
		if source == "" {
			source = "UNKNOWN"
		}
		if json.NewEncoder(out).Encode(struct {
			Version      string `json:"version"`
			SourceSHA256 string `json:"source_sha256"`
			Profile      string `json:"profile"`
		}{version, source, telemetry.FixtureProfile}) != nil {
			return 1
		}
		return 0
	}
	if len(args) > 0 && (args[0] == "identity-request" || args[0] == "identity-import") {
		return runIdentity(args, out, errs)
	}
	flags := flag.NewFlagSet("sherlock-node-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "protected local configuration")
	fixture := flags.Bool("fixture", false, "explicit synthetic source mode")
	if e := flags.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			fmt.Fprintln(out, "sherlock-node-agent --fixture --config <protected-local-config>\nSynthetic fixture.v1 only; no installation or hardware collection.")
			return 0
		}
		fmt.Fprintln(errs, "node telemetry arguments invalid")
		return 2
	}
	if flags.NArg() != 0 || !*fixture || *path == "" {
		fmt.Fprintln(errs, "node telemetry requires explicit fixture mode and protected configuration")
		return 2
	}
	c, identity, ca, e := loadConfig(*path)
	if e != nil {
		fmt.Fprintln(errs, "node telemetry configuration invalid")
		return 2
	}
	client, e := nodegateway.NewClientWithSigningKeys(c.GatewayURL, identity, ca, c.Scope.GatewaySPKISHA256, c.Scope.Keys)
	if e != nil {
		fmt.Fprintln(errs, "node telemetry gateway identity invalid")
		return 2
	}
	defer client.Close()
	// This is a Go GC target, not an OS-enforced RSS guarantee. Deployment/canary
	// must separately qualify the documented 128MiB process resource contract.
	priorLimit := debug.SetMemoryLimit(128 << 20)
	defer debug.SetMemoryLimit(priorLimit)
	runtimeConfig := nodetelemetry.Config{Root: c.Root, Scope: c.Scope, SigningKeyID: c.SigningKeyID, SigningKey: identity.PrivateKey.(ed25519.PrivateKey), Gateway: client, Interval: time.Duration(c.IntervalSeconds) * time.Second, Report: func(error) { fmt.Fprintln(errs, "node telemetry collection or delivery unavailable") }}
	if c.FixtureBootID != "" {
		runtimeConfig.BootID = func() (string, error) { return c.FixtureBootID, nil }
	}
	r, e := nodetelemetry.Open(ctx, runtimeConfig)
	if e != nil {
		fmt.Fprintln(errs, "node telemetry durable startup unavailable")
		return 1
	}
	defer r.Close()
	if e = r.Run(ctx); e != nil && !errors.Is(e, context.Canceled) {
		fmt.Fprintln(errs, "node telemetry runtime stopped")
		return 1
	}
	return 0
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
