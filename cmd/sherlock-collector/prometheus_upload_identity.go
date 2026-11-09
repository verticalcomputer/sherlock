package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/config"
)

func prometheusUploadHTTPClient(cfg config.Collector, probe bool) (*http.Client, error) {
	candidate := os.Getenv("SHERLOCK_PROMETHEUS_PROBE_IDENTITY_VERSION")
	if candidate != "" && !probe {
		return nil, fmt.Errorf("identity version override is for signed readiness only")
	}
	pin := os.Getenv("SHERLOCK_PROMETHEUS_IDENTITY_CA_SHA256")
	if pin == "" {
		if candidate != "" {
			return nil, fmt.Errorf("identity version override requires the pinned identity store")
		}
		return controlHTTPClient(cfg.Transport())
	}
	if cfg.IdentityDir == "" || cfg.TransportAuthMode != config.CollectorTransportCloudflareAccessServiceTokenPoP ||
		os.Getenv("SHERLOCK_COLLECTOR_ID") == "" {
		return nil, fmt.Errorf("rotating upload identity requires an explicit collector, identity directory and Access PoP transport")
	}
	identity := collectorruntime.UploadIdentity{Directory: cfg.IdentityDir, Cluster: cfg.ClusterID, Collector: cfg.CollectorID, CAPin: pin}
	// Check filesystem scope and configuration before doing any work. A leaf
	// that later expires is rejected per request without losing the spool.
	current := func() (string, error) {
		if candidate != "" {
			return candidate, nil
		}
		return identity.Current()
	}
	version, err := current()
	if err != nil {
		return nil, err
	}
	if _, err := identity.Load(version, time.Now()); err != nil {
		return nil, err
	}
	rootsPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return nil, fmt.Errorf("upload control CA has no certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	return &http.Client{
		Timeout: cfg.RequestTimeout,
		Transport: collectorruntime.NewRotatingAccessServiceTokenPoP(transport, func() (tls.Certificate, error) {
			version, err := current()
			if err != nil {
				return tls.Certificate{}, err
			}
			return identity.Load(version, time.Now())
		}, func() (collectorruntime.AccessServiceToken, error) {
			return collectorruntime.ReadAccessServiceToken(strings.TrimSpace(cfg.AccessServiceTokenFile))
		}),
	}, nil
}
