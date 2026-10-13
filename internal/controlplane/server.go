package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/verticalcomputer/sherlock/internal/config"
)

const maxHeaderBytes = 64 << 10

// LoadTLSConfig permits certificate-less enrollment handshakes. Every client
// certificate that is supplied must chain to the collector CA; the transport
// separately rejects certificate-less requests on all non-enrollment routes.
func LoadTLSConfig(cfg config.Control) (*tls.Config, error) {
	serverCertificatePEM, err := os.ReadFile(cfg.ServerCertificate)
	if err != nil {
		return nil, fmt.Errorf("read control server certificate: %w", err)
	}
	serverPrivateKeyPEM, err := ReadProtectedPrivateKey(cfg.ServerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load control server private key: %w", err)
	}
	serverCertificate, err := tls.X509KeyPair(serverCertificatePEM, serverPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load control server identity: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CollectorCA)
	if err != nil {
		return nil, fmt.Errorf("read collector CA certificate: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("collector CA file contains no certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientCAs,
	}, nil
}

func NewHTTPServer(cfg config.Control, handler http.Handler, tlsConfig *tls.Config) (*http.Server, error) {
	if handler == nil || tlsConfig == nil {
		return nil, fmt.Errorf("control handler and TLS configuration are required")
	}
	return &http.Server{
		Addr: cfg.ListenAddress, Handler: handler, TLSConfig: tlsConfig,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}, nil
}

// ReadProtectedPrivateKey rejects keys readable by group or other users.
func ReadProtectedPrivateKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect private key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("private key path must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key file permissions must not allow group or other access")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	return contents, nil
}
