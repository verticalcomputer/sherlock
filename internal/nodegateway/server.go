package nodegateway

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// ServerTLSConfig requires a dedicated node client CA and TLS 1.3 mutual
// authentication. It returns the server SPKI pin for approved enrollment. It
// does not generate certificates, open a listener or install a service.
func ServerTLSConfig(identity tls.Certificate, nodeCA *x509.CertPool) (*tls.Config, string, error) {
	if len(identity.Certificate) == 0 || identity.PrivateKey == nil || nodeCA == nil {
		return nil, "", telemetry.ErrInvalid
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil || leaf.IsCA {
		return nil, "", telemetry.ErrInvalid
	}
	identity.Leaf = leaf
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, ClientCAs: nodeCA, ClientAuth: tls.RequireAndVerifyClientCert}, hex.EncodeToString(pin[:]), nil
}

// NewServer supplies bounded request/header/idle lifetimes. Start and shutdown
// are explicit caller operations; creating this value never mutates a node.
func NewServer(address string, handler *Handler, tlsConfig *tls.Config) (*http.Server, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" || handler == nil || tlsConfig == nil || tlsConfig.MinVersion < tls.VersionTLS13 || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		return nil, telemetry.ErrInvalid
	}
	return &http.Server{Addr: address, Handler: handler, TLSConfig: tlsConfig.Clone(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}, nil
}
