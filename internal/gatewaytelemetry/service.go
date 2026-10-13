package gatewaytelemetry

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/nodegateway"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
	"github.com/verticalcomputer/sherlock/internal/telemetrylocal"
)

// ServiceConfig contains paths and public scope only. No credential is accepted
// inline; loading this file cannot confer cloud enrollment or node authority.
type ServiceConfig struct {
	ProtocolVersion          int      `json:"protocol_version"`
	FixtureOnly              bool     `json:"fixture_only"`
	ResidentSources          bool     `json:"resident_sources,omitempty"`
	ClusterID                string   `json:"cluster_id"`
	CollectorID              string   `json:"collector_id"`
	EnrollmentIDs            []string `json:"enrollment_ids"`
	Root                     string   `json:"root"`
	ListenAddress            string   `json:"listen_address"`
	ServerCertificateFile    string   `json:"server_certificate_file"`
	ServerKeyFile            string   `json:"server_key_file"`
	NodeCAFile               string   `json:"node_ca_file"`
	ControlURL               string   `json:"control_url"`
	ControlCAFile            string   `json:"control_ca_file"`
	ControlSPKISHA256        string   `json:"control_spki_sha256"`
	CollectorCertificateFile string   `json:"collector_certificate_file"`
	CollectorKeyFile         string   `json:"collector_key_file"`
	AuthMode                 string   `json:"auth_mode"`
	AccessTokenFile          string   `json:"access_token_file"`
}

func LoadConfig(path string) (ServiceConfig, error) {
	var c ServiceConfig
	body, e := telemetrylocal.ReadProtected(path, 64<<10)
	if e != nil {
		return c, e
	}
	if telemetry.DecodeStrictJSON(body, "", &c) != nil || c.ProtocolVersion != 1 || c.FixtureOnly == c.ResidentSources || !telemetry.ValidIdentifier(c.ClusterID) || !telemetry.ValidIdentifier(c.CollectorID) || len(c.EnrollmentIDs) == 0 || len(c.EnrollmentIDs) > 4096 || !filepath.IsAbs(c.Root) {
		return ServiceConfig{}, telemetry.ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range c.EnrollmentIDs {
		if !telemetry.ValidIdentifier(id) || seen[id] {
			return ServiceConfig{}, telemetry.ErrInvalid
		}
		seen[id] = true
	}
	if c.AuthMode != "direct_mtls" && c.AuthMode != "cloudflare_access_service_token_pop" {
		return ServiceConfig{}, telemetry.ErrInvalid
	}
	if c.AuthMode == "direct_mtls" && c.AccessTokenFile != "" || c.AuthMode == "cloudflare_access_service_token_pop" && c.AccessTokenFile == "" {
		return ServiceConfig{}, telemetry.ErrInvalid
	}
	return c, nil
}

// acceptsGrantSources keeps certificate relay and journal admission within the
// same explicit source mode. It does not replace current grant validation.
func acceptsGrantSources(c ServiceConfig, grant telemetry.Grant) bool {
	if c.FixtureOnly == c.ResidentSources || len(grant.Sources) == 0 {
		return false
	}
	for _, source := range grant.Sources {
		if !telemetry.KnownProfile(source.ProfileID) || c.FixtureOnly && source.ProfileID != telemetry.FixtureProfile {
			return false
		}
	}
	return true
}

func readCertificate(path string) (*x509.Certificate, *x509.CertPool, error) {
	body, e := telemetrylocal.ReadProtected(path, 64<<10)
	if e != nil {
		return nil, nil, e
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, nil, telemetry.ErrInvalid
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, telemetry.ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return cert, roots, nil
}
func readIdentity(certPath, keyPath string) (tls.Certificate, error) {
	cert, e := telemetrylocal.ReadProtected(certPath, 64<<10)
	if e != nil {
		return tls.Certificate{}, e
	}
	key, e := telemetrylocal.ReadProtected(keyPath, 16<<10)
	if e != nil {
		return tls.Certificate{}, e
	}
	defer clear(key)
	identity, e := tls.X509KeyPair(cert, key)
	if e != nil || len(identity.Certificate) == 0 {
		return tls.Certificate{}, telemetry.ErrInvalid
	}
	return identity, nil
}
func cloudTransport(c ServiceConfig, nodeCA *x509.Certificate) (*collectorruntime.TelemetryClient, *http.Transport, *x509.Certificate, error) {
	ca, roots, e := readCertificate(c.ControlCAFile)
	if e != nil {
		return nil, nil, nil, e
	}
	pin, e := hex.DecodeString(c.ControlSPKISHA256)
	if e != nil || len(pin) != 32 || hex.EncodeToString(pin) != c.ControlSPKISHA256 {
		return nil, nil, nil, telemetry.ErrInvalid
	}
	identity, e := readIdentity(c.CollectorCertificateFile, c.CollectorKeyFile)
	if e != nil {
		return nil, nil, nil, e
	}
	if nodeCA != nil && (nodeidentity.ValidateCASeparation(nodeCA, []*x509.Certificate{ca}) != nil || !separateNodeCA(identity, nodeCA)) {
		return nil, nil, nil, telemetry.ErrInvalid
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return telemetry.ErrUnauthorized
		}
		if nodeCA != nil {
			if nodeidentity.ValidateCASeparation(nodeCA, state.PeerCertificates) != nil {
				return telemetry.ErrUnauthorized
			}
			for _, chain := range state.VerifiedChains {
				if nodeidentity.ValidateCASeparation(nodeCA, chain) != nil {
					return telemetry.ErrUnauthorized
				}
			}
		}
		got := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if hex.EncodeToString(got[:]) != c.ControlSPKISHA256 {
			return telemetry.ErrUnauthorized
		}
		return nil
	}}
	transport := &http.Transport{TLSClientConfig: tc, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, DisableCompression: true}
	var round http.RoundTripper = transport
	switch c.AuthMode {
	case "direct_mtls":
		tc.Certificates = []tls.Certificate{identity}
	case "cloudflare_access_service_token_pop":
		body, e := telemetrylocal.ReadProtected(c.AccessTokenFile, 4<<10)
		if e != nil {
			return nil, nil, nil, e
		}
		defer clear(body)
		var token collectorruntime.AccessServiceToken
		if telemetry.DecodeStrictJSON(body, "", &token) != nil {
			return nil, nil, nil, telemetry.ErrInvalid
		}
		round, e = collectorruntime.NewAccessServiceTokenPoPRoundTripper(transport, token, identity)
		if e != nil {
			return nil, nil, nil, telemetry.ErrInvalid
		}
	default:
		return nil, nil, nil, telemetry.ErrInvalid
	}
	httpClient := &http.Client{Transport: round, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, e := collectorruntime.NewHTTPClient(c.ControlURL, httpClient, time.Minute)
	if e != nil {
		return nil, nil, nil, telemetry.ErrInvalid
	}
	cloud, e := collectorruntime.NewTelemetryClient(client, c.ClusterID, c.CollectorID)
	if e != nil {
		return nil, nil, nil, e
	}
	return cloud, transport, ca, nil
}

// Serve composes the explicitly selected telemetry gateway. It does not install a service or alter
// collector configuration. Current cloud authority is required before listening.
func Serve(ctx context.Context, c ServiceConfig, observer Observer) error {
	if c.ProtocolVersion != 1 || c.FixtureOnly == c.ResidentSources || !filepath.IsAbs(c.Root) {
		return telemetry.ErrInvalid
	}
	nodeCA, nodeRoots, e := readCertificate(c.NodeCAFile)
	if e != nil {
		return e
	}
	cloud, outbound, controlCA, e := cloudTransport(c, nodeCA)
	if e != nil {
		return e
	}
	defer outbound.CloseIdleConnections()
	if nodeCA.Equal(controlCA) {
		return telemetry.ErrInvalid
	}
	serverIdentity, e := readIdentity(c.ServerCertificateFile, c.ServerKeyFile)
	if e != nil {
		return e
	}
	if !separateNodeCA(serverIdentity, nodeCA) {
		return telemetry.ErrInvalid
	}
	tc, pin, e := nodegateway.ServerTLSConfig(serverIdentity, nodeRoots)
	if e != nil {
		return e
	}
	authority, e := nodegateway.NewAuthority(c.ClusterID, c.CollectorID, pin, c.EnrollmentIDs, cloud)
	if e != nil {
		return e
	}
	admission, e := nodegateway.NewGatewayAdmission(authority)
	if e != nil {
		return e
	}
	budget, e := telemetryjournal.OpenGatewayBudget(c.Root, telemetryjournal.DefaultGatewayAggregateLimits())
	if e != nil {
		return e
	}
	defer budget.Close()
	journals := map[string]*telemetryjournal.Queue{}
	drainQueues := map[string]Queue{}
	defer func() {
		for _, q := range journals {
			_ = q.Close()
		}
	}()
	for _, id := range c.EnrollmentIDs {
		grant, e := cloud.Grant(ctx, id)
		if e != nil {
			return e
		}
		if grant.GatewaySPKISHA256 != pin || !acceptsGrantSources(c, grant) {
			return telemetry.ErrUnauthorized
		}
		sources := make([]string, 0, len(grant.Sources))
		for _, source := range grant.Sources {
			sources = append(sources, source.SourceID)
		}
		q, e := telemetryjournal.Open(filepath.Join(c.Root, id), telemetryjournal.Options{Role: telemetryjournal.Gateway, Scope: telemetryjournal.Scope{ClusterID: grant.ClusterID, NodeID: grant.NodeID, EnrollmentID: id}, Limits: telemetryjournal.GatewayLimits(), Verifier: admission, SessionVerifier: admission, ReleaseVerifier: admission, PublicKeys: grant.Keys, RequireSessions: true, GatewayBudget: budget, SourceIDs: sources, Now: time.Now})
		if e != nil {
			return e
		}
		journals[id] = q
		drainQueues[id] = q
	}
	ingress, e := nodegateway.NewJournalIngress(journals)
	if e != nil {
		return e
	}
	handler, e := nodegateway.NewHandler(authority, ingress)
	if e != nil {
		return e
	}
	server, e := nodegateway.NewServer(c.ListenAddress, handler, tc)
	if e != nil {
		return e
	}
	runtime, e := New(drainQueues, cloud, observer)
	if e != nil {
		return e
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	drained := make(chan error, 1)
	served := make(chan error, 1)
	go func() { drained <- runtime.Run(child) }()
	go func() { served <- server.ListenAndServeTLS("", "") }()
	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-served:
		served = nil
	case result = <-drained:
		drained = nil
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if e := server.Shutdown(shutdown); e != nil {
		_ = server.Close()
		result = errors.Join(result, telemetry.ErrUnavailable)
	}
	if served != nil {
		e := <-served
		if !errors.Is(e, http.ErrServerClosed) {
			result = errors.Join(result, telemetry.ErrUnavailable)
		}
	}
	if drained != nil {
		e := <-drained
		if e != nil && !errors.Is(e, context.Canceled) {
			result = errors.Join(result, telemetry.ErrUnavailable)
		}
	}
	return result
}

func separateNodeCA(identity tls.Certificate, nodeCA *x509.Certificate) bool {
	if len(identity.Certificate) == 0 || nodeCA == nil {
		return false
	}
	if len(identity.Certificate) > nodeidentity.MaxSeparationCertificates {
		return false
	}
	chain := make([]*x509.Certificate, 0, len(identity.Certificate))
	for _, der := range identity.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return false
		}
		chain = append(chain, cert)
	}
	return nodeidentity.ValidateCASeparation(nodeCA, chain) == nil
}
