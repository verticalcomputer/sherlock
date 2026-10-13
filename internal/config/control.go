package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

type CollectorAuthMode string

const (
	CollectorAuthDirectMTLS                      CollectorAuthMode = "direct_mtls"
	CollectorAuthCloudflareAccessServiceTokenPoP CollectorAuthMode = "cloudflare_access_service_token_pop"
)

type Control struct {
	DatabaseURL           string
	ListenAddress         string
	ServerCertificate     string
	ServerPrivateKey      string
	CollectorCA           string
	CollectorCAPrivateKey string
	NodeCA                string
	NodeCAPrivateKey      string
	CollectorAuthMode     CollectorAuthMode
	CloudflareTeamDomain  string
	CloudflareAudience    string
	TrustedProxyPrefixes  []netip.Prefix
	CollectorHostname     string
	EnrollmentHostname    string
	IdentityTTL           time.Duration
	ReadHeaderTimeout     time.Duration
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration
	ShutdownTimeout       time.Duration
	// DiagnosticExecutionCollectors names the collectors permitted to claim and
	// execute reviewed diagnostic work. It is empty by default: a control plane
	// that grants no collector execution exposes no execution endpoints at all.
	DiagnosticExecutionCollectors []string
	// CredentialKeyring enables operation-bound credential delivery for the
	// BCM access test. Without it the control plane mounts no delivery route.
	CredentialKeyring CredentialKeyringConfig
}

func LoadControl() (Control, error) {
	if err := loadLocalEnv(); err != nil {
		return Control{}, err
	}
	cfg := Control{
		DatabaseURL:           os.Getenv("SHERLOCK_DATABASE_URL"),
		ListenAddress:         valueOrDefault("SHERLOCK_CONTROL_ADDRESS", "127.0.0.1:8443"),
		ServerCertificate:     os.Getenv("SHERLOCK_CONTROL_CERT_FILE"),
		ServerPrivateKey:      os.Getenv("SHERLOCK_CONTROL_KEY_FILE"),
		CollectorCA:           os.Getenv("SHERLOCK_COLLECTOR_CA_FILE"),
		CollectorCAPrivateKey: os.Getenv("SHERLOCK_COLLECTOR_CA_KEY_FILE"),
		NodeCA:                os.Getenv("SHERLOCK_NODE_CA_FILE"),
		NodeCAPrivateKey:      os.Getenv("SHERLOCK_NODE_CA_KEY_FILE"),
		CollectorAuthMode:     CollectorAuthMode(valueOrDefault("SHERLOCK_CONTROL_COLLECTOR_AUTH_MODE", string(CollectorAuthDirectMTLS))),
		IdentityTTL:           12 * time.Hour,
		ReadHeaderTimeout:     5 * time.Second,
		ReadTimeout:           15 * time.Second,
		WriteTimeout:          45 * time.Second,
		IdleTimeout:           60 * time.Second,
		ShutdownTimeout:       10 * time.Second,
	}
	var err error
	for name, target := range map[string]*time.Duration{
		"SHERLOCK_COLLECTOR_IDENTITY_TTL":      &cfg.IdentityTTL,
		"SHERLOCK_CONTROL_READ_HEADER_TIMEOUT": &cfg.ReadHeaderTimeout,
		"SHERLOCK_CONTROL_READ_TIMEOUT":        &cfg.ReadTimeout,
		"SHERLOCK_CONTROL_WRITE_TIMEOUT":       &cfg.WriteTimeout,
		"SHERLOCK_CONTROL_IDLE_TIMEOUT":        &cfg.IdleTimeout,
		"SHERLOCK_CONTROL_SHUTDOWN_TIMEOUT":    &cfg.ShutdownTimeout,
	} {
		if *target, err = durationEnv(name, *target); err != nil {
			return Control{}, err
		}
	}
	if cfg.DatabaseURL == "" || cfg.ListenAddress == "" {
		return Control{}, fmt.Errorf("SHERLOCK_DATABASE_URL and SHERLOCK_CONTROL_ADDRESS are required")
	}
	for _, value := range strings.Split(os.Getenv("SHERLOCK_DIAGNOSTIC_EXECUTION_COLLECTORS"), ",") {
		if collectorID := strings.TrimSpace(value); collectorID != "" {
			cfg.DiagnosticExecutionCollectors = append(cfg.DiagnosticExecutionCollectors, collectorID)
		}
	}
	if cfg.ServerCertificate == "" || cfg.ServerPrivateKey == "" || cfg.CollectorCA == "" || cfg.CollectorCAPrivateKey == "" {
		return Control{}, fmt.Errorf("control server certificate, key, collector CA, and collector CA key files are required")
	}
	if (cfg.NodeCA == "") != (cfg.NodeCAPrivateKey == "") {
		return Control{}, fmt.Errorf("node CA certificate and key must be configured together")
	}
	if keyringPath := strings.TrimSpace(os.Getenv("SHERLOCK_CREDENTIAL_KEYRING_FILE")); keyringPath != "" {
		if cfg.CredentialKeyring, err = loadCredentialKeyring(keyringPath); err != nil {
			return Control{}, err
		}
	}
	if err := loadCollectorAuth(&cfg); err != nil {
		return Control{}, err
	}
	if cfg.IdentityTTL < 5*time.Minute || cfg.IdentityTTL > 24*time.Hour {
		return Control{}, fmt.Errorf("collector identity lifetime must be between five minutes and 24 hours")
	}
	if cfg.ReadHeaderTimeout <= 0 || cfg.ReadTimeout <= 0 || cfg.WriteTimeout < 31*time.Second || cfg.IdleTimeout <= 0 || cfg.ShutdownTimeout <= 0 {
		return Control{}, fmt.Errorf("control server timeouts must be positive and write timeout must allow bounded long polling")
	}
	return cfg, nil
}

func loadCollectorAuth(cfg *Control) error {
	switch cfg.CollectorAuthMode {
	case CollectorAuthDirectMTLS:
		return nil
	case CollectorAuthCloudflareAccessServiceTokenPoP:
	default:
		return fmt.Errorf("SHERLOCK_CONTROL_COLLECTOR_AUTH_MODE must be direct_mtls or cloudflare_access_service_token_pop")
	}
	host, _, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("SHERLOCK_CONTROL_ADDRESS must be a loopback IP listener in cloudflare_access_service_token_pop mode")
	}
	team, err := url.Parse(strings.TrimSpace(os.Getenv("SHERLOCK_CLOUDFLARE_ACCESS_TEAM_DOMAIN")))
	if err != nil || team.Scheme != "https" || team.Host == "" || team.User != nil || team.RawQuery != "" || team.Fragment != "" || (team.Path != "" && team.Path != "/") {
		return fmt.Errorf("SHERLOCK_CLOUDFLARE_ACCESS_TEAM_DOMAIN must be an absolute HTTPS origin")
	}
	cfg.CloudflareTeamDomain = strings.TrimSuffix(team.String(), "/")
	cfg.CloudflareAudience = strings.TrimSpace(os.Getenv("SHERLOCK_CLOUDFLARE_ACCESS_AUDIENCE"))
	if cfg.CloudflareAudience == "" || strings.ContainsAny(cfg.CloudflareAudience, ", \t\r\n") {
		return fmt.Errorf("SHERLOCK_CLOUDFLARE_ACCESS_AUDIENCE must contain exactly one non-empty audience")
	}
	for _, raw := range strings.Split(os.Getenv("SHERLOCK_CONTROL_TRUSTED_PROXY_CIDRS"), ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !prefix.Addr().IsLoopback() {
			return fmt.Errorf("SHERLOCK_CONTROL_TRUSTED_PROXY_CIDRS must contain only loopback CIDRs")
		}
		cfg.TrustedProxyPrefixes = append(cfg.TrustedProxyPrefixes, prefix.Masked())
	}
	if len(cfg.TrustedProxyPrefixes) == 0 {
		return fmt.Errorf("SHERLOCK_CONTROL_TRUSTED_PROXY_CIDRS is required in cloudflare_access_service_token_pop mode")
	}
	cfg.CollectorHostname = normalizeDNSHostname(os.Getenv("SHERLOCK_CONTROL_COLLECTOR_HOST"))
	cfg.EnrollmentHostname = normalizeDNSHostname(os.Getenv("SHERLOCK_CONTROL_ENROLLMENT_HOST"))
	if cfg.CollectorHostname == "" || cfg.EnrollmentHostname == "" || cfg.CollectorHostname == cfg.EnrollmentHostname {
		return fmt.Errorf("distinct SHERLOCK_CONTROL_COLLECTOR_HOST and SHERLOCK_CONTROL_ENROLLMENT_HOST DNS names are required")
	}
	return nil
}

func normalizeDNSHostname(raw string) string {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(host) < 1 || len(host) > 253 || net.ParseIP(host) != nil || strings.ContainsAny(host, ":/ \t\r\n") {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return ""
			}
		}
	}
	if !strings.Contains(host, ".") {
		return ""
	}
	return host
}

type ControlAdmin struct {
	DatabaseURL  string
	BootstrapTTL time.Duration
}

func LoadControlAdmin() (ControlAdmin, error) {
	if err := loadLocalEnv(); err != nil {
		return ControlAdmin{}, err
	}
	cfg := ControlAdmin{DatabaseURL: os.Getenv("SHERLOCK_DATABASE_URL"), BootstrapTTL: 30 * time.Minute}
	var err error
	if cfg.BootstrapTTL, err = durationEnv("SHERLOCK_BOOTSTRAP_TTL", cfg.BootstrapTTL); err != nil {
		return ControlAdmin{}, err
	}
	if cfg.DatabaseURL == "" {
		return ControlAdmin{}, fmt.Errorf("SHERLOCK_DATABASE_URL is required")
	}
	if cfg.BootstrapTTL < time.Minute || cfg.BootstrapTTL > 24*time.Hour {
		return ControlAdmin{}, fmt.Errorf("bootstrap lifetime must be between one minute and 24 hours")
	}
	return cfg, nil
}
