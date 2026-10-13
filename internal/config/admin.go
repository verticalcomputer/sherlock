package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAdminAddress       = "127.0.0.1:8081"
	defaultAdminAPITimeout    = 10 * time.Second
	minimumServiceTokenLength = 32
)

// Admin contains the private dashboard's runtime configuration. The admin
// listener is a separate trust boundary from the public API and is disabled
// unless explicitly enabled.
type Admin struct {
	Enabled                    bool
	APIURL                     string
	APIToken                   RuntimeSecret
	APIClientTimeout           time.Duration
	ListenAddress              string
	TLSCertificate             string
	TLSPrivateKey              string
	AccessTeamDomain           string
	AccessAudience             string
	HumanAuthorizationRequired bool
	ReadHeaderTimeout          time.Duration
	ReadTimeout                time.Duration
	WriteTimeout               time.Duration
	IdleTimeout                time.Duration
	ShutdownTimeout            time.Duration
}

func LoadAdmin() (Admin, error) {
	if err := loadLocalEnv(); err != nil {
		return Admin{}, err
	}
	cfg := Admin{
		APIURL:            strings.TrimSpace(os.Getenv("SHERLOCK_ADMIN_API_URL")),
		APIToken:          RuntimeSecret{value: os.Getenv("SHERLOCK_ADMIN_API_TOKEN")},
		APIClientTimeout:  defaultAdminAPITimeout,
		ListenAddress:     valueOrDefault("SHERLOCK_ADMIN_ADDRESS", defaultAdminAddress),
		TLSCertificate:    os.Getenv("SHERLOCK_ADMIN_CERT_FILE"),
		TLSPrivateKey:     os.Getenv("SHERLOCK_ADMIN_KEY_FILE"),
		AccessTeamDomain:  strings.TrimSpace(os.Getenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_TEAM_DOMAIN")),
		AccessAudience:    strings.TrimSpace(os.Getenv("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_AUDIENCE")),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
	var err error
	if cfg.Enabled, err = boolEnv("SHERLOCK_ADMIN_ENABLED", false); err != nil {
		return Admin{}, err
	}
	if cfg.HumanAuthorizationRequired, err = boolEnv("SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED", false); err != nil {
		return Admin{}, err
	}
	if cfg.HumanAuthorizationRequired && !cfg.Enabled {
		return Admin{}, fmt.Errorf("SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED requires the admin dashboard")
	}
	for name, target := range map[string]*time.Duration{
		"SHERLOCK_ADMIN_API_TIMEOUT":         &cfg.APIClientTimeout,
		"SHERLOCK_ADMIN_READ_HEADER_TIMEOUT": &cfg.ReadHeaderTimeout,
		"SHERLOCK_ADMIN_READ_TIMEOUT":        &cfg.ReadTimeout,
		"SHERLOCK_ADMIN_WRITE_TIMEOUT":       &cfg.WriteTimeout,
		"SHERLOCK_ADMIN_IDLE_TIMEOUT":        &cfg.IdleTimeout,
		"SHERLOCK_ADMIN_SHUTDOWN_TIMEOUT":    &cfg.ShutdownTimeout,
	} {
		if *target, err = durationEnv(name, *target); err != nil {
			return Admin{}, err
		}
	}

	loopback, err := adminAddressIsLoopback(cfg.ListenAddress)
	if err != nil {
		return Admin{}, err
	}
	tlsConfigured := cfg.TLSCertificate != "" && cfg.TLSPrivateKey != ""
	if (cfg.TLSCertificate == "") != (cfg.TLSPrivateKey == "") {
		return Admin{}, fmt.Errorf("admin TLS certificate and private key must be configured together")
	}
	if !loopback && !tlsConfigured {
		return Admin{}, fmt.Errorf("non-loopback SHERLOCK_ADMIN_ADDRESS requires admin TLS")
	}
	if cfg.APIClientTimeout <= 0 || cfg.APIClientTimeout > time.Minute {
		return Admin{}, fmt.Errorf("SHERLOCK_ADMIN_API_TIMEOUT must be greater than zero and at most one minute")
	}
	if cfg.ReadHeaderTimeout <= 0 || cfg.ReadHeaderTimeout > time.Minute ||
		cfg.ReadTimeout <= 0 || cfg.ReadTimeout > 5*time.Minute ||
		cfg.WriteTimeout <= 0 || cfg.WriteTimeout > 5*time.Minute ||
		cfg.IdleTimeout <= 0 || cfg.IdleTimeout > 10*time.Minute ||
		cfg.ShutdownTimeout <= 0 || cfg.ShutdownTimeout > time.Minute {
		return Admin{}, fmt.Errorf("admin server timeouts are outside safety bounds")
	}
	if cfg.APIURL != "" {
		if err := validateAdminAPIURL(cfg.APIURL); err != nil {
			return Admin{}, err
		}
	}
	if !cfg.Enabled {
		return cfg, nil
	}
	if cfg.APIURL == "" {
		return Admin{}, fmt.Errorf("SHERLOCK_ADMIN_API_URL is required when the admin dashboard is enabled")
	}
	if !validAdminServiceToken(cfg.APIToken.Reveal()) {
		return Admin{}, fmt.Errorf("SHERLOCK_ADMIN_API_TOKEN must contain between 32 and 512 non-whitespace bytes without commas")
	}
	if err := validateCloudflareAccessOrigin(cfg.AccessTeamDomain); err != nil {
		return Admin{}, err
	}
	if cfg.AccessAudience == "" || strings.ContainsAny(cfg.AccessAudience, ", \t\r\n") {
		return Admin{}, fmt.Errorf("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_AUDIENCE must contain exactly one non-empty audience")
	}
	return cfg, nil
}

func validateCloudflareAccessOrigin(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("SHERLOCK_ADMIN_CLOUDFLARE_ACCESS_TEAM_DOMAIN must be an absolute HTTPS origin")
	}
	return nil
}

func validAdminServiceToken(value string) bool {
	return len(value) >= minimumServiceTokenLength && len(value) <= 512 && !strings.ContainsAny(value, " \t\r\n,")
}

func validateAdminAPIURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("SHERLOCK_ADMIN_API_URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("SHERLOCK_ADMIN_API_URL must not include userinfo, a query, or a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("SHERLOCK_ADMIN_API_URL must use the root path")
	}
	if parsed.RawPath != "" && parsed.RawPath != "/" {
		return fmt.Errorf("SHERLOCK_ADMIN_API_URL must use the root path")
	}

	loopback := hostIsLoopback(parsed.Hostname())
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		if !loopback {
			return fmt.Errorf("non-loopback SHERLOCK_ADMIN_API_URL requires HTTPS")
		}
	case "https":
	default:
		return fmt.Errorf("SHERLOCK_ADMIN_API_URL must use HTTP or HTTPS")
	}
	return nil
}

func adminAddressIsLoopback(address string) (bool, error) {
	return addressIsLoopback(address, "SHERLOCK_ADMIN_ADDRESS")
}

func addressIsLoopback(address, environmentName string) (bool, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false, fmt.Errorf("%s must be a host:port address: %w", environmentName, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return false, fmt.Errorf("%s must use a numeric port from 1 to 65535", environmentName)
	}
	return hostIsLoopback(host), nil
}

func hostIsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		ip = net.ParseIP(host[:zone])
	}
	return ip != nil && ip.IsLoopback()
}
