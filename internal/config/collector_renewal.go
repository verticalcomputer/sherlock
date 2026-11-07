package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// LoadCollectorRenewal loads identity/transport only. An expired command pack,
// unavailable Slurm executable or disabled GPU source cannot prevent renewal.
// It never enrolls a collector or skips current certificate validation.
func LoadCollectorRenewal() (CollectorTransport, error) {
	if err := loadLocalEnv(); err != nil {
		return CollectorTransport{}, err
	}
	cfg := CollectorTransport{
		ControlURL:             strings.TrimSpace(os.Getenv("SHERLOCK_CONTROL_URL")),
		CollectorID:            strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_ID")),
		IdentityDir:            strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_IDENTITY_DIR")),
		CertificateFile:        strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_CERT_FILE")),
		PrivateKeyFile:         strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_KEY_FILE")),
		CAFile:                 strings.TrimSpace(os.Getenv("SHERLOCK_CONTROL_CA_FILE")),
		AuthMode:               CollectorTransportAuthMode(valueOrDefault("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE", string(CollectorTransportDirectMTLS))),
		AccessServiceTokenFile: strings.TrimSpace(os.Getenv("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE")),
		RequestTimeout:         35 * time.Second,
	}
	if cfg.IdentityDir == "" {
		return CollectorTransport{}, fmt.Errorf("atomic identity directory is required for renewal")
	}
	if err := resolveCollectorIdentityFiles(&cfg); err != nil {
		return CollectorTransport{}, err
	}
	u, err := url.Parse(cfg.ControlURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || cfg.CollectorID == "" || cfg.PrivateKeyFile == "" || cfg.CertificateFile == "" || cfg.CAFile == "" {
		return CollectorTransport{}, fmt.Errorf("renewal requires HTTPS control, existing collector identity and control trust")
	}
	if cfg.AuthMode != CollectorTransportDirectMTLS && cfg.AuthMode != CollectorTransportCloudflareAccessServiceTokenPoP {
		return CollectorTransport{}, fmt.Errorf("invalid renewal transport authentication mode")
	}
	if (cfg.AuthMode == CollectorTransportCloudflareAccessServiceTokenPoP) != (cfg.AccessServiceTokenFile != "") {
		return CollectorTransport{}, fmt.Errorf("renewal access-token configuration does not match authentication mode")
	}
	cfg.RequestTimeout, err = durationEnv("SHERLOCK_CONTROL_TIMEOUT", cfg.RequestTimeout)
	if err != nil || cfg.RequestTimeout <= 0 || cfg.RequestTimeout > time.Minute {
		return CollectorTransport{}, fmt.Errorf("invalid renewal timeout")
	}
	return cfg, nil
}
