package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultAdminAPIAddress = "127.0.0.1:8082"

type API struct {
	DatabaseURL                     string
	ListenAddress                   string
	TLSCertificate                  string
	TLSPrivateKey                   string
	APIKeyHashKey                   []byte
	AllowedOrigins                  []string
	FreshFor                        time.Duration
	ReadHeaderTimeout               time.Duration
	ReadTimeout                     time.Duration
	WriteTimeout                    time.Duration
	IdleTimeout                     time.Duration
	ShutdownTimeout                 time.Duration
	AdminAPIEnabled                 bool
	AdminAPIListenAddress           string
	AdminAPITLSCertificate          string
	AdminAPITLSPrivateKey           string
	AdminAPIServiceToken            RuntimeSecret
	AdminHumanSessionRequired       bool
	AdminHumanAuthorizationRequired bool
	CommandPackFile                 string
	TrustRootsFile                  string
	DiagnosticInventoryFile         string
	RunnerVersion                   string
	ModelAuditArtifactRoot          string
	ModelAuditArtifactMaxBytes      int64
	ArtifactStorage                 ArtifactStorage
	CredentialKeyring               CredentialKeyringConfig
}

func LoadAPI() (API, error) {
	if err := loadLocalEnv(); err != nil {
		return API{}, err
	}
	cfg := API{
		DatabaseURL:                os.Getenv("SHERLOCK_DATABASE_URL"),
		ListenAddress:              valueOrDefault("SHERLOCK_API_ADDRESS", "127.0.0.1:8080"),
		TLSCertificate:             os.Getenv("SHERLOCK_API_CERT_FILE"),
		TLSPrivateKey:              os.Getenv("SHERLOCK_API_KEY_FILE"),
		CommandPackFile:            os.Getenv("SHERLOCK_COMMAND_PACK_FILE"),
		TrustRootsFile:             os.Getenv("SHERLOCK_COMMAND_TRUST_ROOTS_FILE"),
		DiagnosticInventoryFile:    os.Getenv("SHERLOCK_DIAGNOSTIC_INVENTORY_FILE"),
		RunnerVersion:              os.Getenv("SHERLOCK_RUNNER_VERSION"),
		ModelAuditArtifactRoot:     os.Getenv("SHERLOCK_MODEL_AUDIT_ARTIFACT_ROOT"),
		ModelAuditArtifactMaxBytes: 1 << 20,
		FreshFor:                   60 * time.Second, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second,
		IdleTimeout: 60 * time.Second, ShutdownTimeout: 10 * time.Second,
		AdminAPIListenAddress:  valueOrDefault("SHERLOCK_ADMIN_API_ADDRESS", defaultAdminAPIAddress),
		AdminAPITLSCertificate: os.Getenv("SHERLOCK_ADMIN_API_CERT_FILE"),
		AdminAPITLSPrivateKey:  os.Getenv("SHERLOCK_ADMIN_API_KEY_FILE"),
		AdminAPIServiceToken:   RuntimeSecret{value: os.Getenv("SHERLOCK_ADMIN_API_TOKEN")},
	}
	var err error
	if keyringPath := strings.TrimSpace(os.Getenv("SHERLOCK_CREDENTIAL_KEYRING_FILE")); keyringPath != "" {
		cfg.CredentialKeyring, err = loadCredentialKeyring(keyringPath)
		if err != nil {
			return API{}, err
		}
	}
	if cfg.AdminAPIEnabled, err = boolEnv("SHERLOCK_ADMIN_API_ENABLED", false); err != nil {
		return API{}, err
	}
	if cfg.AdminHumanSessionRequired, err = boolEnv("SHERLOCK_ADMIN_HUMAN_SESSION_REQUIRED", false); err != nil {
		return API{}, err
	}
	if cfg.AdminHumanAuthorizationRequired, err = boolEnv("SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED", false); err != nil {
		return API{}, err
	}
	if cfg.AdminHumanAuthorizationRequired && !cfg.AdminHumanSessionRequired {
		return API{}, fmt.Errorf("SHERLOCK_ADMIN_HUMAN_AUTHORIZATION_REQUIRED requires human sessions")
	}
	if cfg.AdminHumanSessionRequired && !cfg.AdminAPIEnabled {
		return API{}, fmt.Errorf("SHERLOCK_ADMIN_HUMAN_SESSION_REQUIRED requires the private admin API")
	}
	for name, target := range map[string]*time.Duration{
		"SHERLOCK_API_FRESH_FOR":           &cfg.FreshFor,
		"SHERLOCK_API_READ_HEADER_TIMEOUT": &cfg.ReadHeaderTimeout,
		"SHERLOCK_API_READ_TIMEOUT":        &cfg.ReadTimeout,
		"SHERLOCK_API_WRITE_TIMEOUT":       &cfg.WriteTimeout,
		"SHERLOCK_API_IDLE_TIMEOUT":        &cfg.IdleTimeout,
		"SHERLOCK_API_SHUTDOWN_TIMEOUT":    &cfg.ShutdownTimeout,
	} {
		if *target, err = durationEnv(name, *target); err != nil {
			return API{}, err
		}
	}
	if cfg.DatabaseURL == "" || cfg.ListenAddress == "" {
		return API{}, fmt.Errorf("SHERLOCK_DATABASE_URL and SHERLOCK_API_ADDRESS are required")
	}
	if bytes, parseErr := intEnv("SHERLOCK_MODEL_AUDIT_ARTIFACT_MAX_BYTES", int(cfg.ModelAuditArtifactMaxBytes)); parseErr != nil {
		return API{}, parseErr
	} else {
		cfg.ModelAuditArtifactMaxBytes = int64(bytes)
	}
	if (cfg.TLSCertificate == "") != (cfg.TLSPrivateKey == "") {
		return API{}, fmt.Errorf("public API TLS certificate and private key must be configured together")
	}
	adminAPILoopback, err := addressIsLoopback(cfg.AdminAPIListenAddress, "SHERLOCK_ADMIN_API_ADDRESS")
	if err != nil {
		return API{}, err
	}
	adminAPITLSConfigured := cfg.AdminAPITLSCertificate != "" && cfg.AdminAPITLSPrivateKey != ""
	if (cfg.AdminAPITLSCertificate == "") != (cfg.AdminAPITLSPrivateKey == "") {
		return API{}, fmt.Errorf("private admin API TLS certificate and private key must be configured together")
	}
	if !adminAPILoopback && !adminAPITLSConfigured {
		return API{}, fmt.Errorf("non-loopback SHERLOCK_ADMIN_API_ADDRESS requires private admin API TLS")
	}
	if cfg.AdminAPIEnabled {
		if !validAdminServiceToken(cfg.AdminAPIServiceToken.Reveal()) {
			return API{}, fmt.Errorf("SHERLOCK_ADMIN_API_TOKEN must contain between 32 and 512 non-whitespace bytes without commas when the private admin API is enabled")
		}
	}
	diagnosticValues := []string{cfg.CommandPackFile, cfg.TrustRootsFile, cfg.DiagnosticInventoryFile, cfg.RunnerVersion}
	diagnosticConfigured := 0
	for _, value := range diagnosticValues {
		if value != "" {
			diagnosticConfigured++
		}
	}
	if diagnosticConfigured != 0 && diagnosticConfigured != len(diagnosticValues) {
		return API{}, fmt.Errorf("command pack, trust roots, diagnostic inventory, and runner version must be configured together")
	}
	rawHashKey := os.Getenv("SHERLOCK_API_KEY_HASH_KEY")
	if rawHashKey == "" {
		return API{}, fmt.Errorf("SHERLOCK_API_KEY_HASH_KEY is required")
	}
	cfg.APIKeyHashKey, err = decodeHashKey(rawHashKey)
	if err != nil {
		return API{}, err
	}
	if rawOrigins := strings.TrimSpace(os.Getenv("SHERLOCK_API_ALLOWED_ORIGINS")); rawOrigins != "" {
		seen := make(map[string]struct{})
		for _, origin := range strings.Split(rawOrigins, ",") {
			origin = strings.TrimSpace(origin)
			if origin == "*" || (!strings.HasPrefix(origin, "https://") && !strings.HasPrefix(origin, "http://localhost")) {
				return API{}, fmt.Errorf("API CORS origins must be explicit HTTPS origins or localhost")
			}
			if _, exists := seen[origin]; !exists {
				cfg.AllowedOrigins = append(cfg.AllowedOrigins, origin)
				seen[origin] = struct{}{}
			}
		}
	}
	if cfg.FreshFor <= 0 || cfg.FreshFor > 24*time.Hour || cfg.ReadHeaderTimeout <= 0 || cfg.ReadTimeout <= 0 || cfg.WriteTimeout < 31*time.Second || cfg.IdleTimeout <= 0 || cfg.ShutdownTimeout <= 0 {
		return API{}, fmt.Errorf("API durations are invalid; write timeout must permit bounded SSE polling")
	}
	if cfg.ModelAuditArtifactMaxBytes < 1 || cfg.ModelAuditArtifactMaxBytes > 4<<20 {
		return API{}, fmt.Errorf("SHERLOCK_MODEL_AUDIT_ARTIFACT_MAX_BYTES must be between 1 byte and 4 MiB")
	}
	cfg.ArtifactStorage, err = loadArtifactStorage(cfg.ModelAuditArtifactRoot)
	if err != nil {
		return API{}, err
	}
	return cfg, nil
}

func decodeHashKey(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil || len(decoded) < 32 {
		return nil, fmt.Errorf("SHERLOCK_API_KEY_HASH_KEY must be base64-encoded and at least 32 bytes")
	}
	return decoded, nil
}
