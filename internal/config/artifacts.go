package config

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

const (
	ArtifactBackendLocal = "local"
	ArtifactBackendR2    = "r2"
)

// ArtifactStorage identifies the single protected artifact backend shared by
// API writes, private-admin reads, and worker reconciliation. Credentials are
// runtime-only and redact themselves when configuration is formatted.
type ArtifactStorage struct {
	Backend           string
	LocalRoot         string
	R2Endpoint        string
	R2Bucket          string
	R2AccessKeyID     RuntimeSecret
	R2SecretAccessKey RuntimeSecret
	R2Prefix          string
}

func (storage ArtifactStorage) Configured() bool { return storage.Backend != "" }

// LoadArtifactStorage loads only the protected artifact configuration. It is
// used by backend-specific health and migration tools that must not require
// database, public API, or model-provider credentials.
func LoadArtifactStorage() (ArtifactStorage, error) {
	if err := loadLocalEnv(); err != nil {
		return ArtifactStorage{}, err
	}
	return loadArtifactStorage(valueOrDefault("SHERLOCK_MODEL_AUDIT_ARTIFACT_ROOT", ""))
}

func loadArtifactStorage(localRoot string) (ArtifactStorage, error) {
	storage := ArtifactStorage{
		Backend:           strings.TrimSpace(valueOrDefault("SHERLOCK_ARTIFACT_BACKEND", "")),
		LocalRoot:         localRoot,
		R2Endpoint:        strings.TrimSpace(valueOrDefault("SHERLOCK_R2_ENDPOINT", "")),
		R2Bucket:          strings.TrimSpace(valueOrDefault("SHERLOCK_R2_BUCKET", "")),
		R2AccessKeyID:     RuntimeSecret{value: valueOrDefault("SHERLOCK_R2_ACCESS_KEY_ID", "")},
		R2SecretAccessKey: RuntimeSecret{value: valueOrDefault("SHERLOCK_R2_SECRET_ACCESS_KEY", "")},
		R2Prefix:          strings.Trim(strings.TrimSpace(valueOrDefault("SHERLOCK_R2_PREFIX", "")), "/"),
	}
	if storage.Backend == "" && storage.LocalRoot != "" {
		// Preserve the pre-R2 local configuration without making local storage
		// the implicit choice for a newly configured remote deployment.
		storage.Backend = ArtifactBackendLocal
	}
	r2Values := []bool{
		storage.R2Endpoint != "", storage.R2Bucket != "",
		storage.R2AccessKeyID.Configured(), storage.R2SecretAccessKey.Configured(),
		storage.R2Prefix != "",
	}
	anyR2 := false
	for _, configured := range r2Values {
		anyR2 = anyR2 || configured
	}
	if storage.Backend == "" {
		if anyR2 {
			return ArtifactStorage{}, fmt.Errorf("SHERLOCK_ARTIFACT_BACKEND is required when R2 settings are configured")
		}
		return storage, nil
	}
	switch storage.Backend {
	case ArtifactBackendLocal:
		if storage.LocalRoot == "" || !filepath.IsAbs(storage.LocalRoot) {
			return ArtifactStorage{}, fmt.Errorf("SHERLOCK_ARTIFACT_BACKEND=local requires an absolute local artifact root")
		}
	case ArtifactBackendR2:
		if err := validateR2Storage(storage); err != nil {
			return ArtifactStorage{}, err
		}
	default:
		return ArtifactStorage{}, fmt.Errorf("SHERLOCK_ARTIFACT_BACKEND must be local or r2")
	}
	return storage, nil
}

func validateR2Storage(storage ArtifactStorage) error {
	if storage.R2Endpoint == "" || storage.R2Bucket == "" || !storage.R2AccessKeyID.Configured() || !storage.R2SecretAccessKey.Configured() {
		return fmt.Errorf("R2 endpoint, bucket, access key ID, and secret access key must be configured together")
	}
	endpoint, err := url.Parse(storage.R2Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return fmt.Errorf("SHERLOCK_R2_ENDPOINT must be an origin-only HTTPS URL")
	}
	if len(storage.R2Bucket) > 255 || strings.ContainsAny(storage.R2Bucket, "/\\\x00\r\n\t ") {
		return fmt.Errorf("SHERLOCK_R2_BUCKET is invalid")
	}
	if storage.R2Prefix != "" {
		if strings.ContainsAny(storage.R2Prefix, "\\\x00\r\n") || path.Clean(storage.R2Prefix) != storage.R2Prefix {
			return fmt.Errorf("SHERLOCK_R2_PREFIX must be a normalized relative object-key prefix")
		}
		for _, segment := range strings.Split(storage.R2Prefix, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return fmt.Errorf("SHERLOCK_R2_PREFIX must be a normalized relative object-key prefix")
			}
		}
	}
	return nil
}
