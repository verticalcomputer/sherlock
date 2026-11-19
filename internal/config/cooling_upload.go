package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const coolingUploadProfileMaxBytes = 16 << 10

// LoadedCoolingProfile binds the exact private-file bytes, not re-encoded JSON.
type LoadedCoolingProfile struct {
	Profile domain.CoolingUploadProfile
	Hash    string
}

// LoadCoolingUploadProfile binds the opt-in to the exact protected file
// bytes. Both endpoints receive the same artifact independently.
func LoadCoolingUploadProfile() (domain.CoolingUploadProfile, string, error) {
	if os.Getenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILES") != "" {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("collector requires one cooling profile")
	}
	path := os.Getenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE")
	if path == "" {
		return domain.CoolingUploadProfile{}, "", nil
	}
	return loadCoolingUploadProfile(path)
}

func loadCoolingUploadProfile(path string) (domain.CoolingUploadProfile, string, error) {
	if !filepath.IsAbs(path) {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("cooling upload profile requires an absolute file path")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("open cooling upload profile: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() == 0 || info.Size() > domain.CoolingUploadProductionProfileMaxBytes {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("cooling upload profile must be a private regular file within the bounded profile size")
	}
	body, err := io.ReadAll(io.LimitReader(file, domain.CoolingUploadProductionProfileMaxBytes+1))
	if err != nil || len(body) > domain.CoolingUploadProductionProfileMaxBytes || rejectDuplicateJSONKeys(body) != nil {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("invalid cooling upload profile file content")
	}
	var profile domain.CoolingUploadProfile
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("invalid cooling upload profile JSON: %w", err)
	}
	if profile.Version == domain.CoolingUploadVersion && len(body) > coolingUploadProfileMaxBytes {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("V2 cooling profile exceeds 16 KiB")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("trailing cooling profile JSON")
	}
	if err := profile.Validate(); err != nil {
		return domain.CoolingUploadProfile{}, "", err
	}
	return profile, domain.ChecksumSHA256(body).String(), nil
}

// LoadCoolingUploadProfiles is intake-only; a collector remains singleton.
// Each profile is an independently protected file copied identically to its head.
func LoadCoolingUploadProfiles() ([]LoadedCoolingProfile, error) {
	raw := os.Getenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILES")
	if raw == "" {
		p, h, err := LoadCoolingUploadProfile()
		if err != nil {
			return nil, err
		}
		if h == "" {
			return nil, nil
		}
		return []LoadedCoolingProfile{{p, h}}, nil
	}
	if os.Getenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE") != "" || len(raw) > 8192 {
		return nil, fmt.Errorf("ambiguous or oversized cooling profile configuration")
	}
	var paths []string
	d := json.NewDecoder(bytes.NewBufferString(raw))
	if d.Decode(&paths) != nil || d.Decode(new(any)) != io.EOF || len(paths) < 1 || len(paths) > domain.CoolingUploadMaxProfiles {
		return nil, fmt.Errorf("intake requires one or two cooling profile files")
	}
	var result []LoadedCoolingProfile
	collectors, clusters, sources, ids := map[domain.CollectorID]bool{}, map[domain.ClusterID]bool{}, map[domain.SourceID]bool{}, map[string]bool{}
	for _, path := range paths {
		p, h, err := loadCoolingUploadProfile(path)
		if err != nil {
			return nil, err
		}
		if collectors[p.CollectorID] || clusters[p.ClusterID] || sources[p.SourceID] || ids[p.ProfileID] {
			return nil, fmt.Errorf("duplicate cooling profile authority")
		}
		collectors[p.CollectorID], clusters[p.ClusterID], sources[p.SourceID], ids[p.ProfileID] = true, true, true, true
		result = append(result, LoadedCoolingProfile{p, h})
	}
	return result, nil
}
