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

// LoadCoolingUploadProfile binds the opt-in to the exact protected file
// bytes. Both endpoints receive the same artifact independently.
func LoadCoolingUploadProfile() (domain.CoolingUploadProfile, string, error) {
	path := os.Getenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE")
	if path == "" {
		return domain.CoolingUploadProfile{}, "", nil
	}
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
		info.Size() == 0 || info.Size() > coolingUploadProfileMaxBytes {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("cooling upload profile must be a private regular file no larger than 16 KiB")
	}
	body, err := io.ReadAll(io.LimitReader(file, coolingUploadProfileMaxBytes+1))
	if err != nil || len(body) > coolingUploadProfileMaxBytes || rejectDuplicateJSONKeys(body) != nil {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("invalid cooling upload profile file content")
	}
	var profile domain.CoolingUploadProfile
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return domain.CoolingUploadProfile{}, "", fmt.Errorf("invalid cooling upload profile JSON: %w", err)
	}
	if err := profile.Validate(); err != nil {
		return domain.CoolingUploadProfile{}, "", err
	}
	return profile, domain.ChecksumSHA256(body).String(), nil
}
