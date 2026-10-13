package diagnosticrunner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxSSHPasswordBytes = 4 << 10

// SSHCredentialProvider exposes a password only for the lifetime of consume.
// Implementations must clear their own buffer after consume returns. The
// transport also copies and clears the bytes it passes to the SSH library.
type SSHCredentialProvider interface {
	WithPassword(context.Context, string, func([]byte) error) error
}

// FileSSHCredentialProvider resolves an opaque reference to an owner-only raw
// password file under one protected head-local directory. References are safe
// identifiers rather than caller-supplied paths.
type FileSSHCredentialProvider struct {
	directory string
}

func NewFileSSHCredentialProvider(directory string) (*FileSSHCredentialProvider, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\r\n") {
		return nil, errors.New("ssh credential provider: directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&077 != 0 || info.Mode().Perm()&0500 != 0500 || !ownedByEffectiveUser(info) {
		return nil, errors.New("ssh credential provider: directory must be owner-only")
	}
	return &FileSSHCredentialProvider{directory: directory}, nil
}

func (provider *FileSSHCredentialProvider) WithPassword(ctx context.Context, reference string, consume func([]byte) error) error {
	if provider == nil || ctx == nil || !safeIdentifier(reference) || consume == nil {
		return errors.New("ssh credential provider: invalid request")
	}
	if err := ctx.Err(); err != nil {
		return errors.New("ssh credential provider: request cancelled")
	}
	directoryDescriptor, err := unix.Open(provider.directory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return errors.New("ssh credential provider: credential is unavailable or unsafe")
	}
	directory := os.NewFile(uintptr(directoryDescriptor), provider.directory)
	defer directory.Close()
	directoryInfo, err := directory.Stat()
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&077 != 0 || directoryInfo.Mode().Perm()&0500 != 0500 || !ownedByEffectiveUser(directoryInfo) {
		return errors.New("ssh credential provider: credential is unavailable or unsafe")
	}
	fileDescriptor, err := unix.Openat(directoryDescriptor, reference, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("ssh credential provider: credential is unavailable or unsafe")
	}
	file := os.NewFile(uintptr(fileDescriptor), reference)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&077 != 0 || info.Mode().Perm()&0400 == 0 || !ownedByEffectiveUser(info) || info.Size() <= 0 || info.Size() > maxSSHPasswordBytes {
		_ = file.Close()
		return errors.New("ssh credential provider: credential is unavailable or unsafe")
	}
	password, readErr := io.ReadAll(io.LimitReader(file, maxSSHPasswordBytes+1))
	closeErr := file.Close()
	defer clear(password)
	if readErr != nil || closeErr != nil || len(password) == 0 || len(password) > maxSSHPasswordBytes || containsCredentialDelimiter(password) {
		return errors.New("ssh credential provider: credential is invalid")
	}
	return consume(password)
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && status.Uid == uint32(os.Geteuid())
}

func containsCredentialDelimiter(password []byte) bool {
	for _, value := range password {
		if value == 0 || value == '\r' || value == '\n' {
			return true
		}
	}
	return false
}
