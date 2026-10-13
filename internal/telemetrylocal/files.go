// Package telemetrylocal provides bounded protected local input for the resident
// telemetry binaries. Its errors contain no paths, credentials or file content.
package telemetrylocal

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"golang.org/x/sys/unix"
)

// ReadProtected opens every directory component without following symlinks.
// Root-owned sticky temporary ancestors are allowed; the file itself must be
// owned by this effective user, regular, single-linked and exactly mode0600.
func ReadProtected(path string, maximum int64) ([]byte, error) {
	if maximum < 1 || maximum > 1<<20 {
		return nil, telemetry.ErrInvalid
	}
	fd, name, e := openParent(path)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	filefd, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, telemetry.ErrUnavailable
	}
	file := os.NewFile(uintptr(filefd), "protected-telemetry-input")
	defer file.Close()
	var s unix.Stat_t
	if unix.Fstat(filefd, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&0777 != 0600 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 || s.Size < 1 || s.Size > maximum {
		return nil, telemetry.ErrUnauthorized
	}
	data, e := io.ReadAll(io.LimitReader(file, maximum+1))
	if e != nil || len(data) == 0 || int64(len(data)) > maximum {
		return nil, telemetry.ErrInvalid
	}
	// Recheck the descriptor after reading; callers never inspect file paths in
	// errors. The trusted ancestor walk prevents an untrusted rename race.
	var after unix.Stat_t
	if unix.Fstat(filefd, &after) != nil || after.Mode != s.Mode || after.Uid != s.Uid || after.Nlink != 1 || after.Size != s.Size {
		clear(data)
		return nil, telemetry.ErrUnauthorized
	}
	return data, nil
}

func openParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, "", telemetry.ErrInvalid
	}
	if runtime.GOOS == "darwin" {
		for _, alias := range []string{"/var", "/tmp"} {
			if strings.HasPrefix(path, alias+"/") {
				var s unix.Stat_t
				target, e := os.Readlink(alias)
				if unix.Lstat(alias, &s) != nil || s.Uid != 0 || e != nil || target != "private"+alias {
					return -1, "", telemetry.ErrInvalid
				}
				path = "/private" + path
			}
		}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		return -1, "", telemetry.ErrInvalid
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, "", telemetry.ErrUnavailable
	}
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			unix.Close(fd)
			return -1, "", telemetry.ErrUnauthorized
		}
		var s unix.Stat_t
		valid := unix.Fstat(next, &s) == nil && (s.Uid == uint32(os.Geteuid()) || s.Uid == 0) && (s.Mode&0022 == 0 || s.Uid == 0 && s.Mode&unix.S_ISVTX != 0)
		if !valid {
			unix.Close(next)
			unix.Close(fd)
			return -1, "", telemetry.ErrUnauthorized
		}
		unix.Close(fd)
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

// WriteNewProtected atomically publishes a new bounded owner-only output and
// never replaces an existing path. A failed publication leaves no usable output;
// a directory-sync failure may leave the complete protected file for review.
func WriteNewProtected(path string, data []byte) error {
	if len(data) == 0 || len(data) > 64<<10 {
		return telemetry.ErrInvalid
	}
	fd, name, e := openParent(path)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		return telemetry.ErrUnavailable
	}
	temporary := ".telemetry-output-" + hex.EncodeToString(random[:])
	filefd, e := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return telemetry.ErrUnavailable
	}
	defer unix.Unlinkat(fd, temporary, 0)
	file := os.NewFile(uintptr(filefd), "protected-telemetry-output")
	n, e := file.Write(data)
	if e != nil || n != len(data) {
		file.Close()
		return telemetry.ErrUnavailable
	}
	if e = file.Sync(); e != nil {
		file.Close()
		return telemetry.ErrUnavailable
	}
	if e = file.Close(); e != nil {
		return telemetry.ErrUnavailable
	}
	// linkat refuses an existing final name atomically; rename would overwrite.
	if e = unix.Linkat(fd, temporary, fd, name, 0); e != nil {
		return telemetry.ErrConflict
	}
	if e = unix.Unlinkat(fd, temporary, 0); e != nil {
		return telemetry.ErrUnavailable
	}
	if e = unix.Fsync(fd); e != nil {
		return telemetry.ErrUnavailable
	}
	return nil
}
