//go:build linux

package linuxtelemetry

import (
	"context"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type platformReader struct{}

func (platformReader) proc(name string, limit int) ([]byte, error) {
	switch name {
	case "meminfo", "loadavg", "uptime", "self/mountinfo":
	default:
		return nil, errRead
	}
	return readProcFile(name, limit)
}

func readProcFile(name string, limit int) ([]byte, error) {
	fd, err := unix.Open("/proc/"+name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "proc-source")
	defer f.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errUnsupported
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errRead
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, errRead
	}
	return b, nil
}

// rootMount returns an exact local root mount row, never a configured path.
func rootMount(body []byte) (string, string, error) {
	row, kind := "", ""
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[4] != "/" {
			continue
		}
		if row != "" {
			return "", "", errRead
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || len(fields) != separator+4 {
			return "", "", errRead
		}
		row, kind = line, fields[separator+1]
	}
	if row == "" {
		return "", "", errRead
	}
	switch kind {
	case "ext2", "ext3", "ext4", "xfs", "btrfs":
		return row, kind, nil
	}
	return "", "", errUnsupported
}

type pinnedRoot interface {
	mountID() (string, error)
	stats() (unix.Statfs_t, error)
	close() error
}
type rootDescriptor struct{ fd int }

func (r rootDescriptor) close() error { return unix.Close(r.fd) }
func (r rootDescriptor) stats() (unix.Statfs_t, error) {
	var fs unix.Statfs_t
	err := unix.Fstatfs(r.fd, &fs)
	return fs, err
}
func (r rootDescriptor) mountID() (string, error) {
	body, err := readProcFile("self/fdinfo/"+strconv.Itoa(r.fd), 4096)
	if err != nil {
		return "", err
	}
	id := ""
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 || parts[0] != "mnt_id:" {
			continue
		}
		if id != "" || len(parts) != 2 {
			return "", errRead
		}
		n, e := strconv.ParseUint(parts[1], 10, 64)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != parts[1] {
			return "", errRead
		}
		id = parts[1]
	}
	if id == "" {
		return "", errRead
	}
	return id, nil
}
func pinRoot() (pinnedRoot, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return rootDescriptor{fd: fd}, nil
}
func (r platformReader) root(ctx context.Context) (rootStats, error) {
	return readRoot(ctx, r.proc, pinRoot)
}

// Pin before inspecting metadata. Mount IDs cannot be recycled while this
// descriptor keeps the mount alive; statistics never resolve '/' a second time.
func readRoot(ctx context.Context, proc func(string, int) ([]byte, error), pin func() (pinnedRoot, error)) (rootStats, error) {
	if err := ctx.Err(); err != nil {
		return rootStats{}, err
	}
	descriptor, err := pin()
	if err != nil {
		return rootStats{}, err
	}
	defer descriptor.close()
	before, err := proc("self/mountinfo", 256<<10)
	if err != nil {
		return rootStats{}, err
	}
	row, kind, err := rootMount(before)
	if err != nil {
		return rootStats{}, err
	}
	id, err := descriptor.mountID()
	if err != nil {
		return rootStats{}, err
	}
	if fields := strings.Fields(row); len(fields) == 0 || fields[0] != id {
		return rootStats{}, errRead
	}
	if err := ctx.Err(); err != nil {
		return rootStats{}, err
	}
	fs, err := descriptor.stats()
	if err != nil {
		return rootStats{}, err
	}
	// Check actual superblock type as well as the pre-read mount declaration.
	want := int64(unix.EXT4_SUPER_MAGIC)
	if kind == "xfs" {
		want = unix.XFS_SUPER_MAGIC
	}
	if kind == "btrfs" {
		want = unix.BTRFS_SUPER_MAGIC
	}
	if int64(fs.Type) != want {
		return rootStats{}, errRead
	}
	after, err := proc("self/mountinfo", 256<<10)
	if err != nil {
		return rootStats{}, err
	}
	next, _, err := rootMount(after)
	if err != nil || next != row {
		return rootStats{}, errRead
	}
	if err := ctx.Err(); err != nil {
		return rootStats{}, err
	}
	if fs.Frsize <= 0 {
		return rootStats{}, errRead
	}
	unit := uint64(fs.Frsize)
	if fs.Blocks > math.MaxUint64/unit || fs.Bfree > math.MaxUint64/unit || fs.Bavail > math.MaxUint64/unit {
		return rootStats{}, errRead
	}
	return rootStats{Total: fs.Blocks * unit, Free: fs.Bfree * unit, Available: fs.Bavail * unit, Inodes: fs.Files, FreeInodes: fs.Ffree}, nil
}
