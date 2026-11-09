package controlplane

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readUploadServerKey(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, err
	}
	uid := uint32(os.Geteuid())
	if info.Mode&unix.S_IFMT != unix.S_IFREG || uid == 0 {
		return nil, fmt.Errorf("invalid upload server key")
	}
	switch info.Mode & 0o7777 {
	case 0o400, 0o600:
		if info.Uid != 0 && info.Uid != uid {
			return nil, fmt.Errorf("unsafe upload server key owner")
		}
	case 0o440:
		if info.Uid != 0 || !hasSystemdKeyACL(fd, uid) {
			return nil, fmt.Errorf("unsafe upload server key ACL")
		}
	default:
		return nil, fmt.Errorf("unsafe upload server key mode")
	}
	const maxSize = 64 << 10
	key, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(key) > maxSize {
		return nil, fmt.Errorf("oversized upload server key")
	}
	return key, nil
}

func hasSystemdKeyACL(fd int, uid uint32) bool {
	// Linux POSIX ACL v2. The mode's group-read bit represents the mask.
	// The owning group and others have no access. Only the named UID can read.
	const undefined = ^uint32(0)
	entries := [...]struct {
		tag, access uint16
		id          uint32
	}{
		{0x01, 4, undefined}, // owner
		{0x02, 4, uid},       // named user
		{0x04, 0, undefined}, // owning group
		{0x10, 4, undefined}, // mask
		{0x20, 0, undefined}, // others
	}
	var expected [4 + 8*len(entries)]byte
	binary.LittleEndian.PutUint32(expected[:4], 2)
	for i, entry := range entries {
		field := expected[4+8*i:]
		binary.LittleEndian.PutUint16(field, entry.tag)
		binary.LittleEndian.PutUint16(field[2:], entry.access)
		binary.LittleEndian.PutUint32(field[4:], entry.id)
	}
	var actual [len(expected)]byte
	n, err := unix.Fgetxattr(fd, "system.posix_acl_access", actual[:])
	return err == nil && n == len(expected) && bytes.Equal(actual[:], expected[:])
}
