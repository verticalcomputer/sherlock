package collectorruntime

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrJournalInUse reports that another process holds the journal lock. The
// collector and every journal maintenance command must hold it before reading
// or migrating state, so a second collector cannot interleave writes.
var ErrJournalInUse = errors.New("collector journal is in use by another process")

type journalLock struct {
	file *os.File
}

func acquireJournalLock(path string) (*journalLock, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open collector journal lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("collector journal lock must be a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict collector journal lock permissions: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrJournalInUse
		}
		return nil, fmt.Errorf("lock collector journal: %w", err)
	}
	return &journalLock{file: file}, nil
}

// release closes the descriptor, which drops the flock. The lock file itself
// is never removed: unlinking it would let two processes lock different inodes.
func (lock *journalLock) release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := lock.file.Close()
	lock.file = nil
	return err
}
