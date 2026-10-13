package telemetryjournal

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// AggregateLimits bound all allocated bytes beneath one gateway-owned root.
// SQLite/receipts/lifecycle facts/keys are metadata; telemetry contact/loss
// bodies have a dedicated control suffix. No gateway-owned body is TTL-pruned.
type AggregateLimits struct{ Total, Payload, Metadata, LossContact, Staging int64 }

func DefaultGatewayAggregateLimits() AggregateLimits {
	return AggregateLimits{8 << 30, 7 << 30, 512 << 20, 256 << 20, 256 << 20}
}

type GatewayBudget struct {
	mu     sync.Mutex
	root   string
	limits AggregateLimits
	lock   *os.File
	queues map[string]bool
}
type AggregateStats struct{ Total, Payload, Metadata, LossContact, Staging int64 }

func OpenGatewayBudget(root string, limits AggregateLimits) (*GatewayBudget, error) {
	if strings.ContainsAny(root, "?#") || limits.Total < 1 || limits.Payload < 1 || limits.Metadata < 1<<20 || limits.LossContact < 1 || limits.Staging < 1 || limits.Payload > limits.Total || limits.Metadata > limits.Total-limits.Payload || limits.LossContact > limits.Total-limits.Payload-limits.Metadata || limits.Staging > limits.Total-limits.Payload-limits.Metadata-limits.LossContact {
		return nil, ErrInvalid
	}
	if e := secureDirectory(root); e != nil {
		return nil, e
	}
	fd, e := unix.Open(filepath.Join(root, "gateway-owner.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, ErrCorrupt
	}
	f := os.NewFile(uintptr(fd), "gateway-budget-lock")
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, ErrInUse
	}
	if f.Chmod(0600) != nil {
		f.Close()
		return nil, ErrCorrupt
	}
	b := &GatewayBudget{root: root, limits: limits, lock: f, queues: map[string]bool{}}
	if e = b.reserve(0, 0, 0, 0, 0); e != nil {
		b.Close()
		return nil, e
	}
	return b, nil
}
func (b *GatewayBudget) begin() (func(), error) {
	b.mu.Lock()
	if b.lock == nil {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	return b.mu.Unlock, nil
}
func (q *Queue) beginBudget() (func(), error) {
	if q.opts.GatewayBudget == nil {
		return func() {}, nil
	}
	return q.opts.GatewayBudget.begin()
}
func (b *GatewayBudget) contains(path string) bool {
	relative, e := filepath.Rel(b.root, path)
	return e == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}
func (b *GatewayBudget) reserve(payload, control, staging, metadata, total int64) error {
	s, e := aggregatePhysical(b.root)
	if e != nil {
		return e
	}
	if payload < 0 || control < 0 || staging < 0 || metadata < 0 || total < 0 || s.Total > b.limits.Total-total || s.Payload > b.limits.Payload-payload || s.Metadata > b.limits.Metadata-metadata || s.LossContact > b.limits.LossContact-control || s.Staging > b.limits.Staging-staging {
		return ErrCapacity
	}
	return nil
}
func (b *GatewayBudget) Stats() (AggregateStats, error) {
	unlock, e := b.begin()
	if e != nil {
		return AggregateStats{}, e
	}
	defer unlock()
	return aggregatePhysical(b.root)
}
func (b *GatewayBudget) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.queues) > 0 {
		return ErrInUse
	}
	if b.lock == nil {
		return nil
	}
	e := b.lock.Close()
	b.lock = nil
	return e
}
func aggregatePhysical(root string) (AggregateStats, error) {
	var s AggregateStats
	var visit func(string, int) error
	visit = func(path string, depth int) error {
		if depth > 8 {
			return ErrCorrupt
		}
		info, e := os.Lstat(path)
		if e != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return ErrCorrupt
		}
		size := allocated(info)
		s.Total += size
		if info.IsDir() {
			s.Metadata += size
			f, e := os.Open(path)
			if e != nil {
				return ErrCorrupt
			}
			defer f.Close()
			for {
				names, e := f.Readdirnames(256)
				if e != nil && !errors.Is(e, io.EOF) {
					return ErrCorrupt
				}
				for _, name := range names {
					if e := visit(filepath.Join(path, name), depth+1); e != nil {
						return e
					}
				}
				if errors.Is(e, io.EOF) {
					break
				}
			}
			return nil
		}
		if info.Mode().Perm() != 0600 {
			return ErrCorrupt
		}
		switch {
		case strings.HasSuffix(path, ".tmp"):
			s.Staging += size
		case strings.HasSuffix(path, ".payload"):
			s.Payload += size
		case strings.HasSuffix(path, ".control"):
			s.LossContact += size
		default:
			s.Metadata += size
		}
		return nil
	}
	e := visit(root, 0)
	return s, e
}
