//go:build linux

package linuxtelemetry

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"strings"
	"testing"
)

func TestLinuxFixedProcReadsAndBound(t *testing.T) {
	r := platformReader{}
	for _, name := range []string{"meminfo", "loadavg", "uptime", "self/mountinfo"} {
		b, err := r.proc(name, 256<<10)
		if err != nil || len(b) == 0 {
			t.Fatal("Linux proc fixture", name, err)
		}
	}
	for _, name := range []string{"../etc/passwd", "self/environ", "cpuinfo", "/proc/meminfo"} {
		if _, err := r.proc(name, 64<<10); err == nil {
			t.Fatal("non-profile file read")
		}
	}
	if _, err := r.proc("meminfo", 1); err == nil {
		t.Fatal("read bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.root(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("root cancellation")
	}
}

func TestPinnedRootReadsOwnKernelMountIdentity(t *testing.T) {
	d, err := pinRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	id, err := d.mountID()
	if err != nil {
		t.Fatal("own fdinfo mount identity", err)
	}
	body, err := (platformReader{}).proc("self/mountinfo", 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 6 && parts[0] == id && parts[4] == "/" {
			return
		}
	}
	t.Fatal("pinned root mount absent from own kernel metadata")
}

type syntheticRootDescriptor struct {
	id     string
	calls  int
	closed bool
	fs     unix.Statfs_t
}

func (d *syntheticRootDescriptor) mountID() (string, error)      { return d.id, nil }
func (d *syntheticRootDescriptor) stats() (unix.Statfs_t, error) { d.calls++; return d.fs, nil }
func (d *syntheticRootDescriptor) close() error                  { d.closed = true; return nil }

func TestRootDescriptorFencesReplacementBeforeAnyStatistics(t *testing.T) {
	local := "30 1 8:1 / / rw - ext4 /dev/synthetic rw\n"
	remote := "31 1 0:1 / / rw - nfs remote:/synthetic rw\n"
	for _, tc := range []struct {
		name, id, before, after string
		calls                   int
		wantErr                 bool
	}{
		{"local", "30", local, local, 1, false},
		{"replacement_before_pin", "31", local, local, 0, true},
		{"replacement_before_check", "30", remote, remote, 0, true},
		{"replacement_after_check", "30", local, remote, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &syntheticRootDescriptor{id: tc.id, fs: unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC, Frsize: 4096, Blocks: 100, Bfree: 20, Bavail: 10, Files: 100, Ffree: 80}}
			reads := 0
			pinCalled := false
			proc := func(string, int) ([]byte, error) {
				if !pinCalled {
					t.Fatal("root not pinned before metadata")
				}
				reads++
				if reads == 1 {
					return []byte(tc.before), nil
				}
				return []byte(tc.after), nil
			}
			stats, err := readRoot(context.Background(), proc, func() (pinnedRoot, error) { pinCalled = true; return d, nil })
			if (err != nil) != tc.wantErr || d.calls != tc.calls || !d.closed {
				t.Fatal("unsafe replacement ordering", err, d.calls, d.closed)
			}
			if !tc.wantErr && (stats.Total != 409600 || stats.Available != 40960) {
				t.Fatal("fragment size/available units")
			}
		})
	}
}
func TestLinuxRootMountClosedTypesAndAmbiguity(t *testing.T) {
	good := "30 1 8:1 / / rw,relatime - ext4 /dev/synthetic rw\n"
	if _, kind, err := rootMount([]byte(good)); err != nil || kind != "ext4" {
		t.Fatal("valid local root", err)
	}
	for _, body := range []string{good + good, "30 1 8:1 / / rw - nfs remote:/path rw\n", "30 1 0:1 / / rw - overlay overlay rw\n", "30 1 8:1 / / rw - ext4", "30 1 8:1 / /other rw - ext4 /dev/synthetic rw\n"} {
		if _, _, err := rootMount([]byte(body)); err == nil {
			t.Fatal("unsafe/ambiguous root accepted")
		}
	}
}
