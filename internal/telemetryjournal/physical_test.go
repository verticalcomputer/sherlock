package telemetryjournal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPhysicalCategoriesChargeBlocksDirectoriesAndAllocatorStaging(t *testing.T) {
	o := testOptions(Node)
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), o)
	charge, _, e := q.allocationCharge(int64(len(testBody(1, Data, "one"))))
	if e != nil {
		t.Fatal(e)
	}
	q.opts.Limits.Payload = charge
	mustPut(t, q, testBody(1, Data, "one"))
	s, e := aggregatePhysical(q.root)
	if e != nil || s.Payload < charge || s.Metadata == 0 {
		t.Fatal("physical categories missing", s, e)
	}
	_, e = q.Put(ctx, testBody(2, Data, "two"))
	assertError(t, e, ErrCapacity)
	// Metadata nested beneath the queue is charged, not only root-level SQLite.
	dir := filepath.Join(q.root, "private-metadata")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "bounded-fact"), make([]byte, 1<<20), 0600); e != nil {
		t.Fatal(e)
	}
	s, e = aggregatePhysical(q.root)
	if e != nil {
		t.Fatal(e)
	}
	q.opts.Limits.Metadata = s.Metadata + (64 << 10)
	called := false
	e = q.WithMetadataWrite(ctx, 1, func() error { called = true; return nil })
	assertError(t, e, ErrCapacity)
	if called {
		t.Fatal("metadata callback ran without reserved physical growth")
	}
	q.opts.Limits.Metadata = o.Limits.Metadata
	// The allocator's temporary inode consumes the same declared staging category.
	tmp := filepath.Join(q.root, "allocator-interrupted.tmp")
	if e = os.WriteFile(tmp, make([]byte, charge), 0600); e != nil {
		t.Fatal(e)
	}
	q.opts.Limits.Staging = charge
	e = q.WithMetadataWrite(ctx, 1, func() error { called = true; return nil })
	assertError(t, e, ErrCapacity)
	if called {
		t.Fatal("allocator callback overran staging reservation")
	}
	if _, e = q.Read(ctx, testKey(1)); e != nil {
		t.Fatal("capacity refusal lost owned bytes", e)
	}
}

func TestImmutableReaderRejectsChangedFileMode(t *testing.T) {
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), testOptions(Node))
	r := mustPut(t, q, testBody(1, Data, "one"))
	id, _ := keyID(r.Key)
	if e := os.Chmod(q.path(id), 0644); e != nil {
		t.Fatal(e)
	}
	_, e := q.Read(ctx, r.Key)
	assertError(t, e, ErrCorrupt)
	if _, e = os.Stat(q.path(id)); e != nil {
		t.Fatal("unsafe owned file removed", e)
	}
}
