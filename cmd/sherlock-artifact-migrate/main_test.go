package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/application"
)

type importerFake struct {
	seen    map[string]struct{}
	payload [][]byte
}

func (fake *importerFake) ImportContentAddressed(_ context.Context, payload []byte) (bool, error) {
	if fake.seen == nil {
		fake.seen = make(map[string]struct{})
	}
	digest := sha256.Sum256(payload)
	key := hex.EncodeToString(digest[:])
	_, exists := fake.seen[key]
	fake.seen[key] = struct{}{}
	fake.payload = append(fake.payload, append([]byte(nil), payload...))
	return !exists, nil
}

func TestMigrateSourcesVerifiesAndDeduplicatesContentAddressedObjects(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	payload := []byte("legacy audit payload")
	writeMigrationObject(t, rootA, payload)
	writeMigrationObject(t, rootB, payload)
	importer := &importerFake{}
	summary, err := migrateSources(context.Background(), importer, []string{rootA, rootB}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Sources != 2 || summary.ObjectsChecked != 2 || summary.ObjectsCreated != 1 || summary.ObjectsReused != 1 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestMigrateSourcesRejectsCorruptAndUnsafeObjects(t *testing.T) {
	root := t.TempDir()
	payload := []byte("expected")
	path := writeMigrationObject(t, root, payload)
	if err := os.WriteFile(path, []byte("changed!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateSources(context.Background(), &importerFake{}, []string{root}, 1024); !errors.Is(err, application.ErrArtifactCorrupt) {
		t.Fatalf("corrupt migration error=%v", err)
	}
	if _, err := migrateSources(context.Background(), &importerFake{}, []string{"relative"}, 1024); err == nil {
		t.Fatal("relative migration source was accepted")
	}
}

func writeMigrationObject(t *testing.T, root string, payload []byte) string {
	t.Helper()
	digest := sha256.Sum256(payload)
	hexDigest := hex.EncodeToString(digest[:])
	directory := filepath.Join(root, "objects", "sha256", hexDigest[:2])
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, hexDigest)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
