package artifacts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestLocalStoreStagesPromotesAndReadsContentAddressedArtifact(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocalStore(root, 1024)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("bounded raw evidence")
	reference := testArtifactReference(t, payload)
	staged, err := store.Stage(context.Background(), "ev-1", reference, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Promote(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	read, err := store.Read(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(payload) {
		t.Fatalf("read %q, want %q", read, payload)
	}
	checksum := reference.SHA256.String()
	objectPath := filepath.Join(root, "objects", "sha256", checksum[:2], checksum)
	if info, err := os.Stat(objectPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("content-addressed object missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tmp", string(staged.ID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging object remains after promotion: %v", err)
	}

	// An exact replay is accepted without replacing content.
	replay, err := store.Stage(context.Background(), "ev-1", reference, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Promote(context.Background(), replay); err != nil {
		t.Fatalf("idempotent promotion: %v", err)
	}
	if err := os.WriteFile(objectPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(context.Background(), reference); !errors.Is(err, application.ErrArtifactCorrupt) {
		t.Fatalf("corrupt artifact condition = %v", err)
	}
	if condition, err := store.Check(context.Background(), reference); err != nil || condition != domain.ArtifactCorrupt {
		t.Fatalf("corrupt reconciliation condition=%s err=%v", condition, err)
	}
	if err := os.Remove(objectPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(context.Background(), reference); !errors.Is(err, application.ErrArtifactUnavailable) {
		t.Fatalf("missing artifact condition = %v", err)
	}
	if condition, err := store.Check(context.Background(), reference); err != nil || condition != domain.ArtifactUnavailable {
		t.Fatalf("missing reconciliation condition=%s err=%v", condition, err)
	}
}

func TestLocalStoreRejectsBoundsChecksumAndPathEscape(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("12345")
	reference := testArtifactReference(t, payload)
	if _, err := store.Stage(context.Background(), "ev-1", reference, payload); !errors.Is(err, application.ErrArtifactTooLarge) {
		t.Fatalf("oversized stage error = %v", err)
	}

	small := []byte("1234")
	reference = testArtifactReference(t, small)
	if _, err := store.Stage(context.Background(), "ev-1", reference, []byte("abcd")); !errors.Is(err, application.ErrArtifactChecksumMismatch) {
		t.Fatalf("checksum stage error = %v", err)
	}
	malicious := application.StagedArtifact{ID: "../../outside", EvidenceID: "ev-1", Reference: reference}
	if err := store.Promote(context.Background(), malicious); err == nil {
		t.Fatal("staging path escape was accepted")
	}
}

func TestLocalStoreDetectsImmutableObjectCollision(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocalStore(root, 1024)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("original")
	reference := testArtifactReference(t, payload)
	staged, err := store.Stage(context.Background(), "ev-1", reference, payload)
	if err != nil {
		t.Fatal(err)
	}
	checksum := reference.SHA256.String()
	directory := filepath.Join(root, "objects", "sha256", checksum[:2])
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, checksum), []byte("collision"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Promote(context.Background(), staged); !errors.Is(err, application.ErrArtifactConflict) {
		t.Fatalf("collision error = %v", err)
	}
}

func TestLocalStoreRequiresExplicitAbsoluteRoot(t *testing.T) {
	if _, err := NewLocalStore("relative/path", 1024); err == nil {
		t.Fatal("relative root was accepted")
	}
}

func testArtifactReference(t *testing.T, payload []byte) domain.ArtifactReference {
	t.Helper()
	reference, err := domain.NewArtifactReference(domain.ChecksumSHA256(payload), int64(len(payload)), "text/plain", domain.ArtifactUncompressed, "parser-v1", domain.RedactionSummary{PolicyVersion: "policy-v1"}, domain.ArtifactRetentionStandard)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}
