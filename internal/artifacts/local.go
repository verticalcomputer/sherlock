package artifacts

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type LocalStore struct {
	root     string
	temp     string
	objects  string
	maxBytes int64
}

func NewLocalStore(root string, maxBytes int64) (*LocalStore, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("artifact root must be an explicit absolute path")
	}
	if maxBytes < 1 || maxBytes > 100<<20 {
		return nil, fmt.Errorf("artifact byte limit must be between 1 byte and 100 MiB")
	}
	clean := filepath.Clean(root)
	store := &LocalStore{root: clean, temp: filepath.Join(clean, "tmp"), objects: filepath.Join(clean, "objects", "sha256"), maxBytes: maxBytes}
	for _, directory := range []string{store.temp, store.objects} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create artifact directory: %w", err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, fmt.Errorf("restrict artifact directory: %w", err)
		}
	}
	return store, nil
}

func (store *LocalStore) Stage(ctx context.Context, evidenceID domain.EvidenceID, reference domain.ArtifactReference, payload []byte) (application.StagedArtifact, error) {
	if err := ctx.Err(); err != nil {
		return application.StagedArtifact{}, err
	}
	if evidenceID == "" {
		return application.StagedArtifact{}, fmt.Errorf("evidence identifier is required")
	}
	if err := domain.ValidateArtifactReference(reference); err != nil {
		return application.StagedArtifact{}, err
	}
	if int64(len(payload)) > store.maxBytes || reference.Bytes > store.maxBytes {
		return application.StagedArtifact{}, application.ErrArtifactTooLarge
	}
	if int64(len(payload)) != reference.Bytes || domain.ChecksumSHA256(payload) != reference.SHA256 {
		return application.StagedArtifact{}, application.ErrArtifactChecksumMismatch
	}
	token, err := randomToken()
	if err != nil {
		return application.StagedArtifact{}, fmt.Errorf("create artifact staging token: %w", err)
	}
	path := filepath.Join(store.temp, token)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return application.StagedArtifact{}, fmt.Errorf("create staged artifact: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return application.StagedArtifact{}, fmt.Errorf("write staged artifact: %w", err)
	}
	if err := file.Sync(); err != nil {
		return application.StagedArtifact{}, fmt.Errorf("sync staged artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return application.StagedArtifact{}, fmt.Errorf("close staged artifact: %w", err)
	}
	if err := syncDirectory(store.temp); err != nil {
		return application.StagedArtifact{}, err
	}
	remove = false
	return application.StagedArtifact{ID: application.ArtifactStageID(token), EvidenceID: evidenceID, Reference: reference}, nil
}

func (store *LocalStore) Promote(ctx context.Context, staged application.StagedArtifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tempPath, err := store.stagedPath(staged)
	if err != nil {
		return err
	}
	if err := store.verifyFile(tempPath, staged.Reference); err != nil {
		return fmt.Errorf("verify staged artifact: %w", err)
	}
	finalPath := store.objectPath(staged.Reference)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		return fmt.Errorf("create content-addressed artifact directory: %w", err)
	}
	// A hard-link promotion gives the create-once property that os.Rename lacks:
	// it atomically fails if the content address already exists. The temporary
	// name is then unlinked, which has the same atomic visibility as a rename.
	if err := os.Link(tempPath, finalPath); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("promote staged artifact: %w", err)
		}
		if err := store.verifyFile(finalPath, staged.Reference); err != nil {
			return fmt.Errorf("%w: %v", application.ErrArtifactConflict, err)
		}
	}
	if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove promoted staging object: %w", err)
	}
	if err := syncDirectory(filepath.Dir(finalPath)); err != nil {
		return err
	}
	return syncDirectory(store.temp)
}

func (store *LocalStore) Discard(ctx context.Context, staged application.StagedArtifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := store.stagedPath(staged)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("discard staged artifact: %w", err)
	}
	return nil
}

func (store *LocalStore) Read(ctx context.Context, reference domain.ArtifactReference) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := domain.ValidateArtifactReference(reference); err != nil {
		return nil, err
	}
	path := store.objectPath(reference)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, application.ErrArtifactUnavailable
		}
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, store.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	if int64(len(payload)) > store.maxBytes {
		return nil, application.ErrArtifactTooLarge
	}
	if int64(len(payload)) != reference.Bytes || domain.ChecksumSHA256(payload) != reference.SHA256 {
		return nil, application.ErrArtifactCorrupt
	}
	return payload, nil
}

// Check maps storage errors to the only three durable reconciliation states.
// It deliberately returns no underlying path or payload-derived detail.
func (store *LocalStore) Check(ctx context.Context, reference domain.ArtifactReference) (domain.ArtifactAvailability, error) {
	_, err := store.Read(ctx, reference)
	switch {
	case err == nil:
		return domain.ArtifactAvailable, nil
	case errors.Is(err, application.ErrArtifactUnavailable):
		return domain.ArtifactUnavailable, nil
	case errors.Is(err, application.ErrArtifactCorrupt), errors.Is(err, application.ErrArtifactTooLarge):
		return domain.ArtifactCorrupt, nil
	default:
		return "", err
	}
}

func (store *LocalStore) stagedPath(staged application.StagedArtifact) (string, error) {
	token := string(staged.ID)
	if token == "" || filepath.Base(token) != token || strings.ContainsAny(token, `/\\`) {
		return "", fmt.Errorf("artifact staging identifier is invalid")
	}
	if staged.EvidenceID == "" {
		return "", fmt.Errorf("staged artifact evidence identifier is required")
	}
	if err := domain.ValidateArtifactReference(staged.Reference); err != nil {
		return "", err
	}
	return filepath.Join(store.temp, token), nil
}

func (store *LocalStore) objectPath(reference domain.ArtifactReference) string {
	hexChecksum := reference.SHA256.String()
	return filepath.Join(store.objects, hexChecksum[:2], hexChecksum)
}

func (store *LocalStore) verifyFile(path string, reference domain.ArtifactReference) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return application.ErrArtifactConflict
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != reference.Bytes || info.Size() > store.maxBytes {
		return application.ErrArtifactConflict
	}
	payload, err := io.ReadAll(io.LimitReader(file, store.maxBytes+1))
	if err != nil {
		return err
	}
	if domain.ChecksumSHA256(payload) != reference.SHA256 {
		return application.ErrArtifactConflict
	}
	return nil
}

func randomToken() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x.stage", value[:]), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open artifact directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync artifact directory: %w", err)
	}
	return nil
}
