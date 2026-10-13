package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/artifacts"
	"github.com/verticalcomputer/sherlock/internal/config"
)

const migrationMaximumBytes = int64(100 << 20)

type sourceList []string

func (list *sourceList) String() string { return strings.Join(*list, ",") }
func (list *sourceList) Set(value string) error {
	*list = append(*list, value)
	return nil
}

type artifactImporter interface {
	ImportContentAddressed(context.Context, []byte) (bool, error)
}

type migrationSummary struct {
	Sources        int `json:"sources"`
	ObjectsChecked int `json:"objects_checked"`
	ObjectsCreated int `json:"objects_created"`
	ObjectsReused  int `json:"objects_reused"`
}

func main() {
	var sources sourceList
	flag.Var(&sources, "source", "absolute local artifact root to copy; repeat for multiple roots")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, sources, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "artifact migration failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, sources []string, output io.Writer) error {
	if len(sources) == 0 {
		return errors.New("at least one source is required")
	}
	storage, err := config.LoadArtifactStorage()
	if err != nil {
		return err
	}
	if storage.Backend != config.ArtifactBackendR2 {
		return errors.New("R2 artifact backend is not selected")
	}
	store, err := artifacts.NewR2Store(ctx, artifacts.R2Config{
		Endpoint: storage.R2Endpoint, Bucket: storage.R2Bucket,
		AccessKeyID: storage.R2AccessKeyID.Reveal(), SecretAccessKey: storage.R2SecretAccessKey.Reveal(),
		Prefix: storage.R2Prefix, MaxBytes: migrationMaximumBytes,
	})
	if err != nil {
		return err
	}
	summary, err := migrateSources(ctx, store, sources, migrationMaximumBytes)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(summary)
}

func migrateSources(ctx context.Context, importer artifactImporter, sources []string, maxBytes int64) (migrationSummary, error) {
	if importer == nil || len(sources) == 0 || maxBytes < 1 {
		return migrationSummary{}, errors.New("artifact migration dependencies are invalid")
	}
	summary := migrationSummary{Sources: len(sources)}
	for _, source := range sources {
		if !filepath.IsAbs(source) {
			return summary, errors.New("artifact migration source must be absolute")
		}
		objectsRoot := filepath.Join(filepath.Clean(source), "objects", "sha256")
		err := filepath.WalkDir(objectsRoot, func(objectPath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return errors.New("artifact migration source contains a non-regular object")
			}
			digest, err := validateObjectPath(objectsRoot, objectPath)
			if err != nil {
				return err
			}
			payload, err := readBoundedFile(objectPath, maxBytes)
			if err != nil {
				return err
			}
			actual := sha256.Sum256(payload)
			if !strings.EqualFold(hex.EncodeToString(actual[:]), digest) {
				return application.ErrArtifactCorrupt
			}
			summary.ObjectsChecked++
			created, err := importer.ImportContentAddressed(ctx, payload)
			if err != nil {
				return err
			}
			if created {
				summary.ObjectsCreated++
			} else {
				summary.ObjectsReused++
			}
			return nil
		})
		if err != nil {
			return summary, err
		}
	}
	return summary, nil
}

func validateObjectPath(root, objectPath string) (string, error) {
	relative, err := filepath.Rel(root, objectPath)
	if err != nil {
		return "", err
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 2 || len(parts[0]) != 2 || len(parts[1]) != 64 || parts[0] != parts[1][:2] {
		return "", errors.New("artifact migration object path is not content-addressed")
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", errors.New("artifact migration object digest is invalid")
	}
	return parts[1], nil
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBytes {
		return nil, application.ErrArtifactTooLarge
	}
	return payload, nil
}
