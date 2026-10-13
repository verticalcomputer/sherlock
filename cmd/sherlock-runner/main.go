package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
)

type trustRootDocument struct {
	ID          string    `json:"id"`
	Issuer      string    `json:"issuer"`
	PublicKey   []byte    `json:"public_key"`
	ActivatesAt time.Time `json:"activates_at"`
	RetiresAt   time.Time `json:"retires_at"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdin, os.Stdout); err != nil {
		logger.Error("runner.stopped", "reason", "configuration or execution failure")
		os.Exit(1)
	}
}

func run(ctx context.Context, input io.Reader, output io.Writer) error {
	packFile, rootsFile, version := os.Getenv("SHERLOCK_RUNNER_COMMAND_PACK_FILE"), os.Getenv("SHERLOCK_RUNNER_TRUST_ROOTS_FILE"), os.Getenv("SHERLOCK_RUNNER_VERSION")
	targetID, targetRole := os.Getenv("SHERLOCK_RUNNER_TARGET_ID"), commandpack.TargetRole(os.Getenv("SHERLOCK_RUNNER_TARGET_ROLE"))
	if packFile == "" || rootsFile == "" || version == "" || targetID == "" || targetRole == "" {
		return errors.New("runner configuration is incomplete")
	}
	releaseBytes, err := readSecure(packFile, 8<<20)
	if err != nil {
		return err
	}
	release, err := commandpack.DecodeRelease(releaseBytes)
	if err != nil {
		return err
	}
	rootBytes, err := readSecure(rootsFile, 1<<20)
	if err != nil {
		return err
	}
	var documents []trustRootDocument
	if err := decodeStrict(rootBytes, &documents); err != nil || len(documents) == 0 {
		return errors.New("trust roots are invalid")
	}
	roots := make([]commandpack.TrustRoot, len(documents))
	for index, root := range documents {
		roots[index] = commandpack.TrustRoot{ID: root.ID, Issuer: root.Issuer, PublicKey: root.PublicKey, ActivatesAt: root.ActivatesAt, RetiresAt: root.RetiresAt}
	}
	trust, err := commandpack.NewTrustStore(roots)
	if err != nil {
		return err
	}
	catalog, err := trust.Verify(release, version, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return err
	}
	runner, err := diagnosticrunner.New(diagnosticrunner.Config{MaxTimeout: time.Hour, MaxOutputBytes: 64 << 20, MaxInputBytes: 1 << 20, MaxTargets: 1, MaxConcurrency: 1, MaxSuppliedSecrets: 16, MaxSecretBytes: 4 << 10})
	if err != nil {
		return err
	}
	executor, err := diagnosticrunner.NewRemoteExecutor(catalog, runner, commandpack.Target{Name: targetID, Role: targetRole}, 1<<20)
	if err != nil {
		return err
	}
	result, err := executor.Execute(ctx, input, nil)
	if err != nil {
		return err
	}
	if err := diagnosticrunner.EncodeRemoteResult(output, result); err != nil {
		return fmt.Errorf("encode bounded runner result")
	}
	return nil
}

func readSecure(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("runner configuration path is invalid")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("runner configuration file is unsafe")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&022 != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("runner configuration file is unsafe")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return nil, errors.New("runner configuration file is unavailable")
	}
	return payload, nil
}

func decodeStrict(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("configuration has trailing data")
	}
	return nil
}
