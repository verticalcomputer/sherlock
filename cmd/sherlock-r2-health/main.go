package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/verticalcomputer/sherlock/internal/artifacts"
	"github.com/verticalcomputer/sherlock/internal/config"
)

type r2Prober interface{ Probe(context.Context) error }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "R2 artifact health probe failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, output interface{ Write([]byte) (int, error) }) error {
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
		Prefix: storage.R2Prefix, MaxBytes: 1 << 20,
	})
	if err != nil {
		return err
	}
	if err := runProbe(ctx, store, output); err != nil {
		return err
	}
	return nil
}

func runProbe(ctx context.Context, prober r2Prober, output interface{ Write([]byte) (int, error) }) error {
	if prober == nil || output == nil {
		return errors.New("R2 probe dependencies are required")
	}
	if err := prober.Probe(ctx); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Backend string `json:"backend"`
		Status  string `json:"status"`
	}{Backend: "r2", Status: "available"})
}
