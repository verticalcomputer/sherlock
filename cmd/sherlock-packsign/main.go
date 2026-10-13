// Command sherlock-packsign produces the signed command pack and trust-root
// document that every diagnostic-executing process verifies.
//
// A pack pins each approved executable to its content, so its digests belong to
// the machines that will run it: `nvidia-smi` on the pilot's compute nodes is
// not the binary on a build host. Run this where those digests are known, or
// supply them explicitly.
//
// The signing key it can generate is written to disk, which suits a pilot and
// not a production trust root. A real root belongs offline or in an HSM; reuse
// one with -signing-key rather than minting a new root for every release.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
)

type trustRootDocument struct {
	ID          string    `json:"id"`
	Issuer      string    `json:"issuer"`
	PublicKey   []byte    `json:"public_key"`
	ActivatesAt time.Time `json:"activates_at"`
	RetiresAt   time.Time `json:"retires_at"`
}

type repeatedStrings []string

func (values *repeatedStrings) String() string { return strings.Join(*values, ",") }
func (values *repeatedStrings) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type executableFlag struct {
	path   string
	sha256 string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("sherlock-packsign", flag.ContinueOnError)
	outputDir := flags.String("out", "", "directory to write pack.json, trust-roots.json, and any generated key into")
	packID := flags.String("pack-id", "standard.readonly", "pack identifier")
	packVersion := flags.String("pack-version", "1.2.0", "pack version")
	issuer := flags.String("issuer", "sherlock.security", "issuing authority, which must match the trust root")
	trustRootID := flags.String("trust-root-id", "root.current", "trust root identifier")
	minimumRunner := flags.String("minimum-runner", "1.2.0", "lowest compatible sherlock-runner version")
	maximumRunner := flags.String("maximum-runner", "1.9.0", "highest compatible sherlock-runner version")
	validFor := flags.Duration("valid-for", 720*time.Hour, "how long the release stays verifiable")
	signingKeyFile := flags.String("signing-key", "", "existing PKCS#8 ed25519 signing key to reuse; a new key is generated when empty")
	var reviewers repeatedStrings
	flags.Var(&reviewers, "reviewer", "approving reviewer, repeated; at least one reviewer is required")

	nvidiaSMI := executableFlag{}
	journalctl := executableFlag{}
	scontrol := executableFlag{}
	flags.StringVar(&nvidiaSMI.path, "nvidia-smi", "/usr/bin/nvidia-smi", "absolute path to nvidia-smi on the target nodes")
	flags.StringVar(&nvidiaSMI.sha256, "nvidia-smi-sha256", "", "digest of nvidia-smi; computed from the local file when empty")
	flags.StringVar(&journalctl.path, "journalctl", "/usr/bin/journalctl", "absolute path to journalctl on the target nodes")
	flags.StringVar(&journalctl.sha256, "journalctl-sha256", "", "digest of journalctl; computed from the local file when empty")
	flags.StringVar(&scontrol.path, "scontrol", "/usr/bin/scontrol", "absolute path to scontrol on the head node")
	flags.StringVar(&scontrol.sha256, "scontrol-sha256", "", "digest of scontrol; computed from the local file when empty")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *outputDir == "" {
		return fmt.Errorf("-out is required")
	}

	identities := commandpack.PilotIdentities{}
	for _, resolution := range []struct {
		name     string
		flag     executableFlag
		identity *commandpack.ExecutableIdentity
	}{
		{"nvidia-smi", nvidiaSMI, &identities.NvidiaSMI},
		{"journalctl", journalctl, &identities.Journalctl},
		{"scontrol", scontrol, &identities.Scontrol},
	} {
		digest, err := resolveDigest(resolution.flag)
		if err != nil {
			return fmt.Errorf("%s: %w", resolution.name, err)
		}
		*resolution.identity = commandpack.ExecutableIdentity{Path: resolution.flag.path, SHA256: digest}
	}

	definitions, err := commandpack.PilotDefinitions(identities)
	if err != nil {
		return fmt.Errorf("build reviewed definitions: %w", err)
	}
	// The pack's validity is checked at load, and a definition that is not
	// currently active is refused at execution, so both ends of this window are
	// operational deadlines rather than metadata.
	issuedAt := time.Now().UTC().Truncate(time.Second)
	pack := commandpack.Pack{
		SchemaVersion: commandpack.SchemaVersion, ID: *packID, Version: *packVersion, Issuer: *issuer,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(*validFor),
		MinimumRunner: *minimumRunner, MaximumRunner: *maximumRunner,
		Reviews:     reviewDocuments(reviewers, issuedAt),
		Definitions: definitions,
	}
	if err := commandpack.ValidatePack(pack); err != nil {
		return fmt.Errorf("the pack is not valid: %w", err)
	}

	privateKey, generated, err := signingKey(*signingKeyFile)
	if err != nil {
		return err
	}
	release, err := commandpack.Sign(pack, *trustRootID, privateKey)
	if err != nil {
		return fmt.Errorf("sign the pack: %w", err)
	}
	encodedRelease, err := commandpack.EncodeRelease(release)
	if err != nil {
		return err
	}
	roots := []trustRootDocument{{
		ID: *trustRootID, Issuer: *issuer, PublicKey: privateKey.Public().(ed25519.PublicKey),
		// The root brackets the release it signs, so a release cannot outlive the
		// authority that approved it.
		ActivatesAt: issuedAt.Add(-time.Hour), RetiresAt: pack.ExpiresAt.Add(time.Hour),
	}}
	encodedRoots, err := json.Marshal(roots)
	if err != nil {
		return err
	}

	packPath := filepath.Join(*outputDir, "pack.json")
	rootsPath := filepath.Join(*outputDir, "trust-roots.json")
	if err := writeProtected(packPath, encodedRelease); err != nil {
		return err
	}
	if err := writeProtected(rootsPath, encodedRoots); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "pack        %s\n", packPath)
	fmt.Fprintf(stdout, "trust roots %s\n", rootsPath)
	fmt.Fprintf(stdout, "expires     %s\n", pack.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(stdout, "runner      %s to %s\n", pack.MinimumRunner, pack.MaximumRunner)
	if generated {
		keyPath := filepath.Join(*outputDir, "signing-key.pem")
		encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
		if err := writeProtected(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "signing key %s (keep it off the cluster; reuse it with -signing-key)\n", keyPath)
	}
	return nil
}

// resolveDigest prefers the operator's declared digest and falls back to the
// local file, which is correct only when this runs on a machine carrying the
// same binary as the targets.
func resolveDigest(executable executableFlag) (string, error) {
	if executable.path == "" {
		return "", fmt.Errorf("an absolute executable path is required")
	}
	if executable.sha256 != "" {
		return executable.sha256, nil
	}
	binary, err := os.ReadFile(executable.path)
	if err != nil {
		return "", fmt.Errorf("no digest was supplied and %s is not readable here", executable.path)
	}
	digest := sha256.Sum256(binary)
	return hex.EncodeToString(digest[:]), nil
}

func reviewDocuments(reviewers []string, issuedAt time.Time) []commandpack.Review {
	sorted := slices.Clone(reviewers)
	slices.Sort(sorted)
	reviews := make([]commandpack.Review, 0, len(sorted))
	for _, reviewer := range sorted {
		reviews = append(reviews, commandpack.Review{ReviewerID: reviewer, ReviewedAt: issuedAt.Add(-time.Minute), Approved: true})
	}
	return reviews
}

func signingKey(path string) (ed25519.PrivateKey, bool, error) {
	if path == "" {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, err
		}
		return privateKey, true, nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(payload)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, false, fmt.Errorf("signing key must be a PKCS#8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("parse signing key: %w", err)
	}
	privateKey, isEd25519 := parsed.(ed25519.PrivateKey)
	if !isEd25519 {
		return nil, false, fmt.Errorf("signing key must be ed25519")
	}
	return privateKey, false, nil
}

// writeProtected creates the file readable only by its owner. Every consumer
// refuses a group- or world-writable pack, so writing one loosely here would
// only fail later, further from the cause.
func writeProtected(path string, payload []byte) error {
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return os.Chmod(path, 0o600)
}
