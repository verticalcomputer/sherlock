// Command sherlock-recipe-release builds and verifies a complete signed
// remediation-recipe release. It is deliberately an offline tool: it accepts
// an existing private key but never generates, installs, rotates, or transmits
// private material.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/remediation"
)

const maxJSONBytes = 1 << 20

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage: sherlock-recipe-release sign|verify [flags]")
	}
	switch arguments[0] {
	case "sign":
		return sign(arguments[1:], stdout)
	case "verify":
		return verify(arguments[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q; use sign or verify", arguments[0])
	}
}

func sign(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("sherlock-recipe-release sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recipePath := flags.String("recipes", "", "strict JSON array of complete reviewed recipes")
	privateKeyPath := flags.String("private-key", "", "restricted regular PKCS#8 Ed25519 PEM file")
	rootPath := flags.String("public-roots", "", "strict JSON array of public RecipeTrustRoot documents")
	rootID := flags.String("trust-root-id", "", "public root ID that authorizes this release")
	outputPath := flags.String("out", "", "new release JSON path; existing files are refused")
	atRaw := flags.String("at", "", "required RFC3339 verification instant")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *recipePath == "" || *privateKeyPath == "" || *rootPath == "" || *rootID == "" || *outputPath == "" || *atRaw == "" {
		return errors.New("-recipes, -private-key, -public-roots, -trust-root-id, -out, and -at are required")
	}
	now, err := parseInstant(*atRaw)
	if err != nil {
		return err
	}
	var recipes []remediation.Recipe
	if err := readStrictJSON(*recipePath, &recipes); err != nil {
		return fmt.Errorf("read recipes: %w", err)
	}
	// Validate the whole forward/rollback graph before private-key use. A
	// release is all-or-nothing: a valid forward recipe cannot be separated
	// from the exact digest-pinned rollback it references.
	if _, err := remediation.NewCatalog(recipes, now); err != nil {
		return fmt.Errorf("validate complete recipe set: %w", err)
	}
	roots, err := readRoots(*rootPath)
	if err != nil {
		return err
	}
	store, err := remediation.NewRecipeTrustStore(roots)
	if err != nil {
		return fmt.Errorf("validate public roots: %w", err)
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	defer zero(privateKey)
	if err := ensureMatchingRoot(roots, *rootID, privateKey.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	release, err := remediation.SignRecipeRelease(recipes, *rootID, privateKey)
	if err != nil {
		return fmt.Errorf("sign release: %w", err)
	}
	// Verify the exact release bytes through the public-only admission path
	// before writing an artifact that could be distributed.
	if _, err := store.Verify(release, now); err != nil {
		return fmt.Errorf("verify generated release: %w", err)
	}
	encoded, err := json.Marshal(release)
	if err != nil {
		return fmt.Errorf("encode release: %w", err)
	}
	defer zero(encoded)
	if err := writeNewFile(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	printRelease(stdout, *outputPath, release, now)
	return nil
}

func verify(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("sherlock-recipe-release verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	releasePath := flags.String("release", "", "strict JSON signed release")
	rootPath := flags.String("public-roots", "", "strict JSON array of public RecipeTrustRoot documents")
	atRaw := flags.String("at", "", "required RFC3339 verification instant")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *releasePath == "" || *rootPath == "" || *atRaw == "" {
		return errors.New("-release, -public-roots, and -at are required")
	}
	now, err := parseInstant(*atRaw)
	if err != nil {
		return err
	}
	var release remediation.SignedRecipeRelease
	if err := readStrictJSON(*releasePath, &release); err != nil {
		return fmt.Errorf("read release: %w", err)
	}
	roots, err := readRoots(*rootPath)
	if err != nil {
		return err
	}
	store, err := remediation.NewRecipeTrustStore(roots)
	if err != nil {
		return fmt.Errorf("validate public roots: %w", err)
	}
	if _, err := store.Verify(release, now); err != nil {
		return fmt.Errorf("verify release: %w", err)
	}
	printRelease(stdout, *releasePath, release, now)
	return nil
}

func parseInstant(value string) (time.Time, error) {
	now, err := time.Parse(time.RFC3339, value)
	if err != nil || now.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("-at must be a whole-second RFC3339 instant")
	}
	return now.UTC(), nil
}

func readRoots(path string) ([]remediation.RecipeTrustRoot, error) {
	var roots []remediation.RecipeTrustRoot
	if err := readStrictJSON(path, &roots); err != nil {
		return nil, fmt.Errorf("read public roots: %w", err)
	}
	return roots, nil
}

func readStrictJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	payload, err := io.ReadAll(io.LimitReader(f, maxJSONBytes+1))
	if err != nil {
		return err
	}
	if len(payload) > maxJSONBytes {
		return fmt.Errorf("JSON exceeds %d bytes", maxJSONBytes)
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

// rejectDuplicateJSONFields keeps the signer from accepting a document whose
// meaning could differ between JSON implementations. json.Decoder otherwise
// applies a last-field-wins rule while decoding structs.
func rejectDuplicateJSONFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		fields := make(map[string]struct{})
		for decoder.More() {
			field, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := field.(string)
			if !ok {
				return errors.New("object field name is invalid")
			}
			if _, duplicate := fields[name]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", name)
			}
			fields[name] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&0o077 != 0 {
		return nil, errors.New("private key must be a regular file inaccessible to group and other users")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	defer zero(payload)
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("private key must contain exactly one PKCS#8 PEM PRIVATE KEY block")
	}
	defer zero(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("private key must be Ed25519")
	}
	return privateKey, nil
}

func ensureMatchingRoot(roots []remediation.RecipeTrustRoot, id string, public ed25519.PublicKey) error {
	for _, root := range roots {
		if root.ID == id {
			if subtle.ConstantTimeCompare(root.PublicKey, public) != 1 {
				return fmt.Errorf("private key does not match public root %q", id)
			}
			return nil
		}
	}
	return fmt.Errorf("public root %q is not present", id)
}

func writeNewFile(path string, payload []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create release %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		return fmt.Errorf("write release %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close release %s: %w", filepath.Base(path), err)
	}
	return nil
}

func printRelease(stdout io.Writer, path string, release remediation.SignedRecipeRelease, at time.Time) {
	coordinates := make([]string, 0, len(release.Recipes))
	for _, recipe := range release.Recipes {
		coordinates = append(coordinates, fmt.Sprintf("%s@%s sha256:%s", recipe.ID, recipe.Version, hex.EncodeToString(recipe.Digest[:])))
	}
	slices.Sort(coordinates)
	fmt.Fprintf(stdout, "release     %s\nroot        %s\nverified at %s\n", path, release.TrustRootID, at.Format(time.RFC3339))
	for _, coordinate := range coordinates {
		fmt.Fprintf(stdout, "recipe      %s\n", coordinate)
	}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
