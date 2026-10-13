// Command sherlock-packverify verifies a signed command pack exactly as the
// runtime processes do and prints only non-secret release metadata.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
)

type repeatedDefinitions []string

func (values *repeatedDefinitions) String() string { return fmt.Sprint([]string(*values)) }
func (values *repeatedDefinitions) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer, now time.Time) error {
	flags := flag.NewFlagSet("sherlock-packverify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	packFile := flags.String("pack", "", "absolute path to signed pack")
	trustRootsFile := flags.String("trust-roots", "", "absolute path to trust roots")
	runnerVersion := flags.String("runner-version", "", "runner version to verify")
	var required repeatedDefinitions
	flags.Var(&required, "require-definition", "required definition ID@VERSION, repeated")
	if err := flags.Parse(arguments); err != nil || *packFile == "" || *trustRootsFile == "" || *runnerVersion == "" || flags.NArg() != 0 {
		return fmt.Errorf("pack, trust-roots, and runner-version are required")
	}
	catalog, err := commandpack.LoadVerifiedCatalog(*packFile, *trustRootsFile, *runnerVersion, now)
	if err != nil {
		return err
	}
	type definitionMetadata struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	}
	definitions := make([]definitionMetadata, 0, len(required))
	for _, requiredDefinition := range required {
		definitionID, definitionVersion, found := strings.Cut(requiredDefinition, "@")
		if !found || definitionID == "" || definitionVersion == "" || strings.Contains(definitionVersion, "@") {
			return fmt.Errorf("required definition %q must use ID@VERSION", requiredDefinition)
		}
		_, digest, found := catalog.Lookup(definitionID, definitionVersion)
		if !found {
			return fmt.Errorf("required definition %q is absent", requiredDefinition)
		}
		definitions = append(definitions, definitionMetadata{ID: definitionID, Version: definitionVersion, SHA256: digest})
	}
	metadata := catalog.Metadata()
	return json.NewEncoder(output).Encode(struct {
		PackID        string               `json:"pack_id"`
		PackVersion   string               `json:"pack_version"`
		Issuer        string               `json:"issuer"`
		IssuedAt      time.Time            `json:"issued_at"`
		ExpiresAt     time.Time            `json:"expires_at"`
		RunnerVersion string               `json:"runner_version"`
		Definitions   []definitionMetadata `json:"required_definitions"`
	}{metadata.PackID, metadata.PackVersion, metadata.Issuer, metadata.IssuedAt, metadata.ExpiresAt, *runnerVersion, definitions})
}
