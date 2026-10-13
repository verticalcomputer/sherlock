package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/verticalcomputer/sherlock/internal/m11acceptance"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sherlock-m11-acceptance", flag.ContinueOnError)
	flags.SetOutput(stderr)
	fixturePath := flags.String("fixture", "", "path to the reviewed redacted six-turn fixture")
	expected := flags.String("sha256", "", "reviewed SHA-256 of the exact fixture")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *fixturePath == "" || *expected == "" {
		fmt.Fprintln(stderr, "sherlock-m11-acceptance: -fixture and -sha256 are required")
		return 2
	}
	encoded, err := os.ReadFile(*fixturePath)
	if err != nil {
		fmt.Fprintf(stderr, "sherlock-m11-acceptance: %v\n", err)
		return 2
	}
	summary, err := m11acceptance.Evaluate(encoded, *expected)
	if err != nil {
		fmt.Fprintf(stderr, "sherlock-m11-acceptance: %v\n", err)
		return 2
	}
	output, _ := json.MarshalIndent(summary, "", "  ")
	output = append(output, '\n')
	if _, err := stdout.Write(output); err != nil {
		return 2
	}
	if !summary.Passed {
		return 1
	}
	return 0
}
