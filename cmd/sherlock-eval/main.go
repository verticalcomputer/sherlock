package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/verticalcomputer/sherlock/internal/investigationeval"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sherlock-eval", flag.ContinueOnError)
	flags.SetOutput(stderr)
	suitePath := flags.String("suite", "test/evals/v1/suite.json", "path to a versioned offline evaluation suite")
	replayPath := flags.String("replay-suite", "", "path to a versioned orchestrator/provider replay suite")
	outputPath := flags.String("output", "-", "summary path, or - for stdout")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "sherlock-eval: unexpected positional arguments")
		return 2
	}

	var summary investigationeval.Summary
	var err error
	if *replayPath != "" {
		replay, loadErr := investigationeval.LoadReplayFile(*replayPath)
		if loadErr != nil {
			fmt.Fprintf(stderr, "sherlock-eval: %v\n", loadErr)
			return 2
		}
		summary, err = investigationeval.RunReplay(context.Background(), replay)
	} else {
		suite, loadErr := investigationeval.LoadFile(*suitePath)
		if loadErr != nil {
			fmt.Fprintf(stderr, "sherlock-eval: %v\n", loadErr)
			return 2
		}
		summary, err = investigationeval.Evaluate(suite)
	}
	if err != nil {
		fmt.Fprintf(stderr, "sherlock-eval: %v\n", err)
		return 2
	}
	data, err := investigationeval.MarshalSummary(summary)
	if err != nil {
		fmt.Fprintf(stderr, "sherlock-eval: %v\n", err)
		return 2
	}
	if *outputPath == "-" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "sherlock-eval: write summary: %v\n", err)
			return 2
		}
	} else if err := os.WriteFile(*outputPath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "sherlock-eval: write summary: %v\n", err)
		return 2
	}
	if !summary.Passed {
		return 1
	}
	return 0
}
