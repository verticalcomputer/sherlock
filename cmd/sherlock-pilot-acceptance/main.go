// Command sherlock-pilot-acceptance validates immutable machine-derived pilot
// evidence against an independently signed-off operator review.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/verticalcomputer/sherlock/internal/pilotacceptance"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sherlock-pilot-acceptance", flag.ContinueOnError)
	flags.SetOutput(stderr)
	runPath := flags.String("run", "", "immutable machine-derived pilot run JSON")
	reviewPath := flags.String("review", "", "named admin review JSON")
	investigationExportPath := flags.String("investigation-export", "", "investigation snapshot export referenced by the run")
	modelAuditExportPath := flags.String("model-audit-export", "", "model-call audit export referenced by the run")
	evidenceExportPath := flags.String("evidence-manifest", "", "evidence manifest export referenced by the run")
	outputPath := flags.String("output", "-", "closeout summary path, or - for stdout")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *runPath == "" || *reviewPath == "" || *investigationExportPath == "" || *modelAuditExportPath == "" || *evidenceExportPath == "" {
		fmt.Fprintln(stderr, "sherlock-pilot-acceptance: run, review, and all three export paths are required")
		return 2
	}
	runRecord, raw, err := pilotacceptance.LoadRun(*runPath)
	if err != nil {
		fmt.Fprintf(stderr, "sherlock-pilot-acceptance: %v\n", err)
		return 2
	}
	review, err := pilotacceptance.LoadReview(*reviewPath)
	if err != nil {
		fmt.Fprintf(stderr, "sherlock-pilot-acceptance: %v\n", err)
		return 2
	}
	exports := map[string][]byte{}
	for kind, path := range map[string]string{"INVESTIGATION_SNAPSHOT": *investigationExportPath, "MODEL_AUDIT": *modelAuditExportPath, "EVIDENCE_MANIFEST": *evidenceExportPath} {
		payload, err := pilotacceptance.LoadExport(path)
		if err != nil {
			fmt.Fprintf(stderr, "sherlock-pilot-acceptance: %v\n", err)
			return 2
		}
		exports[kind] = payload
	}
	summary := pilotacceptance.Evaluate(raw, runRecord, review, exports)
	data, err := pilotacceptance.MarshalSummary(summary)
	if err != nil {
		fmt.Fprintf(stderr, "sherlock-pilot-acceptance: %v\n", err)
		return 2
	}
	if *outputPath == "-" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "sherlock-pilot-acceptance: write summary: %v\n", err)
			return 2
		}
	} else if err := os.WriteFile(*outputPath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "sherlock-pilot-acceptance: write summary: %v\n", err)
		return 2
	}
	if !summary.Passed {
		return 1
	}
	return 0
}
