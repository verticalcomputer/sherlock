// Package buildinfo exposes the exact release identity without loading runtime configuration.
package buildinfo

import (
	"encoding/json"
	"io"
	"runtime"
)

// Linker values are supplied by scripts/build-production-candidate.py. Developer
// builds identify themselves explicitly and are never approved release artifacts.
var SourceRevision = "UNVERIFIED"
var SourceTree = "UNVERIFIED"

func PrintVersion(args []string, out io.Writer) bool {
	if len(args) != 1 || (args[0] != "--version" && args[0] != "version") {
		return false
	}
	_ = json.NewEncoder(out).Encode(map[string]string{"source_revision": SourceRevision, "source_tree": SourceTree, "go_version": runtime.Version()})
	return true
}
