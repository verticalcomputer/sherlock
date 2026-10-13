package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetrylocal"
)

// Identity commands are explicit local file operations. Public request/bundle
// output grants no enrollment or certificate issuance authority.
func runIdentity(args []string, out, errs io.Writer) int {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	directory := f.String("directory", "", "owner-only local identity directory")
	if args[0] == "identity-request" {
		cluster := f.String("cluster", "", "exact cluster")
		node := f.String("node", "", "exact node")
		enrollment := f.String("enrollment", "", "exact enrollment")
		key := f.String("key", "", "exact key")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *directory == "" {
			fmt.Fprintln(errs, "node identity request arguments invalid")
			return 2
		}
		request, e := nodeidentity.CreateIdentityRequest(*directory, nodeidentity.Scope{ClusterID: *cluster, NodeID: *node, EnrollmentID: *enrollment, KeyID: *key})
		if e != nil {
			fmt.Fprintln(errs, "node identity request unavailable")
			return 1
		}
		if json.NewEncoder(out).Encode(request) != nil {
			fmt.Fprintln(errs, "node identity request output unavailable")
			return 1
		}
		return 0
	}
	bundleFile := f.String("bundle", "", "protected public bundle file")
	pin := f.String("node-ca-sha256", "", "independently approved node CA fingerprint")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *directory == "" || *bundleFile == "" || *pin == "" {
		fmt.Fprintln(errs, "node identity import arguments invalid")
		return 2
	}
	body, e := telemetrylocal.ReadProtected(*bundleFile, nodeidentity.MaxBundleBytes)
	if e != nil {
		fmt.Fprintln(errs, "node identity import input unavailable")
		return 1
	}
	var bundle nodeidentity.CertificateBundle
	if telemetry.DecodeStrictJSON(body, "", &bundle) != nil || nodeidentity.ImportIdentity(*directory, bundle, *pin, time.Now()) != nil {
		fmt.Fprintln(errs, "node identity import rejected")
		return 1
	}
	fmt.Fprintln(out, "node identity imported")
	return 0
}
