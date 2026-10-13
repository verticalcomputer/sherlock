package commandpack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Maximum sizes for the reviewed on-disk documents. A pack carries every
// definition and is the largest; trust roots and the target-role inventory are
// small operator-maintained files.
const (
	MaximumPackFileBytes      = int64(8 << 20)
	MaximumTrustRootFileBytes = int64(1 << 20)
	MaximumInventoryFileBytes = int64(1 << 20)
)

// trustRootDocument is the on-disk shape of a trust root. It is a transport
// type: TrustRoot itself carries no JSON tags, because the signing types must
// not gain an encoding just to avoid a mapper.
type trustRootDocument struct {
	ID          string    `json:"id"`
	Issuer      string    `json:"issuer"`
	PublicKey   []byte    `json:"public_key"`
	ActivatesAt time.Time `json:"activates_at"`
	RetiresAt   time.Time `json:"retires_at"`
}

// LoadVerifiedCatalog reads a signed release and the trust roots that justify
// it, and returns the immutable catalog they produce.
//
// Every process that resolves an argv from the pack -- the API that previews
// and starts a diagnostic, the investigator that dispatches one, and the
// head-node loop that executes it -- performs exactly this load, and each
// verifies independently. That is deliberate duplication of verification and
// must stay that way; it was duplication of the *loading code* that this
// function removes, because three copies of a signature check drift.
//
// A release that cannot be verified is an error, never a degraded catalog: a
// caller that cannot verify the pack must refuse to start rather than execute
// something unverified.
func LoadVerifiedCatalog(packFile, trustRootsFile, runnerVersion string, now time.Time) (*Catalog, error) {
	releaseBytes, err := ReadProtectedFile(packFile, MaximumPackFileBytes)
	if err != nil {
		return nil, fmt.Errorf("load signed command pack: %w", err)
	}
	release, err := DecodeRelease(releaseBytes)
	if err != nil {
		return nil, fmt.Errorf("decode signed command pack: %w", err)
	}
	rootBytes, err := ReadProtectedFile(trustRootsFile, MaximumTrustRootFileBytes)
	if err != nil {
		return nil, fmt.Errorf("load command trust roots: %w", err)
	}
	var documents []trustRootDocument
	if err := decodeStrict(rootBytes, &documents); err != nil || len(documents) == 0 {
		return nil, fmt.Errorf("decode command trust roots")
	}
	roots := make([]TrustRoot, len(documents))
	for index, document := range documents {
		roots[index] = TrustRoot(document)
	}
	trust, err := NewTrustStore(roots)
	if err != nil {
		return nil, err
	}
	catalog, err := trust.Verify(release, runnerVersion, now.UTC().Truncate(time.Second))
	if err != nil {
		return nil, fmt.Errorf("verify signed command pack: %w", err)
	}
	return catalog, nil
}

// LoadTargetRoles reads the operator-maintained inventory that says which hosts
// hold which role, as cluster ID -> target name -> role.
//
// Which machines a diagnostic reaches is a targeting decision, so this file is
// read with the same protections as the pack and rejects unknown fields. It
// remains the source of roles until derivation from Slurm, collector coverage,
// and Redfish is wired; the shape is the same either way.
func LoadTargetRoles(path string) (map[string]map[string]TargetRole, error) {
	payload, err := ReadProtectedFile(path, MaximumInventoryFileBytes)
	if err != nil {
		return nil, fmt.Errorf("load diagnostic inventory: %w", err)
	}
	var inventory map[string]map[string]TargetRole
	if err := decodeStrict(payload, &inventory); err != nil {
		return nil, fmt.Errorf("decode diagnostic inventory: %w", err)
	}
	for cluster, targets := range inventory {
		if cluster == "" || len(targets) == 0 {
			return nil, fmt.Errorf("diagnostic inventory contains an empty cluster entry")
		}
		for target, role := range targets {
			if target == "" {
				return nil, fmt.Errorf("diagnostic inventory contains an unnamed target")
			}
			switch role {
			case TargetHead, TargetCompute, TargetBMCGateway:
			default:
				return nil, fmt.Errorf("diagnostic inventory contains an unknown target role")
			}
		}
	}
	return inventory, nil
}

// ReadProtectedFile reads a reviewed configuration document under the
// properties that make its contents trustworthy: an absolute, clean, unfollowed
// path to a regular file that no group or other user can write.
//
// The symlink and writability checks are the point. A pack file an unprivileged
// user can replace, or a path that resolves elsewhere through a symlink, is a
// command-injection primitive that the signature check downstream would then be
// asked to catch on its own.
func ReadProtectedFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("path must be absolute and clean")
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open protected file")
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("file must be regular and not group/world writable")
	}
	if info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("file size is outside the allowed bound")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return nil, fmt.Errorf("read protected file")
	}
	return payload, nil
}

// decodeStrict refuses unknown fields and trailing data. A security-sensitive
// document that carries a key this build does not understand is a version
// mismatch, not something to interpret partially.
func decodeStrict(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode document: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("document carries trailing data")
	}
	return nil
}
