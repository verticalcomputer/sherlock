// Package gpussh is the local operator's additional, default-deny authority for
// automated compute SSH. It does not replace signed packs, target admission,
// credentials or host-key checks.
package gpussh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

const Environment = "SHERLOCK_GPU_SSH_AUTHORIZATION_FILE"
const PolicyEnvironment = "SHERLOCK_GPU_SSH_POLICY"

// Explicit deny is stronger than an approval. An absent policy retains the
// reviewed-approval interface; unknown/empty explicit policy values deny.
func approvalPolicyAllowed() bool {
	value, present := os.LookupEnv(PolicyEnvironment)
	return !present || value == "approval"
}

// ExplicitDenyProfile also pins empty values so dotenv cannot fill an absent
// file setting and inherited approval paths cannot provide authority.
func ExplicitDenyProfile() bool {
	if os.Getenv(PolicyEnvironment) != "deny" {
		return false
	}
	for _, name := range []string{Environment, "SHERLOCK_GPU_SSH_DISPATCH_APPROVAL_FILE"} {
		value, present := os.LookupEnv(name)
		if !present || value != "" {
			return false
		}
	}
	return true
}

var ErrBlocked = errors.New("automated GPU SSH blocked by operator policy")

type Approval struct {
	Schema     string    `json:"schema"`
	ClusterID  string    `json:"cluster_id"`
	Roles      []string  `json:"roles"`
	ApprovedBy string    `json:"approved_by"`
	ApprovalID string    `json:"approval_id"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Require re-reads protected approval and hold files on every call, including
// every invocation, so an already running claimant cannot retain revoked scope.
func Require(role, cluster string) error {
	if !approvalPolicyAllowed() {
		return fmt.Errorf("%w: explicit process policy", ErrBlocked)
	}
	if err := CheckHolds(); err != nil {
		return err
	}
	return Check(os.Getenv(Environment), role, cluster, time.Now().UTC())
}

// Check reads only a caller-owned regular 0600 file in a protected directory.
// No content or path is included in errors, since approval paths can be private.
func Check(path, role, cluster string, now time.Time) error {
	approval, err := readApproval(path)
	if err != nil {
		return err
	}
	if cluster == "" || approval.Schema != "sherlock.gpu-ssh-approval.v1" || approval.ClusterID != cluster || !slices.Contains(approval.Roles, role) || approval.ApprovedBy == "" || approval.ApprovalID == "" || !now.Before(approval.ExpiresAt) {
		return fmt.Errorf("%w: approval absent, expired or outside scope", ErrBlocked)
	}
	return nil
}

func readApproval(path string) (Approval, error) {
	blocked := func(reason string) (Approval, error) { return Approval{}, fmt.Errorf("%w: %s", ErrBlocked, reason) }
	if path == "" || !filepath.IsAbs(path) {
		return blocked("explicit approval required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 16384 {
		return blocked("approval file is unavailable or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return blocked("approval owner mismatch")
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return blocked("approval directory is unsafe")
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || (parentStat.Uid != uint32(os.Geteuid()) && parentStat.Uid != 0) {
		return blocked("approval directory owner mismatch")
	}
	// No-follow plus nonblocking open avoids a symlink/FIFO replacement race.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return blocked("approval unreadable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return blocked("approval changed while opening")
	}
	var approval Approval
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if d.Decode(&approval) != nil || d.Decode(new(any)) != io.EOF {
		return blocked("invalid approval")
	}
	return approval, nil
}

// CheckHolds also protects renewal, which carries no GPU SSH authority itself.
func CheckHolds() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("%w: home unavailable", ErrBlocked)
	}
	holds := filepath.Join(home, ".local/share/sherlock/service-holds")
	for _, pattern := range []string{filepath.Join(holds, "hold.json"), filepath.Join(holds, "*", "hold.json")} {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) != 0 {
			return fmt.Errorf("%w: persistent service hold", ErrBlocked)
		}
	}
	return nil
}
