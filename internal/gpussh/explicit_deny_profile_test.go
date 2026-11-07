package gpussh

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExplicitPolicyDeniesEvenValidHeadApproval(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "approval.json")
	approved := Approval{Schema: "sherlock.gpu-ssh-approval.v1", ClusterID: "cluster", Roles: []string{"gpu-process"}, ApprovedBy: "operator", ApprovalID: "existing-reviewed-grant", ExpiresAt: time.Now().Add(time.Hour)}
	payload, err := json.Marshal(approved)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(Environment, path)
	t.Setenv(PolicyEnvironment, "approval")
	if err = Require("gpu-process", "cluster"); err != nil {
		t.Fatalf("valid positive authority: %v", err)
	}
	for _, policy := range []string{"deny", "", "unknown", "DENY"} {
		t.Run("policy_"+policy, func(t *testing.T) {
			t.Setenv(PolicyEnvironment, policy)
			if !errors.Is(Require("gpu-process", "cluster"), ErrBlocked) {
				t.Fatal("explicit policy allowed head SSH")
			}
		})
	}
}

func TestExplicitDenyProfileRequiresPresentEmptyApprovalVariables(t *testing.T) {
	t.Setenv(PolicyEnvironment, "deny")
	t.Setenv(Environment, "")
	t.Setenv("SHERLOCK_GPU_SSH_DISPATCH_APPROVAL_FILE", "")
	if !ExplicitDenyProfile() {
		t.Fatal("explicit empty profile rejected")
	}
	for _, name := range []string{Environment, "SHERLOCK_GPU_SSH_DISPATCH_APPROVAL_FILE"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "/inherited/approval.json")
			if ExplicitDenyProfile() {
				t.Fatal("inherited approval accepted")
			}
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
			if ExplicitDenyProfile() {
				t.Fatal("absent value can be filled by dotenv")
			}
		})
	}
}
