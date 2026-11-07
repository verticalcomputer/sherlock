package gpussh

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApprovalFailsClosedAndExpires(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "approval.json")
	good := Approval{Schema: "sherlock.gpu-ssh-approval.v1", ClusterID: "cluster", Roles: []string{"gpu-process"}, ApprovedBy: "operator", ApprovalID: "review-1", ExpiresAt: now.Add(time.Hour)}
	write := func(a Approval) {
		t.Helper()
		b, _ := json.Marshal(a)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		name   string
		mutate func(*Approval)
	}{
		{"wrong cluster", func(a *Approval) { a.ClusterID = "other" }},
		{"wrong role", func(a *Approval) { a.Roles = []string{"diagnostics"} }},
		{"expired", func(a *Approval) { a.ExpiresAt = now }},
		{"no review", func(a *Approval) { a.ApprovalID = "" }},
		{"unknown schema", func(a *Approval) { a.Schema = "other" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := good
			tt.mutate(&a)
			write(a)
			if !errors.Is(Check(path, "gpu-process", "cluster", now), ErrBlocked) {
				t.Fatal("accepted unapproved authority")
			}
		})
	}
	write(good)
	if err := Check(path, "gpu-process", "cluster", now); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Check("", "gpu-process", "cluster", now), ErrBlocked) {
		t.Fatal("missing approval accepted")
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Check(path, "gpu-process", "cluster", now), ErrBlocked) {
		t.Fatal("shared approval accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Check(link, "gpu-process", "cluster", now), ErrBlocked) {
		t.Fatal("symlink accepted")
	}
	for _, bad := range []string{`{} {}`, `{"schema":"sherlock.gpu-ssh-approval.v1","unexpected":true}`, string(make([]byte, 17000))} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(Check(path, "gpu-process", "cluster", now), ErrBlocked) {
			t.Fatal("malformed approval accepted")
		}
	}
}

func TestPersistentHoldOverridesApprovalAndRuntimeRevocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "approval.json")
	a := Approval{Schema: "sherlock.gpu-ssh-approval.v1", ClusterID: "cluster", Roles: []string{"diagnostics"}, ApprovedBy: "operator", ApprovalID: "review", ExpiresAt: time.Now().Add(time.Hour)}
	b, _ := json.Marshal(a)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(Environment, path)
	if err := Require("diagnostics", "cluster"); err != nil {
		t.Fatal(err)
	}
	holds := filepath.Join(home, ".local/share/sherlock/service-holds/repeated-failure-20261105")
	if err := os.MkdirAll(holds, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(holds, "hold.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Require("diagnostics", "cluster"), ErrBlocked) {
		t.Fatal("hold did not block authority")
	}
	if !errors.Is(CheckHolds(), ErrBlocked) {
		t.Fatal("hold did not block renewal")
	}
}
