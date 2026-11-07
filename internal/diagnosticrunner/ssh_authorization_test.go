package diagnosticrunner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/gpussh"
)

func TestBlockedAgentlessAndRestrictedSSHMakeZeroAttempts(t *testing.T) {
	t.Setenv(gpussh.Environment, "")
	marker := filepath.Join(t.TempDir(), "attempt")
	identity := writeFakeSSH(t, "#!/bin/sh\nprintf attempted > "+posixShellQuote(marker)+"\n")
	agentless, err := NewAgentlessSSH(testAgentlessSSHConfig(t, identity))
	if err != nil {
		t.Fatal(err)
	}
	restricted := testSSHAdapter(t)
	// Remove the explicitly installed transport-fixture authority. The production
	// constructor installs this check, independently of leases and command packs.
	restricted.authorize = func() error { return gpussh.Require("diagnostics", "fixture-cluster") }
	for name, invoke := range map[string]func() error{
		"agentless": func() error {
			_, err := agentless.ExecuteInvocation(context.Background(), nil, nil, "attempt", commandpack.Invocation{}, nil)
			return err
		},
		"restricted including native password": func() error {
			_, err := restricted.ExecuteInvocation(context.Background(), nil, nil, "attempt", commandpack.Invocation{}, nil)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(invoke(), gpussh.ErrBlocked) {
				t.Fatal("unapproved SSH reached execution")
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("blocked SSH spawned executable")
	}
}

func TestBlockedNativePasswordSSHDoesNotFetchCredential(t *testing.T) {
	t.Setenv(gpussh.Environment, "")
	server := newNativeSSHTestServer(t, []byte("isolated"), nil)
	provider := &clearingCredentialProvider{password: []byte("isolated")}
	adapter := server.adapter(t, provider)
	adapter.authorize = func() error { return gpussh.Require("diagnostics", "fixture-cluster") }
	if _, err := adapter.ExecuteInvocation(context.Background(), nil, nil, "attempt", commandpack.Invocation{}, nil); !errors.Is(err, gpussh.ErrBlocked) {
		t.Fatal(err)
	}
	if provider.exposed != nil || provider.reference != "" {
		t.Fatal("blocked native path fetched credential")
	}
	server.mutex.Lock()
	defer server.mutex.Unlock()
	if len(server.commands) != 0 {
		t.Fatal("blocked native path reached target")
	}
}
