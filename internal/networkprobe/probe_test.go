package networkprobe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
)

type fakeRunner func(context.Context, string) ([]byte, []byte, error)

func (f fakeRunner) Read(ctx context.Context, node string) ([]byte, []byte, error) {
	return f(ctx, node)
}

const goodSnapshot = `{"boot_id":"12345678-abcd","ports":[{"device":"mlx5_0","port":1,"link_layer":"InfiniBand","state":"4: ACTIVE","physical_state":"5: LinkUp","link_downed":2},{"device":"mlx5_bond_0","port":1,"link_layer":"Ethernet","state":"4: ACTIVE","physical_state":"5: LinkUp","link_downed":null}]}`

func TestProbeClassifiesCompleteAndSourceGaps(t *testing.T) {
	node := PilotNodes[0]
	now := func() time.Time { return time.Date(2026, 9, 29, 1, 2, 3, 0, time.UTC) }
	cases := []struct {
		name, data, stderr, outcome, code string
		err                               error
	}{
		{"complete", goodSnapshot, "", application.NetworkPollComplete, "", nil},
		{"all ports absent from readable directory", `{"boot_id":"12345678","ports":[]}`, "", application.NetworkPollComplete, "", nil},
		{"ports missing from response", `{"boot_id":"12345678"}`, "", application.NetworkPollReadFailed, application.NetworkReadInvalidResponse, nil},
		{"auth", "", "Permission denied (publickey).", application.NetworkPollAuthUnavailable, application.NetworkReadSSHAuthDenied, errors.New("exit 255")},
		{"unreachable", "", "ssh: connect to host fixture1-zone1-comp001: No route to host", application.NetworkPollNodeUnreachable, application.NetworkReadNodeUnreachable, errors.New("exit 255")},
		{"other error", "", "ssh failed: secret-canary", application.NetworkPollReadFailed, application.NetworkReadSourceFailed, errors.New("exit 1")},
		{"malformed", `{"boot_id":"12345678","ports":[{"device":"mlx5_0","port":1}]}`, "", application.NetworkPollReadFailed, application.NetworkReadInvalidResponse, nil},
		{"trailing", goodSnapshot + `{}`, "", application.NetworkPollReadFailed, application.NetworkReadInvalidResponse, nil},
		{"duplicate", `{"boot_id":"12345678","ports":[{"device":"mlx5_0","port":1,"link_layer":"InfiniBand","state":"4: ACTIVE","physical_state":"5: LinkUp"},{"device":"mlx5_0","port":1,"link_layer":"InfiniBand","state":"4: ACTIVE","physical_state":"5: LinkUp"}]}`, "", application.NetworkPollReadFailed, application.NetworkReadInvalidResponse, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			poll, err := Probe(context.Background(), fakeRunner(func(context.Context, string) ([]byte, []byte, error) {
				return []byte(tc.data), []byte(tc.stderr), tc.err
			}), node, now)
			if err != nil || poll.Outcome != tc.outcome || poll.ReadError != tc.code {
				t.Fatalf("poll=%+v err=%v", poll, err)
			}
			if strings.Contains(poll.ReadError, "canary") {
				t.Fatal("raw SSH stderr escaped")
			}
			if tc.name == "complete" && (len(poll.Ports) != 2 || poll.Ports[0].LinkDowned == nil || *poll.Ports[0].LinkDowned != 2) {
				t.Fatalf("lost source values: %+v", poll)
			}
		})
	}
}

func TestProbeRejectsUnapprovedTargetBeforeRunner(t *testing.T) {
	called := false
	_, err := Probe(context.Background(), fakeRunner(func(context.Context, string) ([]byte, []byte, error) {
		called = true
		return nil, nil, nil
	}), "fixture1-zone1-comp009", time.Now)
	if err == nil || called {
		t.Fatalf("unapproved target: called=%v err=%v", called, err)
	}
}

func TestSSHRunnerFixedCommandAndOutputLimit(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	stdinPath := filepath.Join(dir, "stdin")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TEST_ARGS\"\ncat > \"$TEST_STDIN\"\nprintf '%s' '" + goodSnapshot + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TEST_ARGS", argsPath)
	t.Setenv("TEST_STDIN", stdinPath)
	stdout, _, err := (SSHRunner{}).Read(context.Background(), PilotNodes[0])
	if err != nil || string(stdout) != goodSnapshot {
		t.Fatalf("runner output err=%v", err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(args)
	if !strings.Contains(got, "BatchMode=yes\n") || !strings.Contains(got, "StrictHostKeyChecking=yes\n") ||
		!strings.HasSuffix(got, PilotNodes[0]+"\npython3\n-\n") || strings.Contains(got, "sudo") {
		t.Fatalf("unexpected ssh arguments: %q", got)
	}
	stdin, err := os.ReadFile(stdinPath)
	if err != nil || string(stdin) != remoteReader {
		t.Fatalf("fixed script missing: %v", err)
	}
	if _, _, err := (SSHRunner{}).Read(context.Background(), "fixture1-zone1-comp009"); err == nil {
		t.Fatal("unapproved target reached ssh")
	}
	var buf limitedBuffer
	_, _ = buf.Write([]byte(strings.Repeat("x", MaxBytes+1)))
	if !buf.overflow || buf.Len() != MaxBytes {
		t.Fatal("output cap failed")
	}
}

func TestFixedReaderManagementPathsAndIndependentReadFailure(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	root := t.TempDir()
	ib := filepath.Join(root, "ib")
	net := filepath.Join(root, "net")
	boot := filepath.Join(root, "boot")
	write := func(path, value string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(boot, "12345678-abcd")
	for path, value := range map[string]string{"node_guid": "0000:0000:0000:0001", "ports/1/link_layer": "InfiniBand", "ports/1/state": "4: ACTIVE", "ports/1/phys_state": "5: LinkUp"} {
		write(filepath.Join(ib, "mlx5_0", path), value)
	}
	for path, value := range map[string]string{"bonding/mode": "802.3ad 4", "bonding/slaves": "enp55s0f0np0 enp55s0f1np1", "carrier": "1", "operstate": "up"} {
		write(filepath.Join(net, "bond0", path), value)
	}
	for _, member := range []string{"enp55s0f0np0", "enp55s0f1np1"} {
		write(filepath.Join(net, member, "carrier"), "1")
		write(filepath.Join(net, member, "operstate"), "up")
		write(filepath.Join(net, member, "statistics/rx_errors"), "0")
	}
	script := strings.ReplaceAll(remoteReader, "/sys/class/infiniband", ib)
	script = strings.ReplaceAll(script, "/sys/class/net", net)
	script = strings.ReplaceAll(script, "/proc/sys/kernel/random/boot_id", boot)
	read := func() application.NetworkNodePoll {
		t.Helper()
		cmd := exec.Command(python, "-")
		cmd.Stdin = strings.NewReader(script)
		data, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		p, err := Probe(context.Background(), fakeRunner(func(context.Context, string) ([]byte, []byte, error) { return data, nil, nil }), FixtureNetworkNodes[0], time.Now)
		if err != nil || p.Outcome != "COMPLETE" {
			t.Fatalf("%+v %v", p, err)
		}
		return p
	}
	p := read()
	if len(p.Bonds) != 1 || len(p.Bonds[0].Members) != 2 || p.Bonds[0].Members[0].RXErrors == nil || *p.Bonds[0].Members[0].RXErrors != 0 || p.Bonds[0].Members[0].TXErrors != nil {
		t.Fatalf("lost counter support: %+v", p)
	}
	if err := os.Remove(filepath.Join(net, "enp55s0f0np0/carrier")); err != nil {
		t.Fatal(err)
	}
	p = read()
	if p.Bonds[0].ReadError != application.NetworkReadSourceFailed || len(p.Ports) != 1 {
		t.Fatalf("read error corrupted IB: %+v", p)
	}
	if err := os.RemoveAll(filepath.Join(net, "bond0")); err != nil {
		t.Fatal(err)
	}
	p = read()
	if p.Bonds[0].Present || p.Bonds[0].ReadError != "" {
		t.Fatalf("missing bond not distinguished: %+v", p)
	}
}
