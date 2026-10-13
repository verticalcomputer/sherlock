// Package networkprobe performs bounded, read-only node and InfiniBand source
// discovery. It does not enroll an expected rail inventory or send alerts.
package networkprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
)

const (
	MaxNodes       = 16
	MaxBytes       = 32 << 10
	PerNodeTimeout = 8 * time.Second
)

// PilotNodes is the approved read-only target set, not a reviewed network
// topology. The missing comp009 and comp012 are deliberately excluded.
var PilotNodes = []string{
	"fixture1-zone1-comp001", "fixture1-zone1-comp002", "fixture1-zone1-comp003", "fixture1-zone1-comp004",
	"fixture1-zone1-comp005", "fixture1-zone1-comp006", "fixture1-zone1-comp007", "fixture1-zone1-comp008",
	"fixture1-zone1-comp010", "fixture1-zone1-comp011",
}

// FixtureNetworkNodes is the explicitly approved fourteen-node read-only set.
var FixtureNetworkNodes = []string{
	"fixture2-zone1-comp001", "fixture2-zone1-comp002", "fixture2-zone1-comp004", "fixture2-zone1-comp005",
	"fixture2-zone1-comp006", "fixture2-zone1-comp007", "fixture2-zone1-comp008", "fixture2-zone1-comp009",
	"fixture2-zone1-comp010", "fixture2-zone1-comp011", "fixture2-zone1-comp012", "fixture2-zone1-comp013",
	"fixture2-zone1-comp015", "fixture2-zone1-comp017",
}

type Runner interface {
	Read(context.Context, string) ([]byte, []byte, error)
}

type SSHRunner struct{}

// Read invokes only a fixed Python reader over a host-key-checked,
// noninteractive SSH connection. No sudo, traffic test or mutation is part of
// the command. stdout and stderr are capped before parsing/logging.
func (SSHRunner) Read(ctx context.Context, node string) ([]byte, []byte, error) {
	if !approvedNode(node) {
		return nil, nil, errors.New("unapproved network target")
	}
	cmd := exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=3", "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2",
		node, "python3", "-")
	cmd.Stdin = strings.NewReader(remoteReader)
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if stdout.overflow || stderr.overflow {
		return nil, nil, errOutputLimit
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

var errOutputLimit = errors.New("network probe output limit")

type limitedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	remaining := MaxBytes - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return len(data), nil
	}
	if len(data) > remaining {
		b.overflow = true
		_, _ = b.Buffer.Write(data[:remaining])
		return len(data), nil
	}
	return b.Buffer.Write(data)
}

type wirePort struct {
	Device     string  `json:"device"`
	NodeGUID   string  `json:"node_guid,omitempty"`
	Port       int     `json:"port"`
	LinkLayer  string  `json:"link_layer"`
	State      string  `json:"state"`
	Physical   string  `json:"physical_state"`
	LinkDowned *uint64 `json:"link_downed"`
}
type wireSnapshot struct {
	BootID string                           `json:"boot_id"`
	Ports  []wirePort                       `json:"ports"`
	Bonds  []application.NetworkBondReading `json:"bonds,omitempty"`
}

// Probe reads one approved pilot node and classifies the source before any
// port judgment. Returned errors are closed safe codes; raw SSH stderr is
// never returned or included in a durable poll.
func Probe(ctx context.Context, runner Runner, node string, now func() time.Time) (application.NetworkNodePoll, error) {
	if ctx == nil || runner == nil || now == nil || !approvedNode(node) {
		return application.NetworkNodePoll{}, fmt.Errorf("invalid network probe input")
	}
	bounded, cancel := context.WithTimeout(ctx, PerNodeTimeout)
	defer cancel()
	started := now().UTC()
	stdout, stderr, err := runner.Read(bounded, node)
	poll := application.NetworkNodePoll{Node: node, ObservedAt: now().UTC(), Outcome: application.NetworkPollReadFailed}
	if poll.ObservedAt.Before(started) || poll.ObservedAt.Sub(started) > PerNodeTimeout+time.Second {
		poll.ReadError = application.NetworkReadInvalidResponse
		return poll, nil
	}
	if err != nil {
		switch {
		case errors.Is(err, errOutputLimit):
			poll.ReadError = application.NetworkReadOutputLimit
		case errors.Is(bounded.Err(), context.DeadlineExceeded):
			poll.ReadError = application.NetworkReadSSHTimeout
		case bytes.Contains(stderr, []byte("Permission denied (publickey)")):
			poll.Outcome, poll.ReadError = application.NetworkPollAuthUnavailable, application.NetworkReadSSHAuthDenied
		case bytes.Contains(stderr, []byte("Could not resolve hostname")), bytes.Contains(stderr, []byte("No route to host")), bytes.Contains(stderr, []byte("Connection refused")):
			poll.Outcome, poll.ReadError = application.NetworkPollNodeUnreachable, application.NetworkReadNodeUnreachable
		default:
			poll.ReadError = application.NetworkReadSourceFailed
		}
		return poll, nil
	}
	if len(stdout) == 0 || len(stdout) > MaxBytes {
		poll.ReadError = application.NetworkReadInvalidResponse
		return poll, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	decoder.DisallowUnknownFields()
	var snapshot wireSnapshot
	if decoder.Decode(&snapshot) != nil || decoder.Decode(new(any)) != io.EOF ||
		len(snapshot.BootID) < 8 || len(snapshot.BootID) > 64 || snapshot.Ports == nil || len(snapshot.Ports) > 256 {
		poll.ReadError = application.NetworkReadInvalidResponse
		return poll, nil
	}
	seen := map[application.NetworkPortKey]bool{}
	for _, port := range snapshot.Ports {
		key := application.NetworkPortKey{Node: node, Device: port.Device, Port: uint16(port.Port)}
		if port.Port < 1 || port.Port > 256 || !validDevice(port.Device) || seen[key] ||
			len(port.NodeGUID) > 64 || len(port.LinkLayer) > 32 || len(port.State) > 32 || len(port.Physical) > 32 ||
			port.LinkLayer == "" || port.State == "" || port.Physical == "" {
			poll.ReadError = application.NetworkReadInvalidResponse
			return poll, nil
		}
		seen[key] = true
		poll.Ports = append(poll.Ports, application.NetworkPortReading{Key: key, LinkLayer: port.LinkLayer, NodeGUID: port.NodeGUID,
			State: port.State, PhysicalState: port.Physical, LinkDowned: port.LinkDowned})
	}
	sort.Slice(poll.Ports, func(i, j int) bool {
		if poll.Ports[i].Key.Device != poll.Ports[j].Key.Device {
			return poll.Ports[i].Key.Device < poll.Ports[j].Key.Device
		}
		return poll.Ports[i].Key.Port < poll.Ports[j].Key.Port
	})
	for _, b := range snapshot.Bonds {
		if len(snapshot.Bonds) > 1 || b.Name != "bond0" || len(b.Mode) > 32 || len(b.Carrier) > 8 || len(b.OperState) > 32 || len(b.Members) > 16 || b.ReadError != "" && b.ReadError != application.NetworkReadSourceFailed && b.ReadError != application.NetworkReadInvalidResponse {
			poll.ReadError = application.NetworkReadInvalidResponse
			return poll, nil
		}
		seen := map[string]bool{}
		for _, m := range b.Members {
			if len(m.Name) == 0 || len(m.Name) > 32 || seen[m.Name] || len(m.Carrier) > 8 || len(m.OperState) > 32 {
				poll.ReadError = application.NetworkReadInvalidResponse
				return poll, nil
			}
			seen[m.Name] = true
		}
	}
	poll.Bonds = snapshot.Bonds
	poll.Outcome, poll.ReadError, poll.BootID = application.NetworkPollComplete, "", snapshot.BootID
	return poll, nil
}

func approvedNode(node string) bool {
	for _, approved := range FixtureNetworkNodes {
		if node == approved {
			return true
		}
	}
	for _, approved := range PilotNodes {
		if node == approved {
			return true
		}
	}
	return false
}

func validDevice(value string) bool {
	if !strings.HasPrefix(value, "mlx5_") || len(value) > 16 {
		return false
	}
	for _, c := range strings.TrimPrefix(value, "mlx5_") {
		if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return len(value) > len("mlx5_")
}

// The command is sent on stdin to `python3 -`. It reads fixed kernel paths
// only, with no subprocess, sudo, network traffic or file writes.
const remoteReader = `import json
from pathlib import Path

root = Path('/sys/class/infiniband')
boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
ports = []
for device in sorted(root.iterdir()):
    for port in sorted((device / 'ports').iterdir()):
        if not port.name.isdecimal():
            continue
        item = {'device': device.name, 'port': int(port.name),
                'node_guid': (device / 'node_guid').read_text().strip(),
                'link_layer': (port / 'link_layer').read_text().strip(),
                'state': (port / 'state').read_text().strip(),
                'physical_state': (port / 'phys_state').read_text().strip(),
                'link_downed': None}
        counter = port / 'counters' / 'link_downed'
        try:
            item['link_downed'] = int(counter.read_text().strip())
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        ports.append(item)
        if len(ports) > 256:
            raise RuntimeError('port count exceeds bound')
# Read only the approved management bond and members; a bond-specific error
# must not discard successfully read InfiniBand observations.
net = Path('/sys/class/net')
bond = {'name': 'bond0', 'present': False, 'mode': '', 'carrier': '',
        'operstate': '', 'members': []}
try:
    if (net / 'bond0').exists():
        bond['present'] = True
        for field, path in [('mode', 'bonding/mode'), ('carrier', 'carrier'), ('operstate', 'operstate')]:
            bond[field] = (net / 'bond0' / path).read_text().strip()
        names = (net / 'bond0/bonding/slaves').read_text().strip().split()
        if len(names) > 16 or len(set(names)) != len(names):
            raise ValueError('invalid member set')
        for name in sorted(names):
            if name not in ('enp55s0f0np0', 'enp55s0f1np1'):
                # Preserve the unexpected identity without reading its paths.
                bond['members'].append({'name': name, 'present': True, 'carrier': '0', 'operstate': 'down'})
                continue
            member = {'name': name, 'present': (net / name).exists(), 'carrier': '', 'operstate': ''}
            if member['present']:
                for field in ('carrier', 'operstate'):
                    member[field] = (net / name / field).read_text().strip()
                for field in ('rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped'):
                    try:
                        value = int((net / name / 'statistics' / field).read_text().strip())
                        if not 0 <= value <= 18446744073709551615:
                            raise ValueError('invalid counter')
                        member[field] = value
                    except (OSError, ValueError):
                        pass
            bond['members'].append(member)
except (OSError, ValueError):
    bond['read_error'] = 'SOURCE_READ_FAILED'
print(json.dumps({'boot_id': boot, 'ports': ports, 'bonds': [bond]}, separators=(',', ':')))
`
