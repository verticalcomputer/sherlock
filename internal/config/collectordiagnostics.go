package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// CollectorTransport is the outbound control-plane connection a cluster-side
// process uses: where the control plane is, which identity authenticates, and
// how long one request may take. Both the collection runtime and the diagnostic
// head node connect the same way, so they share one description of it rather
// than two that can drift apart.
type CollectorTransport struct {
	ControlURL             string
	CollectorID            string
	IdentityDir            string
	CertificateFile        string
	PrivateKeyFile         string
	CAFile                 string
	AuthMode               CollectorTransportAuthMode
	AccessServiceTokenFile string
	RequestTimeout         time.Duration
}

// Transport reports the control-plane connection of a collection collector.
func (c Collector) Transport() CollectorTransport {
	return CollectorTransport{
		ControlURL: c.ControlURL, CollectorID: c.CollectorID, IdentityDir: c.IdentityDir,
		CertificateFile: c.CertificateFile, PrivateKeyFile: c.PrivateKeyFile, CAFile: c.CAFile,
		AuthMode: c.TransportAuthMode, AccessServiceTokenFile: c.AccessServiceTokenFile,
		RequestTimeout: c.RequestTimeout,
	}
}

// CollectorDiagnostics configures the head-node loop that claims reviewed
// diagnostic work and executes it inside the perimeter.
//
// It is a separate mode with separate configuration because it is a separate
// authority. A collector that polls Prometheus needs a source URL and no
// command pack; a head node that executes needs a verified pack, a target-role
// inventory, and nothing about Prometheus. The control plane enforces the same
// split, refusing a diagnostic claim from a collector that may only collect.
type CollectorDiagnostics struct {
	Transport CollectorTransport
	// ClusterID selects this cluster's entries from the target-role inventory.
	ClusterID string
	// RunnerID is the authenticated collector identity copied into the durable
	// attempt. It cannot be independently overridden without breaking result
	// attribution.
	RunnerID string
	// ExecutionMode selects how a claimed invocation reaches its targets:
	// DiagnosticExecutionLocal runs it on this machine, DiagnosticExecutionSSH
	// carries it to each target's sealed runner, and
	// DiagnosticExecutionAgentlessSSH uses the separately acknowledged
	// reduced-trust login-shell boundary.
	ExecutionMode DiagnosticExecutionMode
	// LocalTarget is the name this machine answers to. Local execution accepts
	// an invocation only when this is its single target.
	LocalTarget string
	// SSHExecutable, SSHExecutableSHA256, SSHKnownHostsFile, and
	// SSHTargetAuthenticationFile configure restricted SSH. The digest is declared by an
	// operator rather than computed here: the point of pinning is that somebody
	// decided which binary is the transport, and a digest taken from whatever
	// currently sits at the path decides nothing.
	SSHExecutable               string
	SSHExecutableSHA256         string
	SSHKnownHostsFile           string
	SSHTargetAuthenticationFile string
	// SSHCredentialDirectory is a protected head-local provider root. It is
	// required at composition only when the target contract contains a password
	// profile; raw credential bytes never enter configuration or process env.
	SSHCredentialDirectory string
	// AgentlessSSH* is a separate reduced-trust configuration surface. It is
	// deliberately not an alternate interpretation of the sealed SSH fields.
	AgentlessSSHExecutable               string
	AgentlessSSHExecutableSHA256         string
	AgentlessSSHKnownHostsFile           string
	AgentlessSSHTargetAuthenticationFile string
	AgentlessSSHPolicyFile               string
	// CommandPackFile, TrustRootsFile, and RunnerVersion verify the pack from
	// which every argv is resolved. InventoryFile says which hosts hold which
	// role.
	CommandPackFile string
	TrustRootsFile  string
	RunnerVersion   string
	InventoryFile   string
	// JournalPath is an owner-only durable claimant journal. It stores lease
	// attribution and already-screened attempt results, never credentials.
	JournalPath string

	PollWait              time.Duration
	IdleBackoff           time.Duration
	FailureBackoffMinimum time.Duration
	FailureBackoffMaximum time.Duration
}

// DiagnosticExecutionMode names how claimed work reaches its targets.
type DiagnosticExecutionMode string

const (
	// DiagnosticExecutionLocal executes on the head node itself. It answers only
	// for this machine, so it suits a single-node cluster and HEAD-role
	// definitions.
	DiagnosticExecutionLocal DiagnosticExecutionMode = "local"
	// DiagnosticExecutionSSH carries each target's invocation to that host's
	// sealed runner, which verifies the pack independently. The head node
	// reaches compute nodes directly, inside the perimeter, so no bastion
	// traversal is involved.
	DiagnosticExecutionSSH DiagnosticExecutionMode = "ssh"
	// DiagnosticExecutionAgentlessSSH is a separately acknowledged pilot mode.
	// It executes one fixed pack-derived command through the remote login shell
	// and does not satisfy the sealed-runner production boundary.
	DiagnosticExecutionAgentlessSSH DiagnosticExecutionMode = "agentless_ssh"
)

func LoadCollectorDiagnostics() (CollectorDiagnostics, error) {
	if err := loadLocalEnv(); err != nil {
		return CollectorDiagnostics{}, err
	}
	hostname, _ := os.Hostname()
	cfg := CollectorDiagnostics{
		Transport: CollectorTransport{
			ControlURL:             strings.TrimSpace(os.Getenv("SHERLOCK_CONTROL_URL")),
			CollectorID:            strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_ID")),
			IdentityDir:            strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_IDENTITY_DIR")),
			CertificateFile:        strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_CERT_FILE")),
			PrivateKeyFile:         strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_KEY_FILE")),
			CAFile:                 strings.TrimSpace(os.Getenv("SHERLOCK_CONTROL_CA_FILE")),
			AuthMode:               CollectorTransportAuthMode(valueOrDefault("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE", string(CollectorTransportDirectMTLS))),
			AccessServiceTokenFile: strings.TrimSpace(os.Getenv("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE")),
			RequestTimeout:         35 * time.Second,
		},
		ClusterID:                            strings.TrimSpace(os.Getenv("SHERLOCK_CLUSTER_ID")),
		RunnerID:                             strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_RUNNER_ID")),
		ExecutionMode:                        DiagnosticExecutionMode(valueOrDefault("SHERLOCK_DIAGNOSTIC_EXECUTION_MODE", string(DiagnosticExecutionLocal))),
		LocalTarget:                          valueOrDefault("SHERLOCK_DIAGNOSTIC_LOCAL_TARGET", hostname),
		SSHExecutable:                        strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_SSH_EXECUTABLE")),
		SSHExecutableSHA256:                  strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_SSH_SHA256")),
		SSHKnownHostsFile:                    strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_SSH_KNOWN_HOSTS_FILE")),
		SSHTargetAuthenticationFile:          strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_SSH_TARGET_AUTH_FILE")),
		SSHCredentialDirectory:               strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_SSH_CREDENTIAL_DIR")),
		AgentlessSSHExecutable:               strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_EXECUTABLE")),
		AgentlessSSHExecutableSHA256:         strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_SHA256")),
		AgentlessSSHKnownHostsFile:           strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_KNOWN_HOSTS_FILE")),
		AgentlessSSHTargetAuthenticationFile: strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_TARGET_AUTH_FILE")),
		AgentlessSSHPolicyFile:               strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_POLICY_FILE")),
		CommandPackFile:                      strings.TrimSpace(os.Getenv("SHERLOCK_COMMAND_PACK_FILE")),
		TrustRootsFile:                       strings.TrimSpace(os.Getenv("SHERLOCK_COMMAND_TRUST_ROOTS_FILE")),
		RunnerVersion:                        strings.TrimSpace(os.Getenv("SHERLOCK_RUNNER_VERSION")),
		InventoryFile:                        strings.TrimSpace(os.Getenv("SHERLOCK_DIAGNOSTIC_INVENTORY_FILE")),
		JournalPath:                          valueOrDefault("SHERLOCK_DIAGNOSTIC_JOURNAL", "./diagnostic-result-journal.json"),

		PollWait:              25 * time.Second,
		IdleBackoff:           time.Second,
		FailureBackoffMinimum: time.Second,
		FailureBackoffMaximum: 30 * time.Second,
	}
	if err := resolveCollectorIdentityFiles(&cfg.Transport); err != nil {
		return CollectorDiagnostics{}, err
	}
	if cfg.RunnerID == "" {
		cfg.RunnerID = cfg.Transport.CollectorID
	}
	if cfg.RunnerID != cfg.Transport.CollectorID {
		return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_RUNNER_ID must match the authenticated SHERLOCK_COLLECTOR_ID")
	}
	for name, target := range map[string]*time.Duration{
		"SHERLOCK_CONTROL_TIMEOUT":            &cfg.Transport.RequestTimeout,
		"SHERLOCK_DIAGNOSTIC_POLL_WAIT":       &cfg.PollWait,
		"SHERLOCK_DIAGNOSTIC_IDLE_BACKOFF":    &cfg.IdleBackoff,
		"SHERLOCK_DIAGNOSTIC_BACKOFF_MINIMUM": &cfg.FailureBackoffMinimum,
		"SHERLOCK_DIAGNOSTIC_BACKOFF_MAXIMUM": &cfg.FailureBackoffMaximum,
	} {
		parsed, err := durationEnv(name, *target)
		if err != nil {
			return CollectorDiagnostics{}, err
		}
		*target = parsed
	}
	if cfg.Transport.ControlURL == "" || cfg.Transport.CollectorID == "" || cfg.ClusterID == "" {
		return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_CONTROL_URL, SHERLOCK_COLLECTOR_ID, and SHERLOCK_CLUSTER_ID are required")
	}
	controlURL, err := url.Parse(cfg.Transport.ControlURL)
	if err != nil || controlURL.Scheme != "https" || controlURL.Host == "" {
		return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_CONTROL_URL must be an absolute HTTPS URL")
	}
	if cfg.Transport.CertificateFile == "" || cfg.Transport.PrivateKeyFile == "" || cfg.Transport.CAFile == "" {
		return CollectorDiagnostics{}, fmt.Errorf("collector certificate, key, and CA files are required for HTTPS control transport")
	}
	switch cfg.Transport.AuthMode {
	case CollectorTransportDirectMTLS:
		if cfg.Transport.AccessServiceTokenFile != "" {
			return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE is only valid in cloudflare_access_service_token_pop mode")
		}
	case CollectorTransportCloudflareAccessServiceTokenPoP:
		if cfg.Transport.AccessServiceTokenFile == "" {
			return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE is required in cloudflare_access_service_token_pop mode")
		}
	default:
		return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE must be direct_mtls or cloudflare_access_service_token_pop")
	}
	// The pack is what turns a definition reference into an argv, and the
	// inventory is what decides which machines are reachable. A head node
	// missing either cannot execute anything safely, so it refuses to start
	// rather than claiming work it will only fail.
	if cfg.CommandPackFile == "" || cfg.TrustRootsFile == "" || cfg.RunnerVersion == "" || cfg.InventoryFile == "" || cfg.JournalPath == "" {
		return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_COMMAND_PACK_FILE, SHERLOCK_COMMAND_TRUST_ROOTS_FILE, SHERLOCK_RUNNER_VERSION, SHERLOCK_DIAGNOSTIC_INVENTORY_FILE, and SHERLOCK_DIAGNOSTIC_JOURNAL are required to execute diagnostics")
	}
	switch cfg.ExecutionMode {
	case DiagnosticExecutionLocal:
		if cfg.LocalTarget == "" {
			return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_LOCAL_TARGET is required when the host name cannot be determined")
		}
	case DiagnosticExecutionSSH:
		// Every one of these is load-bearing. The pinned digest names the
		// transport binary, the known-hosts file is what makes the remote host
		// the intended one, and the target/authentication file is the only place
		// a target name becomes a machine and login identity.
		if cfg.SSHExecutable == "" || cfg.SSHExecutableSHA256 == "" || cfg.SSHKnownHostsFile == "" || cfg.SSHTargetAuthenticationFile == "" {
			return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_SSH_EXECUTABLE, SHERLOCK_DIAGNOSTIC_SSH_SHA256, SHERLOCK_DIAGNOSTIC_SSH_KNOWN_HOSTS_FILE, and SHERLOCK_DIAGNOSTIC_SSH_TARGET_AUTH_FILE are required in ssh execution mode")
		}
	case DiagnosticExecutionAgentlessSSH:
		if cfg.AgentlessSSHExecutable == "" || cfg.AgentlessSSHExecutableSHA256 == "" || cfg.AgentlessSSHKnownHostsFile == "" || cfg.AgentlessSSHTargetAuthenticationFile == "" || cfg.AgentlessSSHPolicyFile == "" {
			return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_EXECUTABLE, SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_SHA256, SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_KNOWN_HOSTS_FILE, SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_TARGET_AUTH_FILE, and SHERLOCK_DIAGNOSTIC_AGENTLESS_SSH_POLICY_FILE are required in agentless_ssh execution mode")
		}
	default:
		return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_EXECUTION_MODE must be %q, %q, or %q", DiagnosticExecutionLocal, DiagnosticExecutionSSH, DiagnosticExecutionAgentlessSSH)
	}
	if cfg.RunnerID == "" {
		return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_RUNNER_ID is required")
	}
	if cfg.PollWait < time.Second || cfg.PollWait > 30*time.Second {
		return CollectorDiagnostics{}, fmt.Errorf("SHERLOCK_DIAGNOSTIC_POLL_WAIT must be between one and thirty seconds")
	}
	if cfg.Transport.RequestTimeout < cfg.PollWait {
		return CollectorDiagnostics{}, fmt.Errorf("collector request timeout must cover the diagnostic poll wait")
	}
	if cfg.IdleBackoff <= 0 || cfg.FailureBackoffMinimum <= 0 || cfg.FailureBackoffMaximum < cfg.FailureBackoffMinimum {
		return CollectorDiagnostics{}, fmt.Errorf("diagnostic backoff configuration is invalid")
	}
	return cfg, nil
}

// resolveCollectorIdentityFiles points the certificate and key at the current
// identity directory and adopts the identifier stored beside them. Enrollment
// and renewal own that directory, so a process must not be configured with a
// certificate path that disagrees with the identity it renewed.
func resolveCollectorIdentityFiles(transport *CollectorTransport) error {
	if transport.IdentityDir == "" {
		return nil
	}
	transport.CertificateFile = transport.IdentityDir + "/current/cert.pem"
	transport.PrivateKeyFile = transport.IdentityDir + "/current/key.pem"
	if transport.CollectorID != "" {
		return nil
	}
	identifier, err := os.ReadFile(transport.IdentityDir + "/current/collector_id")
	if err != nil {
		return fmt.Errorf("read collector identity identifier: %w", err)
	}
	transport.CollectorID = strings.TrimSpace(string(identifier))
	return nil
}
