package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type CollectorTransportAuthMode string

const (
	CollectorTransportDirectMTLS                      CollectorTransportAuthMode = "direct_mtls"
	CollectorTransportCloudflareAccessServiceTokenPoP CollectorTransportAuthMode = "cloudflare_access_service_token_pop"
)

// Collector contains the cluster-side collector process configuration.
type Collector struct {
	ControlURL  string
	CollectorID string
	IdentityDir string
	SourceID    string
	Version     string
	BuildCommit string
	// Operations is the reviewed local execution allow-list. Capabilities is
	// derived from it for the existing v1 heartbeat and claim protocol.
	Operations               []domain.CollectionOperationID
	Capabilities             []string
	CertificateFile          string
	PrivateKeyFile           string
	CAFile                   string
	TransportAuthMode        CollectorTransportAuthMode
	AccessServiceTokenFile   string
	JournalPath              string
	MetricsAddress           string
	PrometheusURL            string
	PrometheusBearer         string
	PrometheusUser           string
	PrometheusPassword       string
	ClusterID                string
	SlurmClusterID           string
	SlurmSourceID            string
	SlurmNodes               map[domain.StableNodeID]string
	SlurmSchedulerNamespace  string
	SlurmSchedulerCluster    string
	SlurmCurrentJobsComplete bool
	SlurmAccountingComplete  bool
	SlurmAccountingOverlap   time.Duration
	HeartbeatInterval        time.Duration
	ClaimWait                time.Duration
	RenewInterval            time.Duration
	RequestTimeout           time.Duration
	BackoffMinimum           time.Duration
	BackoffMaximum           time.Duration
	ExecutionRetries         int
	ExecutionBackoff         time.Duration
	// BCMAccessTest enables the BCM-only credential access test worker. It is
	// off by default so existing collectors never advertise the capability.
	BCMAccessTest BCMAccessTestConfig
	// GPUProcessObservation is a separate default-off read-only source. It has
	// its own protected command pack, target auth and policy files.
	GPUProcessObservation GPUProcessObservationConfig
}

// BCMAccessTestConfig binds the head-local BCM access test to one expected
// host identity and a fixed executable pair. No command text is configurable.
type BCMAccessTestConfig struct {
	Enabled        bool
	ExternalWorker bool
	ExpectedHost   string
	SudoPath       string
	CmshPath       string
	ReleaseFile    string
}

func LoadCollector() (Collector, error) {
	if err := loadLocalEnv(); err != nil {
		return Collector{}, err
	}
	cfg := Collector{
		ControlURL:              os.Getenv("SHERLOCK_CONTROL_URL"),
		CollectorID:             os.Getenv("SHERLOCK_COLLECTOR_ID"),
		IdentityDir:             os.Getenv("SHERLOCK_COLLECTOR_IDENTITY_DIR"),
		SourceID:                valueOrDefault("SHERLOCK_SOURCE_ID", "local-prometheus"),
		Version:                 valueOrDefault("SHERLOCK_COLLECTOR_VERSION", "dev"),
		BuildCommit:             os.Getenv("SHERLOCK_COLLECTOR_BUILD_COMMIT"),
		CertificateFile:         os.Getenv("SHERLOCK_COLLECTOR_CERT_FILE"),
		PrivateKeyFile:          os.Getenv("SHERLOCK_COLLECTOR_KEY_FILE"),
		CAFile:                  os.Getenv("SHERLOCK_CONTROL_CA_FILE"),
		TransportAuthMode:       CollectorTransportAuthMode(valueOrDefault("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE", string(CollectorTransportDirectMTLS))),
		AccessServiceTokenFile:  strings.TrimSpace(os.Getenv("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE")),
		JournalPath:             valueOrDefault("SHERLOCK_COLLECTOR_JOURNAL", defaultCollectorJournal),
		MetricsAddress:          strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_METRICS_ADDRESS")),
		PrometheusURL:           os.Getenv("SHERLOCK_PROMETHEUS_URL"),
		PrometheusBearer:        os.Getenv("SHERLOCK_PROMETHEUS_BEARER_TOKEN"),
		PrometheusUser:          os.Getenv("SHERLOCK_PROMETHEUS_USERNAME"),
		PrometheusPassword:      os.Getenv("SHERLOCK_PROMETHEUS_PASSWORD"),
		ClusterID:               strings.TrimSpace(os.Getenv("SHERLOCK_CLUSTER_ID")),
		SlurmClusterID:          os.Getenv("SHERLOCK_CLUSTER_ID"),
		SlurmSourceID:           valueOrDefault("SHERLOCK_SLURM_SOURCE_ID", "local-slurm"),
		SlurmSchedulerNamespace: strings.TrimSpace(os.Getenv("SHERLOCK_SLURM_SCHEDULER_NAMESPACE")),
		SlurmSchedulerCluster:   strings.TrimSpace(os.Getenv("SHERLOCK_SLURM_SCHEDULER_CLUSTER")),
		SlurmAccountingOverlap:  5 * time.Minute,
		HeartbeatInterval:       30 * time.Second,
		ClaimWait:               25 * time.Second,
		RenewInterval:           10 * time.Second,
		RequestTimeout:          35 * time.Second,
		BackoffMinimum:          250 * time.Millisecond,
		BackoffMaximum:          15 * time.Second,
		ExecutionRetries:        2,
		ExecutionBackoff:        200 * time.Millisecond,
	}
	transport := cfg.Transport()
	if err := resolveCollectorIdentityFiles(&transport); err != nil {
		return Collector{}, err
	}
	cfg.CollectorID, cfg.CertificateFile, cfg.PrivateKeyFile = transport.CollectorID, transport.CertificateFile, transport.PrivateKeyFile
	operations, capabilities, err := loadCollectorOperations(
		os.Getenv("SHERLOCK_COLLECTION_OPERATIONS"), os.Getenv("SHERLOCK_COLLECTOR_CAPABILITIES"),
	)
	if err != nil {
		return Collector{}, err
	}
	cfg.Operations, cfg.Capabilities = operations, capabilities
	if cfg.BCMAccessTest, err = loadBCMAccessTest(); err != nil {
		return Collector{}, err
	}
	if cfg.GPUProcessObservation, err = loadGPUProcessObservation(strings.TrimSpace(os.Getenv("SHERLOCK_CLUSTER_ID"))); err != nil {
		return Collector{}, err
	}
	gpuProcessEnabled := false
	for _, id := range operations {
		op, _ := domain.ReviewedCollectionOperation(id)
		if op.Source == domain.CollectionSourceGPUProcess {
			gpuProcessEnabled = true
			if id != domain.OperationGPUProcessObservations {
				return Collector{}, fmt.Errorf("GPU process operation has no installed typed executor")
			}
		}
		if op.Source == domain.CollectionSourceSlurm {
			if id != domain.OperationSlurmInventory && id != domain.OperationSlurmSnapshot {
				return Collector{}, fmt.Errorf("slurm operation has no installed typed executor")
			}
			if cfg.SlurmClusterID == "" || cfg.SlurmSourceID == "" {
				return Collector{}, fmt.Errorf("slurm collection requires cluster and source identifiers")
			}
			cfg.SlurmNodes = make(map[domain.StableNodeID]string)
			seen := make(map[string]bool)
			for _, mapping := range strings.Split(os.Getenv("SHERLOCK_SLURM_NODE_MAP"), ",") {
				stable, name, ok := strings.Cut(strings.TrimSpace(mapping), "=")
				stable, name = strings.TrimSpace(stable), strings.TrimSpace(name)
				if !ok || stable == "" || name == "" || cfg.SlurmNodes[domain.StableNodeID(stable)] != "" || seen[name] {
					return Collector{}, fmt.Errorf("SHERLOCK_SLURM_NODE_MAP requires unique stable_id=node_name entries")
				}
				cfg.SlurmNodes[domain.StableNodeID(stable)], seen[name] = name, true
			}
			if len(cfg.SlurmNodes) > 1024 {
				return Collector{}, fmt.Errorf("slurm node mapping exceeds its limit")
			}
			if id == domain.OperationSlurmSnapshot {
				if cfg.SlurmSchedulerNamespace == "" || cfg.SlurmSchedulerCluster == "" {
					return Collector{}, fmt.Errorf("slurm snapshot requires scheduler namespace and cluster")
				}
				if cfg.SlurmCurrentJobsComplete, err = boolEnv("SHERLOCK_SLURM_CURRENT_JOBS_COMPLETE", false); err != nil {
					return Collector{}, err
				}
				if cfg.SlurmAccountingComplete, err = boolEnv("SHERLOCK_SLURM_ACCOUNTING_COMPLETE", false); err != nil {
					return Collector{}, err
				}
				if cfg.SlurmAccountingOverlap, err = durationEnv("SHERLOCK_SLURM_ACCOUNTING_OVERLAP", cfg.SlurmAccountingOverlap); err != nil || cfg.SlurmAccountingOverlap <= 0 || cfg.SlurmAccountingOverlap > domain.SlurmSnapshotMaxAccountingOverlap {
					return Collector{}, fmt.Errorf("SHERLOCK_SLURM_ACCOUNTING_OVERLAP must be within (0,24h]")
				}
			}
		}
	}
	if cfg.GPUProcessObservation.Enabled != gpuProcessEnabled {
		return Collector{}, fmt.Errorf("GPU process observations must be enabled exactly when %s is configured", domain.OperationGPUProcessObservations)
	}
	for name, target := range map[string]*time.Duration{
		"SHERLOCK_HEARTBEAT_INTERVAL": &cfg.HeartbeatInterval,
		"SHERLOCK_CLAIM_WAIT":         &cfg.ClaimWait,
		"SHERLOCK_RENEW_INTERVAL":     &cfg.RenewInterval,
		"SHERLOCK_CONTROL_TIMEOUT":    &cfg.RequestTimeout,
		"SHERLOCK_BACKOFF_MINIMUM":    &cfg.BackoffMinimum,
		"SHERLOCK_BACKOFF_MAXIMUM":    &cfg.BackoffMaximum,
		"SHERLOCK_EXECUTION_BACKOFF":  &cfg.ExecutionBackoff,
	} {
		parsed, err := durationEnv(name, *target)
		if err != nil {
			return Collector{}, err
		}
		*target = parsed
	}
	if retries, parseErr := intEnv("SHERLOCK_EXECUTION_RETRIES", cfg.ExecutionRetries); parseErr != nil {
		return Collector{}, parseErr
	} else {
		cfg.ExecutionRetries = retries
	}
	if cfg.ControlURL == "" || cfg.CollectorID == "" || (len(cfg.Capabilities) > 0 && cfg.PrometheusURL == "") {
		return Collector{}, fmt.Errorf("control URL, collector ID, and the URL for enabled Prometheus operations are required")
	}
	controlURL, err := url.Parse(cfg.ControlURL)
	if err != nil || controlURL.Scheme != "https" || controlURL.Host == "" {
		return Collector{}, fmt.Errorf("SHERLOCK_CONTROL_URL must be an absolute HTTPS URL")
	}
	if cfg.CertificateFile == "" || cfg.PrivateKeyFile == "" || cfg.CAFile == "" {
		return Collector{}, fmt.Errorf("collector certificate, key, and CA files are required for HTTPS control transport")
	}
	switch cfg.TransportAuthMode {
	case CollectorTransportDirectMTLS:
		if cfg.AccessServiceTokenFile != "" {
			return Collector{}, fmt.Errorf("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE is only valid in cloudflare_access_service_token_pop mode")
		}
	case CollectorTransportCloudflareAccessServiceTokenPoP:
		if cfg.AccessServiceTokenFile == "" {
			return Collector{}, fmt.Errorf("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE is required in cloudflare_access_service_token_pop mode")
		}
	default:
		return Collector{}, fmt.Errorf("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE must be direct_mtls or cloudflare_access_service_token_pop")
	}
	if cfg.PrometheusBearer != "" && (cfg.PrometheusUser != "" || cfg.PrometheusPassword != "") {
		return Collector{}, fmt.Errorf("prometheus bearer and basic authentication are mutually exclusive")
	}
	if cfg.HeartbeatInterval <= 0 || cfg.ClaimWait <= 0 || cfg.ClaimWait > cfg.HeartbeatInterval || cfg.RenewInterval <= 0 || cfg.RequestTimeout < cfg.ClaimWait || cfg.BackoffMinimum <= 0 || cfg.BackoffMaximum < cfg.BackoffMinimum {
		return Collector{}, fmt.Errorf("collector timing configuration is invalid")
	}
	if cfg.ExecutionRetries < 0 || cfg.ExecutionRetries > 2 || (cfg.ExecutionRetries > 0 && cfg.ExecutionBackoff <= 0) {
		return Collector{}, fmt.Errorf("collector execution retries must remain between zero and two with positive backoff")
	}
	if cfg.MetricsAddress != "" {
		loopback, err := addressIsLoopback(cfg.MetricsAddress, "SHERLOCK_COLLECTOR_METRICS_ADDRESS")
		if err != nil {
			return Collector{}, err
		}
		if !loopback {
			return Collector{}, fmt.Errorf("SHERLOCK_COLLECTOR_METRICS_ADDRESS must be a loopback address")
		}
	}
	return cfg, nil
}

func loadCollectorOperations(rawOperations, rawLegacyCapabilities string) ([]domain.CollectionOperationID, []string, error) {
	if strings.TrimSpace(rawOperations) != "" && strings.TrimSpace(rawLegacyCapabilities) != "" {
		return nil, nil, fmt.Errorf("SHERLOCK_COLLECTION_OPERATIONS and SHERLOCK_COLLECTOR_CAPABILITIES cannot both be set")
	}
	if strings.TrimSpace(rawOperations) != "" {
		operations := make([]domain.CollectionOperationID, 0)
		legacy := make([]domain.CollectionOperationID, 0)
		seen := make(map[domain.CollectionOperationID]bool)
		for _, raw := range strings.Split(rawOperations, ",") {
			id := domain.CollectionOperationID(strings.TrimSpace(raw))
			if id == "" {
				return nil, nil, fmt.Errorf("SHERLOCK_COLLECTION_OPERATIONS contains an empty operation")
			}
			op, known := domain.ReviewedCollectionOperation(id)
			if !known {
				return nil, nil, fmt.Errorf("SHERLOCK_COLLECTION_OPERATIONS contains unknown operation %q", id)
			}
			if seen[id] {
				return nil, nil, fmt.Errorf("SHERLOCK_COLLECTION_OPERATIONS contains a duplicate operation")
			}
			seen[id] = true
			if op.Query != "" {
				legacy = append(legacy, id)
			}
			operations = append(operations, id)
		}
		capabilities, err := domain.LegacyCollectionCapabilities(legacy)
		return operations, capabilities, err
	}
	capabilities := []string{"prometheus_source_health", "dcgm_gpu_identity", "dcgm_gpu_utilization", "dcgm_gpu_xid"}
	if strings.TrimSpace(rawLegacyCapabilities) != "" {
		capabilities = nil
		for _, raw := range strings.Split(rawLegacyCapabilities, ",") {
			capability := strings.TrimSpace(raw)
			if capability == "" {
				return nil, nil, fmt.Errorf("SHERLOCK_COLLECTOR_CAPABILITIES contains an empty capability")
			}
			capabilities = append(capabilities, capability)
		}
	}
	operations, err := domain.CollectionOperationsForLegacyCapabilities(capabilities)
	if err != nil {
		return nil, nil, err
	}
	return operations, capabilities, nil
}

const defaultCollectorJournal = "./collector-journal.json"

// LoadCollectorJournalPath resolves only the journal location so journal
// maintenance commands run without control-plane or source credentials.
func LoadCollectorJournalPath() (string, error) {
	if err := loadLocalEnv(); err != nil {
		return "", err
	}
	return valueOrDefault("SHERLOCK_COLLECTOR_JOURNAL", defaultCollectorJournal), nil
}

type CollectorIdentity struct {
	ControlURL             string
	BootstrapCAFile        string
	IdentityDir            string
	BootstrapTokenFile     string
	DisplayName            string
	Version                string
	BuildCommit            string
	TransportAuthMode      CollectorTransportAuthMode
	AccessServiceTokenFile string
}

func LoadCollectorIdentity() (CollectorIdentity, error) {
	if err := loadLocalEnv(); err != nil {
		return CollectorIdentity{}, err
	}
	hostname, _ := os.Hostname()
	cfg := CollectorIdentity{
		ControlURL: os.Getenv("SHERLOCK_CONTROL_URL"), BootstrapCAFile: valueOrDefault("SHERLOCK_BOOTSTRAP_CA_FILE", os.Getenv("SHERLOCK_CONTROL_CA_FILE")),
		IdentityDir: os.Getenv("SHERLOCK_COLLECTOR_IDENTITY_DIR"), BootstrapTokenFile: os.Getenv("SHERLOCK_BOOTSTRAP_TOKEN_FILE"),
		DisplayName: valueOrDefault("SHERLOCK_COLLECTOR_DISPLAY_NAME", hostname), Version: valueOrDefault("SHERLOCK_COLLECTOR_VERSION", "dev"),
		BuildCommit:            os.Getenv("SHERLOCK_COLLECTOR_BUILD_COMMIT"),
		TransportAuthMode:      CollectorTransportAuthMode(valueOrDefault("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE", string(CollectorTransportDirectMTLS))),
		AccessServiceTokenFile: strings.TrimSpace(os.Getenv("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE")),
	}
	controlURL, err := url.Parse(cfg.ControlURL)
	if err != nil || controlURL.Scheme != "https" || controlURL.Host == "" {
		return CollectorIdentity{}, fmt.Errorf("SHERLOCK_CONTROL_URL must be an absolute HTTPS URL")
	}
	if cfg.BootstrapCAFile == "" || cfg.IdentityDir == "" || cfg.DisplayName == "" {
		return CollectorIdentity{}, fmt.Errorf("bootstrap CA, collector identity directory, and display name are required")
	}
	switch cfg.TransportAuthMode {
	case CollectorTransportDirectMTLS:
		if cfg.AccessServiceTokenFile != "" {
			return CollectorIdentity{}, fmt.Errorf("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE is only valid in cloudflare_access_service_token_pop mode")
		}
	case CollectorTransportCloudflareAccessServiceTokenPoP:
		if cfg.AccessServiceTokenFile == "" {
			return CollectorIdentity{}, fmt.Errorf("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE is required in cloudflare_access_service_token_pop mode")
		}
	default:
		return CollectorIdentity{}, fmt.Errorf("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE must be direct_mtls or cloudflare_access_service_token_pop")
	}
	return cfg, nil
}

func loadBCMAccessTest() (BCMAccessTestConfig, error) {
	enabled, err := boolEnv("SHERLOCK_BCM_ACCESS_TEST_ENABLED", false)
	if err != nil {
		return BCMAccessTestConfig{}, err
	}
	externalWorker, err := boolEnv("SHERLOCK_BCM_ACCESS_TEST_EXTERNAL_WORKER", false)
	if err != nil {
		return BCMAccessTestConfig{}, err
	}
	cfg := BCMAccessTestConfig{
		Enabled:        enabled,
		ExternalWorker: externalWorker,
		ExpectedHost:   strings.TrimSpace(os.Getenv("SHERLOCK_BCM_ACCESS_TEST_HOST")),
		SudoPath:       valueOrDefault("SHERLOCK_BCM_SUDO_EXECUTABLE", "/usr/bin/sudo"),
		CmshPath:       valueOrDefault("SHERLOCK_BCM_CMSH_EXECUTABLE", "/cm/local/apps/cmd/bin/cmsh"),
		ReleaseFile:    valueOrDefault("SHERLOCK_BCM_RELEASE_FILE", "/etc/cm-release"),
	}
	if enabled && externalWorker {
		return BCMAccessTestConfig{}, fmt.Errorf("SHERLOCK_BCM_ACCESS_TEST_ENABLED and SHERLOCK_BCM_ACCESS_TEST_EXTERNAL_WORKER cannot both be true")
	}
	if !enabled && !externalWorker {
		return BCMAccessTestConfig{}, nil
	}
	if cfg.ExpectedHost == "" || len(cfg.ExpectedHost) > 256 || strings.ContainsAny(cfg.ExpectedHost, " \t\r\n\x00") {
		return BCMAccessTestConfig{}, fmt.Errorf("SHERLOCK_BCM_ACCESS_TEST_HOST is required when the BCM access test is enabled")
	}
	for name, path := range map[string]string{
		"SHERLOCK_BCM_SUDO_EXECUTABLE": cfg.SudoPath, "SHERLOCK_BCM_CMSH_EXECUTABLE": cfg.CmshPath, "SHERLOCK_BCM_RELEASE_FILE": cfg.ReleaseFile,
	} {
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t\r\n\x00") {
			return BCMAccessTestConfig{}, fmt.Errorf("%s must be an absolute path", name)
		}
	}
	return cfg, nil
}
