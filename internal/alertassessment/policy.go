package alertassessment

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Asset struct {
	EntityKey string `json:"entity_key"`
	NodeID    string `json:"node_id"`
	GPUUUID   string `json:"gpu_uuid"`
}
type Binding struct {
	Metric            string   `json:"metric"`
	Operation         string   `json:"operation"`
	ScheduleRevision  int64    `json:"schedule_revision"`
	ScopeNodes        []string `json:"scope_nodes"`
	UploadCollectorID string   `json:"upload_collector_id,omitempty"`
	UploadProfileID   string   `json:"upload_profile_id,omitempty"`
	UploadProfileHash string   `json:"upload_profile_hash,omitempty"`
}

func (b *Binding) UnmarshalJSON(data []byte) error {
	type binding Binding
	var wire struct {
		binding
		CollectorID json.RawMessage `json:"upload_collector_id"`
		ProfileID   json.RawMessage `json:"upload_profile_id"`
		ProfileHash json.RawMessage `json:"upload_profile_hash"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if len(wire.CollectorID) > 0 || len(wire.ProfileID) > 0 || len(wire.ProfileHash) > 0 {
		if json.Unmarshal(wire.CollectorID, &wire.UploadCollectorID) != nil || json.Unmarshal(wire.ProfileID, &wire.UploadProfileID) != nil ||
			json.Unmarshal(wire.ProfileHash, &wire.UploadProfileHash) != nil ||
			!ValidID(wire.UploadCollectorID, 128) || !ValidID(wire.UploadProfileID, 128) || !ValidHash(wire.UploadProfileHash) {
			return ErrInvalid
		}
	}
	*b = Binding(wire.binding)
	return nil
}

type Routes struct {
	Investigate string `json:"investigate"`
	Urgent      string `json:"urgent"`
	Monitoring  string `json:"monitoring"`
}
type FallbackConfig struct {
	Action string `json:"action"`
	Route  string `json:"route"`
}
type Limits struct {
	GPUCount           int64 `json:"gpu_count"`
	NodeCount          int64 `json:"node_count"`
	PhysicalCandidates int64 `json:"physical_candidates"`
	FactCount          int64 `json:"fact_count"`
	PayloadBytes       int64 `json:"payload_bytes"`
}
type Config struct {
	Schema             int64           `json:"schema"`
	RunID              string          `json:"run_id"`
	Category           string          `json:"category"`
	Contract           int64           `json:"contract"`
	Implementation     int64           `json:"implementation"`
	ClusterID          string          `json:"cluster_id"`
	SourceID           string          `json:"source_id"`
	InventoryRevision  string          `json:"inventory_revision"`
	Assets             []Asset         `json:"assets"`
	Bindings           []Binding       `json:"bindings"`
	Policy             json.RawMessage `json:"policy"`
	BudgetsMS          []int64         `json:"budgets_ms"`
	Routes             Routes          `json:"routes"`
	Fallback           FallbackConfig  `json:"fallback"`
	RunDurationSeconds int64           `json:"run_duration_seconds"`
	Limits             Limits          `json:"limits"`

	production        bool
	originalInputHash string
	boundTypedHash    string
}

func (c Config) usesUpload() bool {
	return len(c.Bindings) > 0 && c.Bindings[0].UploadProfileID != ""
}

func ParseConfig(ctx context.Context, data []byte, r *Registry) (Config, error) {
	var c Config
	if e := DecodeStrict(data, &c, 64<<10); e != nil {
		return c, e
	}
	return NormalizeConfig(ctx, c, r)
}

// NormalizeConfig validates an in-memory config and returns the copy whose
// typed policy bytes must be used to persist, compare or hash that config.
func NormalizeConfig(ctx context.Context, c Config, r *Registry) (Config, error) {
	inputHash, err := c.InputConfigHash()
	if err != nil {
		return Config{}, err
	}
	p, e := c.validate(ctx, r)
	if e != nil {
		return Config{}, e
	}
	c = c.copyWithPolicy(p)
	typedHash, err := c.Hash()
	if err != nil {
		return Config{}, err
	}
	c.originalInputHash, c.boundTypedHash = inputHash, typedHash
	return c, nil
}

// ParseRecoveryConfig reads only the common V1 envelope. Its result is not a
// new enrollment and must be matched to an existing immutable run.
func ParseRecoveryConfig(data []byte) (Config, error) {
	var c Config
	if err := DecodeStrict(data, &c, 64<<10); err != nil {
		return Config{}, ErrInvalid
	}
	if err := c.validateCommon(nil); err != nil {
		return Config{}, err
	}
	p, err := NewPayload(c.Category, "policy", 1, c.Policy)
	if err != nil {
		return Config{}, err
	}
	return c.copyWithPolicy(p), nil
}

// InputConfigHash identifies the strict common input with its original policy
// number tokens. A saved witness is valid only while all typed fields match
// the config to which the codec bound it.
func (c Config) InputConfigHash() (string, error) {
	if err := c.validateCommon(nil); err != nil || len(c.Policy) > MaxPayloadBytes {
		return "", ErrInvalid
	}
	body, err := Canonical(c)
	if err != nil || len(body) > 64<<10 {
		return "", ErrInvalid
	}
	if c.originalInputHash != "" && Hash("config", c.Category, 1, body) == c.boundTypedHash {
		return c.originalInputHash, nil
	}
	return Hash("config_input", c.Category, 1, body), nil
}

// NormalizeRecoveryConfig validates host-owned fields against a persisted
// descriptor. This deliberately treats the pinned policy as an opaque body.
func NormalizeRecoveryConfig(c Config, d Descriptor) (Config, error) {
	if err := validateDescriptor(d); err != nil {
		return Config{}, err
	}
	if err := c.validateCommon(&d); err != nil {
		return Config{}, err
	}
	p, err := NewPayload(c.Category, "policy", d.PolicySchema, c.Policy)
	if err != nil || int64(len(p.Body)) > d.PayloadLimits.Policy {
		return Config{}, ErrInvalid
	}
	c = c.copyWithPolicy(p)
	if b, err := Canonical(c); err != nil || len(b) > 64<<10 {
		return Config{}, ErrInvalid
	}
	return c, nil
}

func (c Config) copyWithPolicy(p Payload) Config {
	c.Policy = p.Body
	c.Assets = slices.Clone(c.Assets)
	c.Bindings = slices.Clone(c.Bindings)
	for i := range c.Bindings {
		c.Bindings[i].ScopeNodes = slices.Clone(c.Bindings[i].ScopeNodes)
	}
	c.BudgetsMS = slices.Clone(c.BudgetsMS)
	return c
}

func (c Config) Validate(ctx context.Context, r *Registry) error {
	_, err := c.validate(ctx, r)
	return err
}

func (c Config) validate(ctx context.Context, r *Registry) (Payload, error) {
	if r == nil {
		return Payload{}, ErrInvalid
	}
	cat, d, _, err := r.LookupVersion(c.Category, c.Implementation)
	if err != nil {
		return Payload{}, err
	}
	if err := c.validateCommon(&d); err != nil {
		return Payload{}, err
	}
	p, err := configPolicy(ctx, cat, d, c.Policy)
	if err != nil {
		return Payload{}, err
	}
	c.Policy = p.Body
	if b, err := Canonical(c); err != nil || len(b) > 64<<10 {
		return Payload{}, ErrInvalid
	}
	return p, nil
}

func (c Config) validateCommon(d *Descriptor) error {

	if c.Schema != 1 || c.Contract != ContractVersion || !ValidID(c.Category, 128) || c.Implementation < 1 || !ValidID(c.RunID, 128) || !ValidID(c.ClusterID, 128) || !ValidID(c.SourceID, 128) || !ValidID(c.InventoryRevision, 128) || !c.validLifecycle() {
		return ErrInvalid
	}
	if d != nil && (c.Category != d.Category || c.Contract != d.Contract || c.Implementation != d.Implementation) {
		return ErrInvalid
	}

	l := c.Limits
	if l.GPUCount < 1 || l.GPUCount > 8 || l.NodeCount < 1 || l.NodeCount > 2 || l.PhysicalCandidates < 1 || l.PhysicalCandidates > 256 || l.FactCount < 1 || l.FactCount > 200000 || l.PayloadBytes < 8<<20 || l.PayloadBytes > 512<<20 {
		return ErrInvalid
	}
	if len(c.Assets) < 1 || int64(len(c.Assets)) > l.GPUCount || c.Bindings == nil || len(c.Bindings) > 3 {
		return ErrInvalid
	}
	nodes := map[string]bool{}
	gpus := map[string]bool{}
	for i, a := range c.Assets {
		if !validAsset(a.EntityKey) || !ValidID(a.NodeID, 128) || !ValidID(a.GPUUUID, 128) || a.EntityKey != fmt.Sprintf("%s/GPU/%s/%s/", c.ClusterID, a.NodeID, a.GPUUUID) || i > 0 && c.Assets[i-1].EntityKey >= a.EntityKey || gpus[a.GPUUUID] {
			return ErrInvalid
		}
		nodes[a.NodeID] = true
		gpus[a.GPUUUID] = true
	}
	if int64(len(nodes)) > l.NodeCount {
		return ErrInvalid
	}
	for i, b := range c.Bindings {
		if !ValidID(b.Metric, 128) || d != nil && !slices.ContainsFunc(d.Metrics, func(m Metric) bool { return m.Metric == b.Metric }) || !ValidID(b.Operation, 128) || b.ScheduleRevision < 1 || Set(b.ScopeNodes, 2) != nil || i > 0 && c.Bindings[i-1].Metric >= b.Metric {
			return ErrInvalid
		}
		first := c.Bindings[0]
		if b.UploadProfileID != first.UploadProfileID || b.UploadProfileHash != first.UploadProfileHash || b.UploadCollectorID != first.UploadCollectorID {
			return ErrInvalid
		}
		if b.UploadProfileID != "" || b.UploadProfileHash != "" || b.UploadCollectorID != "" {
			operation, ok := domain.ReviewedCollectionOperation(domain.CollectionOperationID(b.Operation))
			field, cooling := domain.CoolingUploadField(operation.Query)
			if !ValidID(b.UploadProfileID, 128) || !ValidHash(b.UploadProfileHash) || !ValidID(b.UploadCollectorID, 128) ||
				!ok || operation.Source != domain.CollectionSourcePrometheus || !cooling || field.Name != b.Metric ||
				b.ScheduleRevision != first.ScheduleRevision || len(b.ScopeNodes) == 0 || !slices.Equal(b.ScopeNodes, first.ScopeNodes) {
				return ErrInvalid
			}
		}
		for node := range nodes {
			if len(b.ScopeNodes) > 0 && !slices.Contains(b.ScopeNodes, node) {
				return ErrInvalid
			}
		}
	}
	if d != nil {
		for _, m := range d.Metrics {
			if !m.Required {
				continue
			}
			if !slices.ContainsFunc(c.Bindings, func(b Binding) bool { return b.Metric == m.Metric }) {
				return ErrInvalid
			}
		}
	}
	if c.Routes != (Routes{"hardware_investigation", "hardware_investigation", "monitoring_failure"}) || c.Fallback != (FallbackConfig{"INVESTIGATE", "hardware_investigation"}) {
		return ErrInvalid
	}
	return nil
}

// PolicyPayload returns the schema-pinned canonical policy for this config.
func (c Config) PolicyPayload(ctx context.Context, r *Registry) (Payload, error) {
	cat, d, _, err := r.LookupVersion(c.Category, c.Implementation)
	if err != nil {
		return Payload{}, err
	}
	return configPolicy(ctx, cat, d, c.Policy)
}

// A typed normalizer lets config input use equivalent JSON number spellings
// while hashes retain the exact integer/float distinction of the policy codec.
type policyNormalizer interface {
	NormalizePolicy(context.Context, json.RawMessage) (json.RawMessage, error)
}

func configPolicy(ctx context.Context, c Category, d Descriptor, raw json.RawMessage) (p Payload, err error) {
	defer func() {
		if recover() != nil {
			p, err = Payload{}, ErrInvalid
		}
	}()
	if int64(len(raw)) > d.PayloadLimits.Policy {
		return Payload{}, ErrInvalid
	}
	if n, ok := c.(policyNormalizer); ok {
		raw, err = n.NormalizePolicy(ctx, slices.Clone(raw))
		if err != nil {
			return Payload{}, err
		}
	}
	p, err = NewPayload(d.Category, "policy", d.PolicySchema, raw)
	if err != nil || int64(len(p.Body)) > d.PayloadLimits.Policy {
		return Payload{}, ErrInvalid
	}
	if err := c.ValidatePolicy(ctx, copyPayload(p)); err != nil {
		return Payload{}, err
	}
	return p, ctx.Err()
}

// Hash identifies the config returned by ParseConfig or NormalizeConfig.
func (c Config) Hash() (string, error) { return Identity("config", c.Category, c) }

// Production reports the host-owned lifecycle. Ordinary Config JSON cannot set it.
func (c Config) Production() bool { return c.production }
func (c Config) validLifecycle() bool {
	if c.production {
		return slices.Equal(c.BudgetsMS, []int64{120000}) && c.RunDurationSeconds == 0 && c.usesUpload()
	}
	return slices.Equal(c.BudgetsMS, v1Budgets[:]) && c.RunDurationSeconds >= 1 && c.RunDurationSeconds <= 86400
}
