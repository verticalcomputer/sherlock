package commandpack

import "time"

const SchemaVersion = 1

type Risk string

const (
	RiskLow        Risk = "LOW"
	RiskModerate   Risk = "MODERATE"
	RiskPrivileged Risk = "PRIVILEGED"
)

type TargetRole string

const (
	TargetHead       TargetRole = "HEAD"
	TargetCompute    TargetRole = "COMPUTE"
	TargetBMCGateway TargetRole = "BMC_GATEWAY"
)

type ParameterType string

const (
	ParameterString  ParameterType = "STRING"
	ParameterInteger ParameterType = "INTEGER"
	ParameterBoolean ParameterType = "BOOLEAN"
)

type Parameter struct {
	Name      string        `json:"name"`
	Type      ParameterType `json:"type"`
	Required  bool          `json:"required"`
	Enum      []string      `json:"enum,omitempty"`
	Pattern   string        `json:"pattern,omitempty"`
	Minimum   *int64        `json:"minimum,omitempty"`
	Maximum   *int64        `json:"maximum,omitempty"`
	MaxLength int           `json:"max_length,omitempty"`
}

type ArgumentToken struct {
	Literal   string `json:"literal,omitempty"`
	Parameter string `json:"parameter,omitempty"`
}

type TargetConstraints struct {
	Roles        []TargetRole `json:"roles"`
	NamePattern  string       `json:"name_pattern"`
	MaximumCount int          `json:"maximum_count"`
}

type Limits struct {
	TimeoutSeconds     int `json:"timeout_seconds"`
	MaximumOutputBytes int `json:"maximum_output_bytes"`
	MaximumConcurrency int `json:"maximum_concurrency"`
}

type Definition struct {
	ID                    string            `json:"id"`
	Version               string            `json:"version"`
	Owner                 string            `json:"owner"`
	Purpose               string            `json:"purpose"`
	SupportedCapabilities []string          `json:"supported_capabilities"`
	Risk                  Risk              `json:"risk"`
	ExecutablePath        string            `json:"executable_path"`
	ExecutableSHA256      string            `json:"executable_sha256"`
	Arguments             []ArgumentToken   `json:"arguments"`
	Parameters            []Parameter       `json:"parameters"`
	Targets               TargetConstraints `json:"targets"`
	RequiresPrivilege     bool              `json:"requires_privilege"`
	SudoRule              string            `json:"sudo_rule,omitempty"`
	Limits                Limits            `json:"limits"`
	OutputSchema          string            `json:"output_schema"`
}

type Review struct {
	ReviewerID string    `json:"reviewer_id"`
	ReviewedAt time.Time `json:"reviewed_at"`
	Approved   bool      `json:"approved"`
}

type Pack struct {
	SchemaVersion int          `json:"schema_version"`
	ID            string       `json:"id"`
	Version       string       `json:"version"`
	Issuer        string       `json:"issuer"`
	IssuedAt      time.Time    `json:"issued_at"`
	ExpiresAt     time.Time    `json:"expires_at"`
	MinimumRunner string       `json:"minimum_runner_version"`
	MaximumRunner string       `json:"maximum_runner_version"`
	Reviews       []Review     `json:"reviews"`
	Definitions   []Definition `json:"definitions"`
}

type SignedRelease struct {
	SchemaVersion int    `json:"schema_version"`
	TrustRootID   string `json:"trust_root_id"`
	Pack          Pack   `json:"pack"`
	Signature     []byte `json:"signature"`
}

type TrustRoot struct {
	ID          string
	Issuer      string
	PublicKey   []byte
	ActivatesAt time.Time
	RetiresAt   time.Time
}

type Target struct {
	Name string
	Role TargetRole
}

type Invocation struct {
	DefinitionID      string
	DefinitionVersion string
	Arguments         []ArgumentValue
	Targets           []Target
}

// ArgumentValue is a closed tagged value. Exactly one value field must be set,
// and its kind must match the signed parameter definition.
type ArgumentValue struct {
	Name    string
	String  *string
	Integer *int64
	Boolean *bool
}

type ExecutionPlan struct {
	definitionID      string
	definitionVersion string
	definitionDigest  string
	executablePath    string
	executableSHA256  string
	argv              []string
	targets           []Target
	risk              Risk
	requiresPrivilege bool
	sudoRule          string
	limits            Limits
	validNotBefore    time.Time
	validBefore       time.Time
}

type CatalogMetadata struct {
	PackID      string
	PackVersion string
	Issuer      string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}
