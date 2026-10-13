package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

const EvidenceSchemaVersion = 1

type EvidenceID string
type ArtifactID string
type EvidenceTargetID string
type EvidenceOperationID string
type EvidenceSourceLocator string

type SHA256 [sha256.Size]byte

func ChecksumSHA256(payload []byte) SHA256 { return sha256.Sum256(payload) }

func ParseSHA256(value string) (SHA256, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return SHA256{}, fmt.Errorf("SHA-256 must contain exactly 64 hexadecimal characters")
	}
	var checksum SHA256
	copy(checksum[:], decoded)
	return checksum, nil
}

func (checksum SHA256) String() string { return hex.EncodeToString(checksum[:]) }

type EvidenceStatus string

const (
	EvidenceComplete    EvidenceStatus = "COMPLETE"
	EvidencePartial     EvidenceStatus = "PARTIAL"
	EvidenceNoData      EvidenceStatus = "NO_DATA"
	EvidenceUnavailable EvidenceStatus = "UNAVAILABLE"
)

type EvidenceTargetKind string

const (
	EvidenceTargetCluster EvidenceTargetKind = "CLUSTER"
	EvidenceTargetNode    EvidenceTargetKind = "NODE"
	EvidenceTargetGPU     EvidenceTargetKind = "GPU"
	EvidenceTargetSource  EvidenceTargetKind = "SOURCE"
)

type EvidenceTarget struct {
	Kind EvidenceTargetKind
	ID   EvidenceTargetID
}

type EvidenceCoverage struct {
	Expected []EvidenceTarget
	Covered  []EvidenceTarget
}

func (coverage EvidenceCoverage) Complete() bool {
	return len(coverage.Expected) > 0 && len(coverage.Expected) == len(coverage.Covered)
}

type EvidenceSourceReference struct {
	SourceID SourceID
	// RunID names the collection run that produced this evidence. A diagnostic
	// has no collection run and sets DiagnosticRunID instead; the two are
	// mutually exclusive, and conflating them was why a completed diagnostic
	// could never be committed.
	RunID             RunID
	DiagnosticRunID   DiagnosticRunID
	Operation         EvidenceOperationID
	DefinitionVersion string
	Reference         EvidenceSourceLocator
}

type EvidenceTimeRange struct {
	Start time.Time
	End   time.Time
}

type ArtifactCompression string

const (
	ArtifactUncompressed ArtifactCompression = "NONE"
	ArtifactGZIP         ArtifactCompression = "GZIP"
	ArtifactZSTD         ArtifactCompression = "ZSTD"
)

type ArtifactRetentionClass string

const (
	ArtifactRetentionShort    ArtifactRetentionClass = "SHORT"
	ArtifactRetentionStandard ArtifactRetentionClass = "STANDARD"
	ArtifactRetentionExtended ArtifactRetentionClass = "EXTENDED"
)

type ArtifactAvailability string

const (
	ArtifactPending     ArtifactAvailability = "PENDING"
	ArtifactAvailable   ArtifactAvailability = "AVAILABLE"
	ArtifactUnavailable ArtifactAvailability = "UNAVAILABLE"
	ArtifactCorrupt     ArtifactAvailability = "CORRUPT"
)

type EvidenceArtifactAvailability struct {
	EvidenceID EvidenceID
	ArtifactID ArtifactID
	Condition  ArtifactAvailability
}

func (availability EvidenceArtifactAvailability) Validate() error {
	if availability.EvidenceID == "" || availability.ArtifactID == "" {
		return fmt.Errorf("evidence and artifact identifiers are required for availability")
	}
	switch availability.Condition {
	case ArtifactPending, ArtifactAvailable, ArtifactUnavailable, ArtifactCorrupt:
		return nil
	default:
		return fmt.Errorf("unknown artifact availability %q", availability.Condition)
	}
}

type RedactionSummary struct {
	PolicyVersion string
	MatchCount    int
}

type ArtifactReference struct {
	ArtifactID     ArtifactID
	SHA256         SHA256
	Bytes          int64
	MediaType      string
	Compression    ArtifactCompression
	ParserVersion  string
	Redactions     RedactionSummary
	RetentionClass ArtifactRetentionClass
}

// EvidenceEnvelope is an immutable value. Construction validates all fields and
// accessors return copies of slice-backed data.
type EvidenceEnvelope struct {
	id            EvidenceID
	schemaVersion int
	clusterID     ClusterID
	status        EvidenceStatus
	source        EvidenceSourceReference
	timeRange     EvidenceTimeRange
	collectedAt   time.Time
	coverage      EvidenceCoverage
	artifact      *ArtifactReference
	supersedes    *EvidenceID
}

type NewEvidenceEnvelope struct {
	ID            EvidenceID
	SchemaVersion int
	ClusterID     ClusterID
	Status        EvidenceStatus
	Source        EvidenceSourceReference
	TimeRange     EvidenceTimeRange
	CollectedAt   time.Time
	Coverage      EvidenceCoverage
	Artifact      *ArtifactReference
	Supersedes    *EvidenceID
}

func CreateEvidenceEnvelope(input NewEvidenceEnvelope) (EvidenceEnvelope, error) {
	if input.ID == "" || input.ClusterID == "" {
		return EvidenceEnvelope{}, fmt.Errorf("evidence and cluster identifiers are required")
	}
	if input.SchemaVersion != EvidenceSchemaVersion {
		return EvidenceEnvelope{}, fmt.Errorf("unsupported evidence schema version %d", input.SchemaVersion)
	}
	if err := validateEvidenceStatus(input.Status); err != nil {
		return EvidenceEnvelope{}, err
	}
	if err := validateEvidenceSource(input.Source); err != nil {
		return EvidenceEnvelope{}, err
	}
	if input.TimeRange.Start.IsZero() || input.TimeRange.End.IsZero() || input.TimeRange.End.Before(input.TimeRange.Start) {
		return EvidenceEnvelope{}, fmt.Errorf("evidence observed time range is invalid")
	}
	if input.CollectedAt.IsZero() || input.CollectedAt.Before(input.TimeRange.End) {
		return EvidenceEnvelope{}, fmt.Errorf("evidence collection time must not precede its observed range")
	}
	coverage, err := validateEvidenceCoverage(input.Coverage)
	if err != nil {
		return EvidenceEnvelope{}, err
	}
	if err := validateEvidenceCoverageStatus(input.Status, coverage); err != nil {
		return EvidenceEnvelope{}, err
	}
	if input.Artifact != nil {
		if err := ValidateArtifactReference(*input.Artifact); err != nil {
			return EvidenceEnvelope{}, err
		}
	}
	if input.Supersedes != nil && (*input.Supersedes == "" || *input.Supersedes == input.ID) {
		return EvidenceEnvelope{}, fmt.Errorf("superseded evidence identifier is invalid")
	}
	artifact := cloneArtifact(input.Artifact)
	supersedes := cloneEvidenceID(input.Supersedes)
	return EvidenceEnvelope{
		id: input.ID, schemaVersion: input.SchemaVersion, clusterID: input.ClusterID,
		status: input.Status, source: input.Source,
		timeRange: EvidenceTimeRange{
			Start: input.TimeRange.Start.UTC().Truncate(time.Microsecond),
			End:   input.TimeRange.End.UTC().Truncate(time.Microsecond),
		},
		collectedAt: input.CollectedAt.UTC().Truncate(time.Microsecond), coverage: coverage, artifact: artifact, supersedes: supersedes,
	}, nil
}

func (envelope EvidenceEnvelope) ID() EvidenceID                  { return envelope.id }
func (envelope EvidenceEnvelope) SchemaVersion() int              { return envelope.schemaVersion }
func (envelope EvidenceEnvelope) ClusterID() ClusterID            { return envelope.clusterID }
func (envelope EvidenceEnvelope) Status() EvidenceStatus          { return envelope.status }
func (envelope EvidenceEnvelope) Source() EvidenceSourceReference { return envelope.source }
func (envelope EvidenceEnvelope) TimeRange() EvidenceTimeRange    { return envelope.timeRange }
func (envelope EvidenceEnvelope) CollectedAt() time.Time          { return envelope.collectedAt }
func (envelope EvidenceEnvelope) Coverage() EvidenceCoverage {
	return EvidenceCoverage{Expected: slices.Clone(envelope.coverage.Expected), Covered: slices.Clone(envelope.coverage.Covered)}
}
func (envelope EvidenceEnvelope) Artifact() (ArtifactReference, bool) {
	if envelope.artifact == nil {
		return ArtifactReference{}, false
	}
	return *envelope.artifact, true
}
func (envelope EvidenceEnvelope) Supersedes() (EvidenceID, bool) {
	if envelope.supersedes == nil {
		return "", false
	}
	return *envelope.supersedes, true
}

func (envelope EvidenceEnvelope) Validate() error {
	_, err := CreateEvidenceEnvelope(NewEvidenceEnvelope{
		ID: envelope.id, SchemaVersion: envelope.schemaVersion, ClusterID: envelope.clusterID,
		Status: envelope.status, Source: envelope.source, TimeRange: envelope.timeRange,
		CollectedAt: envelope.collectedAt, Coverage: envelope.coverage,
		Artifact: cloneArtifact(envelope.artifact), Supersedes: cloneEvidenceID(envelope.supersedes),
	})
	return err
}

func (envelope EvidenceEnvelope) Equal(other EvidenceEnvelope) bool {
	return envelope.id == other.id && envelope.schemaVersion == other.schemaVersion &&
		envelope.clusterID == other.clusterID && envelope.status == other.status &&
		envelope.source == other.source && envelope.timeRange == other.timeRange &&
		envelope.collectedAt.Equal(other.collectedAt) &&
		slices.Equal(envelope.coverage.Expected, other.coverage.Expected) &&
		slices.Equal(envelope.coverage.Covered, other.coverage.Covered) &&
		equalArtifact(envelope.artifact, other.artifact) && equalEvidenceID(envelope.supersedes, other.supersedes)
}

func ValidateArtifactReference(reference ArtifactReference) error {
	if reference.ArtifactID == "" || reference.ArtifactID != ArtifactID("sha256:"+reference.SHA256.String()) {
		return fmt.Errorf("artifact identifier must be its SHA-256 content address")
	}
	if reference.Bytes < 0 {
		return fmt.Errorf("artifact byte length cannot be negative")
	}
	if len(reference.MediaType) < 3 || len(reference.MediaType) > 128 || !strings.Contains(reference.MediaType, "/") || strings.ContainsAny(reference.MediaType, "\r\n") {
		return fmt.Errorf("artifact media type is invalid")
	}
	switch reference.Compression {
	case ArtifactUncompressed, ArtifactGZIP, ArtifactZSTD:
	default:
		return fmt.Errorf("unknown artifact compression %q", reference.Compression)
	}
	if reference.ParserVersion == "" || len(reference.ParserVersion) > 128 {
		return fmt.Errorf("artifact parser version is required and bounded")
	}
	if reference.Redactions.PolicyVersion == "" || len(reference.Redactions.PolicyVersion) > 128 || reference.Redactions.MatchCount < 0 {
		return fmt.Errorf("artifact redaction summary is invalid")
	}
	switch reference.RetentionClass {
	case ArtifactRetentionShort, ArtifactRetentionStandard, ArtifactRetentionExtended:
	default:
		return fmt.Errorf("unknown artifact retention class %q", reference.RetentionClass)
	}
	return nil
}

func NewArtifactReference(checksum SHA256, bytes int64, mediaType string, compression ArtifactCompression, parserVersion string, redactions RedactionSummary, retention ArtifactRetentionClass) (ArtifactReference, error) {
	reference := ArtifactReference{
		ArtifactID: ArtifactID("sha256:" + checksum.String()), SHA256: checksum, Bytes: bytes,
		MediaType: mediaType, Compression: compression, ParserVersion: parserVersion,
		Redactions: redactions, RetentionClass: retention,
	}
	return reference, ValidateArtifactReference(reference)
}

func validateEvidenceStatus(status EvidenceStatus) error {
	switch status {
	case EvidenceComplete, EvidencePartial, EvidenceNoData, EvidenceUnavailable:
		return nil
	default:
		return fmt.Errorf("unknown evidence status %q", status)
	}
}

func validateEvidenceSource(source EvidenceSourceReference) error {
	if source.SourceID == "" || source.Operation == "" || source.DefinitionVersion == "" || source.Reference == "" {
		return fmt.Errorf("evidence source, operation, definition version, and reference are required")
	}
	if len(source.Operation) > 128 || len(source.DefinitionVersion) > 128 || len(source.Reference) > 1024 || strings.ContainsAny(string(source.Reference), "\r\n") {
		return fmt.Errorf("evidence source reference exceeds its bounds")
	}
	return nil
}

func validateEvidenceCoverage(coverage EvidenceCoverage) (EvidenceCoverage, error) {
	if len(coverage.Expected) > 10_000 || len(coverage.Covered) > len(coverage.Expected) {
		return EvidenceCoverage{}, fmt.Errorf("evidence target coverage exceeds its bounds")
	}
	expected := make(map[EvidenceTarget]struct{}, len(coverage.Expected))
	for _, target := range coverage.Expected {
		if err := validateEvidenceTarget(target); err != nil {
			return EvidenceCoverage{}, err
		}
		if _, exists := expected[target]; exists {
			return EvidenceCoverage{}, fmt.Errorf("evidence expected targets contain a duplicate")
		}
		expected[target] = struct{}{}
	}
	covered := make(map[EvidenceTarget]struct{}, len(coverage.Covered))
	for _, target := range coverage.Covered {
		if _, exists := expected[target]; !exists {
			return EvidenceCoverage{}, fmt.Errorf("covered evidence target was not expected")
		}
		if _, exists := covered[target]; exists {
			return EvidenceCoverage{}, fmt.Errorf("evidence covered targets contain a duplicate")
		}
		covered[target] = struct{}{}
	}
	return EvidenceCoverage{Expected: slices.Clone(coverage.Expected), Covered: slices.Clone(coverage.Covered)}, nil
}

func validateEvidenceTarget(target EvidenceTarget) error {
	switch target.Kind {
	case EvidenceTargetCluster, EvidenceTargetNode, EvidenceTargetGPU, EvidenceTargetSource:
	default:
		return fmt.Errorf("unknown evidence target kind %q", target.Kind)
	}
	if target.ID == "" || len(target.ID) > 512 || strings.ContainsAny(string(target.ID), "\r\n") {
		return fmt.Errorf("evidence target identifier is invalid")
	}
	return nil
}

func validateEvidenceCoverageStatus(status EvidenceStatus, coverage EvidenceCoverage) error {
	complete := coverage.Complete()
	if status == EvidenceComplete && !complete {
		return fmt.Errorf("complete evidence requires complete non-empty target coverage")
	}
	if status == EvidenceNoData && len(coverage.Expected) != len(coverage.Covered) {
		return fmt.Errorf("no-data evidence requires complete target coverage")
	}
	if status == EvidenceUnavailable && len(coverage.Covered) != 0 {
		return fmt.Errorf("unavailable evidence cannot claim covered targets")
	}
	return nil
}

func cloneArtifact(value *ArtifactReference) *ArtifactReference {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneEvidenceID(value *EvidenceID) *EvidenceID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func equalArtifact(left, right *ArtifactReference) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func equalEvidenceID(left, right *EvidenceID) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}
