package application

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const ModelPayloadRedactionPolicy = "model-io-redaction-v1"

type ModelPayloadRole string

const (
	ModelPayloadInput  ModelPayloadRole = "INPUT"
	ModelPayloadOutput ModelPayloadRole = "OUTPUT"
)

type ModelPayloadEvidence struct {
	InvestigationID domain.InvestigationID
	ClusterID       domain.ClusterID
	CallKey         string
	Kind            ModelCallKind
	Role            ModelPayloadRole
	Payload         []byte
	OccurredAt      time.Time
}

type ModelPayloadEvidenceSink interface {
	RecordModelPayload(context.Context, ModelPayloadEvidence) (domain.EvidenceID, error)
}

type ModelPayloadSourceStore interface {
	EnsureModelAuditSource(context.Context, domain.ClusterID, domain.SourceID) error
}

type modelPayloadWriter interface {
	Record(context.Context, RecordEvidence) (RecordEvidenceOutcome, error)
}

type ModelPayloadRecorder struct {
	sources  ModelPayloadSourceStore
	evidence modelPayloadWriter
	maxBytes int64
}

func NewModelPayloadRecorder(sources ModelPayloadSourceStore, evidence modelPayloadWriter, maxBytes int64) (*ModelPayloadRecorder, error) {
	if sources == nil || evidence == nil || maxBytes < 1 || maxBytes > 4<<20 {
		return nil, fmt.Errorf("model payload evidence dependencies or bound are invalid")
	}
	return &ModelPayloadRecorder{sources: sources, evidence: evidence, maxBytes: maxBytes}, nil
}

func (recorder *ModelPayloadRecorder) RecordModelPayload(ctx context.Context, input ModelPayloadEvidence) (domain.EvidenceID, error) {
	if input.InvestigationID == "" || input.ClusterID == "" || !validAuditToken(input.CallKey) || input.OccurredAt.IsZero() || len(input.Payload) == 0 || int64(len(input.Payload)) > recorder.maxBytes {
		return "", fmt.Errorf("model payload evidence attribution or size is invalid")
	}
	if input.Kind != ModelCallPlanning && input.Kind != ModelCallSynthesis || input.Role != ModelPayloadInput && input.Role != ModelPayloadOutput {
		return "", fmt.Errorf("model payload evidence kind or role is invalid")
	}
	payload, redactions, mediaType, err := redactModelPayload(input.Payload)
	if err != nil {
		return "", err
	}
	if int64(len(payload)) > recorder.maxBytes {
		return "", ErrArtifactTooLarge
	}
	clusterDigest := domain.ChecksumSHA256([]byte(input.ClusterID))
	sourceID := domain.SourceID("model-audit-" + clusterDigest.String()[:24])
	if err := recorder.sources.EnsureModelAuditSource(ctx, input.ClusterID, sourceID); err != nil {
		return "", err
	}
	payloadDigest := domain.ChecksumSHA256(payload)
	reference, err := domain.NewArtifactReference(payloadDigest, int64(len(payload)), mediaType, domain.ArtifactUncompressed, "model-io-v1", domain.RedactionSummary{PolicyVersion: ModelPayloadRedactionPolicy, MatchCount: redactions}, domain.ArtifactRetentionExtended)
	if err != nil {
		return "", err
	}
	attribution := strings.Join([]string{string(input.ClusterID), string(input.InvestigationID), input.CallKey, string(input.Kind), string(input.Role), payloadDigest.String()}, "\x00")
	evidenceID := domain.EvidenceID("model-io-" + domain.ChecksumSHA256([]byte(attribution)).String())
	operation := domain.EvidenceOperationID("model_" + strings.ToLower(string(input.Kind)) + "_" + strings.ToLower(string(input.Role)))
	target := domain.EvidenceTarget{Kind: domain.EvidenceTargetCluster, ID: domain.EvidenceTargetID(input.ClusterID)}
	observedAt := input.OccurredAt.UTC().Truncate(time.Microsecond)
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{
		ID: evidenceID, SchemaVersion: domain.EvidenceSchemaVersion, ClusterID: input.ClusterID, Status: domain.EvidenceComplete,
		Source:    domain.EvidenceSourceReference{SourceID: sourceID, Operation: operation, DefinitionVersion: "model-io-v1", Reference: domain.EvidenceSourceLocator("model-call:" + input.CallKey + ":" + strings.ToLower(string(input.Role)))},
		TimeRange: domain.EvidenceTimeRange{Start: observedAt, End: observedAt}, CollectedAt: observedAt,
		Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}, Covered: []domain.EvidenceTarget{target}}, Artifact: &reference,
	})
	if err != nil {
		return "", err
	}
	if _, err := recorder.evidence.Record(ctx, RecordEvidence{Envelope: envelope, RawArtifact: payload}); err != nil {
		return "", fmt.Errorf("record model payload evidence: %w", err)
	}
	return evidenceID, nil
}

var modelSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9._~+/=-]+`),
	regexp.MustCompile(`shk_live_[A-Za-z0-9_-]+`),
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{12,}`),
}

func redactModelPayload(payload []byte) ([]byte, int, string, error) {
	if json.Valid(payload) {
		var value any
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, 0, "", fmt.Errorf("decode model payload for redaction")
		}
		redactions := 0
		value = redactModelValue(value, &redactions)
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, 0, "", fmt.Errorf("encode redacted model payload")
		}
		return encoded, redactions, "application/json", nil
	}
	text, redactions := redactModelString(string(payload))
	return []byte(text), redactions, "text/plain; charset=utf-8", nil
}

func redactModelValue(value any, redactions *int) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if modelSensitiveKey(key) {
				typed[key] = "[REDACTED]"
				*redactions += 1
				continue
			}
			typed[key] = redactModelValue(child, redactions)
		}
		return typed
	case []any:
		for index := range typed {
			typed[index] = redactModelValue(typed[index], redactions)
		}
		return typed
	case string:
		redacted, count := redactModelString(typed)
		*redactions += count
		return redacted
	default:
		return value
	}
}

func modelSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_"))
	switch normalized {
	case "authorization", "api_key", "password", "secret", "access_token", "refresh_token", "credential", "cookie", "set_cookie":
		return true
	default:
		return false
	}
}

func redactModelString(value string) (string, int) {
	count := 0
	for _, pattern := range modelSecretPatterns {
		matches := pattern.FindAllStringIndex(value, -1)
		count += len(matches)
		value = pattern.ReplaceAllString(value, "[REDACTED]")
	}
	return value, count
}
