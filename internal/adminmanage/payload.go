package adminmanage

import (
	"context"
	"errors"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	PayloadAvailable   = "AVAILABLE"
	PayloadNotRecorded = "NOT_RECORDED"
	PayloadUnavailable = "UNAVAILABLE"
)

type ModelPayloadReader interface {
	ReadModelPayload(context.Context, string) (ModelPayload, error)
}

type evidenceLoader interface {
	LoadEvidence(context.Context, domain.EvidenceID) (domain.EvidenceEnvelope, domain.ArtifactAvailability, bool, error)
}

type artifactReader interface {
	Read(context.Context, domain.ArtifactReference) ([]byte, error)
}

type EvidencePayloadReader struct {
	evidence  evidenceLoader
	artifacts artifactReader
}

func NewEvidencePayloadReader(evidence evidenceLoader, artifacts artifactReader) (*EvidencePayloadReader, error) {
	if evidence == nil || artifacts == nil {
		return nil, fmt.Errorf("%w: evidence and artifact readers are required", ErrInvalid)
	}
	return &EvidencePayloadReader{evidence: evidence, artifacts: artifacts}, nil
}

func (reader *EvidencePayloadReader) ReadModelPayload(ctx context.Context, id string) (ModelPayload, error) {
	if id == "" {
		return ModelPayload{Availability: PayloadNotRecorded}, nil
	}
	payload := ModelPayload{EvidenceID: id, Availability: PayloadUnavailable}
	envelope, availability, found, err := reader.evidence.LoadEvidence(ctx, domain.EvidenceID(id))
	if err != nil {
		return ModelPayload{}, fmt.Errorf("load model payload evidence: %w", err)
	}
	if !found || availability != domain.ArtifactAvailable {
		return payload, nil
	}
	reference, ok := envelope.Artifact()
	if !ok {
		return payload, nil
	}
	content, err := reader.artifacts.Read(ctx, reference)
	if errors.Is(err, application.ErrArtifactUnavailable) || errors.Is(err, application.ErrArtifactCorrupt) {
		return payload, nil
	}
	if err != nil {
		return ModelPayload{}, fmt.Errorf("read model payload artifact: %w", err)
	}
	payload.Availability = PayloadAvailable
	payload.MediaType = reference.MediaType
	payload.Content = string(content)
	return payload, nil
}
