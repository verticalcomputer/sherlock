package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
)

const CollectorResultSchemaVersion = 1

// CollectorResultDocument is the canonical, transport-neutral result submitted
// for one leased work attempt. Its JSON encoding is checksummed before ingestion.
type CollectorResultDocument struct {
	SchemaVersion int              `json:"schema_version"`
	WorkID        WorkID           `json:"work_id"`
	Attempt       int              `json:"attempt"`
	Result        CollectionResult `json:"result"`
}

func EncodeCollectorResult(document CollectorResultDocument) ([]byte, error) {
	if document.SchemaVersion != CollectorResultSchemaVersion {
		return nil, fmt.Errorf("unsupported collector result schema version %d", document.SchemaVersion)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode collector result: %w", err)
	}
	return encoded, nil
}

// DecodeCollectorResult rejects unknown fields, trailing data, and non-canonical
// encodings so a checksum identifies exactly one logical result document.
func DecodeCollectorResult(encoded []byte) (CollectorResultDocument, error) {
	var document CollectorResultDocument
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return CollectorResultDocument{}, fmt.Errorf("decode collector result: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return CollectorResultDocument{}, err
	}
	canonical, err := EncodeCollectorResult(document)
	if err != nil {
		return CollectorResultDocument{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return CollectorResultDocument{}, fmt.Errorf("collector result is not canonically encoded")
	}
	return document, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("collector result contains trailing JSON data")
		}
		return fmt.Errorf("decode trailing collector result data: %w", err)
	}
	return nil
}

func ValidateCollectorResult(document CollectorResultDocument, work CollectorWork, attempt int) error {
	if document.SchemaVersion != CollectorResultSchemaVersion {
		return fmt.Errorf("unsupported collector result schema version %d", document.SchemaVersion)
	}
	if document.WorkID != work.WorkID || document.Attempt != attempt || attempt < 1 {
		return fmt.Errorf("collector result work or attempt identity does not match its lease")
	}
	result := document.Result
	if !sameCollectionTask(result.Task, work.Task) {
		return fmt.Errorf("collector result task identity does not match assigned work")
	}
	if !validResultStatus(result.Status) {
		return fmt.Errorf("unknown collector result status %q", result.Status)
	}
	if result.StartedAt.IsZero() || result.CompletedAt.IsZero() || result.CompletedAt.Before(result.StartedAt) {
		return fmt.Errorf("collector result timestamps are invalid")
	}
	if result.Coverage.SeriesReturned < 0 || result.Coverage.SeriesReturned > work.Task.MaxSeries || result.Coverage.BytesRead < 0 || result.Coverage.BytesRead > work.Task.MaxBytes {
		return fmt.Errorf("collector result coverage exceeds assigned limits")
	}
	if result.Coverage.SeriesExpected != nil && (*result.Coverage.SeriesExpected < 0 || *result.Coverage.SeriesExpected < result.Coverage.SeriesReturned) {
		return fmt.Errorf("collector result expected-series coverage is invalid")
	}
	if len(result.Coverage.ExpectedTargets) > work.Task.MaxSeries*2 {
		return fmt.Errorf("collector result expected-target coverage exceeds assigned limits")
	}
	seenTargets := make(map[EvidenceTarget]struct{}, len(result.Coverage.ExpectedTargets))
	for _, target := range result.Coverage.ExpectedTargets {
		if err := validateEvidenceTarget(target); err != nil {
			return err
		}
		if _, duplicate := seenTargets[target]; duplicate {
			return fmt.Errorf("collector result expected targets contain a duplicate")
		}
		seenTargets[target] = struct{}{}
	}
	if err := validateResultSemantics(result); err != nil {
		return err
	}
	if err := validateFailures(result.Failures); err != nil {
		return err
	}
	return validateObservations(result)
}

func sameCollectionTask(left, right CollectionTask) bool {
	if left.RunID != right.RunID || left.ClusterID != right.ClusterID || left.SourceID != right.SourceID ||
		left.Query != right.Query || left.Node != right.Node || left.MaxSeries != right.MaxSeries ||
		left.MaxBytes != right.MaxBytes || left.IdempotencyKey != right.IdempotencyKey ||
		!left.ScheduledFor.Equal(right.ScheduledFor) || !left.Deadline.Equal(right.Deadline) {
		return false
	}
	if left.Range == nil || right.Range == nil {
		return left.Range == nil && right.Range == nil
	}
	return left.Range.Start.Equal(right.Range.Start) && left.Range.End.Equal(right.Range.End) && left.Range.Step == right.Range.Step
}

func validResultStatus(status ResultStatus) bool {
	return status == ResultSucceeded || status == ResultNoData || status == ResultPartial || status == ResultFailed
}

func validateResultSemantics(result CollectionResult) error {
	switch result.Status {
	case ResultSucceeded:
		if !result.Coverage.Complete || result.Coverage.SeriesReturned == 0 || len(result.Observations) == 0 || len(result.Failures) != 0 {
			return fmt.Errorf("succeeded collector result has inconsistent coverage, observations, or failures")
		}
	case ResultNoData:
		if !result.Coverage.Complete || result.Coverage.SeriesReturned != 0 || len(result.Observations) != 0 || len(result.Failures) != 0 {
			return fmt.Errorf("no-data collector result has inconsistent coverage, observations, or failures")
		}
	case ResultPartial:
		if result.Coverage.Complete || len(result.Failures) == 0 {
			return fmt.Errorf("partial collector result must preserve incomplete coverage and failures")
		}
	case ResultFailed:
		if result.Coverage.Complete || len(result.Observations) != 0 || len(result.Failures) == 0 {
			return fmt.Errorf("failed collector result must have incomplete coverage, no observations, and failures")
		}
	}
	return nil
}

func validateFailures(failures []CollectionFailure) error {
	for _, failure := range failures {
		switch failure.Code {
		case FailureSourceUnavailable, FailureDeadlineExceeded, FailureMalformedResponse, FailureResultLimit,
			FailureUnauthorized, FailureInvalidArgument, FailurePartialData, FailureCollectorUnavailable, FailureInternal:
		default:
			return fmt.Errorf("unknown collector failure code %q", failure.Code)
		}
		if failure.Message == "" || len(failure.Message) > 1024 || len(failure.Target) > 512 {
			return fmt.Errorf("collector failure has invalid safe message or target")
		}
	}
	return nil
}

func validateObservations(result CollectionResult) error {
	identifiers := make(map[ObservationID]struct{}, len(result.Observations))
	for _, observation := range result.Observations {
		if observation.ID == "" || observation.SchemaVersion != 1 || observation.ClusterID != result.Task.ClusterID || observation.SourceID != result.Task.SourceID {
			return fmt.Errorf("collector observation identity or schema is invalid")
		}
		if _, duplicate := identifiers[observation.ID]; duplicate {
			return fmt.Errorf("duplicate collector observation identifier %q", observation.ID)
		}
		identifiers[observation.ID] = struct{}{}
		if observation.Kind == "" || observation.EntityKey == "" || observation.Metric == "" || observation.Unit == "" || observation.SourceReference == "" {
			return fmt.Errorf("collector observation fields are required")
		}
		if math.IsNaN(observation.Value) || math.IsInf(observation.Value, 0) || observation.ObservedAt.IsZero() || observation.CollectedAt.IsZero() || observation.CollectedAt.Before(observation.ObservedAt) || !observation.CollectedAt.Equal(result.CompletedAt) {
			return fmt.Errorf("collector observation value or timestamps are invalid")
		}
		if !slices.IsSortedFunc(observation.Labels, func(a, b Label) int {
			if a.Name < b.Name {
				return -1
			}
			if a.Name > b.Name {
				return 1
			}
			return 0
		}) {
			return fmt.Errorf("collector observation labels are not canonically ordered")
		}
		for index, label := range observation.Labels {
			if label.Name == "" || (index > 0 && observation.Labels[index-1].Name == label.Name) {
				return fmt.Errorf("collector observation labels are empty or duplicated")
			}
		}
	}
	return nil
}

// NormalizeCollectorResultTimes strips monotonic clock readings and normalizes
// all result timestamps to UTC before canonical encoding.
func NormalizeCollectorResultTimes(document CollectorResultDocument) CollectorResultDocument {
	document.Result.Task.ScheduledFor = document.Result.Task.ScheduledFor.UTC()
	document.Result.Task.Deadline = document.Result.Task.Deadline.UTC()
	document.Result.StartedAt = document.Result.StartedAt.UTC()
	document.Result.CompletedAt = document.Result.CompletedAt.UTC()
	if document.Result.Task.Range != nil {
		document.Result.Task.Range.Start = document.Result.Task.Range.Start.UTC()
		document.Result.Task.Range.End = document.Result.Task.Range.End.UTC()
	}
	for index := range document.Result.Observations {
		document.Result.Observations[index].ObservedAt = document.Result.Observations[index].ObservedAt.UTC()
		document.Result.Observations[index].CollectedAt = document.Result.Observations[index].CollectedAt.UTC()
	}
	return document
}
