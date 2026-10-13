package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestVersionedPayloadRoundTrip(t *testing.T) {
	completed := time.Date(2026, 8, 20, 10, 11, 12, 0, time.FixedZone("test", 5*60*60+30*60))
	tests := []struct {
		name      string
		eventType string
		payload   Payload
	}{
		{name: "collection", eventType: CollectionUpdatedType, payload: CollectionUpdatedV1{
			RunID: "run-1", SourceID: "source-1", Status: domain.ResultPartial,
			CompletedAt: completed, CoverageComplete: false,
		}},
		{name: "source", eventType: SourceUpdatedType, payload: SourceUpdatedV1{
			SourceID: "source-1", Availability: SourceAvailable, LastAttemptAt: completed,
			LastSuccessAt: &completed,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodePayload(test.eventType, PayloadSchemaV1, encoded)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.eventType() != test.eventType || decoded.schemaVersion() != PayloadSchemaV1 {
				t.Fatalf("unexpected decoded payload: %#v", decoded)
			}
		})
	}
}

func TestPayloadAndReadBounds(t *testing.T) {
	if err := (CollectionUpdatedV1{}).validate(); err == nil {
		t.Fatal("empty collection payload accepted")
	}
	if err := (SourceUpdatedV1{SourceID: "source", Availability: "HEALTHY", LastAttemptAt: time.Now()}).validate(); err == nil {
		t.Fatal("unknown source availability accepted")
	}
	for _, limit := range []int{0, MaxPageSize + 1} {
		if err := validateRead("cluster", limit); err == nil {
			t.Fatalf("limit %d accepted", limit)
		}
	}
	if _, err := decodePayload(CollectionUpdatedType, 2, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected schema error: %v", err)
	}
}

func TestNormalizedPayloadCopiesAndUsesUTC(t *testing.T) {
	local := time.Date(2026, 8, 20, 10, 0, 0, 0, time.FixedZone("test", 19800))
	original := &SourceUpdatedV1{SourceID: "source", Availability: SourceAvailable, LastAttemptAt: local, LastSuccessAt: &local}
	normalized := normalizedPayload(original).(SourceUpdatedV1)
	if normalized.LastAttemptAt.Location() != time.UTC || normalized.LastSuccessAt.Location() != time.UTC {
		t.Fatalf("payload times were not normalized: %#v", normalized)
	}
	normalized.Availability = SourceUnavailable
	if original.Availability != SourceAvailable {
		t.Fatal("normalization aliased caller payload")
	}
}
