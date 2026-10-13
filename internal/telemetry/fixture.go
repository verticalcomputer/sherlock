package telemetry

import (
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// NewFixtureFrame creates explicit synthetic facts for the stage4 transport
// qualification. It never reads host, GPU, filesystem, network or workload state.
func NewFixtureFrame(sourceID, clusterID, nodeID, recordPrefix string, at time.Time, counter uint64) (SourceFrame, error) {
	if !validID(sourceID) || !validID(clusterID) || !validID(nodeID) || !validID(recordPrefix) || len(recordPrefix) > 100 || !validInstant(at) {
		return SourceFrame{}, ErrInvalid
	}
	identity, err := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: domain.ClusterID(clusterID), Kind: domain.EntityNode, NodeID: domain.StableNodeID(nodeID)})
	if err != nil {
		return SourceFrame{}, ErrInvalid
	}
	gauge, flag := 1.0, false
	values := []Scalar{{Kind: "float", Float: &gauge}, {Kind: "unsigned", Unsigned: strconv.FormatUint(counter, 10)}, {Kind: "boolean", Boolean: &flag}, {Kind: "enum", Enum: "OK"}}
	frame := SourceFrame{SourceID: sourceID, SchemaVersion: 1, AdapterVersion: FixtureProfile, ProfileID: FixtureProfile, StartedAt: at, CompletedAt: at, Status: "SUCCEEDED", Coverage: Coverage{Expected: 4, Returned: 4, Complete: true}}
	for i, metric := range fixtureMetrics {
		unit, kind, reset := "1", "gauge", "not_applicable"
		if metric == "fixture.counter" {
			unit, kind, reset = "count", "counter", "session_epoch"
		}
		if metric == "fixture.state" {
			kind = "state"
		}
		frame.Fields = append(frame.Fields, FieldSupport{EntityKey: identity.Key(), Metric: metric, State: "SUPPORTED", Reason: "OBSERVED"})
		frame.Records = append(frame.Records, Record{ID: recordPrefix + "-" + metric, EntityKey: identity.Key(), Metric: metric, Unit: unit, Kind: kind, Reset: reset, ObservedAt: at, CollectedAt: at, Value: values[i]})
	}
	return frame, nil
}
