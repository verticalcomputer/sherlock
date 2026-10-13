package telemetry

import (
	"math"
	"strconv"
	"testing"
)

func linuxBatch(profile string) NodeBatch {
	b := fixture()
	s := b.Sources[0]
	s.ProfileID = profile
	s.AdapterVersion = profile
	s.Fields = nil
	s.Records = nil
	for i, f := range ProfileFields(profile) {
		value := Scalar{Kind: "unsigned", Unsigned: "18446744073709551615"}
		if f.ScalarKind == "float" {
			n := 1.5
			value = Scalar{Kind: "float", Float: &n}
		}
		s.Fields = append(s.Fields, FieldSupport{EntityKey: "fixture-cluster/NODE/node-a//", Metric: f.Metric, State: "SUPPORTED", Reason: "OBSERVED"})
		s.Records = append(s.Records, Record{ID: "linux-" + strconv.Itoa(i), EntityKey: "fixture-cluster/NODE/node-a//", Metric: f.Metric, Unit: f.Unit, Kind: "gauge", Reset: "not_applicable", ObservedAt: b.CreatedAt, CollectedAt: b.CreatedAt, Value: value})
	}
	s.Coverage = Coverage{Expected: int64(len(s.Fields)), Returned: int64(len(s.Records)), Complete: true}
	b.Sources = []SourceFrame{s}
	return b
}
func TestClosedLinuxSchemaAndOriginalFixtureGoldens(t *testing.T) {
	for _, profile := range []string{LinuxHostProfile, LinuxRootProfile} {
		if ValidateNodeBatch(linuxBatch(profile)) != nil {
			t.Fatal("valid Linux schema", profile)
		}
		for _, change := range []func(*SourceFrame){
			func(s *SourceFrame) { s.ProfileID = "linux.unreviewed.v1" },
			func(s *SourceFrame) { s.AdapterVersion = FixtureProfile },
			func(s *SourceFrame) { s.Fields[0].Metric = "arbitrary.metric" },
			func(s *SourceFrame) { s.Records[0].ResetObserved = true },
			func(s *SourceFrame) { s.Records[0].Kind = "counter" },
			func(s *SourceFrame) { s.Records[0].Value.Unsigned = "01" },
			func(s *SourceFrame) { s.Records[0].Value.Enum = "OK" },
			func(s *SourceFrame) { s.Records[0].Unit = "1" },
			func(s *SourceFrame) { s.Records[0].EntityKey = "fixture-cluster/NODE/foreign//" },
		} {
			b := linuxBatch(profile)
			change(&b.Sources[0])
			if ValidateNodeBatch(b) == nil {
				t.Fatal("malformed Linux schema admitted")
			}
		}
	}
	for _, v := range []float64{-1, math.Inf(1), math.NaN()} {
		b := linuxBatch(LinuxHostProfile)
		b.Sources[0].Records[2].Value.Float = &v
		if ValidateNodeBatch(b) == nil {
			t.Fatal("invalid float")
		}
	}
}
func TestProfileGrantBindingAndClosedSourceMap(t *testing.T) {
	b := linuxBatch(LinuxHostProfile)
	g, _ := fixtureGrant(t, b.CreatedAt)
	b.Key.ClusterID = g.ClusterID
	b.Key.NodeID = g.NodeID // Both fixtures use the same bound identity.
	if ValidateBatchForGrant(b, g, b.CreatedAt) == nil {
		t.Fatal("Linux batch under fixture grant")
	}
	g.Sources[0].ProfileID = LinuxHostProfile
	if ValidateBatchForGrant(b, g, b.CreatedAt) != nil {
		t.Fatal("approved Linux grant rejected")
	}
	if SourceProfile(nil, "a") != FixtureProfile || !ValidSourceProfiles([]string{"a"}, map[string]string{"a": LinuxRootProfile}) {
		t.Fatal("legacy/additive map")
	}
	for _, profiles := range []map[string]string{{"foreign": LinuxRootProfile}, {"a": ""}, {"a": "arbitrary"}} {
		if ValidSourceProfiles([]string{"a"}, profiles) {
			t.Fatal("unapproved profile map")
		}
	}
}
