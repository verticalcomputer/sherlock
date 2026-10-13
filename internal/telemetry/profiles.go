package telemetry

import "math"

const LinuxHostProfile = "linux.host.v1"
const LinuxRootProfile = "linux.rootfs.v1"

// ProfileField is a closed schema definition, not arbitrary metric admission.
type ProfileField struct{ Metric, Unit, ScalarKind string }

func ProfileFields(profile string) []ProfileField {
	switch profile {
	case FixtureProfile:
		return []ProfileField{{"fixture.gauge", "1", "float"}, {"fixture.counter", "count", "unsigned"}, {"fixture.flag", "1", "boolean"}, {"fixture.state", "1", "enum"}}
	case LinuxHostProfile:
		return []ProfileField{{"host.memory.total_bytes", "bytes", "unsigned"}, {"host.memory.available_bytes", "bytes", "unsigned"}, {"host.load.one", "1", "float"}, {"host.load.five", "1", "float"}, {"host.load.fifteen", "1", "float"}, {"host.uptime_seconds", "seconds", "float"}}
	case LinuxRootProfile:
		return []ProfileField{{"filesystem.root.total_bytes", "bytes", "unsigned"}, {"filesystem.root.free_bytes", "bytes", "unsigned"}, {"filesystem.root.available_bytes", "bytes", "unsigned"}, {"filesystem.root.total_inodes", "count", "unsigned"}, {"filesystem.root.free_inodes", "count", "unsigned"}}
	}
	return nil
}

func KnownProfile(profile string) bool { return len(ProfileFields(profile)) != 0 }

// SourceProfile preserves legacy fixture semantics only for omitted entries.
func SourceProfile(profiles map[string]string, source string) string {
	if profile, exists := profiles[source]; exists {
		return profile
	}
	return FixtureProfile
}

func ValidSourceProfiles(ids []string, profiles map[string]string) bool {
	for id, profile := range profiles {
		found := false
		for _, declared := range ids {
			if declared == id {
				found = true
				break
			}
		}
		if !found || !KnownProfile(profile) {
			return false
		}
	}
	return true
}

func profileMetric(profile, metric string) bool {
	for _, f := range ProfileFields(profile) {
		if f.Metric == metric {
			return true
		}
	}
	return false
}

func profileRecord(profile string, r Record) bool {
	if profile == FixtureProfile {
		return fixtureRecord(r)
	}
	if r.Kind != "gauge" || r.Reset != "not_applicable" || r.ResetObserved || r.Value.Boolean != nil || r.Value.Enum != "" {
		return false
	}
	for _, f := range ProfileFields(profile) {
		if f.Metric != r.Metric {
			continue
		}
		if r.Unit != f.Unit || r.Value.Kind != f.ScalarKind {
			return false
		}
		if f.ScalarKind == "unsigned" {
			_, ok := decimal(r.Value.Unsigned, true)
			return ok && r.Value.Float == nil
		}
		return r.Value.Float != nil && r.Value.Unsigned == "" && !math.IsNaN(*r.Value.Float) && !math.IsInf(*r.Value.Float, 0) && *r.Value.Float >= 0
	}
	return false
}
