package monitoring

import (
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func LookupRule(id RuleID, version int) (RuleDefinition, bool) {
	for _, rule := range Registry() {
		if rule.ID == id && rule.Version == version {
			return rule, true
		}
	}
	return RuleDefinition{}, false
}

func validID(value string) bool {
	return len(value) > 0 && len(value) <= 256 && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

// ValidatePolicy validates the versioned local contract, never durable source
// authority. The store must additionally revalidate the enabled exact schedule
// revision and expected inventory under its enrollment/evaluation transaction.
func ValidatePolicy(policy Policy) error {
	rule, ok := LookupRule(policy.Rule, policy.RuleVersion)
	if !ok || rule.Owner != "monitoring" {
		return fmt.Errorf("unavailable monitoring rule version")
	}
	if !validID(policy.ID) || len(policy.ID) > 128 || policy.Revision != 1 || !validID(string(policy.ClusterID)) || !validID(string(policy.SourceID)) || !validID(policy.EntityKey) || policy.EnrolledAt.IsZero() {
		return fmt.Errorf("invalid policy identity or enrollment")
	}
	operation, ok := domain.ReviewedCollectionOperation(policy.Binding.Operation)
	if !ok || operation.Source != domain.CollectionSourcePrometheus || !operation.Query.IsGPU() || policy.Binding.ScheduleRevision < 0 {
		return fmt.Errorf("v1 requires an exact reviewed Prometheus GPU schedule")
	}
	if policy.AllowEmptySuccess {
		return fmt.Errorf("complete-empty source contact is unsupported by monitoring v1")
	}
	if len(policy.Binding.Scope.Nodes) > 1024 {
		return fmt.Errorf("monitoring scope exceeds bound")
	}
	nodes := map[domain.StableNodeID]bool{}
	for index, node := range policy.Binding.Scope.Nodes {
		if !validID(string(node)) || nodes[node] || index > 0 && node <= policy.Binding.Scope.Nodes[index-1] {
			return fmt.Errorf("invalid or duplicate monitoring scope node")
		}
		nodes[node] = true
	}
	if policy.StartupGraceSeconds < 0 || policy.StartupGraceSeconds > 86400 || policy.FreshForSeconds < 1 || policy.FreshForSeconds > 86400 ||
		policy.ConfirmCount < 1 || policy.ConfirmCount > 10 || policy.RecoverCount < 1 || policy.RecoverCount > 10 ||
		policy.ConfirmWindowSeconds < 1 || policy.ConfirmWindowSeconds > 86400 || policy.RecoverWindowSeconds < 1 || policy.RecoverWindowSeconds > 86400 {
		return fmt.Errorf("invalid bounded monitoring duration or confirmation policy")
	}
	if policy.ConfirmMinDurationSeconds < 0 || policy.ConfirmMinDurationSeconds > policy.ConfirmWindowSeconds || policy.RecoverMinDurationSeconds < 0 || policy.RecoverMinDurationSeconds > policy.RecoverWindowSeconds || policy.MaxSampleGapSeconds < 1 || policy.MaxSampleGapSeconds > 86400 {
		return fmt.Errorf("invalid minimum hold duration, maximum window or sample gap")
	}
	if policy.Severity != domain.HealthSeverityWarning && policy.Severity != domain.HealthSeverityCritical {
		return fmt.Errorf("invalid monitoring fault severity")
	}
	if policy.Rule == RuleTelemetryLoss {
		if policy.ConfirmCount != 1 || policy.ConfirmMinDurationSeconds != 0 || policy.Metric != "" || policy.Unit != "" || policy.OpenThreshold != 0 || policy.RecoverBelow != 0 {
			return fmt.Errorf("telemetry v1 uses one duration deadline and no sensor threshold")
		}
		return nil
	}
	if !validID(policy.Binding.InventoryRevisionID) {
		return fmt.Errorf("physical monitoring requires expected inventory revision")
	}
	identity, valid := domain.ResolveGPUObservationIdentity(policy.ClusterID, policy.SourceID, domain.Observation{ClusterID: policy.ClusterID, SourceID: policy.SourceID, EntityKey: policy.EntityKey})
	if !valid || !identity.Canonical || identity.EntityKey != policy.EntityKey || len(nodes) > 0 && !nodes[identity.NodeID] {
		return fmt.Errorf("physical monitoring requires canonical GPU in exact scope")
	}
	metricAllowed := false
	if policy.Rule == RuleRemapFailure && policy.Metric == "DCGM_FI_DEV_ROW_REMAP_FAILED" {
		return fmt.Errorf("row-remap enrollment requires canonical DCGM_FI_DEV_ROW_REMAP_FAILURE; FAILED is a historical read alias")
	}
	for _, metric := range rule.Metrics {
		metricAllowed = metricAllowed || policy.Metric == metric
	}
	if !metricAllowed || policy.Unit != rule.Unit {
		return fmt.Errorf("metric or unit does not match monitoring rule")
	}
	metricOperation, metricOwned := domain.CollectionOperationForQuery(operation.Query)
	if !metricOwned || metricOperation.ID != policy.Binding.Operation {
		return fmt.Errorf("invalid monitoring operation")
	}
	owned := false
	for _, field := range domain.DCGMFields(operation.Query) {
		owned = owned || field.Name == policy.Metric
	}
	if !owned {
		return fmt.Errorf("sensor belongs to a different collection operation")
	}
	if math.IsNaN(policy.OpenThreshold) || math.IsInf(policy.OpenThreshold, 0) || math.IsNaN(policy.RecoverBelow) || math.IsInf(policy.RecoverBelow, 0) {
		return fmt.Errorf("monitoring thresholds must be finite")
	}
	if policy.Rule == RuleGPUThermal || policy.Rule == RuleHBMThermal {
		if policy.OpenThreshold <= policy.RecoverBelow {
			return fmt.Errorf("thermal policy requires explicit lower recovery hysteresis")
		}
		return nil
	}
	definition, _ := domain.GPUHealthSensor(policy.Metric)
	if policy.OpenThreshold != 1 || policy.RecoverBelow != 0 || policy.Severity != definition.PositiveSeverity {
		return fmt.Errorf("ECC/remap v1 requires explicit positive-state threshold and severity")
	}
	return nil
}

// ValidateEnrollmentRequest checks an immutable semantic request before the
// store assigns its initial revision and database enrollment timestamp.
func ValidateEnrollmentRequest(policy Policy) error {
	if policy.Revision != 0 || !policy.EnrolledAt.IsZero() {
		return fmt.Errorf("enrollment revision and time are server-owned")
	}
	policy.Revision, policy.EnrolledAt = 1, time.Unix(1, 0).UTC()
	return ValidatePolicy(policy)
}
