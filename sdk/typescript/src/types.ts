// Code generated from api/openapi/sherlock-v1.yaml; DO NOT EDIT.
// Sherlock-OpenAPI-SHA256: 13decf32bd524545379fd08fbd86c5cf345d189b996712dce317dfe3f4eba4c3

export type Freshness = "FRESH" | "STALE" | "UNKNOWN";
export type CollectionStatus = "SUCCEEDED" | "NO_DATA" | "PARTIAL" | "FAILED";
export type SourceStatus = "AVAILABLE" | "DEGRADED" | "UNAVAILABLE" | "UNKNOWN";
export type SourceSupport = "SUPPORTED" | "NOT_SUPPORTED" | "UNKNOWN";
export type HealthState = "NORMAL" | "PARTIAL" | "STALE" | "UNAVAILABLE" | "NO_DATA" | "XID" | "ECC" | "THERMAL" | "MEMORY" | "POWER" | "UTILIZATION";
export type HealthSeverity = "UNKNOWN" | "INFO" | "WARNING" | "CRITICAL";
export type EvidenceStatus = "COMPLETE" | "PARTIAL" | "NO_DATA" | "UNAVAILABLE";
export type EventType = "collection_run.updated" | "source.updated";

export interface Coverage {
  requested: number;
  successful: number;
  failed: number;
  complete: boolean;
  series_expected?: number | null;
  series_returned?: number;
  bytes_read?: number;
}

export interface CollectionError {
  code: "SOURCE_UNAVAILABLE" | "DEADLINE_EXCEEDED" | "MALFORMED_RESPONSE" | "RESULT_LIMIT_EXCEEDED" | "UNAUTHORIZED" | "INVALID_ARGUMENT" | "PARTIAL_DATA" | "COLLECTOR_UNAVAILABLE" | "INTERNAL";
  source_id?: string;
  target_id?: string;
  retryable: boolean;
  message?: string;
}

export interface ResponseMeta {
  request_id: string;
  generated_at: string;
  collection_status: CollectionStatus;
  freshness: Freshness;
  coverage: Coverage;
  warnings: string[];
  next_page_token?: string;
}

export interface StateMetadata {
  observed_at: string;
  collected_at: string;
  freshness: Freshness;
  coverage: Coverage;
  collection_status: CollectionStatus;
}

export interface Cluster extends StateMetadata { cluster_id: string; name: string; capabilities: string[] }
export interface Source extends StateMetadata { source_id: string; kind: string; status: SourceStatus; last_success_at?: string | null; last_error?: CollectionError | null; coverage_by_scope?: SourceCoverage[] }
export interface SourceProvenance { source_id: string; source_at: string; effective_at: string; observed_at: string; source_reference?: string; evidence_ids?: string[] }
export interface SourceCoverage { scope: "INVENTORY" | "ALLOCATIONS" | "PROGRESS" | "METRICS" | "EVENTS"; support: SourceSupport; state: "UNKNOWN" | "COMPLETE" | "PARTIAL" | "UNAVAILABLE" | "UNSUPPORTED"; expected: number; observed: number; provenance: SourceProvenance }
export interface Label { name: string; value: string }
export interface Observation extends StateMetadata {
  observation_id: string; schema_version: number; cluster_id: string; source_id: string; kind: string; entity_key: string;
  metric: string; labels: Label[]; value: number; unit: string; source_reference: string; evidence_ids?: string[];
}
export interface HealthSignal {
  schema_version: number; type: HealthState; category: HealthState; severity: HealthSeverity; source_id: string; entity_key: string;
  metric?: string; observed_at: string; projected_at: string; freshness: Freshness; coverage: Coverage; evidence: string[];
  counter_evidence: string[]; reason: string;
}
export interface ClusterCapacityView { condition: string; expected_nodes: number | null; expected_gpus: number | null; observed_nodes: number | null; observed_gpus: number | null; expected_revision_id?: string; observed_revision_id?: string }
export interface ClusterMonitoringView { collector_condition: string; freshness_condition: string; coverage_condition: string; support_condition: string; expected_collectors: number; fresh_collectors: number; fresh_sources: number; stale_sources: number; sources_without_data: number; complete_streams: number; partial_streams: number; no_data_streams: number; unavailable_streams: number; historical_streams: number; expected_operations: number; fresh_operations: number; late_operations: number; failed_operations: number }
export interface ClusterHealthView { schema_version: 1; cluster_id: string; generated_at: string; window_start: string; window_end: string; capacity: ClusterCapacityView; monitoring: ClusterMonitoringView; workload_condition: string; progress_state: "UNKNOWN" | "MEASURED" | "UNMEASURED" | "UNSUPPORTED"; attention: string[] }
export interface HealthSummary extends StateMetadata { cluster_id: string; state: HealthState; severity: HealthSeverity; signals: HealthSignal[]; errors: CollectionError[]; shared?: ClusterHealthView }
export interface GPUMetric { value: number; unit: string; observed_at: string }
export interface GPUSummary extends StateMetadata { gpu_id: string; node_id: string; uuid?: string; model?: string; health: HealthState; severity: HealthSeverity; signals: HealthSignal[]; metrics: Record<string, GPUMetric> }
export interface CollectionRun extends StateMetadata {
  run_id: string; cluster_id: string; source_id: string; query: string; status: CollectionStatus; scheduled_for: string;
  started_at: string; completed_at: string; failures: CollectionError[];
}
export interface EvidenceTarget { kind: "CLUSTER" | "NODE" | "GPU" | "SOURCE"; id: string }
export interface EvidenceCoverage { expected: EvidenceTarget[]; covered: EvidenceTarget[]; complete: boolean }
export interface EvidenceSourceReference { source_id: string; run_id: string; operation: string; definition_version: string; reference: string }
export interface ArtifactReference {
  artifact_id: string; sha256: string; bytes: number; media_type: string; compression: "NONE" | "GZIP" | "ZSTD";
  parser_version: string; redactions: { policy_version: string; match_count: number }; retention_class: "SHORT" | "STANDARD" | "EXTENDED";
  availability: "PENDING" | "AVAILABLE" | "UNAVAILABLE" | "CORRUPT";
}
export interface Evidence {
  evidence_id: string; schema_version: 1; cluster_id: string; status: EvidenceStatus; source: EvidenceSourceReference;
  time_range: { start: string; end: string }; collected_at: string; coverage: EvidenceCoverage; artifact?: ArtifactReference | null; supersedes?: string | null;
}
export interface DiagnosticDefinitionReference { pack_id: string; pack_version: string; definition_id: string; definition_version: string; definition_sha256: string }
export interface DiagnosticArgument { name: string; value: string }
export interface DiagnosticRunRequest { definition: DiagnosticDefinitionReference; targets: string[]; arguments: DiagnosticArgument[]; deadline?: string; max_attempts?: number }
export interface DiagnosticAuthorizationPreview { allowed: boolean; approval_required: boolean; reason_code: string }
export interface DiagnosticTargetResult { target: string; status: "SUCCEEDED" | "FAILED" | "TIMED_OUT" | "REJECTED"; retryable: boolean; exit_code?: number | null; signal?: string; timed_out: boolean; stdout_truncated: boolean; stderr_truncated: boolean; stdout_bytes: number; stderr_bytes: number; stdout_sha256: string; stdout_transformation_state: "UNKNOWN" | "UNMODIFIED" | "TRANSFORMED"; stderr_sha256: string; error_code?: string }
export interface DiagnosticAttempt { attempt: number; runner_id: string; status: "CLAIMED" | "RUNNING" | "SUCCEEDED" | "PARTIAL" | "FAILED" | "EXPIRED"; lease_expires_at: string; plan_sha256?: string; started_at?: string; completed_at?: string; targets: DiagnosticTargetResult[] }
export interface DiagnosticRun { run_id: string; cluster_id: string; definition: DiagnosticDefinitionReference; privilege: "UNPRIVILEGED" | "PRIVILEGED"; status: "AWAITING_APPROVAL" | "QUEUED" | "RUNNING" | "SUCCEEDED" | "PARTIAL" | "FAILED" | "CANCELLED"; requested_by: string; requested_at: string; deadline: string; completed_at?: string; version: number; work_id?: string; attempts: DiagnosticAttempt[] }
export type IncidentSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "MONITORING" | "RESOLVED" | "CLOSED";
export type InvestigationStatus = "INITIALIZING" | "PLANNING" | "POLICY_CHECK" | "AWAITING_APPROVAL" | "EXECUTING" | "AWAITING_EVIDENCE" | "RECORDING_EVIDENCE" | "UPDATING_LEDGER" | "SYNTHESIZING" | "COMPLETED" | "PARTIAL" | "BLOCKED" | "CANCELLED";
export interface CreateIncidentRequest { title: string; summary: string; severity: IncidentSeverity; target_ids: string[]; evidence_ids: string[] }
export interface Incident { incident_id: string; cluster_id: string; title: string; summary: string; severity: IncidentSeverity; status: IncidentStatus; target_ids: string[]; evidence_ids: string[]; created_by: string; created_at: string; updated_at: string; version: number; investigation_ids: string[] }
export interface IncidentListResponse { data: Incident[]; next_page_token?: string }
export interface InvestigationBudget { max_decisions: number; max_tool_calls: number; max_diagnostic_calls?: number; max_privileged_calls: number; max_fan_out: number; max_model_tokens: number; max_cost_micros: number; decisions_used: number; tool_calls_used: number; diagnostic_calls_used?: number; privileged_calls_used: number; fan_out_used: number; model_tokens_used: number; cost_micros_used: number }
export interface InvestigationScope { entity_kind: string; entity_ids: string[]; start: string; end: string }
export interface StartInvestigationRequest { cluster_id: string; incident_id: string; question: string; scope: InvestigationScope; success_criteria: string[]; budget: InvestigationBudget; deadline: string }
export interface InvestigationAction { action_id: string; tool_id: string; action_sha256: string; privileged: boolean; fan_out: number }
export interface Investigation { investigation_id: string; cluster_id: string; incident_id: string; question: string; scope: InvestigationScope; success_criteria: string[]; status: InvestigationStatus; stop_reason?: string; budget: InvestigationBudget; pending_action?: InvestigationAction; finding_ids: string[]; created_by: string; created_at: string; deadline: string; updated_at: string; completed_at?: string; version: number }
export interface CancelInvestigationRequest { expected_version: number; reason: string }
export interface ApproveInvestigationRequest { approval_id: string; action_id: string; action_sha256: string; expected_version: number; expires_at: string }
export interface InvestigationEvent { event_id: string; schema_version: 1; investigation_id: string; cluster_id: string; sequence: number; type: "CREATED" | "STATE_CHANGED" | "BUDGET_CONSUMED" | "APPROVAL_GRANTED" | "EVIDENCE_ADDED" | "HYPOTHESIS_UPDATED" | "FINDING_ADDED"; from_status?: InvestigationStatus; to_status?: InvestigationStatus; occurred_at: string; attributes?: Record<string, unknown> }
export interface InvestigationEvidence { investigation_id: string; evidence_id: string; cluster_id: string; entity_ids: string[]; recorded_at: string }
export interface Hypothesis { hypothesis_id: string; investigation_id: string; statement: string; status: "PROPOSED" | "SUPPORTED" | "WEAKENED" | "REFUTED" | "UNRESOLVED"; confidence: number; supporting_evidence_ids: string[]; counter_evidence_ids: string[]; unresolved_tests: string[]; version: number }
export interface Finding { finding_id: string; investigation_id: string; kind: "OBSERVATION" | "DERIVED_SIGNAL" | "HYPOTHESIS" | "RECOMMENDATION"; statement: string; entity_ids: string[]; severity: string; confidence?: number; evidence_ids: string[]; counter_evidence_ids: string[]; status: "CURRENT" | "SUPERSEDED"; validation_status: "VALID" | "INVALID"; validation_errors: string[] }
export interface InvestigationEventListResponse { data: InvestigationEvent[] }
export interface InvestigationEvidenceListResponse { data: InvestigationEvidence[] }
export interface HypothesisListResponse { data: Hypothesis[] }
export interface FindingListResponse { data: Finding[] }
export interface ListResponse<T> { data: T[]; meta: ResponseMeta; errors: CollectionError[] }
export type ClusterListResponse = ListResponse<Cluster>;
export type SourceListResponse = ListResponse<Source>;
export type ObservationListResponse = ListResponse<Observation>;
export type GPUSummaryListResponse = ListResponse<GPUSummary>;
export type CollectionRunListResponse = ListResponse<CollectionRun>;
export type EvidenceListResponse = ListResponse<Evidence>;
export interface Problem { type: string; title: string; status: number; code: string; detail: string; request_id: string; violations?: Array<{ field: string; reason: string }> }
export interface CollectionRunEvent { schema_version: 1; cluster_id: string; occurred_at: string; run_id: string; status: CollectionStatus }
export interface SourceEvent { schema_version: 1; cluster_id: string; occurred_at: string; source_id: string; status: SourceStatus; freshness: Freshness }
export interface SherlockEvent { id: string; type: EventType; data: CollectionRunEvent | SourceEvent }
