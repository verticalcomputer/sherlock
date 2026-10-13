// Code generated from api/openapi/sherlock-v1.yaml; DO NOT EDIT.
// Sherlock-OpenAPI-SHA256: 13decf32bd524545379fd08fbd86c5cf345d189b996712dce317dfe3f4eba4c3

import type {
  Cluster, ClusterListResponse, CollectionRunListResponse, CollectionStatus, Evidence, EvidenceListResponse, EvidenceStatus,
  DiagnosticAuthorizationPreview, DiagnosticRun, DiagnosticRunRequest,
  ApproveInvestigationRequest, CancelInvestigationRequest, CreateIncidentRequest, FindingListResponse, HypothesisListResponse,
  Incident, IncidentListResponse, IncidentSeverity, IncidentStatus, Investigation, InvestigationEvidenceListResponse,
  InvestigationEventListResponse, StartInvestigationRequest,
  EventType, GPUSummaryListResponse, HealthState, HealthSummary, ObservationListResponse, Problem, SherlockEvent,
  SourceListResponse, SourceStatus,
} from "./types.js";

export interface ListOptions { pageSize?: number; pageToken?: string }
export interface ObservationListOptions extends ListOptions {
  sourceId?: string; entityKey?: string; kind?: string; metric?: string; observedAfter?: string; observedBefore?: string;
}
export interface StreamOptions { lastEventId?: string; eventTypes?: EventType[]; signal?: AbortSignal }
export interface SherlockClientOptions { baseUrl: string; apiKey: string; fetch?: typeof globalThis.fetch }

export class SherlockAPIError extends Error {
  constructor(readonly problem: Problem, readonly response: Response) {
    super(`Sherlock API: ${problem.status} ${problem.code}: ${problem.detail}`);
    this.name = "SherlockAPIError";
  }
}

export class SherlockClient {
  readonly #baseUrl: string;
  readonly #apiKey: string;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: SherlockClientOptions) {
    const parsed = new URL(options.baseUrl);
    if (!parsed.protocol.startsWith("http")) throw new TypeError("baseUrl must use HTTP or HTTPS");
    if (!options.apiKey) throw new TypeError("apiKey is required");
    this.#baseUrl = options.baseUrl.replace(/\/$/, "");
    this.#apiKey = options.apiKey;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  listClusters(options: ListOptions = {}): Promise<ClusterListResponse> { return this.#get("/clusters", listQuery(options)) }
  getCluster(clusterId: string): Promise<Cluster> { return this.#get(clusterPath(clusterId)) }
  getHealth(clusterId: string): Promise<HealthSummary> { return this.#get(`${clusterPath(clusterId)}/health`) }
  listSources(clusterId: string, options: ListOptions & { status?: SourceStatus } = {}): Promise<SourceListResponse> {
    return this.#get(`${clusterPath(clusterId)}/sources`, listQuery(options, { status: options.status }));
  }
  listObservations(clusterId: string, options: ObservationListOptions = {}): Promise<ObservationListResponse> {
    return this.#get(`${clusterPath(clusterId)}/observations`, listQuery(options, {
      source_id: options.sourceId, entity_key: options.entityKey, kind: options.kind, metric: options.metric,
      observed_after: options.observedAfter, observed_before: options.observedBefore,
    }));
  }
  listGPUSummaries(clusterId: string, options: ListOptions & { nodeId?: string; health?: HealthState } = {}): Promise<GPUSummaryListResponse> {
    return this.#get(`${clusterPath(clusterId)}/gpus`, listQuery(options, { node_id: options.nodeId, health: options.health }));
  }
  listCollectionRuns(clusterId: string, options: ListOptions & { sourceId?: string; status?: CollectionStatus } = {}): Promise<CollectionRunListResponse> {
    return this.#get(`${clusterPath(clusterId)}/collection-runs`, listQuery(options, { source_id: options.sourceId, status: options.status }));
  }
  listEvidence(clusterId: string, options: ListOptions & { status?: EvidenceStatus; targetId?: string } = {}): Promise<EvidenceListResponse> {
    return this.#get(`${clusterPath(clusterId)}/evidence`, listQuery(options, { status: options.status, target_id: options.targetId }));
  }
  getEvidence(clusterId: string, evidenceId: string): Promise<Evidence> {
    if (!evidenceId) throw new TypeError("evidenceId is required");
    return this.#get(`${clusterPath(clusterId)}/evidence/${encodeURIComponent(evidenceId)}`);
  }
  previewDiagnosticRun(clusterId: string, input: DiagnosticRunRequest): Promise<DiagnosticAuthorizationPreview> {
    return this.#post(`${clusterPath(clusterId)}/diagnostic-runs/preview`, input);
  }
  startDiagnosticRun(clusterId: string, idempotencyKey: string, input: DiagnosticRunRequest): Promise<DiagnosticRun> {
    if (!idempotencyKey) throw new TypeError("idempotencyKey is required");
    return this.#post(`${clusterPath(clusterId)}/diagnostic-runs`, input, idempotencyKey);
  }
  getDiagnosticRun(clusterId: string, runId: string): Promise<DiagnosticRun> {
    if (!runId) throw new TypeError("runId is required");
    return this.#get(`${clusterPath(clusterId)}/diagnostic-runs/${encodeURIComponent(runId)}`);
  }
  approveDiagnosticRun(clusterId: string, runId: string, expiresAt: string): Promise<DiagnosticRun> {
    if (!runId) throw new TypeError("runId is required");
    return this.#post(`${clusterPath(clusterId)}/diagnostic-runs/${encodeURIComponent(runId)}/approval`, { expires_at: expiresAt });
  }
  createIncident(clusterId: string, idempotencyKey: string, input: CreateIncidentRequest): Promise<Incident> {
    if (!idempotencyKey) throw new TypeError("idempotencyKey is required");
    return this.#post(`${clusterPath(clusterId)}/incidents`, input, idempotencyKey);
  }
  listIncidents(clusterId: string, options: ListOptions & { status?: IncidentStatus; severity?: IncidentSeverity } = {}): Promise<IncidentListResponse> {
    return this.#get(`${clusterPath(clusterId)}/incidents`, listQuery(options, { status: options.status, severity: options.severity }));
  }
  getIncident(incidentId: string): Promise<Incident> {
    if (!incidentId) throw new TypeError("incidentId is required");
    return this.#get(`/incidents/${encodeURIComponent(incidentId)}`);
  }
  startInvestigation(idempotencyKey: string, input: StartInvestigationRequest): Promise<Investigation> {
    if (!idempotencyKey) throw new TypeError("idempotencyKey is required");
    return this.#post("/investigations", input, idempotencyKey);
  }
  getInvestigation(investigationId: string): Promise<Investigation> { return this.#get(investigationPath(investigationId)) }
  cancelInvestigation(investigationId: string, input: CancelInvestigationRequest): Promise<Investigation> { return this.#post(`${investigationPath(investigationId)}/cancel`, input) }
  approveInvestigationAction(investigationId: string, input: ApproveInvestigationRequest): Promise<Investigation> { return this.#post(`${investigationPath(investigationId)}/approvals`, input) }
  listInvestigationEvents(investigationId: string, options: { lastEventId?: string; limit?: number } = {}): Promise<InvestigationEventListResponse> {
    const query = new URLSearchParams(); if (options.limit !== undefined) query.set("limit", String(options.limit));
    return this.#get(`${investigationPath(investigationId)}/events`, query, options.lastEventId);
  }
  listInvestigationEvidence(investigationId: string): Promise<InvestigationEvidenceListResponse> { return this.#get(`${investigationPath(investigationId)}/evidence`) }
  listInvestigationHypotheses(investigationId: string): Promise<HypothesisListResponse> { return this.#get(`${investigationPath(investigationId)}/hypotheses`) }
  listInvestigationFindings(investigationId: string): Promise<FindingListResponse> { return this.#get(`${investigationPath(investigationId)}/findings`) }

  async *streamEvents(clusterId: string, options: StreamOptions = {}): AsyncGenerator<SherlockEvent> {
    const query = new URLSearchParams();
    for (const eventType of options.eventTypes ?? []) query.append("event_type", eventType);
    const init: RequestInit = { headers: this.#headers("text/event-stream", options.lastEventId) };
    if (options.signal) init.signal = options.signal;
    const response = await this.#fetch(this.#url(`${clusterPath(clusterId)}/events`, query), init);
    if (!response.ok) throw await apiError(response);
    if (!response.body) throw new Error("Sherlock SSE response has no body");
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
    let pending = "";
    try {
      while (true) {
        const { value = "", done } = await reader.read();
        pending += value.replace(/\r\n/g, "\n");
        let boundary: number;
        while ((boundary = pending.indexOf("\n\n")) >= 0) {
          const frame = pending.slice(0, boundary); pending = pending.slice(boundary + 2);
          const event = parseEvent(frame); if (event) yield event;
        }
        if (done) break;
      }
    } finally { reader.releaseLock() }
  }

  async #get<T>(path: string, query = new URLSearchParams(), lastEventId?: string): Promise<T> {
    const response = await this.#fetch(this.#url(path, query), { headers: this.#headers("application/json", lastEventId) });
    if (!response.ok) throw await apiError(response);
    return response.json() as Promise<T>;
  }
  async #post<T>(path: string, body: unknown, idempotencyKey?: string): Promise<T> {
    const headers = this.#headers("application/json"); headers.set("Content-Type", "application/json");
    if (idempotencyKey) headers.set("Idempotency-Key", idempotencyKey);
    const response = await this.#fetch(this.#url(path, new URLSearchParams()), { method: "POST", headers, body: JSON.stringify(body) });
    if (!response.ok) throw await apiError(response);
    return response.json() as Promise<T>;
  }
  #url(path: string, query: URLSearchParams): string { const suffix = query.size ? `?${query}` : ""; return `${this.#baseUrl}${path}${suffix}` }
  #headers(accept: string, lastEventId?: string): Headers {
    const headers = new Headers({ Accept: accept, Authorization: `Bearer ${this.#apiKey}` });
    if (lastEventId) headers.set("Last-Event-ID", lastEventId); return headers;
  }
}

function clusterPath(clusterId: string): string { if (!clusterId) throw new TypeError("clusterId is required"); return `/clusters/${encodeURIComponent(clusterId)}` }
function investigationPath(investigationId: string): string { if (!investigationId) throw new TypeError("investigationId is required"); return `/investigations/${encodeURIComponent(investigationId)}` }
function listQuery(options: ListOptions, fields: Record<string, string | undefined> = {}): URLSearchParams {
  const query = new URLSearchParams();
  if (options.pageSize !== undefined) query.set("page_size", String(options.pageSize));
  if (options.pageToken) query.set("page_token", options.pageToken);
  for (const [key, value] of Object.entries(fields)) if (value !== undefined && value !== "") query.set(key, value);
  return query;
}
async function apiError(response: Response): Promise<SherlockAPIError> {
  let problem: Problem;
  try { problem = await response.json() as Problem } catch { problem = { type: "about:blank", title: response.statusText, status: response.status, code: "HTTP_ERROR", detail: response.statusText, request_id: "" } }
  if (!problem.status) problem.status = response.status;
  return new SherlockAPIError(problem, response);
}
function parseEvent(frame: string): SherlockEvent | undefined {
  let id = "", type: EventType | undefined; const data: string[] = [];
  for (const line of frame.split("\n")) {
    if (!line || line.startsWith(":")) continue;
    const colon = line.indexOf(":"); const field = colon < 0 ? line : line.slice(0, colon); let value = colon < 0 ? "" : line.slice(colon + 1); if (value.startsWith(" ")) value = value.slice(1);
    if (field === "id") id = value; else if (field === "event") type = value as EventType; else if (field === "data") data.push(value);
  }
  if (!type || data.length === 0) return undefined;
  return { id, type, data: JSON.parse(data.join("\n")) } as SherlockEvent;
}
