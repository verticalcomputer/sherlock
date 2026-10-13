import assert from "node:assert/strict";
import { SherlockAPIError, SherlockClient } from "../../sdk/typescript/dist/index.js";

const requests = [];
const mockFetch = async (input, init = {}) => {
  const request = new Request(input, init);
  requests.push(request);
  if (request.url.includes("/investigations")) {
    return Response.json({ investigation_id: "investigation-1", cluster_id: "cluster-1", incident_id: "incident-1", question: "explain XID", scope: { entity_kind: "NODE", entity_ids: ["comp001"], start: "2026-08-20T11:00:00Z", end: "2026-08-20T12:00:00Z" }, success_criteria: ["identify cause"], status: "PLANNING", budget: { max_decisions: 5, max_tool_calls: 10, max_privileged_calls: 1, max_fan_out: 2, max_model_tokens: 0, max_cost_micros: 0, decisions_used: 0, tool_calls_used: 0, privileged_calls_used: 0, fan_out_used: 0, model_tokens_used: 0, cost_micros_used: 0 }, finding_ids: [], created_by: "key-1", created_at: "2026-08-20T12:00:00Z", deadline: "2026-08-20T13:00:00Z", updated_at: "2026-08-20T12:00:00Z", version: 2 });
  }
  if (request.url.includes("/events")) {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('id: evt_42\nevent: source.updated\ndata: {"schema_version":1,"cluster_id":"cluster-1","occurred_at":"2026-08-19T12:00:00Z","source_id":"prometheus","status":"DEGRADED","freshness":"STALE"}\n\n'));
        controller.close();
      },
    });
    return new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } });
  }
  if (request.url.includes("cluster-denied")) {
    return Response.json({ type: "https://sherlock.dev/problems/forbidden", title: "Forbidden", status: 403, code: "CLUSTER_SCOPE_DENIED", detail: "wrong cluster", request_id: "req_2" }, { status: 403, headers: { "Content-Type": "application/problem+json" } });
  }
  if (request.url.includes("/diagnostic-runs")) {
    return Response.json({ run_id: "run-1", cluster_id: "cluster-1", definition: { pack_id: "base", pack_version: "2.0.0", definition_id: "gpu-query", definition_version: "1.3.0", definition_sha256: "a".repeat(64) }, privilege: "UNPRIVILEGED", status: "QUEUED", requested_by: "key-1", requested_at: "2026-08-20T12:00:00Z", deadline: "2026-08-20T12:10:00Z", version: 1, attempts: [] });
  }
  return Response.json({
    data: [{ source_id: "prometheus", kind: "PROMETHEUS", status: "DEGRADED", observed_at: "2026-08-19T12:00:00Z", collected_at: "2026-08-19T12:00:04Z", freshness: "STALE", coverage: { requested: 80, successful: 78, failed: 2, complete: false }, collection_status: "PARTIAL" }],
    meta: { request_id: "req_1", generated_at: "2026-08-19T12:00:05Z", collection_status: "PARTIAL", freshness: "STALE", coverage: { requested: 80, successful: 78, failed: 2, complete: false }, warnings: [], next_page_token: "next" },
    errors: [{ code: "PARTIAL_DATA", retryable: true }],
  });
};

const client = new SherlockClient({ baseUrl: "https://sherlock.test/api/v1", apiKey: "shk_test", fetch: mockFetch });
const sources = await client.listSources("cluster-1", { pageSize: 25, pageToken: "opaque", status: "DEGRADED" });
assert.equal(sources.meta.collection_status, "PARTIAL");
assert.equal(sources.meta.coverage.complete, false);
assert.equal(sources.meta.next_page_token, "next");
assert.equal(requests[0].headers.get("Authorization"), "Bearer shk_test");
assert.match(requests[0].url, /page_size=25/);

const events = [];
for await (const event of client.streamEvents("cluster-1", { lastEventId: "evt_41", eventTypes: ["source.updated"] })) events.push(event);
assert.equal(events[0].id, "evt_42");
assert.equal(events[0].data.freshness, "STALE");
assert.equal(requests[1].headers.get("Last-Event-ID"), "evt_41");

const diagnostic = await client.startDiagnosticRun("cluster-1", "request-1", { definition: { pack_id: "base", pack_version: "2.0.0", definition_id: "gpu-query", definition_version: "1.3.0", definition_sha256: "a".repeat(64) }, targets: ["comp001"], arguments: [], deadline: "2026-08-20T12:10:00Z" });
assert.equal(diagnostic.status, "QUEUED");
assert.equal(requests[2].method, "POST");
assert.equal(requests[2].headers.get("Idempotency-Key"), "request-1");

const investigation = await client.startInvestigation("investigate-1", { cluster_id: "cluster-1", incident_id: "incident-1", question: "explain XID", scope: { entity_kind: "NODE", entity_ids: ["comp001"], start: "2026-08-20T11:00:00Z", end: "2026-08-20T12:00:00Z" }, success_criteria: ["identify cause"], budget: { max_decisions: 5, max_tool_calls: 10, max_privileged_calls: 1, max_fan_out: 2, max_model_tokens: 0, max_cost_micros: 0, decisions_used: 0, tool_calls_used: 0, privileged_calls_used: 0, fan_out_used: 0, model_tokens_used: 0, cost_micros_used: 0 }, deadline: "2026-08-20T13:00:00Z" });
assert.equal(investigation.status, "PLANNING");
assert.equal(requests[3].url, "https://sherlock.test/api/v1/investigations");
assert.equal(requests[3].headers.get("Idempotency-Key"), "investigate-1");
await client.approveInvestigationAction("investigation-1", { approval_id: "approval-1", action_id: "action-1", action_sha256: "a".repeat(64), expected_version: 1, expires_at: "2026-08-20T12:10:00Z" });
assert.match(requests[4].url, /investigations\/investigation-1\/approvals$/);

await assert.rejects(client.getHealth("cluster-denied"), (error) => error instanceof SherlockAPIError && error.problem.code === "CLUSTER_SCOPE_DENIED");
