# Mesta-Ares service map

Bounded contexts, contracts, failure semantics. Keep this file updated when a
service or contract changes — it is the consumer-facing view.

## Contexts and ownership

| Service | Port | Owns | Depends on (sync) | Events (async, NATS `ares.*`) |
|---|---|---|---|---|
| ingestion-gateway | 8091 | Envelope normalization, JetStream publish | — | pub `ares.alerts` |
| orchestrator | — | Routing, dedupe (`seen_alerts`), DLQ | postgres | `ares.*` → `ares.triage|respond|detection|hunt`, `ares.dlq` |
| triage-agent | — | Enrichment fan-out, verdicts | llm, enrichment providers, tool-server (`thehive.case.create`), opensearch | sub `ares.triage`, pub `ares.respond`, `ares.activity` |
| response-agent | — | Plan build + execution record (`response_actions`) | tool-server, thehive, wazuh | sub `ares.respond`, pub `ares.activity` |
| tool-server | 8090 | Policy gate + all side-effect executors | policy files, postgres audit_log, cortex/misp/shuffle/wazuh/entra | — |
| api-gateway | 8082 | Edge routing (`/api`, `/ingest`, `/tools`), API-key auth, rate limits, GET cache, metrics, `/aggregate/dashboard` | api-server, ingestion-gateway, tool-server, policy files | — |
| detection-agent | — | Sigma draft→pending→active, monitor deploy | llm, opensearch, sigma CLI | sub `ares.detection`, pub `ares.activity` |
| hunt-agent | — | Scheduled hunts, findings | opensearch, tool-server (`thehive.case.create`) | sub `ares.hunt`, pub `ares.activity` |
| api-server | 8080 | Read model + control API for console, A2A (`a2a_tasks`) and ACP (`acp_runs`) protocol endpoints | opensearch, postgres, thehive | sub `ares.activity` (SSE relay), pub `ares.triage|respond|detection|hunt` (A2A tasks, ACP runs) |
| vuln-agent | — | NVD/KEV watchlist poll, advisories (`vuln_advisories`), TheHive cases via tool-server | nvd, postgres, tool-server | pub `ares.vulns`, `ares.activity` |
| bas-runner | — | Scenario exec, MTTD/MTTR (`bas_results`) | opensearch, postgres | pub `ares.bas`, `ares.detection` |

Shared Postgres is split per service by table ownership. Each owner creates
its own tables at boot (`CREATE TABLE IF NOT EXISTS`) from its binary:
`seen_alerts`→orchestrator, `response_actions`→response-agent,
`bas_results`→bas-runner, `a2a_tasks`/`agent_checkpoints`→api-server,
`acp_runs`→api-server, `audit_log`→tool-server (`audit::ensure_schema`),
`vuln_advisories`→vuln-agent, `idempotency`→tool-server.
No service reads another's table except audit_log (api-server read-model only)
and `agent_checkpoints` (api-server folds it into task/run status).

## HTTP contracts

- `POST tool-server:8090/invoke` — body `ToolCall`; **always HTTP 200**, verdict
  is `InvokeResponse{decision:{kind:allow|deny|approval_required,reason},result:ToolResult}`.
  Idempotent via `idempotency_key` (case_id+tool+sha256(args)); cached replays return the first result.
- `GET tool-server:8090/tools` — effective allowlist (from `policies/tools.yml`).
- `GET|POST tool-server:8090/approvals…` — calls parked by `autonomy: approval`.
  Statuses: `pending → approved` (approved *and* executed), `execution_failed`
  (approved but the tool failed; `result.error` says why), `rejected`, `expired`.
  Approve re-runs policy with the **live** kill switch (read at decision time,
  not the cached value from `/invoke`); a denial — e.g. the switch is engaged —
  lands in `execution_failed` and the stored call is not executed.
- `GET api-server:8080/…` — `/health /alerts /alerts/:id /cases /cases/:id /audit /metrics /coverage /plans/:case_id`.
- `POST /controls/kill-switch` — engages/disengages `$POLICIES_DIR/kill`; `GET` reads state. Fail-closed reads.
- `GET /stream/activity` — SSE, event `{workflow_run_id, agent, step, detail, ts}`.
- A2A interop: `GET /.well-known/agent.json` (platform card), `GET /a2a/agents`, `GET /a2a/{agent}/.well-known/agent.json`, `POST /a2a/{agent}` (JSON-RPC `tasks/send|get|cancel|sendSubscribe`), `GET /a2a/tasks/{id}/events` (per-task SSE). Agents: `triage-agent`, `response-agent`, `detection-agent`, `hunt-agent`. Task → `Envelope` (source `a2a:<task_id>`, correlation_id = task UUID) published on the agent's subject.
- `POST ingestion-gateway:8091/webhook/wazuh` — Wazuh integratord JSON → `Envelope`. `202 Accepted` on publish, `502` if the publish fails (caller retries; integratord does not, so monitor this).
- `GET|POST api-gateway:8082/…` — single entry point: `/api/*`→api-server, `/ingest/*`→ingestion-gateway, `/tools/*`→tool-server (prefix stripped, method/headers/body forwarded, response streamed). Auth: `Authorization: Bearer <key>` or `X-API-Key` against `GATEWAY_API_KEYS`; `/health` and `/metrics` exempt; empty key list fails closed unless `GATEWAY_ALLOW_ANONYMOUS=1`. `GET /aggregate/dashboard` fans in metrics + alerts + advisories. `GET /metrics` is Prometheus text (`ares_gateway_requests_total{route,status}`, latency sums, cache hits). GETs under `GATEWAY_CACHE_PREFIXES` are cached for `GATEWAY_CACHE_TTL_SECONDS` and answer `x-gateway-cache: hit|miss`.

Errors: JSON `{"error": {"code", "message", "details"?}}` from every service
(`http_limits::error::ApiError`); 4xx = caller fixable, 5xx = retryable. ACP
routes keep their spec-mandated `{code, message, data}` body. All handlers set
explicit timeouts (see table).

## Resilience table

| Dependency | Timeout | Retry | Fallback |
|---|---|---|---|
| LLM provider (triage) | 30s | 1 retry, jitter | verdict `suspicious` + `enrichment_partial` flag |
| LLM provider (response/detection) | 120s | 1 retry | hold plan, retry next delivery |
| Enrichment provider (VT/Shodan/AbuseIPDB/GreyNoise/MISP) | 8s each | none | provider skipped, `raw` notes failure |
| Redis cache | 1s | none | bypass cache, enrich direct |
| NATS publish | 5s | 3 attempts | ingress returns 503 (drop only on `ares.dlq` after 3 deliveries) |
| tool-server `/invoke` (agent side) | 15s | 3 retries, full jitter (agent-core `HttpToolGateway`) | plan step recorded `error`; plan stops |
| Postgres | 10s | connect retry loop at boot | service exits (restart) |
| OpenSearch | 10s | 2 on 429/5xx | skip backtest/hunt cycle |
| TheHive/Cortex/Wazuh/Shuffle executors | 15s | none (idempotency at tool layer) | `ToolResult.ok=false` + audit |
| OpenShell CLI/gateway (exec.sandbox, exec.bas.run) | 30s (kill on expiry) | none | fail closed — exec tools return `sandbox unavailable`; non-exec tools unaffected |

Circuit breakers: blast-radius caps in policy-engine act as action-class
breakers (trip on rate anomaly); a global `policies/kill` file is the
system-level breaker. Per-provider breakers: not implemented — first signal
for adding is sustained provider 5xx.

## Consistency

- **Idempotent consumers**: orchestrator dedupe (`seen_alerts`, 24h key);
  tool-server `idempotency_key` → NATS redelivery is always safe.
- **Compensation**: reversible actions store `rollback_json` in
  `response_actions`; a `rollback` tool call inverts it (isolate→unisolate,
  block→unblock). No saga coordinator — response-agent owns plan-level
  compensation linearly.
- **Outbox**: not used; audit_log is written inside tool-server's invoke path
  before execution, so a crash mid-action leaves a decided-but-unexecuted
  audit row — acceptable (audit is the forensics record, replay by NATS
  redelivery).

## Graceful shutdown / health

Every binary: `tracing` init, `/health` where HTTP, SIGTERM → stop consuming,
finish in-flight envelope (agent loop checkpoints to Postgres so restart
resumes, not restarts).

## Observability

`workflow_run_id` = `Envelope.correlation_id`, carried through NATS subjects,
agent spans, audit rows, and `ares.activity` SSE. Metrics surface: `/metrics`
(alerts/hr, verdict mix, MTTD/MTTR from `bas_results`), audit deny-spike is a
SIEM alert itself.

## Rate limits

Per-key token buckets on the edge services (`crates/http-limits`).
**Key = authenticated actor** when a valid key is presented, else a hash of
the presented token, else peer IP (`ConnectInfo`). Numbers load from
`policies/rate-limits.yml` (defaults
below when the file is absent); metering is request count, burst = bucket
capacity, sustained = refill rate.

| Surface | Tier | Sustained | Burst | Notes |
|---|---|---|---|---|
| api-server general reads | `general` | 60 req/s | 120 | all routes not listed below |
| `POST /cvss/score`, `POST /a2a/{agent}` (JSON-RPC), `POST /acp/runs` | `expensive` | 10 req/s | 20 | LLM/expensive |
| `POST /controls/kill-switch` | `kill_switch` | 1 req/s | 5 | tight but never fully closed — safety endpoint stays reachable |
| `GET /stream/activity`, `GET /a2a/tasks/{id}/events`, `GET /acp/runs/{id}/events` | `stream` | — | — | exempt from request counting; capped at **20 concurrent connections/key** |
| ingestion-gateway `POST /webhook/{wazuh,generic}` | `ingest` | 100 req/s | 500 | Wazuh alert storms |
| `GET /health` (both services) | — | — | — | exempt, unmetered |

Every metered response carries `x-ratelimit-limit` (burst capacity, or the
concurrency cap for streams), `x-ratelimit-remaining`, and
`x-ratelimit-reset` (**epoch seconds** when the bucket refills; "now" for
streams, which have no refill schedule). Rejection is **429** +
`Retry-After: <seconds>` (delay-seconds form) + JSON
`{"error":"rate_limit_exceeded","retry_after":N}` — no 200-throttled
responses. A 429 costs no token against the tier that rejected it.

Limits are operational hints, not SLAs; we reserve the right to tighten
them without notice, and they are per-instance (each replica counts
independently).

## API Security Assessment

OWASP API Security Top 10 (2023), static review of `api-server` (:8080),
`ingestion-gateway` (:8091) and `tool-server` (:8090). **Authn now exists**:
every route except `/health` requires `ARES_API_KEYS`
(`key:actor[:role],...`, `Authorization: Bearer` or `X-API-Key`) and the
authenticated actor is what policy and audit see. Empty key set still runs
open (dev) unless `ARES_REQUIRE_AUTH=1` refuses the boot; role `approver`
is required for `/approvals/*` decisions and self-approval is denied.
Probe script: `scripts/api-security-check.sh`.

| # | Category | Verdict | Detail |
|---|---|---|---|
| API1 | Broken Object Level Authorization | PARTIAL | Authn landed, but there is no per-actor object scoping: any valid key reads `/alerts/{id}`, `/cases/{id}`, `/plans/{case_id}`, `/audit`, any task. Single-tenant assumption — revisit if a `viewer` role ever ships. |
| API2 | Broken Authentication | RESOLVED (default caveat) | `require_auth` on all edge routes; keys are server-side lookups, never body-claimed. Caveats: fail-open when `ARES_API_KEYS` is unset (set `ARES_REQUIRE_AUTH=1`), keys <32 chars rejected under that flag, rotation = secret edit + restart. |
| API3 | Broken Object Property Level Authorization | VULNERABLE | `SendParams` accepts arbitrary `parts`, `metadata`, `sessionId` (a2a `task.rs:196-208`) → `build_payload` → `Envelope` → agent LLM context and, for response-agent, the planner `goal` (`a2a.rs:366-384`); no property-level validation beyond serde shape. `/webhook/generic` accepts arbitrary JSON incl. attacker-chosen `source` (`ingestion-gateway/main.rs:79-89`). |
| API4 | Unrestricted Resource Consumption | PARTIAL | Router-level token buckets are in place on both edge services (see *Rate limits*); what remains is the 2 MiB `DefaultBodyLimit` body cap, unbounded SSE fan-out per key (capped at 20 concurrent), and per-request filesystem scans in `/playbooks` + `/coverage`. `/vulns*` serialize on the ≥6 s NVD client mutex (`connectors/lib.rs:695-740`) → trivial connection-queue exhaustion; NVD fetches `resultsPerPage=2000` (`lib.rs:773`); `/playbooks` + `/coverage` rescan/parse the filesystem per request; SSE streams are unbounded per client. |
| API5 | Broken Function Level Authorization | PARTIAL | All mutating routes now require a valid key; `/approvals/*` decisions additionally require the `approver` role + non-requester identity. Remaining: no per-function role tiers beyond approvals (kill-switch is any-operator). |
| API6 | Unrestricted Access to Sensitive Business Flows | PARTIAL | Webhooks now require a key; a valid key can still flood triage with junk alerts (LLM cost) — per-key rate limits bound it but there's no per-source quota yet (tracked as threat-model T-12). |
| API7 | Server-Side Request Forgery | VULNERABLE (limited) | Connector base URLs are env-pinned — no arbitrary-origin SSRF found. But tool args steer internal requests: `opensearch.query` takes caller `index` + Lucene `q` + DSL `body` with no schema (`executors/mod.rs:88-99` — read any index); `thehive.case.update` joins raw `case_id` into the URL path (`connectors/lib.rs:182-191`). Reachable unauthenticated via `:8090/invoke`. |
| API8 | Security Misconfiguration | PARTIAL | CORS is now restrictive-by-default (`CORS_ALLOW_ORIGIN` opt-in; the console is same-origin through its BFF proxy). Remaining: permissive compose secrets (`WAZUH_API_PASS:-`, `postgres ares/ares` dev default, MISP admin default), no security headers, tool-server `:8090` still host-published in compose, upstream/DB error strings echoed in bodies. |
| API9 | Improper Inventory Management | PARTIAL | Route inventory is now documented in *HTTP contracts* (including `/playbooks*`, `/vulns*`, `/cvss/score`, `/acp/*`, `/webhook/generic`); remaining drift: console calls a nonexistent `POST /hunt` (`apps/console/lib/api.ts:373`). The `503`-vs-`502` drift is resolved (code returns `502`, doc now agrees) and the HTTP surface is specified in `docs/openapi/`. |
| API10 | Unsafe Consumption of APIs | VULNERABLE | Attacker-controlled JSON (webhook payloads, A2A `message`) flows verbatim into LLM prompts — triage context (`triage-agent/main.rs:297-304`) and response planner (`response-agent/main.rs:247-248`) — so prompt injection becomes planned tool calls; `exec.sandbox` permits `bash -c` and `FORBIDDEN_SUBSTRINGS` misses `\n`, `>`, `&`, `<(` (`executors/openshell.rs:50-55,92-96`); `/stream/activity` relays raw NATS payloads to browsers (`stream.rs:48-68`). |

### Findings (ordered)

1. ~~**Unauthenticated end-to-end command path.**~~ **Resolved:** every edge
   route except `/health` requires `ARES_API_KEYS`; agents call tool-server
   with `ARES_TOOL_KEY`; the gateway strips client credentials and injects
   its own service key upstream. Remaining posture: keys are static and
   env-resident (rotation = restart).
2. **Kill-switch has no dedicated role.** `POST /controls/kill-switch` is
   authenticated but any operator key toggles the global safety control —
   consider a `kill-switch` role tag like `approver` if key-based RBAC
   grows. It also takes a raw
   `Bytes` body (any content-type → simple-request CSRF under permissive CORS);
   engaging = fleet-wide tool-exec DoS, disengaging = re-arms a safety
   boundary (`kill.rs:39-46`). Separately it is non-functional in compose:
   api-server has no `/policies` mount so the file lands in its own container
   FS, and tool-server's `../policies:/policies:ro` mount never sees it —
   `POST` lies to the operator (`docker-compose.yml:307-348`). *Fix:* authz-gate
   the POST + propagate state over a shared writable mount or a NATS control
   subject, not a per-container file.
3. **Prompt injection → tool execution.** `/webhook/generic` and A2A message
   text reach the LLM unquoted/unisolated (`triage-agent/main.rs:297-304`,
   `response-agent/main.rs:77-83,247-248`); a hostile "alert" or task goal can
   steer the planner. Worst-case sink: `exec.sandbox` allows `bash -c` and the
   metachar denylist misses `\n`, `>`, `&`, `<(` (`openshell.rs:55`), so
   `bash -c "id > /tmp/x"`-shaped args pass the schema *and* the executor.
   *Fix:* quote/tag untrusted fields in prompts, add `\n`/`>`/`&`/`<` to
   `FORBIDDEN_SUBSTRINGS` (or drop `bash`), and set `autonomy: approval` on
   high-impact tools in `policies/tools.yml`.
4. **Anonymous read of operational internals (BOLA + info leak).**
   `/plans/{case_id}` returns executed tool args/results/rollbacks
   (`main.rs:249-274`); `/audit` dumps the decision log (`main.rs:176-193`);
   `tasks/get`, `tasks/cancel`, `/a2a/tasks/{id}/events` read/mutate any task;
   `/stream/activity` broadcasts internal ops detail; `GET tool-server/tools`
   discloses the full allowlist (`tool-server/main.rs:152-154`). *Fix:* authn +
   per-object authz at the route layer when identity lands.
5. **No inbound resource controls.** No rate limit, no explicit body cap beyond
   axum's 2 MiB default, unbounded SSE fan-out, per-request filesystem scans in
   `/playbooks` & `/coverage`, and `/vulns` requests serialize behind a ≥6 s
   NVD mutex — a handful of slow requests parks every connection. *Fix:* add
   `tower` rate-limit + `DefaultBodyLimit::max`, cache playbook/coverage scans,
   bound SSE clients, cap `resultsPerPage`.
6. **Verbose errors + permissive CORS + weak compose defaults.** Handlers
   return `e.to_string()` from sqlx/reqwest/anyhow — upstream URLs, SQL and
   connector internals leak to clients (`main.rs:119,154,165,191,262`;
   `vulns.rs:73,107,121,145`); `CorsLayer::permissive()` on a state-changing
   API (`main.rs:339`); shipped dev secrets and a published tool-server port
   (`docker-compose.yml:42,62,103,175,205,330`). *Fix:* map errors to generic
   bodies + log internals, scope CORS to the console origin, remove published
   ports for internal services, drop empty-string secret defaults.
7. **Inventory drift.** `POST /hunt` called by the console doesn't exist; dead
   `API_BIND` env. *Fix:* regenerate the route table from `api_router()` and
   reconcile `services.md`. (`webhook/generic` and the `502` status are now
   documented, and `docs/openapi/` carries the machine-readable contract.)

Positive notes worth keeping: deny-by-default tool allowlist + compiled JSON
Schemas + protected-asset boundary (`policy-engine/lib.rs:327-423`); all SQL is
parameterized (`sqlx::query*.bind`); `valid_cve_id` shape-checks before NVD
(`vulns.rs:18-26`); CVE lookups are Redis-cached/negative-cached
(`enrichment-lib/lib.rs:427-472`); exec runs inside OpenShell and fails closed
(`openshell.rs:123-176`).
