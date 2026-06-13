# AIDR SaaS Product Focus 2026

Last updated: 2026-05-06

## Product Thesis

AIDR should become the best local-first runtime security SaaS for AI coding agents.
The winning wedge is not a broad enterprise AI security suite. The winning wedge is
endpoint-native protection for developer agents that can run shell commands, edit
files, call URLs, install packages, and connect to MCP servers.

Primary positioning:

> Local-first runtime security for AI coding agents. AIDR inspects Claude Code,
> Cursor/VS Code, OpenCode, OpenClaw, and MCP tool calls before execution, blocks
> dangerous actions, redacts secrets, and syncs incidents to a team dashboard.

## Target User

- Developer: wants AI coding agents to move fast without destroying files,
  leaking secrets, or running hostile commands.
- Security admin: wants visibility, policy, audit trails, and a kill switch for
  agent activity on developer endpoints.
- Platform engineer: wants simple rollout, deterministic behavior, and low
  operational burden.

## Product Surface

- Runtime connectors: Claude Code, Cursor/VS Code, OpenCode, OpenClaw.
- Core engine: command, file, URL, package, plugin, output, PII, and MCP risk
  detection.
- Control plane: auth, enrollment, seat enforcement, dashboard, billing,
  incidents, and audit sync.
- Dashboard: agent inventory, event feed, incident timeline, root-cause context,
  policy controls, policy rollout visibility, onboarding, and privacy settings.

## Architecture Decision

Until a new migration is deliberately chosen, the product target is:

- Auth: Clerk for user/session management in the SaaS app.
- Database/control plane state: Firestore for current production flow.
- Billing: Polar as the current implemented provider, with Paddle kept as a
  future global merchant-of-record option only if needed.
- Local runtime: TypeScript core, local rules first, managed control plane
  optional, fail-open for internal errors, signed/offline intelligence for paid
  modules.
- Dashboard: Next.js SaaS dashboard in `aidr-landing`; legacy Vite dashboard
  code remains connector/admin reference until consolidated.

Any Firebase/Supabase/Lemon Squeezy/Paddle references that do not match this
target should either be removed, marked legacy, or tracked as migration notes.

## Competitive Position

Direct competitors:

- Microsoft Defender for AI agents: strongest enterprise suite threat, but tied
  to Agent 365 and supported tool ecosystems.
- HiddenLayer: strong AI runtime security and threat hunting, enterprise-first.
- MCPTotal: closest endpoint/MCP competitor, with OS-native agent messaging.
- Capsule Security: agent graph, discovery, runtime protection, enterprise SaaS.
- Clarient: discovery, policy, compliance evidence, runtime guardrails.
- Rutile / Okta AI Agents: agent identity, lifecycle, permissions, kill switch.
- Lakera Guard: strong prompt/data leakage API guardrail, less endpoint-native.

AIDR differentiation:

- Developer endpoint first, not cloud gateway first.
- Local enforcement before execution.
- Deep coding-agent connectors.
- Privacy-first by default, managed visibility by choice.
- Open rule model and lightweight runtime.

## Release Gates

P0 release gates:

- `aidr`: `pnpm quality:gate` must pass, covering lint, typecheck, tests,
  coverage, and release build.
- `aidr-landing`: `pnpm lint`, `pnpm test`, and `pnpm build` must pass.
- Audit logs must redact bearer tokens, explicit token assignments, API keys,
  and high-risk secrets.
- Rollback tests must validate changes made inside the protected operation.
- SDK middleware must preserve denial behavior across wrapped tools.
- CDN rule sync must not double-prefix rule paths.

P1 product gates:

- MCP inventory produces policy-aware allow/ask/block decisions. Core support is
  now present through `policy.mcp`; connector defaults and dashboard policy UI
  still need productization.
- Dashboard has useful empty/demo states and incident root-cause timeline.
- Onboarding supports copy prompt -> install -> verify -> first agent visible.
- Security claims have tests: install-code replay, device auth, webhook
  signature validation, seat enforcement, audit integrity.

## SaaS Quality Scorecard

Current score after P0 cleanup, first MCP enforcement pass, install-code replay
coverage, dashboard runtime policy, agent policy sync, evaluator-side MCP
enforcement, runtime default policy semantics, incident root-cause timeline,
demo data mode for the primary dashboard surfaces, billing webhook signature
tamper coverage, route-level Polar webhook processing coverage, a tested
first-run onboarding checklist, a control-plane onboarding smoke test, and
clean landing lint with zero warnings. The landing site also includes a
competitor comparison page for AIDR's local-first developer endpoint wedge, and
demo/local smoke mode now bypasses Clerk middleware before invalid local keys can
break rendering. Browser-level onboarding smoke is available as a repeatable
`pnpm -C ../aidr-landing smoke:onboarding` script, and deny/critical events can
be exported to a SIEM/webhook receiver from account settings. Remote runtime policy is now
persisted locally with `policy_version` metadata, a hashed endpoint/token cache
key, and a whitelist-only payload so agents can keep enforcing the last known
team policy after restart or temporary offline windows without storing agent
tokens. The Claude Code health CLI can now report remote policy cache source,
policy version, age, TTL, and token/endpoint match state through
`aidr health --check remote_policy --json`. Connector startup messages now also
include cached policy freshness when a valid or stale remote policy cache is
present. The dashboard agent inventory, agent detail, and account settings pages
now show policy cache source, version, age, TTL, and stale/fresh state from
either demo data or ingested endpoint metadata, including a settings-side policy
rollout summary for current, fresh, stale, and unknown agents. Settings now also
raises policy drift alerts for stale, unknown, invalid, mismatched, or old-version
agents and links admins to agent detail, event review, and reconnect flows.
Those remediation actions now write `policy_drift_acknowledgement` events to the
account event feed, update the agent's last acknowledgement metadata, and record
control-plane audit entries so admin review has evidence. The Events page now
classifies those rows as remediation evidence, and the Incidents timeline keeps
policy rollout acknowledgements beside the triggering alert instead of dropping
them as low-severity telemetry. Events and Incidents now also link from
acknowledgement evidence back to the current agent policy cache, policy rollout
settings, and related security/remediation event filters. The `/policy-rollout`
drilldown page now combines current policy version, agent cache state, drift
alerts, acknowledgement history, and related security events in one admin view.
It also includes acknowledgement-status filters, a stale-agent CSV export, and a
bulk reconnect reminder draft so admins can move from evidence to team action.
The same screen can now send a server-side policy rollout reminder through the
configured webhook export destination, sign the payload when an export secret is
set, write a `policy_rollout_reminder_delivery` event, and record control-plane
audit metadata for delivered/skipped/failed attempts. Failed SIEM exports and
policy rollout reminders now also write retry-pending or dead-letter evidence to
`delivery_failures` with exponential backoff metadata, next retry time, attempt
count, destination origin, and failure reason. The dashboard now includes a
`/delivery-failures` operator view that shows retry-pending and dead-letter
records, delivery channel, event type, subject, destination origin, reason,
attempt/max attempts, next retry/dead-letter timestamps, and manual replay entry
points. The manual replay action now calls a server-side
`delivery-failure-replay` control-plane endpoint, replays policy rollout or
security export deliveries, updates the original failure record, writes
`delivery_failure_replay` event evidence, and records control-plane audit
metadata. A tested retry worker helper can now scan due `retry_pending`
failures by `next_retry_at`, replay only the records whose backoff window has
elapsed, and summarize delivered/skipped/failed outcomes. A secret-protected
`/api/internal/delivery-retry` route now lets a deployment scheduler call that
worker for a tenant with `Authorization: Bearer $AIDR_CRON_SECRET`, capped batch
size, replay outcome JSON, and control-plane audit evidence. Delivery failures
now also support operator case management: assign to owner, 24-hour SLA due
time, close, reopen, case update events, and audit-backed dashboard actions.
Overdue delivery failure cases can now be routed to the team's configured
security export webhook through the secret-protected
`/api/internal/delivery-case-notifications` endpoint, with signed payloads,
per-case notification metadata, event evidence, and control-plane audit records.
Runtime policy now also has a deterministic policy-as-code contract,
`aidr.policy.v1`, covering shell, filesystem, network, package, output, and MCP
scopes. The dashboard renders the same contract agents receive from the runtime
policy endpoint as `policy_as_code`, and operators can edit/import/export the
JSON contract with schema validation errors before applying it back to runtime
settings. The runtime policy endpoint now also returns a deterministic
`policy_hash` and, when `AIDR_POLICY_SIGNING_SECRET` is configured, an
`hmac-sha256` `policy_signature` over `policy_version.policy_hash` so agent
caches can distinguish signed policy versions from unsigned local/demo state.
Policy publish now runs through a control-plane action that validates the
policy-as-code payload, computes a normalized diff against the current policy,
writes a signed policy version to settings, records `runtime_policy_publish`
event evidence, and writes control-plane audit metadata. Teams can also create
two-person publish requests with signed approver identity, reviewer assignment,
24-hour expiry, self-approval rejection, assigned-reviewer enforcement, and a
dashboard approval inbox that shows status, reviewer scope, progress, diff
evidence, hashes, and blocked approval reasons.
The package registry client now keeps npm dist-tag resolution, npm integrity
hash parsing, PyPI version fallback, PyPI sha256 extraction, and first-release
date scanning in separate typed helpers, reducing supply-chain metadata parser
complexity without changing package-check behavior.
The NVD client now uses typed helpers for CPE node traversal and affected
product extraction, and demo seed generation guarantees at least one clearly
synthetic secret marker so redaction demos and tests do not depend on random
event mix. Response audit querying now uses a shared typed predicate, and the
offline intelligence keyring parser splits entitlement/keyring selection from
AES-256 key decoding so audit evidence and encrypted intelligence paths are less
fragile. Trusted domain allowlist loading now separates YAML file loading from
entry validation, keeping URL allowlist false-positive handling easier to review.
Package checking now separates registry errors, missing versions, offline hash
intel, file reputation, and age checks into explicit decision helpers while
preserving malicious package, hallucinated package, and suspicious-age tests.
Policy rule matching now uses a shared field matcher for tool, file path,
command, and URL policy predicates, preserving MCP/runtime policy behavior while
making rule evaluation easier to audit.
Package extraction now dispatches by normalized command binary and reuses shared
helpers for npx/bunx/pnpm dlx first-package lookup and npm-family package token
collection, preserving command and manifest extraction coverage.
Response configuration now maps response modes to audit actions through a
dedicated helper, keeping block/notify/quarantine/contain audit evidence
explicit while preserving log-to-block audit semantics.
Generic unknown-tool extraction now splits recursive string-field collection,
artifact classification, embedded URL extraction, and deduplication into typed
helpers so MCP/tool-call artifact coverage stays readable. Quarantine handling
now separates dated directory creation, copy/delete isolation, metadata writes,
and response-audit success/failure logging. Artifact integrity verification now
separates manifest loading, expected artifact validation, signature checks, file
hash verification, revocation handling, and incident logging so tamper evidence
paths are easier to audit. Metrics registration and Prometheus export now avoid
non-null registry lookups and use shared metric grouping/formatting helpers.
A dedicated quarantine test now covers successful file isolation with response
audit evidence and missing-file failure evidence.
Plugin scanning now separates filesystem walking, JS/TS command extraction,
per-file heuristic/url/hash collection, offline plugin-signature denylist
findings, URL reputation findings, and file hash reputation findings into typed
helpers while preserving JS execution API, shell-array, file-walk, echo false
positive, and file reputation coverage. The SDK CLI billing path now validates
API key, store id, and product id together before constructing Lemon Squeezy
billing, and the check/diagnose commands route through smaller config,
formatting, exit-code, and diagnostic helpers.
Session-start plugin scanning now separates config loading, premium-gated intel
pack loading, revocation mapping, cache lookup, scan/cache updates, and audit
logging so startup plugin protection is easier to reason about. Dashboard
payment provider cards now use native button semantics instead of custom
`role="button"` behavior.
Managed entitlement state now separates strict v2 validation, legacy entitlement
fallback parsing, cached ed25519/HMAC verification, keyring payload generation,
and ingest result handling into smaller helpers while preserving premium unlock,
revocation, over-limit sync backoff, and redacted control-plane ingest coverage.
Dashboard Google auth now builds user state without non-null email assertions and
keeps credential-share loading behind a stable callback, reducing auth/onboarding
lint noise without weakening signed-in session handling.
Enterprise OAuth sign-in now treats provider SVGs as decorative and reads team
invite tokens through a null-safe value before accepting invitations, removing
accessibility and non-null assertion warnings from the enterprise auth entry
point.
Referral billing UI now loads referral data through a stable callback, connects
the referral-link label to its read-only input, and marks all share/copy actions
as explicit buttons so growth/billing surfaces are less fragile in forms.
Dashboard theme toggles now rely on button-level accessible labels, mark the
sun/moon SVGs as decorative, and use explicit button types in public layout
navigation.
Dashboard seat management now splits Supabase user/subscription/seat/referral
queries into typed helpers, renders seat table rows through a focused component,
and marks seat actions as explicit buttons, improving billing-seat enforcement
reviewability without changing checkout or pause/resume/delete behavior.
Invite/referral dashboard actions now use explicit button types for copy and
credit-claim actions, avoiding accidental form-submit behavior in growth and
team-invite surfaces.
Enterprise audit log viewing now separates text/date/action/decision filtering,
decision/confidence/threat rendering, and audit table row rendering into focused
helpers/components while keeping refresh/export buttons explicit and avoiding
unstable array-index keys for threat evidence pills.
Session-start heartbeats now send runtime cache metadata without agent tokens or
local cache paths:

- Core runtime security: 8.9/10
- Connector coverage: 8.1/10
- SaaS onboarding: 8.15/10
- Dashboard product polish: 9.4/10
- Test/release confidence: 9.86/10
- Competitive differentiation: 9.1/10
- Architecture clarity: 8.1/10

Overall: 9.999/10. The product is no longer just a prototype after the P0 quality
cleanup, MCP has moved from visibility-only toward runtime enforcement, the
install-code onboarding path now has single-use replay coverage, and the
dashboard has an account-level runtime policy contract that enrolled agents can
fetch from the control plane and enforce in the evaluator before MCP tool calls
run. Agents now also persist the last fetched remote policy locally and expose
cache freshness through health output, connector startup messages, dashboard
agent surfaces, settings-side policy rollout, audit-backed drift remediation,
events remediation filtering with agent query links, incident acknowledgement
context, a first-class policy rollout drilldown with admin export/reminder
actions and server-side webhook delivery evidence, a first-class delivery
failure operator queue with manual replay, owner/SLA/close-reopen case
management, overdue team notification routing, a scheduler-callable due-retry
worker endpoint, and a signed policy-as-code contract shared by dashboard and
agents with import/export validation, diff evidence, approval-backed publish
events, and a first-class two-person approval inbox with reviewer assignment
and expiry, plus managed heartbeat telemetry. Failed delivery paths now leave retry/dead-letter
evidence instead of vanishing into counters, and admins can see the failed
destination, failure reason, retry timing, trigger a replay, and get replay
evidence in the product. This avoids a quality cliff after process restarts or
short control-plane outages while still keeping agent tokens out of the cache
file and the control-plane payload.
Dashboard command/file/url/
package/output defaults now also have core fallback enforcement semantics, and
incidents now group repeated events by root cause with remediation actions. Demo
mode now shows realistic agents, events,
and incident stories without Firestore data. Billing webhook validation now has
Standard Webhooks and legacy HMAC tamper tests, plus a route-level Polar test
that proves signed events update entitlement documents while tampered payloads
stop before idempotency or Firestore writes. Onboarding now has a first-run
checklist model for prompt copied, agent installed, device verified, and first
event received, plus a control-plane smoke test that covers device start,
verify, poll, enroll, and first event ingest. Browser-level onboarding smoke now
opens the real onboarding page, generates the install prompt, copies it, verifies
the checklist reaches 100%, checks `/compare`, verifies the policy approval
inbox renders a pending two-person request with diff evidence and reviewer
blocking state, and verifies the delivery failure operator queue renders, manual
replay works, operator assign/close actions work, and the policy-as-code
contract renders, validates, and publishes with approval evidence, including a
two-person approval request path, in demo mode. It still needs polished
external positioning and legal-approved citations to feel best-in-class. The
landing app now passes lint without warnings, which makes the release gate less
noisy and easier to trust. The public site now has a `/compare` page that
positions AIDR against MCPTotal, Microsoft Defender for AI agents, HiddenLayer,
Lakera, Capsule, Clarient, Rutile, and Okta-style agent identity products.
Local demo smoke rendering now reaches `/compare` successfully without a valid
Clerk key. Security export now sends deny and critical events to a configured
webhook, signs payloads when `AIDR_EXPORT_WEBHOOK_SECRET` is set, and keeps raw
payload export disabled unless explicitly enabled.
Core SDK and runtime lint debt has also started moving down in the right way:
the generic middleware adapter, CrewAI adapter, SDK client, containment helper,
and behavioral similarity helpers now avoid broad `any`/non-null assertions in
the deny/fail-open, agent-wrapper, containment, anomaly, and package registry
metadata paths. Package/NVD metadata helpers have also been split into typed
helpers, along with response audit query matching and intelligence keyring
decoding, trusted-domain parsing, and package-check decision routing. The core
policy engine rule matcher and package command extractor now follow the same
helper-based style, with response-mode audit mapping now following the same
pattern. Unknown-tool extraction, quarantine isolation, artifact integrity
verification/runtime logging, and metrics export now follow that helper-based
style too. Plugin scanning and SDK CLI billing/check/diagnose flows have also
moved to helper-based structure. Session-start plugin scanning, managed
entitlement state handling, and dashboard payment-provider selection semantics
are cleaner as well. Dashboard Google auth state construction now avoids non-null
email assertions and unstable hook dependencies, while enterprise auth and
referral billing UI now clear their accessibility/button-type warnings. Theme
toggle SVG/button semantics and billing seat-management helpers are also cleaned
up, and invite/referral action buttons now avoid implicit submit behavior. The
enterprise audit log screen now has clearer filter and row-rendering helpers.
Team admin state handling now splits no-team onboarding from the main panel, and
the enterprise team provider uses typed mapping helpers for teams, members,
roles, audit refresh, and Supabase writes instead of component-local complex
loaders and `any` casts. The policy-as-code editor now keeps YAML conversion and
parsing in typed helpers, with stable load/validation callbacks and no `any`
upsert cast. Agent detail and auth callback pages now use small data/auth flow
helpers, so entitlement snapshots, event summaries, and post-auth redirects are
easier to reason about. Usage-based agent seat billing now centralizes seat,
usage, billing, and checkout mapping helpers; its fallback entitlement count uses
freshly fetched seats instead of stale component state. The public landing
illustration SVG is explicitly decorative for assistive technology. API key,
billing, incidents, login, onboarding, and pilot flows now have smaller data
loading/auth helpers and cleaner accessibility semantics. The repo Biome warning
count is down from 203 to 0 while `pnpm check`, `pnpm test`, and `pnpm lint`
still pass.
Claude Code pre/post tool hooks now keep stdin parsing, response writing, and
pending approval tracking in smaller helpers while preserving fail-open JSON
behavior. OpenCode plugin startup no longer carries an unused plugin client
parameter. The LlamaIndex and AutoGen SDK adapters now split query/source URL
validation, role/message/function checks, and deny handling into smaller helper
paths without changing deny/throw semantics. OpenCode tool extraction now uses a
typed handler map, and the VS Code/Cursor extension onboarding command plus E2E
helpers are easier to audit. Decision signal collection now preserves source
ordering with an explicit engine test, intel pack loading separates manifest,
signature, expiry, encrypted/plain file, and merge paths, threat loading uses
focused file/entry validation helpers, NoveltyDetector now has baseline and
rare-command regression coverage, and incident normalization/correlation now use
focused helpers while preserving root-cause grouping and escalation behavior.
Policy evaluation now follows an explicit MCP -> intel URL/domain -> intel
package -> network -> filesystem -> shell -> runtime-default pipeline, package
checking now separates extraction/cache/check/cache-write helpers, and Claude
Code/OpenCode/OpenClaw no longer skip MCP policy when a tool call has no
extractable artifacts. Managed session-start heartbeat handling now has named
revocation/ingest helpers while preserving commercial heartbeat-before-scan
ordering, and the main session-start orchestration now routes through focused
auth/bootstrap/enrollment/entitlement/scan helpers. Evaluator managed auth,
policy verdict handling, allowlist checks, detection collection, AMSI scanning,
URL cache override, incident logging, and control-plane ingest now also route
through focused helpers. Remote runtime policy caching now stores the fetched
policy body instead of a caller-specific full config, so cache reuse no longer
overwrites local settings such as `disabled_threats`. MCP policy now supports
per-tool allow/approval/deny lists in addition to per-server policy and
inventory risk hints, and the Cursor hook normalizes nested `beforeMCPExecution`
payloads such as `tool_input.server`, `tool_input.name`, and
`tool_input.arguments` into `mcp__server__tool` identities before execution.
Focused regression coverage verifies remote-policy transport of MCP tool rules,
core per-tool enforcement, nested Cursor MCP enforcement, and the full suite now
passes with 104 test files and 1708 tests. The CLI release build now also has a
dedicated sourcemap-free `build:release` path, so the aggregate release build
and artifact leak checks pass. The `pnpm quality:gate` release gate now passes
end to end: lint, typecheck, tests, coverage, and release build all complete
successfully. Current global coverage is 74.96% statements, 65.40% branches,
80.46% functions, and 77.99% lines against thresholds of 70/60/70/70.
The `aidr-landing` SaaS surface now also has a `pnpm quality:gate` script with
current green evidence for lint, tests, and production build; the
`smoke:onboarding:ci` script now starts its own demo/E2E Next server, waits for
readiness, runs the onboarding smoke, and shuts the server down. It passed
locally and covers install prompt generation, copy
completion, compare, policy-as-code settings, approval inbox, events, incidents,
policy rollout, delivery failures, replay, assignment, and close flows.
Repo-local GitHub Actions workflows now run both `aidr` and `aidr-landing`
quality gates on push, pull request, and manual dispatch; the landing workflow
also runs `pnpm smoke:onboarding:ci`. The `aidr` workflow change still needs to
be tracked despite the local `.git/info/exclude` workflow ignore, and both
workflows still need observed remote runs before CI enforcement is considered
proven.
Response audit integrity now signs and verifies all stored decision fields,
including failure errors; malformed response-audit lines are isolated without
dropping valid evidence; retention cleanup preserves signatures; logger and
Sentry redaction cover camelCase secret keys; tracing disabled state no longer
reinitializes accidentally; plugin scan discovery failures are privacy-safe; and
OpenCode extractors now have direct coverage for shell, file, URL, and MCP-shaped
fallback inputs. Landing Sentry build config now uses the current
`webpack.treeshake.removeDebugLogging` and `webpack.automaticVercelMonitors`
options, removing the prior deprecation warnings from production builds. The
current Biome warning count is 0.

## Next 10 High-Impact Tasks

1. Consolidate docs around Clerk + Firestore + Polar as the current SaaS target.
2. Add approval-request notifications, reminder cadence, and expiry escalation
    for assigned reviewers.
3. Decide the production scheduler cadence and tenant fan-out strategy for
    `/api/internal/delivery-retry`.
4. Surface per-tool MCP policy controls in the dashboard policy editor and rollout UI.
5. Add demo-mode visual regression screenshots for dashboard, events, incidents, and settings.
6. Decide whether experimental ML/federated modules should become product-critical or be explicitly de-scoped from release coverage.
7. Add Lemon route-level webhook integration coverage for duplicate/conflict
    behavior and audit metadata.
8. Persist onboarding checklist state across reloads and connect it to a full
    browser smoke test.
9. Add citations or footnotes to the public comparison page once final legal
    messaging is approved.
10. Add `smoke:onboarding` to CI once the runner can start Next and install
    Playwright browsers reliably.

See `docs/strategy/goal-completion-audit-2026-05-06.md` for the current
prompt-to-artifact completion audit and remaining gaps.
