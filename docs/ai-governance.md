# AI governance: register, intake, exceptions and change control

AI governance in the Singularity AIDR dashboard answers the questions that
security, privacy (DPO) and AI governance boards ask about AI use:

- **Which AI systems are in use**, who owns each one, what it is used for and
  which kinds of data it processes?
- **Who may use which AI**, who approved it, when, and why?
- **Which exceptions** to a ban are in force, for whom, and until when?
- **Who changed security policy**, and did a second person approve it?

It is designed to support accountability work under frameworks such as the EU
AI Act, GDPR and KVKK. It is a record-keeping and control tool; it is not a
certification or a statement of legal compliance.

All governance pages live under **AI governance** in the dashboard:

| Page | Path | Who can use it |
|------|------|----------------|
| Asset register | `/governance/register` | Everyone reads; owners/admins change entries |
| Requests & exceptions | `/governance/requests` | Owners, admins and members file requests; see below for decisions |
| Change control | `/governance/change-control` | Everyone reads; owners/admins decide and change settings |

Every change and decision requires multi-factor verification (AAL2) and is
written to the workspace audit log in the same database transaction.
Filing a request does not require step-up.

## Asset register

One register per workspace of the AI systems in use:

| Type | Examples | Identifier |
|------|----------|------------|
| Coding agent / connector | Claude Code, Cursor, Codex CLI | connector runtime, e.g. `claude-code` |
| MCP server | GitHub, filesystem, internal tools | the server name used in tool calls (`mcp__<server>__…`) |
| AI chat site / SaaS | ChatGPT, Gemini, DeepSeek | Browser Guard site id (`chatgpt`, `deepseek`, …) or a hostname |
| Model / AI service | internal LLM endpoints | host, e.g. `llm.internal:8443` |

Each entry records:

- **Owner** (a workspace member) and **business purpose**
- **Data categories processed**: personal data, special category data, source
  code, secrets/credentials, customer data
- **Risk tier** (EU AI Act style: prohibited, high, limited, minimal, or not
  assessed) and an optional **internal risk score** (0–100)
- **Status**: proposed, approved, restricted, banned or retired
- **Next review date** and the last review (who and when)
- **Linked evidence**: AI security posture findings, incidents and dashboard
  approval requests from the same workspace (identifiers and a short label only)

A prohibited-tier system can only be banned or retired. An entry's type and
identifier are fixed once created: to rename, retire the entry and add a new
one, so a rename can never quietly lift a ban.

### Populating the register from what AIDR already sees

**Import observed AI systems** (owners/admins) adds a `proposed` entry for
each AI system the control plane has observed and that is not yet registered:

- coding agents from enrolled connectors,
- MCP servers from uploaded MCP inventory posture findings,
- AI chat sites from Browser Guard counts-only site telemetry,
- model/AI service endpoints from managed discovery.

Existing entries only get their observation window refreshed; their status,
owner, purpose and risk assessment are never changed by an import.

## What a status actually enforces

The register only ever **adds** restrictions on top of your published runtime
policy. It never relaxes a policy an administrator published.

| Asset | Status | Effect |
|-------|--------|--------|
| MCP server | banned | Blocked by every managed connector (deny, `POL-MCP-006`) |
| MCP server | restricted | Each call needs out-of-band approval (`ask`) |
| AI chat site with a Browser Guard site id | banned | Listed in the Browser Guard managed-policy snippet (`blockedSites`) |
| AI site with a Browser Guard Shadow AI catalog id (`poe`, `midjourney`, …) | banned | Blocked by enrolled Browser Guard installs (signed dashboard policy, below) |
| AI site with a Browser Guard Shadow AI catalog id | approved | Reported as sanctioned by enrolled Browser Guard installs, unless their managed policy blocks it |
| Anything else | any | Recorded in the register only |

How the MCP restrictions reach connectors: the control plane serves them as a
`governance` block next to the published runtime policy on the policy endpoint,
with its own SHA-256 digest. Connectors verify the digest, add the lists on top
of the published policy at their next policy refresh (about 30 seconds), and
keep them in the local policy cache. A malformed or mismatching block makes the
whole policy response unusable, exactly like a malformed policy. When the policy
endpoint signs its runtime policy, the signed envelope also carries
`governance_sha256` (the digest of the empty overlay when nothing is banned), so a
connector configured with policy public keys refuses a response whose bans were
stripped, swapped or injected (`governance_mismatch`). An overlay from an older
signer that does not bind it is still applied, because it can only add
restrictions, and the connector logs that it is not signature-bound. Requirements
and limits:

- The workspace must have published a runtime policy (Policies page); without
  one, connectors do not fetch managed policy and the register page warns.
- Connectors must be on a release that understands the `governance` block;
  older connectors ignore it.
- The published revision, its digest and agent load receipts are unchanged:
  load receipts confirm the published policy version, not the governance block.

Browser Guard and the `blockedSites` key: the register page shows the
managed-policy JSON for banned built-in AI chat sites; deploy it through your
browser management (Chrome/Edge policy for the extension).

Shadow AI allow/block from the dashboard: owners and administrators allow or
block a detected AI service on Browser Guard → Shadow AI (or here, as an
`ai_site` entry with the catalog id). Each decision is an `upsert_asset` call:
AAL2, audited (`ai_asset.created` / `ai_asset.status_changed`), optimistic
versioning, and four-eyes when relaxing a ban with four-eyes on. Enrolled
Browser Guard installs fetch `GET /functions/v1/browser-guard-policy` with
their telemetry key; the response carries `browser_guard.shadow_ai`
(`blocked`, `sanctioned`) inside the runtime-policy Ed25519 envelope
(`policy_version` `browser-guard/v1`, document digest, tenant, sequence,
expiry). The extension applies it only when its managed `dashboardPolicy` key
pins the signing public key; unsigned, tampered or replayed documents are
ignored. Precedence is **most restrictive wins**: a dashboard block always
applies, a dashboard allow never unblocks what the browser's managed `shadowAi`
blocks, and an expired document keeps its blocks only. The endpoint refuses to
serve (503) without a provisioned policy signing key. Browser Guard keys carry
no member identity, so only tenant-wide exceptions waive a ban for browsers.
The `shadowAi` managed-policy snippet remains the alternative for browsers
without a control plane.

Require native NER from the dashboard: owners and administrators can make
Browser Guard's native NER mandatory for every enrolled browser (Browser Guard
Guard → Require native NER). The `update_browser_guard_settings` action (AAL2,
rate-limited) calls the `update_browser_guard_settings` RPC, which re-checks
owner/admin on an active tenant under row locks, stores
`tenant_ai_governance_settings.browser_guard_require_native_ner` and writes a
`browser_guard.settings_updated` audit row (from/to) for each change. Switching it
**off** while four-eyes is on is refused (`browser_guard_four_eyes_required`):
four-eyes must be turned off first, which a second approver decides. The setting
reaches browsers as `browser_guard.require_native_ner: true` in the same signed
document (omitted when off; covered by the document digest). The extension merges
it with its managed `requireNativeNer` key, `true` wins, and keeps it in force
after the document expires. An unreadable settings row makes the endpoint answer
503 rather than serve a document without the requirement.

Separation of duties for agent approvals: owners and administrators choose
whether the person whose key or agent raised an `ask` approval request may
approve it themselves (Approvals → Separation of duties). The
`update_approval_settings` action (AAL2, rate-limited) stores
`tenant_ai_governance_settings.approval_require_distinct_approver` (`true`,
`false`, or `null` for the plan default: required on Business and Enterprise,
allowed on Free and Team; an unresolvable plan counts as required) and writes an
`approval.settings_updated` audit row. Relaxing it while four-eyes is on is
refused (`approval_separation_four_eyes_required`). `decide_approval_request`
enforces the rule in the database; see `docs/contracts/dashboard-approvals.md`.

At most 500 MCP servers can be banned or restricted per workspace.

## Intake: "may we use this AI tool?"

Anyone with the owner, admin or member role can request a new AI tool, MCP
server, site or service — or a change of status for one already in the register
— with a business purpose, the data it will process and the requested outcome
(approved or restricted use).

Requests are decided by an **owner, administrator or designated AI governance
reviewer**, and **never by the person who filed them** (enforced by the
database, not only the dashboard). Every decision needs a reason. Approving a
new system adds it to the register with the requester as owner; approving a
status change updates the entry. Pending requests expire after 90 days.

**Designated reviewers** are members an owner or administrator names on the
Change control page. They can decide intake requests and record periodic
reviews, but they cannot lift a ban or restriction, decide exceptions or
approve policy changes. Designation is not a new workspace role, and removing
the member removes the designation.

## Exceptions (waivers)

An exception waives a ban or restriction for a limited time, for example "allow
the `shell-runner` MCP server for these three developers until the end of the
migration":

- **Scope**: named members, named enrolled agents, or everyone in the workspace
- **Justification** (required) and an **end date** within 365 days
- Requested by an owner, admin or member; **approved by an owner or
  administrator other than the requester**
- Owners/admins can **revoke** an active exception at any time

An exception applies from approval until its end date. Enforcement evaluates
the end date on every policy fetch, so an expired exception stops applying
without waiting for any background job. A maintenance job then marks it
`expired` and writes an audit entry. For MCP servers the exception lifts the
governance restriction for its scope; for other assets it is a recorded waiver.
An exception never lifts a restriction written into the published runtime
policy itself, and prohibited-tier systems cannot be waived.

An exception waives only the level it was approved against: one approved while
an MCP server was `restricted` stops applying as soon as the server is
escalated to `banned` (for example during incident response), and applies again
only if the status is lowered back. Waiving a ban needs an exception decided
against the ban.

## Policy change control (four-eyes)

Owners and administrators can turn on **four-eyes change control** (it needs at
least two active owners/administrators). While it is on, these actions no
longer take effect when their author clicks publish:

- publishing runtime policy JSON or compiled policy YAML,
- rolling back to an earlier revision,
- staging a revision for selected agents or starting an ordered canary rollout,
- saving the DLP policy,
- relaxing an enforced register status (for example banned → approved) —
  use an intake request decided by someone else instead.

Instead the dashboard files a **change request**. A second owner or
administrator opens it on the Change control page, reviews the **diff** between
the current and the proposed policy, and approves or rejects it with a reason.
Approval runs the normal publication with the author as publisher, so both
people must still hold the owner or admin role. If someone published in between,
the request is marked **superseded** and nothing is applied; the author files a
new change against the current version. Change requests expire after 7 days.

The rule is enforced by the database: while four-eyes is on, a new runtime or
DLP policy revision can only be written by the approval of a pending change
request for the same workspace. Turning four-eyes **off** is itself a change
request that another owner or administrator must approve; turning it on is
immediate.

The Change control page also shows the **runtime policy history** with a diff of
each revision against the previous one and a **roll back** button. Rollback
republishes the chosen revision through the normal publication path (and
therefore through four-eyes when it is on). Staged and ordered rollouts,
receipts and rollback are the existing policy rollout features; change control
adds approval in front of them.

DLP change requests contain the DLP policy; their content is shown only to
owners and administrators after multi-factor verification. Every other
workspace member sees only the request metadata (kind, author, status, digest
and counts).

## Periodic review

Each entry has a next review date, set from the workspace **review interval**
(default 180 days, configurable from 30 to 730 on the Change control page) when
an entry is created or reviewed. Entries past their review date are counted and
listed at the top of the register ("Reviews overdue") and can be filtered.
Owners, administrators and designated reviewers record a review with **Mark
reviewed**, which stores who reviewed it and when and schedules the next review.

Review reminders are shown in the dashboard. They are not sent to email, chat or
webhook channels in this release.

## Audit, retention and workspace closure

- Every create, update, import, evidence link, review, request, decision,
  cancellation, revocation, expiry, settings change and policy change is written
  to the workspace audit log (and the privileged audit log) in the same
  transaction as the change.
- Register entries are configuration: they are kept for the life of the
  workspace.
- Closed intake requests, exceptions and policy change requests are deleted after
  the workspace's security-audit retention period (at least 365 days), unless a
  legal hold is active.
- When closure of a workspace is requested, pending requests are cancelled and
  active exceptions are revoked immediately. All governance data is deleted in
  the policy-configuration phase of workspace offboarding, under the same legal
  hold checks, and the workspace cannot be closed while any of it remains.

## Security properties

- Tenant isolation by row-level security plus the workspace identity policy
  (MFA/SSO requirements, session revocation) on every governance table.
- The browser never writes governance tables; every change goes through a
  server-side function that re-checks role and state under row locks.
- No agent-facing surface: connectors only receive the resulting restrictions.
  Requests and approvals are made by people in the dashboard.
- Four-eyes is structural: a request's decider can never be its requester.
