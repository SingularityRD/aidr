# AI governance: framework mapping, scorecard and acceptable use

Singularity AIDR guards the actions of AI coding agents, the prompts people send to AI
chat sites and the MCP servers agents use. This page explains how those product
controls relate to the frameworks governance, risk and data-protection teams work with,
what the **Governance** scorecard shows, how the scheduled summary is delivered, and
how the AI acceptable-use notice works.

> **What this is and is not.** The mapping and the scorecard *support* your obligations
> under the NIST AI Risk Management Framework, ISO/IEC 42001, the EU AI Act,
> KVKK/GDPR, ISO/IEC 27001:2022 Annex A, the BDDK information systems and electronic
> banking regulation and the Presidency's Information and Communication Security Guide
> by showing which technical controls are in place for the AI tools AIDR guards, with
> evidence from your own records. They are vendor mappings. They are not a certification, an audit
> opinion or legal advice. Coverage percentages describe product controls, not whether
> your organisation meets any framework or law.

## 1. Framework control mapping

The mapping is data, kept in the repository and embedded in the dashboard:

| File | Content |
| --- | --- |
| `governance/frameworks/capabilities.yaml` | Product capabilities (what AIDR does), the files that implement them, and the evidence sources (tables, report sections, exports) that show them working |
| `governance/frameworks/nist-ai-rmf.yaml` | NIST AI RMF 1.0 subcategories (GOVERN, MAP, MEASURE, MANAGE) |
| `governance/frameworks/iso-iec-42001.yaml` | ISO/IEC 42001:2023 Annex A controls |
| `governance/frameworks/eu-ai-act.yaml` | EU AI Act (Regulation (EU) 2024/1689) deployer-side articles |
| `governance/frameworks/kvkk-gdpr.yaml` | KVKK and GDPR articles the compliance evidence report already covers |
| `governance/frameworks/iso-iec-27001.yaml` | ISO/IEC 27001:2022 Annex A controls (identifier and title only) |
| `governance/frameworks/bddk-bsebh.yaml` | BDDK *Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik* (Resmî Gazete 15.03.2020, No. 31069), by requirement topic |
| `governance/frameworks/cbddo-big.yaml` | Presidency Digital Transformation Office *Bilgi ve İletişim Güvenliği Rehberi*, by measure topic |

Each control lists the capabilities that support it, the evidence source that proves
it, a coverage level and a note that states the limit of the support:

| Coverage | Meaning |
| --- | --- |
| **Full** | When deployed, the capability performs the activity for the AI tools AIDR guards (still limited to those tools). |
| **Partial** | The capability supports part of the activity; the note says which part remains with you. |
| **Customer responsibility** | Your organisation performs the activity. Listed capabilities and evidence can only serve as input. |

Only controls to which the product contributes, or that customers commonly ask about
for AI tool use, are listed; the rest of each framework is out of the product's scope.

**BDDK and the Presidency guide are mapped by topic.** Their rows use this mapping's own
topic codes (`BSEBY-*`, `BIG-*`: for example `BSEBY-IZKAYDI` for audit trails, `BIG-OLAY`
for cyber incident response) rather than article or measure numbers, because article
numbering and the guide's measure numbering change between consolidated texts and
versions. The institution's compliance function maps each topic to the article or
measure of the text it applies. None of these rows is a regulatory approval, an audit
result or a statement that an institution meets the regulation or the guide.
NIST AI RMF titles quote the subcategory's first sentence; ISO/IEC 42001 rows give the
Annex A identifier and control title only (the standard's text is not reproduced).

Examples of what is mapped:

- **Human oversight**: NIST AI RMF MAP 3.5, ISO/IEC 42001 A.3.2, EU AI Act Art. 14
  (a provider design obligation, used as a reference for agent oversight) and
  Art. 26(2). Supported by out-of-band human approval of `ask` decisions and by the
  oversight analytics on the scorecard.
- **AI literacy**: EU AI Act Art. 4 and NIST AI RMF GOVERN 2.2. Supported by the
  acceptable-use notice and its acknowledgement counts (awareness, not training).
- **Logging**: ISO/IEC 42001 A.6.2.8 and EU AI Act Art. 26(6). Decision logs are kept
  according to your telemetry retention policy; Art. 26(6) applies to deployers of
  high-risk AI systems and asks for at least six months, so the scorecard flags a
  shorter retention period.
- **KVKK/GDPR**: GDPR Art. 5(1)(c), 25 and 32 and KVKK Art. 4, 7 and 12 are supported
  by masking, DLP, access control and retention evidence; GDPR Art. 30 and 33 and KVKK
  Art. 9 remain the controller's, with product data as input.

**Applicability.** Article 26 of the EU AI Act applies to deployers of *high-risk*
AI systems (Annex III use cases). General-purpose coding agents and AI chat assistants
used for ordinary work are typically not high-risk; those rows are provided as a
good-practice reference. The mapping does not classify any AI system.

**Integrity checks.** `node scripts/sync-governance-frameworks.mjs` validates the
mapping (every capability path, table, report section, function and file it
references must exist; identifiers follow each framework's scheme; every control has
a note) and fails when either embed has drifted: the dashboard's
(`packages/dashboard/src/lib/governance-frameworks.generated.ts`) and the compliance
report's control-mapping section (`supabase/functions/_shared/governance-frameworks.generated.ts`).
`--write` regenerates both. The dashboard test suite runs the same checks.

## 2. Governance scorecard (dashboard → Governance)

Owners and admins open **Governance** (`/governance`). The page is computed by the
`governance_scorecard(p_tenant_id, p_days)` database function from the workspace's
own records, for a 7, 30 or 90 day window of whole UTC days. It returns counts,
enums, versions and dates; no prompt text, event payloads, policy bodies or page
addresses. The function checks that the caller is an active owner or admin of an
active workspace and applies the workspace's sign-in policy (MFA, single sign-on,
session revocation) before reading anything.

| Panel | What it shows |
| --- | --- |
| Top risks | Items derived from the numbers below (open critical/high incidents, critical posture findings, owners/admins without MFA, approvers to review, held actions that expired, MCP servers not approved, missing or stale runtime policy, short or missing retention, acceptable-use coverage). Nothing is listed without data behind it. |
| Framework coverage | Per framework: the share of mapped controls that AIDR supports **and** this workspace has deployed (full = 1, partial = 0.5, customer responsibility = 0), and the share if every mapped capability were deployed. A capability counts as deployed from observable signals, for example agents or browsers reporting in the window, a workspace runtime or DLP policy, MFA required, a retention policy, an acceptable-use acknowledgement. Capabilities that run only on endpoints (MCP gateway, SIEM export) are shown as not visible here. |
| AI usage | Coding agents and browser installs enrolled and active, AI sites seen by Browser Guard, MCP servers reported by inventory scans. |
| Agent decisions | Allowed, held for approval (ask) and denied tool calls per day. |
| Human oversight | Approval requests, approve/deny ratio, median and 90th-percentile decision time, requests that expired without a decision, releases after dashboard or local operator approval (local releases are counted only when a connector reports them), and a per-approver table. |
| Incidents and posture | Incidents reported and still open by severity; CVE, MCP and skill findings. |
| Browser Guard and acceptable use | Sends scanned, masked, warned and blocked; acceptable-use acknowledgements per notice version against active browser installs. |
| Policy freshness | Runtime, DLP and team policy versions and age, revisions in the window, MFA/SSO and retention settings. |
| Framework control matrix | Every mapped control with its coverage, its status in this workspace, capabilities, evidence and note. |

**Human-oversight review prompt.** An approver is marked *Review pattern* when, in the
window, they made at least *minimum decisions* decisions and at least *fast-approval
share* of them were approvals within *fast approval* seconds of the request (defaults:
10 decisions, 90 %, 30 seconds; owners and admins change them under Scheduled
summary). It is a prompt to check for automatic approval (automation bias), not a
finding about the person. Approver identities appear only on this page for owners and
admins; they are left out of the printable export and the e-mailed summary.

**Export.** *Print / save as PDF* and *Download printable HTML* produce a
self-contained A4 document with the scorecard, top risks and the full control matrix.
It is a convenience edition; for signed evidence use the compliance evidence report
(`docs/compliance-report.md`).

**Empty states.** A workspace that has not enrolled agents or browsers sees zeros
labelled as such and a prompt to connect them; a malformed or partial answer from the
server is shown as unavailable, never as zeros.

## 3. Scheduled governance summary

Owners and admins can enable a **weekly** (Monday 06:00 UTC, covering the previous
Monday-to-Monday week) or **monthly** (1st of the month 06:00 UTC, covering the previous
calendar month) summary, sent to the workspace's owners, or owners and admins. The
e-mail carries counts only: usage, decisions, approvals and oversight counts, incidents,
Browser Guard figures, acknowledgement coverage and policy age. Recipients are resolved
from the workspace membership on the server; no address is accepted from a request.

How it runs:

1. The hourly maintenance run (`scripts/deployment-maintenance.mjs`, systemd timer
   `deploy/maintenance/aidr-export-retention.timer`) calls the `governance-digest`
   Edge Function with the deployment's service credential. A dry run
   (`deployment-maintenance.mjs <dir>` without `--apply`) only counts due summaries.
2. The function claims due schedules under a 15-minute lease, reads the counts-only
   summary, sends one message per recipient through the deployment mailer
   (`RESEND_API_KEY` and `AIDR_MAIL_FROM`; see `supabase/functions/_shared/mailer.ts`)
   and records a delivery receipt (status and counts, no addresses).
3. A failed send is retried by a later run after 30 minutes, at most three times per
   period. After an outage only the most recent completed period is summarised.
4. Without a mail transport nothing is sent and the receipt says `no_transport`; the
   dashboard shows it. *Send a test summary now* sends the last window immediately to
   the same recipients (rate limited, recorded in the admin audit log).

Set `AIDR_DASHBOARD_URL` on the function to include a link to `/governance`. The
maintenance evidence file (`maintenance-evidence.json`) records the dispatch counts
under `governance_digest`; a dispatch failure keeps the run incomplete (exit code 2)
without discarding the retention results.

**Language, executive summary and attachment.** Each workspace chooses the e-mail
language (**English** or **Turkish**, default English) and whether the printable
executive report is attached (default on) under **Executive reports** (`/reports`);
the change needs an AAL2 owner/admin session and is audited as
`governance_report_options.updated`. The message opens with an executive summary
(*Needs attention* or *No action needed*, and up to eight headlines: open critical or
high incidents, incidents without an owner, approvals that expired undecided,
approvers to review, MCP servers not approved, a runtime policy unchanged for more than
180 days, blocked and held actions, masked AI sends) and adds the incident triage
counts (open, acknowledged, resolved, false positive, snoozed, without owner, median
time to close; see `docs/incidents.md`). The function reads them with
`governance_report_context`; when they cannot be read nothing is sent and the period is
retried, as for the summary itself.

The attachment is a **self-contained HTML document** (inline CSS, no scripts or
external resources, `default-src 'none'` content security policy), not a PDF. The
reader opens it in a browser and prints it to PDF. A server-side PDF is not generated:
the standard PDF fonts cannot show Turkish letters (ğ, ş, ı, İ) and the Edge runtime
has no font to embed. Delivery uses the same deployment mailer as before; a mail
transport that does not support attachments must still deliver the message body.

Settings changes are recorded in the admin audit log (`governance_settings.updated`).
When a workspace is offboarded, the summary stops at the offboarding request and the
settings and receipts are deleted with the telemetry phase.

## 3a. Executive reports and team rollup (dashboard → Executive reports)

Owners and admins open **Executive reports** (`/reports`), served by the `reports` Edge
Function (`supabase/functions/reports/index.ts`; shared builder
`supabase/functions/_shared/executive-report.ts`; migration
`supabase/migrations/20261014000200_executive_reports.sql`):

| Part | What it shows |
| --- | --- |
| Executive summary | The same headlines and figures as the scheduled e-mail, for a 7, 30 or 90 day window of whole UTC days, in English or Turkish. |
| Team rollup | One row per workspace where the signed-in user is an active owner or admin (at most 50): agents active, allowed / held / denied actions, masked AI sends, incidents to handle, critical, without owner, approvals pending. Each workspace's sign-in policy (MFA, SSO, session revocation) is checked against the current session; a workspace whose policy the session does not meet is listed by name only, without figures. |
| Printable report | The executive report as a downloadable HTML file (optionally with the team rollup), the same document the e-mail attaches. |
| Scheduled e-mail | Language and attachment choice, the current schedule (set on **Governance**) and *Send a test now*. |

Everything is counts, enums and workspace names: no prompt text, matched values, page
addresses, incident notes or approver identities. A summary that cannot be read or
validated is shown as an error, never as zeros. The executive report is not a
certification or an audit opinion.

## 4. AI acceptable-use notice (AI literacy)

Administrators publish an acceptable-use notice in the Browser Guard managed policy
(key `acceptableUse`; the **Browser Guard** page builds the JSON):

```json
{
  "acceptableUse": {
    "id": "acme-ai-use",
    "version": 2,
    "title": "Using AI at Acme",
    "text": "Do not paste customer records.\n\nCheck AI answers before you rely on them.",
    "url": "https://intranet.example.com/ai-policy"
  }
}
```

- `id`: letters, digits and `. _ : -`, up to 64 characters. `version`: 1 to 999999.
  `title`: up to 120 characters. `text`: plain text, up to 4000 characters, blank lines
  separate paragraphs. `url`: optional, `https://` only. A notice with any field out of
  range is ignored as a whole (and reported as an ignored managed key).
- On the first visit to a protected AI site after a version is published, Browser Guard
  shows the notice in its own dialog (closed shadow root, `role="alertdialog"`, focus on
  **I understand**, Tab stays inside, Escape postpones it). The text is rendered as
  plain text, never as markup. The notice informs; it never blocks sending.
- **I understand** is remembered per browser profile. **Remind me later** or Escape shows
  it again on the next page load. Raising `version` shows the notice again to everyone.
- Each acknowledgement is reported once per install and version as a counts-only
  `aup_acknowledgement` event (site, notice id, version; never the text or the user;
  see `docs/contracts/privacy-telemetry.md`). An acknowledgement made while telemetry is
  not configured is not reported later.
- The scorecard shows, per notice version, how many browser installs acknowledged it
  and what share of active browser installs that is.

Coding-agent connectors do not show the notice; it is a Browser Guard feature.

## Limitations

- Everything is computed from telemetry that reached this control plane: offline,
  local-mode and unmanaged endpoints are not represented, and data older than the
  retention window has been deleted.
- Coverage is a product view. It cannot see organisational measures (training,
  policies on paper, contracts, impact assessments) or controls in other tools.
- The approver review prompt is a heuristic over timing; it cannot tell a careful quick
  decision from an automatic one.
- Local operator approvals appear only when the connector reports the release to the
  control plane.
- Scheduled summaries need the deployment's mail transport and its maintenance timer.
