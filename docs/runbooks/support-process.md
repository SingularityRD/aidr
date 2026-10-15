# Support process: intake, severity, secure diagnostics and on-call

> **DRAFT — business approval and staffing required.** This is how Support will
> run once it exists. Today there is **no** staffed ticket desk, on-call rota,
> approved SLA or published support address
> ([support diagnostics](../support-diagnostics.md#support-channel)). Do not tell
> a customer that any of the channels below are live until the
> [activation checklist](#7-activation-checklist-needs-a-human) is complete.
> Customer-facing targets are in the [SLA draft](../legal/sla.en.md)
> ([Türkçe](../legal/sla.tr.md)); the detailed security-update and EOL
> procedure is [support-v7.md](support-v7.md). Version: draft 0.1, 14 October 2026.

## 1. Severity levels

One scale for the customer, mapped to the internal scale used by
[support-v7.md](support-v7.md) and the [incident response runbook](incident-response.md).

| Customer severity ([SLA](../legal/sla.en.md#2-severity-levels)) | Internal | Security incident | First action |
|---|---|---|---|
| 1 — Critical | P0 | SEV1 | Page primary on-call immediately; open the restricted incident timeline if security-related; name an incident commander |
| 2 — High | P1 | SEV2 | Primary on-call within coverage hours; promote to 1 on evidence of broad impact or exploitation |
| 3 — Medium | P2 | SEV3 | Owning team queue; patch decision tracked |
| 4 — Low | P3 | — | Support queue |

Two shortcuts that always apply:

- **Fleet-wide denies after a change** (update, policy publication, pack
  import) are Severity 1 even when the customer reports them as a nuisance:
  every developer is blocked. The first mitigation is to roll back the change
  (policy rollback in the dashboard, previous pack, previous installer), never
  to tell the customer to switch AIDR off.
- **Anything that suggests a bypass, a forged signature, cross-tenant access or
  a leaked key** is a security case: restrict it, page the security lead, and
  follow the [incident response runbook](incident-response.md).

## 2. Ticket intake

Channels (once live): ticket portal, `<support e-mail>`, and for Severity 1
under `CRT` the on-call phone. Every case, whatever the channel, ends up as one
ticket with an **opaque case ID** (`AIDR-CASE-YYYY-NNNNNN`).

The intake form asks for:

| Field | Required | Note |
|---|---|---|
| Customer and authorised contact | Yes | Checked against the Order Form contact list |
| Proposed severity and business impact | Yes | Support confirms or changes it with a reason |
| Deployment: on-prem / air-gapped / hosted; control-plane version | Yes | From `deployment.json` or the dashboard |
| Affected endpoints: OS, AIDR version, AI agent host and version | Yes | From `aidr status` |
| What happened, expected vs actual, since when, what changed | Yes | |
| `actionId` or rule ID from the block message | If a block | Lets us find the verdict without the command text |
| Diagnostics | No | Only through §3; the form rejects attachments other than a verified bundle |

The form and the first reply tell the customer **not** to send credentials,
API keys, prompts, source code, customer data, raw logs or screenshots of
them. If they arrive anyway: delete them from the ticket, note the deletion,
and ask the customer to rotate any credential that was sent.

Triage within the response target: confirm severity, assign an owner, reproduce
on the same version with a benign fixture where possible, give the customer
the case ID, the impact as understood, any proven mitigation and the next
update time.

## 3. Secure support-bundle upload

Two collectors exist, both read-only and local; neither uploads anything:

| Collector | Where | What | Procedure |
|---|---|---|---|
| `aidr support-bundle` | Endpoint | Redacted archive: versions, doctor checks, hooks, config with secrets removed, recent verdict metadata, rule hashes | [support diagnostics](../support-diagnostics.md) |
| `scripts/support-bundle.mjs` | On-prem control-plane host | Allowlisted deployment summary with a consent manifest | [support-bundle.md](support-bundle.md) |

Upload procedure:

1. **Consent first.** The ticket records which bundle is requested, why, who at
   the customer approved it, and when. Use the case ID as the consent
   reference; it contains no personal data.
2. **Customer creates and reviews the bundle.** Endpoint: `aidr support-bundle
   --out ./AIDR-CASE-....tar.gz` and open it before sharing. Server: run the
   collector with `--customer-consent --consent-reference <case ID>`, then
   `node scripts/verify-support-bundle.mjs <dir>`.
3. **Customer encrypts it to the case key.** Support attaches a per-case
   public key to the ticket (age or OpenPGP; one key pair per case, private
   half only on the support engineer's managed device). The customer encrypts
   the archive to that key and records its SHA-256 in the ticket. Never e-mail
   an unencrypted bundle.
4. **Upload to the per-case drop.** The portal issues a single-use upload link
   bound to the case, valid for [72] hours, size-limited, HTTPS only, with
   storage in [Turkey / the customer's agreed region]. Air-gapped customers
   hand the encrypted file over on approved media or use their own approved
   file-exchange system; the procedure is the same.
5. **Support verifies.** Compare the SHA-256 with the ticket, decrypt on the
   managed device, re-run the verifier for server bundles, and review for
   anything that should not be there. If something sensitive is present, stop,
   delete, and tell the customer.
6. **Retention and deletion.** Keep the bundle only in the case store; delete
   it, the decrypted copy and the case key within [30] days of case closure
   (DPA §11) and record the deletion in the ticket. Grant any remote access
   just in time, with MFA, a named reason and an expiry, and revoke it at
   closure.

## 4. On-call

| Role | Duty | Coverage |
|---|---|---|
| Primary on-call engineer | Acknowledges pages, triages Severity 1–2, starts mitigation | Per support level ([SLA](../legal/sla.en.md#3-response-targets-proposals)) |
| Backup on-call | Takes the page if primary has not acknowledged in [15] minutes | Same |
| Incident commander | Owns Severity 1: decisions, customer updates, timeline | Named per incident (security lead for security cases) |
| Security lead (PSIRT) | Vulnerabilities, key compromise, data exposure | On call for SEV1 |
| Release engineer | Rollback, emergency signed release | Best effort outside hours; on call for `CRT` customers |

Rules:

- Weekly rotation, handover on [Monday 10:00 TRT] with a written handover note
  (open cases, risks, pending updates).
- A page that is not acknowledged escalates to backup, then to the support
  manager; a silent handoff does not stop a clock.
- Customer updates go out at the cadence in the SLA even when there is no news
  ("no change; next update at ...").
- After every Severity 1: a written post-incident review within [5] business
  days, shared with the customer without secrets.
- Paging tool, phone bridge and status page are chosen and tested before the
  first `ADV`/`CRT` contract is signed.

## 5. Common first answers

| Symptom | First step |
|---|---|
| "AIDR blocks a normal command" | Ask for the `actionId` and rule ID; check whether it is a known false positive; offer a narrow exception (dashboard Detection exceptions or allowlist) for the exact case, never a broad disable |
| "Everything is blocked" | Severity 1 if fleet-wide. Check for a recent policy/pack change and roll it back; check `aidr doctor` on one endpoint (release key, clock, policy) |
| "Enrollment fails" | `aidr doctor`; TLS chain and internal CA; proxy; clock skew (the doctor's clock check); seat capacity |
| "Dashboard down (on-prem)" | `node scripts/deployment-doctor.mjs --deployment /srv/aidr --online`; endpoints keep enforcing locally meanwhile |

## 6. Drills

Before the first contract with a support level, and every [6] months: run one
synthetic Severity 1 ticket through the whole path (intake, page, backup
escalation, customer update, closure) and validate the receipt with
`node scripts/verify-support-ticket-drill.mjs` as described in the
[support schedule template](../production-readiness/support-sla-template.md).

## 7. Activation checklist (needs a human)

- [ ] Ticket portal and support e-mail chosen, configured and reachable from a
      customer network; test ticket opened and closed.
- [ ] Per-case upload drop and per-case encryption keys working; deletion job
      tested.
- [ ] On-call rota with at least two named people; paging tool tested.
- [ ] SLA and support levels approved by Legal and the business owner.
- [ ] Status page and security contact published; `security.txt` live.
- [ ] Drill receipt recorded for the release candidate (COM-005).
