# Compliance evidence report

The compliance evidence report is a tenant-scoped, period-bounded JSON document that a
security or data-protection (DPO) team can hand to an internal or external auditor. It
collects, from the records Singularity AIDR already holds, the evidence that is usually
asked for during KVKK and GDPR accountability work: what is protected, what the product
did with personal data and secrets, which policies were in force, who can administer the
workspace, what incidents occurred, and how retention and deletion are applied. It
also carries the product's **control mappings** to ISO/IEC 27001:2022 Annex A, the BDDK
information systems and electronic banking regulation, the Presidency's Information and
Communication Security Guide and the other frameworks in `governance/frameworks/`.

> **What it is not.** The report is designed to *support* KVKK and GDPR accountability.
> It is not a certification, an audit opinion or legal advice. It does not state that
> your organization, your deployment or Singularity AIDR is compliant with any law or
> standard. Conclusions about compliance remain with your DPO, counsel and auditors.
> The control mappings are the vendor's mapping of product capabilities; they are not a
> certification, a regulatory approval or an audit result.

- Edge Function: `supabase/functions/compliance-report/index.ts`
- Shared schema and integrity code: `supabase/functions/_shared/compliance-report.ts`
- SQL: `supabase/migrations/20260926000030_compliance_report.sql`
  (`public.compliance_report_evidence`, `public.record_compliance_report`)
- Dashboard: **Compliance** (`/compliance`), owners and admins only
- Offline verification: `aidr compliance verify <report.json>`

## Who can generate a report

| Control | Behaviour |
| --- | --- |
| Role | Active **owner** or **admin** of the workspace. Members, viewers, expired and just-in-time support memberships are refused. |
| Step-up | The session must be at **AAL2** (multi-factor), even when the workspace MFA policy is optional. |
| Identity barrier | Session revocation, a required SAML provider and the workspace MFA policy are enforced first. |
| Workspace state | The workspace must be `active`. |
| Rate limit | 3 reports per minute per user, 6 per minute per workspace. An unreadable counter refuses the request. |
| Period | At most **366 days**, not before 2020-01-01 and not ending in the future. |
| Receipt | Each issued report is appended to the admin audit log as `compliance_report.generated` (report id, period, SHA-256, signing key id) **before** it is returned. If the receipt cannot be written, no report is returned. |

The SQL function repeats the role and workspace checks under row locks, so a demotion or
closure that races the request cannot slip through. Both functions are executable by the
service role only.

Every control fails closed: an unreadable membership, assurance level, rate-limit
counter, evidence row, signing key or audit receipt produces an error, never a partial
or unsigned report.

## How to generate and download

1. Open **Compliance** in the dashboard (visible to owners and admins).
2. Pick a period: last 30, 90, 180 or 365 days, or a custom range of whole UTC days.
3. Press **Generate report**. The browser recomputes the report's SHA-256 before showing
   anything; a response that does not match its own digest is rejected.
4. Download:
   - **JSON**: the authoritative, verifiable artifact.
   - **CSV bundle (.zip)**: one CSV per section table, plus `README.txt` with the report id
     and digest. Built in the browser from the JSON; not signed. Values that a spreadsheet
     would execute as a formula are prefixed with `'`.
   - **Printable report** in **English or Turkish**: a self-contained HTML page with print
     CSS. Use **Print / save as PDF**, or download the HTML. It is derived from the JSON.

API form:

```http
POST /functions/v1/compliance-report
Authorization: Bearer <AAL2 user session>
Content-Type: application/json

{ "tenant_id": "<uuid>", "from": "2026-06-27T00:00:00Z", "to": "2026-09-25T00:00:00Z" }
```

The response is `{ "ok": true, "report": { ... } }`. Errors are machine-readable codes:
`mfa_required`, `compliance_role_insufficient`, `workspace_forbidden`,
`workspace_not_active`, `rate_limited`, `invalid_period`, `period_too_long`,
`period_in_future`, `compliance_evidence_invalid`, `compliance_signing_unavailable`,
`compliance_audit_unavailable`, `compliance_report_unavailable`.

## Report structure

```text
schema            "aidr.compliance-report/v1"
report_id         random UUID, also in the audit receipt
generated_at      database time of the evidence snapshot
generated_by      { user_id, role }
period            { from, to, days }   (from inclusive, to exclusive)
statement         the "what this is / is not" text above
sections          ten sections, below
limitations       fixed list of what the report cannot show
integrity         { canonicalization, hash_algorithm, hashed_scope, sha256, signature }
```

## Sections: what each one shows and what it does not prove

| Section | What it shows | Can support evidence for | What it does **not** prove |
| --- | --- | --- | --- |
| `tenant_profile` | Workspace id, name, kind, status, hosting region (when recorded) and default retention days. | Identifying the controller workspace and where it is hosted. | That the region matches your contracts; a missing region means it was not recorded. |
| `protection_coverage` | Agents and browser installs by runtime: enrolled, active in the period, first enrolment, last seen. | Scope of the technical measure; which endpoints were covered. | That every device in your organization is enrolled. Unmanaged and local-mode endpoints are invisible to the control plane. |
| `data_protection_activity` | Browser Guard scans masked, warned, blocked and allowed, by entity type (TCKN, IBAN, e-mail, secret and so on), AI site, channel and day; managed browser policy ids reported by installs. Agent runtime decisions (allow/ask/deny) by source, with the DLP/prompt-protection subset. **Counts only.** | Operation of data-minimisation and security-of-processing measures (for example GDPR Art. 25 and 32, KVKK Art. 12). | That no personal data ever reached an AI service: a masked send still sent the redacted text, `monitor`/`allowed` sends went unchanged, and unreported browsers are not counted. |
| `policy_inventory` | DLP policy version, SHA-256 digest and rule/label/exception counts; runtime policy version, digest, default actions and list sizes; team policy digest; revisions in the period; the approval model (`ask` is an out-of-band human approval, never an agent-callable tool). | Which configuration was in force and when it changed (change management). | What the rules contain. Bodies are deliberately excluded; compare the digest with your own policy export if you need to prove content. |
| `access_identity` | MFA required, SSO required, break-glass enabled; SCIM token and provisioning counts; members by role; the owner/admin list (user id, e-mail, role, joined, expiry, whether a verified MFA factor exists); admin audit actions in the period by type. | Access control and periodic access-review evidence. | Who else has infrastructure or database access outside the product (hosting provider, on-prem operators). |
| `incidents` | Security incidents in the period by severity and status; plugin scans with findings. | Incident awareness and handling volume. | Whether an incident was a personal-data breach, or whether notification duties (72 hours under GDPR, KVKK Board notification) were met. |
| `ai_security_posture` | Reported CVE findings by severity (distinct CVEs, confirmed applicability, maximum CVSS), MCP server findings by attestation state, transport and risk category, skill/plugin findings by risk type. | Vulnerability management of the AI tool chain. | That the scans were complete or recent across your whole estate. Only uploaded scans are counted. |
| `data_flows` | The product's privacy data-flow matrix (purpose, destination, region, subprocessor, lawful basis, retention, deletion, transfer mechanism) with its SHA-256, the list of named subprocessors and the number of open unknowns. | Input for your records of processing activities and transfer assessment. | Your actual deployment's flows. Values marked `unknown` must be completed per deployment; the matrix is embedded at build time from `docs/production-readiness/privacy-data-flow-matrix.json`. |
| `control_mappings` | `kind: "vendor_mapping"`, a fixed statement, the mapping source and its SHA-256, and per framework (NIST AI RMF, ISO/IEC 42001, EU AI Act, KVKK/GDPR, ISO/IEC 27001:2022 Annex A, BDDK `bddk-bsebh`, Presidency guide `cbddo-big`) every mapped control with its coverage (`full`, `partial`, `customer-responsibility`), the product capabilities that support it, its evidence sources (report sections, tables, functions) and a note on the limit of that support. BDDK and guide rows use topic codes (`BSEBY-*`, `BIG-*`) that you map to the article or measure numbers of the text you apply. The section is the same for every workspace: it describes the product, not this workspace's deployment (see **Governance** for what this workspace has deployed). | Building a Statement of Applicability or a regulatory gap analysis for AI tool use; showing an auditor which product measure and which evidence answers which control. | That any control is met. The mapping is the vendor's; applicability, implementation and the conformity assessment are yours and your auditor's. |
| `retention_deletion` | Retention days per data class, whether backups are covered, the oldest retained telemetry event and whether it is within the telemetry window (1-day grace), legal-hold state and counts (no reasons), offboarding runs with phase receipts and deleted row counts, audit exports created, stored and pending clean-up. | Storage limitation and deletion evidence. | Deletion from backups (governed separately), or per-run retention job receipts (retention jobs are deployment-level; the report shows their effect). |

### Data minimisation in the report itself

The report never contains prompt or tool text, matched values, event payloads, page
addresses, DLP keywords or regular expressions, policy bodies, legal-hold references or
reasons, API keys or tokens, or member e-mail addresses other than the owner/admin
access list. This is enforced three times:

1. The SQL function selects only counts, enums, bounded identifiers, timestamps and
   SHA-256 digests.
2. The Edge Function projects the SQL result through a declarative schema
   (`COMPLIANCE_EVIDENCE_SPEC`). Unknown fields are dropped; a field that breaks its
   pattern (for example a site that looks like a URL) refuses the whole report.
3. A static test walks the published schema and fails if a field name suggests content
   or a free-text field appears outside an explicit allowlist
   (`supabase/functions/__tests__/compliance-report-contract.test.ts`).

## Integrity: hash and signature

`integrity.sha256` is the SHA-256 of the report **without** its `integrity` member,
serialized as `aidr-canonical-json/v1`:

- object keys sorted by UTF-16 code units at every level; arrays keep their order,
- no insignificant whitespace, standard JSON string escaping, UTF-8 bytes,
- `undefined` and non-finite numbers are refused.

Pretty-printing or re-ordering keys therefore does not change the digest; changing any
value does.

When the deployment has a signing key, `integrity.signature` carries an **Ed25519**
signature over the same canonical bytes:

```json
{
  "algorithm": "ed25519",
  "key_id": "compliance-2026-09",
  "public_key_spki_b64": "<DER SubjectPublicKeyInfo, base64>",
  "signed_payload": "canonical_json_utf8",
  "value_b64": "<signature, base64>"
}
```

Without a key the report is hash-only (`signature: null`) and the dashboard says so.

### Verifying a report offline

```bash
aidr compliance verify report.json                                  # hash + embedded-key signature
aidr compliance verify report.json --public-key issuer.pem          # also pins the issuer
aidr compliance verify report.json --public-key issuer.pem --require-signature --json
```

Exit codes: `0` verified, `2` not verified (altered content, missing signature when
required, invalid signature, or signed by a key other than `--public-key`), `1` the file
or key could not be read. The command runs entirely offline.

What each check proves:

- **Hash matches**: the JSON has not been changed since the digest was computed. On its
  own this only detects accidental change: anyone who edits the report can recompute a
  digest.
- **Signature valid against the embedded key**: the content was signed by whoever holds
  that key. An attacker can re-sign an edited report with their own key, so this alone
  does not identify the issuer.
- **Signature valid with `--public-key` pinned**: the report was issued by the holder of
  the operator's signing key and not altered afterwards. This is the check auditors
  should use. Obtain the public key from the operator through a separate channel.
- **Issuance receipt**: the admin audit log entry `compliance_report.generated` records
  the report id and SHA-256, so the operator can confirm that a presented report was
  actually issued (for example through the Team audit export).

A valid signature does **not** prove the underlying records are complete or correct; it
proves who issued the report and that it was not altered.

## Operating the signing key

The signing key uses the same format as the entitlement key, but use a **dedicated**
key so compliance reports and licences can be rotated independently.

```bash
openssl genpkey -algorithm ed25519 -outform DER -out compliance-signing.der
base64 -w0 compliance-signing.der          # AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64
openssl pkey -inform DER -in compliance-signing.der -pubout -out compliance-signing.pub.pem
```

Set both `AIDR_COMPLIANCE_SIGNING_KEY_ID` (for example `compliance-2026-09`) and
`AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64` on the `compliance-report` function.
Setting only one of them is refused as a misconfiguration (HTTP 500
`server_misconfigured`), and a key that cannot sign returns
`compliance_signing_unavailable` instead of an unsigned report. Publish
`compliance-signing.pub.pem` to the people who verify reports. To rotate, issue a new
key id; reports signed with the previous key remain verifiable with the previous public
key.

The on-prem configuration generators (`deploy/helm/generate-secrets.mjs`,
`deploy/onprem/.env.onprem.example`) do not create this key yet. On-prem operators who
want signed reports set the two variables on the functions container by hand; without
them reports are hash-only.

## Limitations

- Counts cover only telemetry that reached this control plane. Offline, local-mode and
  unmanaged endpoints are not represented.
- Telemetry older than the workspace retention window has been deleted, so counts for
  older periods can be lower than what happened.
- The data-flow and subprocessor inventory is the product's engineering matrix; values
  marked `unknown` must be completed for your deployment.
- Retention job runs are deployment-level operations; the report shows their effect
  (oldest retained telemetry), not per-run receipts.
- Backups are outside live-data deletion receipts.
- CSV and printable editions are conveniences derived in the browser; only the JSON is
  hashed and signed.
- The printable Turkish edition translates labels, the statement and the fixed
  limitations; data-flow descriptions come from the engineering matrix in English, and
  control-mapping notes come from `governance/frameworks/` in English (BDDK and guide
  topic titles are in Turkish with an English gloss).
- Control mappings are the vendor's mapping by control or requirement topic; they are
  not a certification, a regulatory approval or an audit result.
