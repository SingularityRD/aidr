# Singularity AIDR — Security FAQ

Answers for security reviewers and procurement questionnaires. Answers point at the
sources or documents they come from. Where something is not in place, the answer says so.
The release decision is **NO-GO** today
([first-customer-ready.md](../production-readiness/first-customer-ready.md)); these
answers describe the implemented design, not an accepted production service.

---

## Data flows

### What leaves the device by default?

In the default `local` mode, **detection needs no network access**. Agent connectors
evaluate tool calls in-process against the bundled rules; Browser Guard scans and masks in
the browser. Outbound flows exist only when they are enabled:

| Flow | Default | What is sent | Reference |
| --- | --- | --- | --- |
| URL reputation | Off | The URL (host and path; query only if enabled) | [privacy.md](../privacy.md) |
| Package / file reputation | Off | Package names, versions, registry metadata; SHA-256 file hashes | [privacy.md](../privacy.md) |
| Version check | Off | Version, runtime, OS/arch, random installation ID | [privacy.md](../privacy.md) |
| Managed agent telemetry | Off (managed mode + key) | Verdict events after credential redaction; tool summaries and artifacts hashed by default | [privacy.md](../privacy.md) |
| Browser Guard telemetry | Off (needs control-plane URL + key) | Site, action, channel and per-type counts only | [privacy-telemetry.md](../contracts/privacy-telemetry.md) |
| AI Security Posture upload | Off (explicit `--upload` on `aidr scan` / `aidr discover`, enrolled API key) | Identifiers and digests only: CVE/GHSA id, severity, CVSS, component and version, MCP risk category codes, skill rule ids and T01–T09 codes, SHA-256 digests. Never target URLs, host names, file paths, matched text, MCP commands or credentials | [ai-security-posture.md](../ai-security-posture.md) |
| AI Security Posture deep scan | Explicit command | Target and options to the configured deep-scan bridge (loopback by default) | [privacy.md](../privacy.md) |
| Diagnostics (Sentry) | Off | Scrubbed error events, only with an explicit opt-in and DSN | [privacy.md](../privacy.md) |

### Are prompts, source code or files uploaded to SingularityRD?

No. Local heuristics do not upload source files, file contents or full prompts. Browser
Guard never sends prompt text, masked text, detected values or page URLs in telemetry.
Where the control plane runs on-prem, telemetry goes to the customer's server, not to
SingularityRD.

### What does the AI provider (ChatGPT, Gemini, Claude…) receive when Browser Guard is on?

The prompt with detected values replaced by placeholders such as `[EMAIL_1]` or
`[TCKN_1]`. The placeholder-to-value mapping lives only in the page's content-script
memory. It is not written to extension storage or sent anywhere, and a page reload
forgets it. Undetected data is sent as typed; detection is not perfect and has not been
measured on customer data. Binary files (PDF, DOCX, images) cannot be inspected in the
browser: `block` mode stops them, other modes let them through with a warning.

### What does the optional native host receive?

If an administrator enables it, Browser Guard sends prompt text to the AIDR Privacy
native host, a process on the same endpoint, for NER. It does not leave the device
through this path. See [native-host.md](../../packages/browser-guard/docs/native-host.md).

---

## Enforcement and failure behaviour

### Is AIDR fail-open or fail-closed?

It depends on the layer, and we state each one:

- **Connector entry points fail closed.** Claude Code, Cursor/VS Code, OpenClaw,
  OpenCode and Codex return a deny on an internal error. Plugin initialisation failures
  register a deny-all handler instead of leaving the host unguarded.
- **Browser Guard's content script fails closed.** A missing policy, unreadable editor,
  scan error or incomplete scan blocks the send (except in `monitor` mode).
- **Detection internals** skip a failing signal, log it and continue. A skipped signal
  is never reported as a clean result.
- **Security controls** (authentication, tenant isolation, rate limits, webhook
  signatures, approvals) fail closed.
- **The host has the last word.** If a host does not invoke a hook (disabled, untrusted,
  killed), the action proceeds. Codex documents this for untrusted or crashed hooks.
  AIDR is a guardrail at the hook boundary, not endpoint isolation.

### Can a compromised or prompt-injected agent approve its own block?

No. `ask` is a block pending out-of-band human approval. No connector exposes an
approval tool to the agent, and MCP Gateway approvals are a separate operator command,
never an MCP tool or HTTP endpoint.

---

## Encryption and signing

- **In transit:** HTTPS/TLS to the control plane. On-prem, TLS terminates at the
  customer's ingress; the generated stack binds services to loopback.
- **At rest:** relies on the storage encryption of the hosting environment: the
  managed database provider for cloud, the customer's volumes for on-prem. Confirm it
  for the approved region.
- **Signing:** Ed25519 signatures on release artifact manifests, runtime policy, tenant
  detector bundles, rule/intel packs, the offline license and (optionally) local audit
  entries. Signing private keys are never distributed to endpoints.
- **Credentials:** tenant API keys are stored as hashes only. The CLI stores its
  credential in the OS vault by default; a reduced-protection file fallback must be
  selected explicitly.

---

## Tenancy and access control

- Multi-tenant control plane on Postgres with **row-level security** on tenant tables.
  Policies use `app.is_tenant_member(tenant_id)` and role-aware variants; anonymous users
  get no write access.
- Roles (owner, admin, member, viewer) with audited role transitions.
- Device enrollment uses short-lived device codes (start, verify, poll); a device gets a
  signed configuration bound to its tenant.
- Cross-tenant negative tests run against Postgres in the repository (for example
  `scripts/tenant-lifecycle-rls-postgres.test.mjs`). A live two-tenant test on an
  accepted deployment is still open (FCR-05).

## Identity: SSO and SCIM

- **SSO:** Microsoft Entra ID via OAuth and SAML 2.0 identity providers; MFA and recovery
  codes for local accounts.
- **SCIM:** user and group provisioning endpoints (`supabase/functions/scim`).
- Live acceptance with the customer's IdP (Entra ID, Okta or other) is required per
  deployment.

## Audit

- **Endpoint:** JSONL audit log with size-based rotation; an optional tamper-evident mode
  chains SHA-256 hashes and signs entries with Ed25519.
- **Control plane:** tenant events, incidents and administrative actions (enrollment,
  invitations, role changes, policy publication) are recorded. Audit export produces
  JSONL/CSV through short-lived private downloads with signed pagination cursors.
- **SIEM:** delivery in a portable `aidr.siem.event/v1` schema for Splunk, Microsoft
  Sentinel and Elastic ingestion.

## Retention and deletion

- Telemetry is pruned per tenant according to the tenant's retention policy.
- Legal holds block routine retention and offboarding deletion for the held tenant.
- Tenant offboarding removes tenant data with recorded authorizations; export objects
  cannot be deleted directly.
- Endpoint audit logs are retained locally by size (5 MiB active file, three rotated
  backups by default).
- Retention periods for a hosted tenant are set in the customer agreement.

## On-premises and air-gapped

The full control plane can run in the customer's environment on Docker Compose or
Kubernetes (Helm), and air-gapped with a signed offline license and signed offline packs.
With the control plane on-prem, no telemetry is sent to SingularityRD. See
[onprem.md](../deployment/onprem.md).

## Privacy regulations (KVKK, GDPR)

AIDR is **designed to support** KVKK and GDPR obligations: data minimisation (local
detection, counts-only telemetry, hashed artifacts), masking of personal data before it
reaches third-party AI providers, tenant-scoped retention and legal holds, deletion on
offboarding, and an on-prem option for data residency. Using AIDR does not by itself make
an organisation compliant. A DPA, subprocessor list and regional hosting terms are part
of the open commercial gates (COM-002, COM-003, COM-011).

Owners and admins can generate a **compliance evidence report** for up to 366 days from
the dashboard (**Compliance**): coverage, counts-only data-protection activity, policy
versions and digests, access and identity, incidents, AI security posture, the data-flow
inventory and retention/deletion evidence, sealed with a SHA-256 and optionally an
Ed25519 signature that `aidr compliance verify` checks offline. It is evidence for your
DPO and auditors, not a certification. See [compliance-report.md](../compliance-report.md)
for what each section proves and what it does not.

## Certifications and assessments

**None.** AIDR has no SOC 2 report, no ISO 27001 certification and no completed
independent penetration test. An independent security review is a release gate
(SEC-EXT-001) and has not been done. We do not give dates for certifications we have not
started.

## Vulnerability reporting and support

The dashboard's public `/security` page is where the security contact is published; its
destination is not configured yet. A monitored support channel with named owners and response targets is a release
prerequisite (FCR-06/08) and is not yet in place.

## Related

- [Privacy and telemetry data flow](../privacy.md)
- [Compliance evidence report](../compliance-report.md)
- [Product overview](../product/overview.md)
- [SaaS deployment](../deployment/saas.md) · [On-prem deployment](../deployment/onprem.md)
