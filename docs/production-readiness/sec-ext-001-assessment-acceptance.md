# SEC-EXT-001 — independent security assessment acceptance

**Status: OPEN.** No independent assessor has been engaged and no signed assessment or retest report exists. Internal tests, the historical May 2026 source audit, and a passing receipt-shape check are not a penetration test or GA approval.

Freeze one signed Release Candidate first. The Security Lead and assessor must agree a written scope covering tenant isolation/RLS, identity and recovery, each sold runtime connector and response path, cloud and on-prem deployment boundaries, distribution/update provenance, and secret handling. Include the deployed configuration, versions, dates, exclusions, test accounts, permitted attack methods, and a channel for critical findings. The assessor must be independent of implementation and hold report-signing authority outside the repository.

Keep the full signed report and signed remediation/retest letter in restricted evidence storage under the ignored `.release-evidence/` tree. Bind a repository-local JSON manifest to their exact bytes; the `SEC-EXT-001` closed receipt's `evidence_path` points to that manifest and its `evidence_sha256` hashes it. The manifest fields are:

```json
{
  "schema_version": 1,
  "candidate_digest": "<SHA-256 of release-inventory.json>",
  "assessor_name": "<real independent assessor>",
  "scope": ["tenant", "identity", "runtime", "distribution", "secrets"],
  "started_at_utc": "<RFC3339 UTC with milliseconds>",
  "completed_at_utc": "<RFC3339 UTC with milliseconds>",
  "retest_at_utc": "<RFC3339 UTC with milliseconds>",
  "valid_until_utc": "<RFC3339 UTC with milliseconds>",
  "unresolved_critical": 0,
  "unresolved_high": 0,
  "signed_report": { "path": "<path under evidence root>", "sha256": "<SHA-256>" },
  "retest_letter": { "path": "<different path under evidence root>", "sha256": "<SHA-256>" }
}
```

`node scripts/verify-commercial-gate-receipts.mjs` checks the candidate digest, required scope labels, chronology/expiry, zero unresolved critical/high counts, distinct report and retest files, and both file hashes. The receipt must be recorded after retest. This is an integrity and consistency check only: it cannot authenticate a PDF signature, verify the assessor's independence, or prove that declared findings match the report. Security must verify those facts manually against the signed documents and finding ledger, then a separate reviewer approves the exact candidate. Critical findings cannot be waived. A high-finding exception requires documented non-exploitability, named approval and expiry under the registry; the automatic closed-receipt path intentionally remains blocked until the finding is resolved and retested.

Before closure, triage the 296 full-history secret-scan matches without disclosing raw values, rotate confirmed live credentials, rerun the candidate-bound secret/dependency/release gates, and give the assessor the current architecture and data-flow inventories. Any code or deployment change affecting the assessed boundary requires assessor impact review and, when material, a scoped retest. Do not copy a report from an earlier or different candidate into this manifest.
