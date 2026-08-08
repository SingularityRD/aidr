# Privacy, Licensing and Legal Review — Template

Status: **DRAFT / NOT APPROVED**
Release scope: proprietary first-party AIDR + preserved third-party/vendor notices.

## Licensing and notices

| Item | Evidence / status |
|---|---|
| First-party terms | LICENSE draft; counsel approval **not held** |
| Root/package metadata | All first-party workspace packages declare `Proprietary`; stale docs/plugin text must be reconciled |
| Product notice | NOTICE reviewed and references third-party bundle |
| Third-party bundle | THIRD_PARTY_NOTICES + lockfile-derived SBOM/notice archive **not held** |
| Threat rules | DRL 1.1 in `threats/LICENSE`; attribution propagation **not held** |
| AIG vendor | Vendor LICENSE/NOTICE and “Based on Tencent Zhuque Lab AI-Infra-Guard” attribution |
| Chain of title | Source/vendor/contributor records **not held** |

## Data-flow and privacy review

| Data class | Source / purpose | Destination/region | Retention/deletion | Approval |
|---|---|---|---|---|
| Commands/tool inputs | Runtime protection and audit | | | |
| URLs/paths/prompts | Detection and incident evidence | | | |
| Managed events/incidents | Dashboard and support | | | |
| AIG scan payloads/results | Deep scanning and evidence | | | |
| Sentry/traces/browser telemetry | Reliability/security diagnostics | | | |
| Support artifacts/exports | Customer support and PoV | | | |
| Backups/queues/caches | Reliability and recovery | | | |

## Legal approvals

- [ ] Controller/processor/service-provider role approved per deployment mode.
- [ ] EU/US/APAC placement and cross-border transfer mechanism approved.
- [ ] Subprocessor list, DPA/TOM/SCC and change-notice process approved.
- [ ] Numeric retention, deletion, export, backup expiry and legal-hold behavior approved.
- [ ] Privacy claims match payload assertions and Claim Registry.
- [ ] MSA, Order Form, SLA/support, vulnerability disclosure and acceptable-use terms approved.
- [ ] Counsel signs the exact Release Candidate/version and evidence hash.
