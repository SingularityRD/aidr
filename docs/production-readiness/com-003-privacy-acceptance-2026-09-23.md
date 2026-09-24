# COM-003 privacy/DPA acceptance handoff — 23 September 2026

**Decision: OPEN.** This is an engineering-to-Privacy/Legal handoff, not a DPA, a privacy notice, a legal opinion, or approval to process customer data. It does not change the [commercial gate receipt](./commercial-gate-receipts.json) or authorize a sales claim. Approval must bind to the exact signed release candidate and each deployment profile actually offered (AIDR cloud and customer on-prem).

## Verified local state

- The [user-facing engineering description](../privacy.md) distinguishes local processing from optional managed telemetry, reputation, deep scan, diagnostics, update checks and notifications. It explicitly disclaims DPA status.
- The [source-grounded data-flow register](./data-flow-privacy-v6.md) identifies principal paths and says it is neither a deployed egress capture nor regional/retention proof.
- The [machine-readable matrix](./privacy-data-flow-matrix.json) retains open flow rows and explicit unknowns. `pnpm verify:commercial-compliance` passed on 23 September 2026 with an open matrix. That result validates template consistency only; it does not measure or accept the flows. Rerun it after inventory changes and use its current counts rather than this dated snapshot.
- The [local privacy canary](../../scripts/privacy-verify.mjs) tests selected redaction and support-bundle boundaries. Even a `LOCAL_PASS` leaves field acceptance and legal approval open. Its existing evidence must be regenerated against the final candidate; no current production packet capture is asserted here.
- The [retention/hold protocol](./retention-holds.md) documents database/Storage authorization and its limits. A Storage absence check is not proof of erasure from replicas, caches, offsite backups or third-party processors. Financial offboarding and trial-claim changes under development require their own final migration and end-to-end acceptance before this handoff can be signed.

## Complete the deployed data map

For **each** cloud and on-prem configuration being sold, the Privacy owner must inventory every observed source-to-destination path, not only the current template rows. In particular, examine authentication and email delivery; legal/trial acceptance records; billing checkout, provider webhooks, invoices and refunds; enterprise IdP/SCIM; hosting logs, CDN and edge functions; queue and backup copies; support access; exports; and optional AIG, reputation, Sentry, SIEM and response webhooks. A disabled optional path needs a configuration and negative-network-test receipt; a configured path needs a redacted field-level payload capture.

For every path record the exact host/provider, fields (including identifiers and free text), trigger, purpose, customer/AIDR role, region and backup region, access roles, storage and transfer path, retention start/end, deletion owner, subprocessor, and evidence location. Do not fill `unknown` with a modelled provider or generic region. Keep separate records when cloud and on-prem responsibilities differ. Attach the network and persistence observations to the release-candidate digest, environment, configuration and timestamp; preserve failures and unexpected destinations.

## Required acceptance receipts

| Owner | Evidence required before COM-003 can close |
| --- | --- |
| Engineering + Privacy | Final-candidate data map with no unresolved mandatory fields; instrumented payload and egress captures for all enabled paths, opt-out tests for disabled paths, and field-level assertions for server, browser and endpoint diagnostics. |
| Operations + Security | Actual provider/region/subprocessor inventory; access-control and encryption/key-custody evidence; regional routing and cross-region negative tests; queue, database, Storage and offsite-backup retention schedules. |
| Customer Success + Operations | Real tenant export and offboarding receipts, including held and non-held cases, local endpoint/queue cleanup, support artifact removal, backup expiry or documented legal exception, and third-party provider requests/confirmations. A local SQL receipt alone is insufficient. |
| Privacy/DPO + Legal | Approved customer-facing notice, controller/processor responsibility schedule for both delivery models, DPA and technical/organizational measures, applicable transfer documentation, subprocessor/change-notice process, approved retention and deletion/DSAR wording. Record named approvers, effective version/date and exact candidate digest. |

The [privacy/legal template](./privacy-legal-review-template.md) remains unsigned. The [COM-003 receipt](./commercial-gate-receipts.json) must remain `open` until the named approvers link the final evidence and review all limitations. No repository validator, synthetic canary, draft DPA wording or absence of observed traffic alone substitutes for that approval.
