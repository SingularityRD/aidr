# POV-001 — first-customer acceptance run sheet

**Status: OPEN / NO-GO.** This is a run sheet, not a signed charter, customer result or release approval. As of 23 September 2026 there is no named evaluator, signed Evaluation Charter, independently executed customer run, intervention log or customer acceptance. The local Windows/Docker rehearsal and component tests are engineering evidence only. Keep the [`POV-001` receipt](commercial-gate-receipts.json) open until the exact-candidate external record exists.

## Freeze the evaluation before granting access

Customer and AIDR sign an Evaluation Charter identifying the legal parties and authorized evaluators; exact signed release envelope, source commit, build/deployment digests and expiry; cloud or on-prem environment and region; supported connector, host, OS and version rows; allowed synthetic data and outbound destinations; mandatory versus excluded `VAL-001`–`VAL-025` cases; each case's pass/fail rule, latency/availability limit and sample denominator; baseline policy and safe canaries; permitted assistance; stop and emergency contacts; logging/screen-recording consent; data retention/deletion; defect severity and retest rules; and the two people empowered to sign technical results and commercial reservations. The customer must approve the safe targets. No real credentials, customer source, defence data or production network target may enter an unapproved PoV.

Use an isolated tenant and fresh customer-controlled browser/host. The customer executes the mandatory cases for 2–5 business days after a guided orientation; the guided session is not independent acceptance. Record each intervention, hidden environment reset, deployment or policy change, with UTC time and before/after digests. A changed candidate invalidates earlier passes until the affected and cross-cutting cases are rerun. AIDR operators must not silently repair the environment during a measured run.

## Case worksheet

The [`VAL-001`–`VAL-025` definitions](customer-investor-validation-master-plan.md) give full steps. For **each** case below, predeclare `mandatory / optional / excluded` and its measurable threshold in the charter. An excluded case cannot be advertised as accepted. Capture the exact candidate digest, tenant, host/browser versions, UTC start/end, operator, customer observer, redacted raw result, artefact SHA-256, defects, deviations and result (`pass / fail / blocked / not-run`). `Blocked` and `not-run` are never passes.

| Case | Customer-visible observation and minimum evidence |
| --- | --- |
| VAL-001 onboarding | Fresh sign-in/tenant, short-lived single-use device code; auth and device IDs without a displayed secret. |
| VAL-002 enrollment | Actual host approval/poll/restart, exactly one connected agent; reused and cross-tenant codes rejected. |
| VAL-003 benign twin | Harmless command/file/URL actions complete within charter latency; allowed audit, no false incident. |
| VAL-004 deny/ask twin | Safe malicious canaries give the declared verdict **and independently observed absent side effect**; visible rule and incident. Never execute a real harmful target. |
| VAL-005 approval/policy | Narrow, time-limited approval/allowlist works only for its exact action; changed artefact still blocked; revocation audited. |
| VAL-006 incident | Agent/event/rule/timeline/filter/export correlate; redaction and release/tenant attribution observed. |
| VAL-007 offline | Before/disconnect/reconnect traces show local protection, explicit cloud degradation and no silent/duplicate buffered event. |
| VAL-008 AIG infra | Known vulnerable and patched authorized fixtures yield distinct expected result and incident; no unapproved target scan. |
| VAL-009 AIG MCP | Clean and malicious authorized MCP fixtures, finding/severity, no token leak, cross-tenant denial. |
| VAL-010 AIG outage | Bridge outage makes readiness/scan error truthful; local protection persists; recovery observable. |
| VAL-011 upgrade/rollback | Signed previous-to-candidate update, migrated state, supported rollback/recovery and rechecked golden path. |
| VAL-012 tenant boundary | Two-tenants negative reads/writes across UI/API/DB/object/AIG/queue/exports/telemetry, with actual denials. |
| VAL-013 paid access | Approved order/invoice and/or online checkout **per sold channel** reconcile settlement, seats, finite term, refund/cancel/expiry and revocation; never equate payment with access. |
| VAL-014 export/deletion | Enumerated data, scoped export, actual deletion and explicit legal-hold/backup exceptions with receipt. |
| VAL-015 false positive | Independently labelled benign edge, narrow auditable override, successful retry, malicious non-bypass and override revocation. |
| VAL-016 invitation/RBAC | Invite, supported roles, privilege denial, member removal and stale-session replay; tenant logs. |
| VAL-017 keys | Scope/rotate/revoke API and enrollment credentials; replay/cross-tenant denial and secret-free output. |
| VAL-018 deprovision | Host uninstall and device revoke remove protected status; re-enrollment requires fresh authorization. |
| VAL-019 customer fixture | Customer-authorized fixture hashed before execution; expected verdict frozen before run; no detector tuning mid-run. |
| VAL-020 support | Real customer-visible test ticket, acknowledged/triaged/escalated/closed against the approved schedule; diagnostic consent and redaction. |
| VAL-021 seat lifecycle | Approved order to licensed grant, seat add/remove/over-limit, cancellation and finance-to-enforcement audit without ad-hoc SQL. |
| VAL-022 closure | Access expiry, export, user/device/key revoke, storage/backup exception and signed destruction/deletion receipt. |
| VAL-023 browser crawl | Every declared route/link/auth return path at clean desktop/mobile profiles: correct auth, no loop/console error, version and freshness. |
| VAL-024 enrollment states | Pending/approved/denied/unknown/expired/cancelled/network recovery; bounded polling, masked display, no secret in logs/export. |
| VAL-025 accessibility | Keyboard/focus/zoom/reflow/reduced-motion and automated + NVDA/VoiceOver checks on the deployed candidate; limitations recorded. |

## Evidence and decision rule

For every mandatory case, retain a customer-run record and raw redacted artefacts in an access-controlled, immutable index bound to the **same** release candidate. Include host-side side-effect proof for blocking claims, provider/settlement records for paid claims, and both cloud and on-prem results if both deployment paths are offered. Report the denominator as `passed / mandatory`, plus optional, blocked, excluded and retested counts separately; do not collapse `ask` into `deny` or component tests into live-host passes. Report assisted and unassisted onboarding time, every AIDR intervention and environment deviation, and all P0/P1 defects. Never use synthetic dashboard fixtures as live events.

The customer technical signer and AIDR Product/QA reviewer sign the scorecard, limitations and written reservations. Mandatory cases must be 100% passed, no P0/P1 unresolved, no unlogged intervention or hidden reset, and the customer must accept the result for this candidate. A reservation may narrow the sold scope but cannot waive a mandatory safety failure. Attach the signed charter, run report, intervention/deviation log, limitations, defect/retest record and signed result to the release evidence index; only then may the authorized reviewer update `POV-001` with a non-null evidence path/hash and candidate digest. A successful pre-customer rehearsal can prepare the kit but **cannot** close this external gate.

## Local rehearsal observed, not customer acceptance

On this checkout, the focused synthetic OpenCode AIDR contract passed **8/8** only after the workspace build completed; the dashboard integration suite passed **24/24** with mocked/local data. The first OpenCode attempt failed to import missing `packages/core/dist`; that is a build-order failure, not a threat-detection result. The separate 98-migration disposable self-hosted installation passed **77/77** smoke checks while `/readyz` remained HTTP 503 for absent signing, backup, durable queue and certificate evidence. None of these runs has a signed candidate digest, customer host observation, independent evaluator or PoV acceptance. The [`controlled-demo runbook`](controlled-demo-runbook.md) and [`threat matrix`](../demo/customer-threat-demo-matrix.md) are safe orientation aids, not a substitute for this worksheet.
