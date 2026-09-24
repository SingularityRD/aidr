# Isolated self-hosted installation acceptance — 2026-09-23

This is a disposable Windows/Docker development rehearsal, not a signed customer release or production acceptance. The prepared manifest records `source_has_changes: true`; later workspace edits and a test-only dashboard rebuild mean its artifact inventory is no longer candidate-bound. Keep the project isolated from the live pilot.

## Reproduce on a free loopback host

Ports 8000 and 8080 must be vacant. `deployment-prepare` requires a new output directory for each run. Run from the repository root in PowerShell; do not reuse the existing `.aidr-deploy` directory:

```powershell
$env:PATH = 'C:\Users\anill\AppData\Local\Programs\DockerDesktop\resources\bin;' + $env:PATH
$id = [guid]::NewGuid().ToString('N').Substring(0, 8)
$installation = ".tmp-test/onprem-$id"
$project = "aidr-onprem-$id"
node scripts/deployment-prepare.mjs --mode self-hosted --output $installation --development --project-name $project --dashboard-url http://localhost:8080 --supabase-url http://localhost:8000 --region self-hosted --tenant-region self-hosted
docker compose --project-directory $installation -f "$installation/compose.yml" up -d --build --wait --wait-timeout 180
node scripts/deployment-migrate.mjs $installation
node scripts/deployment-smoke.mjs $installation
node scripts/deployment-doctor.mjs --deployment $installation --online
```

The smoke runner creates only synthetic users, tenants, keys and policy in that installation; it writes one evidence receipt and refuses a second run against the same directory. On Windows, the online doctor is expected to remain red for host systemd timers and missing TLS/signing/backup/queue evidence. The required checks must stay enabled for production.

## Observed on this machine

| Check | Result |
| --- | --- |
| Generated Compose configuration | Passed with 11 services. |
| Docker first boot | All 11 services running and healthy. |
| Canonical database migration | 77 migrations applied atomically in the prepared snapshot. Later unprepared migrations are not in that manifest. |
| First customer owner | `bootstrap_customer` completed; five seats provisioned. The synthetic password was not retained. |
| Licensed-owner browser | The synthetic owner logged in; policy YAML save, server dry-run and publish v1 passed. DLP correctly required MFA and blocked save without step-up. Test-only migration 30 exposed the selected team's owner email without a directory warning. Switching to a personal/takımless tenant showed no licensed Dashboard/Events/Incidents data. This selectively updated UI/DB is not the full current candidate. |
| Isolated API/tenant/device/policy flow | 72 smoke checks passed after the fixture retained a second active owner before expiring the first. This predates the later operator-bootstrap fixture and enrollment migration; rerun the updated smoke against a fresh prepared snapshot before candidate acceptance. |
| Database readiness regression | Old anonymous `/rest/v1/` probe returned 403. New invoker-only `/rest/v1/rpc/aidr_readiness_probe` returned 200 `{"ok":true}`; anonymous execution permitted, authenticated execution not granted. After a disposable dashboard rebuild, `/readyz` reports database, storage and functions `ok`. |
| Overall readiness | `/livez` 200; `/readyz` 503 because signing, backup, queue and certificate evidence is absent. |
| Online installation doctor | 102 checks passed, one failed (`dashboard readiness`), two host scheduler checks unverified on Windows; overall failed as intended. |
| Cold backup | CLI refused before stopping services because the source is dirty; no backup archive was created and all 11 services stayed healthy. |
| Upgrade/rollback | 29 isolated orchestration checks passed with a fake Docker driver; no real upgrade or independent restore was performed. |
| Host scheduler | Windows cannot verify installation or activation of Linux systemd units. |
| Resource isolation | Docker reports no CPU quota or memory limit on any of the 11 containers. No production sizing follows from this developer host. |

The on-prem installer now installs the backup service's `OnFailure` unit with its timer; eight focused backup lifecycle tests pass. This prevents a missing failure handler from leaving stale green backup readiness after a systemd startup failure.

The endpoint fleet installer now rejects same-digest release directories left incomplete by an interrupted publish instead of nesting a retry inside them. Linux and Windows package gates also preflight the sum of archived regular-file sizes against the 512 MiB expanded limit before extraction; compressed archive limits alone do not prevent disk exhaustion. These are local signed-fixture checks, not customer-host acceptance.

## Bounded two-tenant load rehearsal

The first 60-second run exposed a fixture error, not a capacity result: the harness selected a `viewer` member for the noisy tenant, and the API-key guard correctly returned 403 on all 960 noisy requests. The harness now selects an active `owner`, `admin` or `member` of an active tenant and confirms **both** synthetic keys receive policy HTTP 200 before starting traffic. Its 19 focused load tests pass.

The second 60-second run scheduled 1,200 policy requests at 20 requests/second. All 1,200 responses were expected, with zero unexpected responses, transport errors or dropped requests. The baseline tenant returned 240 HTTP 200 responses (p95 30.1 ms); the noisy tenant returned 599 HTTP 200 and 361 designed HTTP 429 quota responses (p95 29.8 ms). The local workload thresholds passed. Twelve Docker snapshots across that window sampled a peak aggregate 57.93% CPU and 1,802.22 MiB memory; the functions container sampled 14.97% CPU and 823.7 MiB memory. These are sampled values on this developer host, not host-sizing or capacity limits.

The top-level noisy-neighbour gate remained `failed` with `candidate_binding: NOT_PROVIDED` because this dirty, test-modified installation has no signed candidate inventory. The result deliberately does not claim production acceptance, HA, SLA, an eight-hour soak or cross-host isolation. The second run's local artefacts are under `.tmp-test/onprem-ga-20260923/evidence-noisy-valid-20260923/`; the first failing fixture is preserved separately under `evidence-noisy-20260923/`. Both runs revoked their own temporary rehearsal keys.

The current billing page on this older snapshot showed five allowed seats but unavailable portal, settlement ledger and finance reconciliation, plus no configured sales/invoice contact. Later billing/admission migrations and external provider configuration are absent here; this read-only observation neither validates current licensing nor closes billing acceptance. A separate full-migration installation is required.

## Later full-migration rehearsal (still in progress)

A second, independent project at loopback API `18000` and dashboard `18080` started 11/11 services healthy and applied all 94 migrations in its prepared snapshot atomically, through migration 39. `/livez` returned 200. `/readyz` returned 503 with database/storage/functions `ok` and the four absent host evidence legs failed. The updated CLI bootstrapped a separate synthetic owner with five seats, taking its password through stdin and a finite 30-day test license term/reference as arguments without printing the password; this is not an actual customer contract.

The updated smoke failed after 28 checks with PostgreSQL `P0003` during its second synthetic `bootstrap_customer`: Auth had already created an owner team, and the fixture explicitly created another one, while the bootstrap RPC intentionally requires a unique owner team. The fixture was corrected; this failed receipt is preserved in the second project. No full-smoke success, full billing acceptance or candidate-bound claim is made from this project.

A third independent project at loopback API `28000` and dashboard `28080` uses the corrected smoke fixture and a fresh 97-migration snapshot through migration 43. All 11 services started healthy; the canonical migration runner applied all 97 migrations atomically. The live smoke passed **77/77** checks, including a finite licensed operator bootstrap, denial of free-team API keys and enrollment tokens, tenant admission, signed device entitlement, runtime policy/hook enforcement, audit export, reputation checks, suspension/expiry and credential revocation. A separate current CLI bootstrap with a synthetic 30-day license reference and password supplied through stdin provisioned five seats. The password was discarded, not stored in the evidence.

The third project's online doctor reports 122 checks passed, one failure (`dashboard readiness`) and two Windows scheduler checks unverified. Its `/readyz` reports database/storage/functions `ok` but signing/backup/queue/certificate `failed`, so overall HTTP 503 is correct. This is still a dirty source and a synthetic contract on a developer Windows host, not an approved customer install, signed candidate or production-ready deployment.

## Current 98-migration rehearsal and installation defects

The first attempt at an independent 98-migration installation exposed a real `deployment-prepare` defect before migration: custom development loopback URLs were written into runtime configuration, while generated Compose still published fixed host ports 8000/8080. Docker correctly refused the already-allocated 8080 binding. The partially started project was stopped without removing its volumes or evidence. The generator now binds development Compose host ports to the selected loopback origins while keeping production ingress-facing defaults; its focused preparation suite passes 12/12 checks.

A fresh 38000/38080 project then started 11/11 services, atomically applied 98 migrations and bootstrapped a finite synthetic five-seat owner. Its smoke reached the signed device ingress step but failed because the generated bridge still pointed at 8000. The subsequent 48000/48080 project also reached that step and exposed the bridge's strict numeric-loopback requirement: a `localhost` upstream is correctly rejected. The generator now uses `http://127.0.0.1:<published API port>/functions/v1/device-start` for this local route; failed receipts and both disposable projects were preserved, not relabeled as passes.

The new project `aidr-onprem-ga98-58000-20260923` at API `58000` and dashboard `58080` used that corrected generator. All 11 services are healthy, 98 canonical migrations through migration 43 applied atomically, a separate operator bootstrap provisioned five seats with a finite synthetic term/reference, and the live deployment smoke passed **77/77** checks, including signed ingress/device enrollment. Its online doctor reports 123 passes, one failure (dashboard readiness) and two Windows host timers unverified. `/readyz` remains HTTP 503: database, storage and functions are `ok`; signing, backup, durable queue and certificate evidence is absent and therefore failed. Service-role PostgREST confirmed the migration 41 legal cutover: documents are unconfigured, the old two-argument trial RPC is absent, and the new four-argument RPC fails closed with `legal_not_configured`. On the corrected seat view, browser billing showed five allowed/one recorded seats in A and one/one in B; each populated synthetic team had a distinct agent, deny event and incident, and selecting A for B's agent detail returned not found. After a dashboard-only bundle refresh, Team Audit showed B's row and a 383-byte one-action CSV download; switching to A hid B's row/link and showed A's row, with a null actor rendered as `Not recorded`. That later UI check is workspace-only and not bound to the prepared dashboard hash. This 98-migration snapshot remains dirty and unsigned, and it cannot represent later migrations or bundle edits.

A separate sacrificial Auth Admin deletion probe on this same disposable database exposed an unresolved GA blocker. Soft-delete of a synthetic `aidr_trial` account returned HTTP 500 / SQLSTATE `42501 trial_claim_immutable`; the account and claim remained. Hard-delete first hit the active sole-owner tenant guard (`23514`); after exact personal/team offboarding, hard-delete returned HTTP 200 and the account became 404. Both sacrificial accounts are gone, while their four tenants are `closing` with offboarding requested, not fully purged. Hard-delete also removes the account-bound claim, so the current mechanism cannot prevent the same email from starting a fresh trial. This probe did not touch the licensed/browser owner or live data. Auth lifecycle correction and repeat-trial privacy policy need separate acceptance before GA.

## Required customer-host acceptance

Use the exact signed-kit verification and `/srv/aidr` installation sequence in [FIRST_CUSTOMER.md](../../deploy/FIRST_CUSTOMER.md). On the customer's Linux host, record the same signed candidate and manifest digest for the following commands and receipts:

1. Verify the publisher envelope with an independently delivered trust policy, extract into an empty staging directory, run `customer-kit-verify.mjs`, then prepare `/srv/aidr` with approved HTTPS origins, artifact public key, real fleet queue and declared region.
2. Start Compose, apply the canonical migrations, configure TLS and the protected device-start signer, bootstrap the first owner through stdin, and verify login, device enrollment, a blocked malicious action and a benign action on the actual supported host.
3. Install/enable the SIEM/readiness, TLS renewal, retention and backup units. Confirm fresh signing, durable queue, certificate and offsite backup receipts; require the online doctor and `/readyz` to pass.
4. Create and verify an encrypted cold backup with key custody separate from installation and backup. Recover it to a distinct project and volumes; compare database and object storage, then measure RPO/RTO.
5. Prepare a separate clean target, approve the compatibility contract, run upgrade preflight and apply/resume, then rehearse post-migration recovery with the reviewed source runtime as specified in [UPGRADE.md](../../deploy/UPGRADE.md). Test rollback rejection and repeat owner login, enrollment, policy block and audit export before traffic cutover.

This workstation has no approved publisher identity, clean candidate, customer TLS/MDM host, enabled Linux timers, offsite target or independent restore evidence. Those items remain open; local container and mock results cannot close them.
