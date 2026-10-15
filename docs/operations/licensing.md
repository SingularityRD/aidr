# On-prem and air-gapped licensing

Self-hosted and air-gapped installations are admitted by a **vendor-signed
license file** (`aidr-license-v1`). The license replaces the seat count, expiry
and contract reference that an operator previously typed on the bootstrap
command line: those terms now come from a document Singularity R&D signs, and a
changed seat count or date breaks the signature.

What the license controls, and what it never controls:

| Area | Governed by the license | After expiry + grace |
|------|-------------------------|----------------------|
| Seat admission, device enrollment and control-plane event ingest (`tenant_admission_capacity`) | Yes (`tenant_admissions.expires_at`) | Degraded: capacity drops to 0, so enrollment and agent event ingest are refused and the dashboard stops receiving new endpoint telemetry |
| Local detection on every endpoint (hooks, rules, allowlists, audit log) | **No** | **Keeps enforcing.** Detection never depends on a license, enrollment or network access |
| Accepting **new** signed rule/intel update packs on a licensed endpoint (per-customer builds) | Yes: a pack is accepted only while its signed `issued_at` is within `expires_at + grace_days`, and only if its optional audience names the license's `customer_id` | New packs are refused, also for a license listed in the signed revocation list; rules and packs already installed keep enforcing. See [customer builds](customer-builds.md) and [intel pack releases](intel-pack-releases.md) |
| Signed per-installation entitlement of an enrolled endpoint | No (issued by the control plane) | Missing, invalid or expired beyond its offline grace period: managed-only features stop on that endpoint; local detection keeps deciding every tool call |

This follows the product's enforcement default: a connector evaluates every tool
call locally, and managed features are an opt-in layer on top.

On the endpoint this holds in every build, source and commercial. When the
server-signed entitlement an endpoint holds is missing, invalid, expired past its
grace period or revoked, or the control plane disabled its sync (revoked device,
rejected key, seat limit), the endpoint switches managed features off (remote
policy, telemetry upload, dashboard approvals, paid intel) and keeps deciding
every tool call with its local rules, policy and allowlists: `curl … | bash` and
`rm -rf /` are still denied, and a benign command is still allowed. Each verdict
carries a notice ("Singularity AIDR managed features are off (…). Local
detection is still enforcing on this device.") and the session banner reads
"Local protection ACTIVE (managed features unavailable: …)". There is no
licensing hard stop on endpoints. The only state that holds every call is a
failed artifact integrity check in a commercial build (degraded safe mode,
including a missing release trust key, below), which is a tamper control, not a license control; a local `deny` stays a `deny`
there too. See [configuration: `mode`](../configuration.md#mode).

Separate from licensing, signed release builds verify their own artifacts before they
inspect anything. That needs the release trust key in each endpoint's
`integrity.public_keys_pem` ([Integrity verification](../integrity.md)); without it a
release connector blocks every tool call. Release builds are managed-only (they run in
`managed` mode whatever `config.json` says), so the trust key is part of every
installation, including one that never enrolls.

## What the license can and cannot enforce

License enforcement on a self-hosted or air-gapped installation is
**operator-side**. The customer's operator controls the deployment: the hosts,
their clocks, the files in the deployment directory (including the trust
registry) and the database. Nothing in this design can stop that operator from
running more seats than they bought; it makes doing so deliberate, visible and
attributable instead.

What is checked, and where:

| Check | Where it runs | Who can bypass it |
|-------|---------------|-------------------|
| Signature, key status and window, term cap | `license-verify.mjs` and `deployment-bootstrap.mjs --license-file`, on the operator's host | The operator (replace the registry, edit the scripts, set the clock) |
| Trust root = the vendor-published registry | `deployment-bootstrap.mjs`; a custom `--license-public-keys` is refused unless `--allow-custom-license-keys` is passed, and the receipt records it | The operator, with an explicit, recorded flag |
| Seats and admission end | The database (`tenant_admissions`, `tenant_admission_capacity`) enforces the terms **as written by the bootstrap or an admission operator** | Anyone with database or service-role access |
| Validity dates | The verifier's clock (host clock, or `--now`) | Whoever sets the host clock |

The database does **not** re-verify the license signature: it stores the seats,
admission end and license reference it was given. An admission operator who
calls `grant_licensed_tenant_admission` directly, or anyone with the service-role
credential, can write different terms. What the signed license gives the vendor
and the customer is evidence, not DRM: the license file and its SHA-256, the
bootstrap receipt (trust root, registry digest, any override warning), and the
admission audit log show which terms were applied and by whom. Commercial
remedies (true-up, audit rights) rest on that evidence and on the contract.

In the SaaS deployment Singularity R&D operates the control plane, so the same
database checks are vendor-operated there.

## License format

```json
{
  "format": "aidr-license-v1",
  "key_id": "aidr-license-2026-1",
  "payload": {
    "license_id": "LIC-2026-0042",
    "customer": "Example Customer AG",
    "customer_id": "example-ag",
    "plan_id": "enterprise",
    "seats": 250,
    "features": ["managed_policy", "premium_intel"],
    "deployment": "onprem",
    "issued_at": "2026-09-24T00:00:00Z",
    "not_before": "2026-10-01T00:00:00Z",
    "expires_at": "2027-10-01T00:00:00Z",
    "grace_days": 14
  },
  "sig": "<base64 Ed25519 signature>"
}
```

- `sig` is an Ed25519 signature over `aidr-license-v1\n` followed by the
  canonical JSON of `payload` (keys sorted, no whitespace). Reformatting the file
  is harmless; changing any term is not.
- `deployment` is `onprem` or `airgap`. `grace_days` is 0..90.
- `plan_id` is a catalog plan (`free`, `team`, `business`, `enterprise`), and an
  `airgap` license requires `enterprise` (catalog feature `air_gapped_deployment`):
  `license-issue.mjs` will not sign one for another plan and the verifier refuses
  it with `plan_feature_required`.
- `customer_id` is optional: `^[a-z0-9][a-z0-9-]{1,31}$` (2..32 lowercase
  letters, digits and `-`). It names the customer a per-customer build is made
  for, binds the license to that customer's [customer packet](customer-builds.md)
  and to update packs addressed to that customer, and doubles as a leak-trace
  mark. Licenses issued without it stay valid; a customer packet requires it.
- Unknown fields are refused, so a term this verifier does not understand is
  never silently ignored.

### States

| State | Condition | Managed features | Local detection |
|-------|-----------|------------------|-----------------|
| `not_yet_valid` | before `not_before` | not admitted | enforced |
| `valid` | `not_before` ≤ now < `expires_at` | enabled | enforced |
| `grace` | `expires_at` ≤ now < `expires_at + grace_days` | enabled, with warnings | enforced |
| `expired` | after the grace period | degraded | enforced |

The customer packet verifier and the endpoint report the `valid` state as
`active`; the conditions are the same.

## Trust root and key rotation

The verifier trusts only `deploy/onprem/license-public-keys.json`
(`aidr-license-public-keys-v1`). **The shipped file has no keys**, so every
license is refused until the vendor-published registry for your release is
installed (fail closed). Install the registry delivered with the signed customer
kit and compare its SHA-256 with the value in the release notes.

Each entry is `{ key_id, algorithm: "ed25519", public_key_pem, not_before,
not_after, status }`:

- `active`: signs new licenses.
- `retired`: no longer signs. The entry must carry `retired_at` (inside the
  key's `not_before`..`not_after` window). It still verifies licenses that claim
  `issued_at <= retired_at`, so a rotation does not invalidate licenses already
  delivered, but only until `retired_at + 1920 days` on the verifier's clock
  (the longest possible license life: 1830-day term + 90 grace days). After
  that it verifies nothing (`retired_key_expired`).
- `revoked`: verifies nothing (use after a key compromise, then reissue).

A license names its `key_id`; a key that is unknown, revoked or outside its
window is refused. The registry never holds private keys, and the development
test keys used by the automated tests are generated in memory and never placed
in this file.

### Clock semantics

- `issued_at`, `not_before` and `expires_at` are **signed but signer-chosen**.
  They prove what the vendor issued only while the signing key is uncompromised.
- Every comparison uses the **verifier's clock**: the host clock of the machine
  running `license-verify.mjs` or the bootstrap, or `--now` for audits and
  rehearsals. Nothing is compared against a time the license asserts about
  itself.
- Every license term is capped: `expires_at` is at most **1830 days** after
  `issued_at`, at signing and at verification.
- Together these bound what a leaked **retired** key can do: it can only sign
  licenses that claim issuance before `retired_at`, each such license ends
  within 1830 + 90 days of that claim, and the verifier stops honouring the key
  entirely at `retired_at + 1920 days`. A key known to be compromised must be
  marked `revoked`, which takes effect immediately.
- An operator who controls the host clock controls these checks (see
  [What the license can and cannot enforce](#what-the-license-can-and-cannot-enforce)).

## Verifying a license (customer operator)

```sh
node scripts/license-verify.mjs --license-file /secure-delivery/aidr-license.json
```

The command prints the terms and state as JSON. Exit codes: `0` valid, `2`
grace, `3` expired, `4` not yet valid, `1` refused (malformed, tampered, wrong or
revoked key, or no trusted keys installed). `--public-keys <file>` and `--now
<ISO>` exist for audits and rehearsals.

## Bootstrapping with a license

```sh
printf '%s' "$AIDR_PASSWORD" | node scripts/deployment-bootstrap.mjs \
  --deployment /srv/aidr --email owner@customer.example \
  --license-file /secure-delivery/aidr-license.json
```

The bootstrap verifies the license **before any API call** and derives:

- seats: `payload.seats`;
- license reference: `payload.license_id`;
- admission end: `expires_at + grace_days` (the moment managed features stop);
- tenant name: `payload.customer` unless `--name` is given.

It refuses a license that is tampered, signed by an unknown or revoked key,
not yet valid or past its grace period, and it refuses `--seats`,
`--license-expires-at` and `--license-reference` next to `--license-file`. A
license in its grace period still bootstraps, with a warning. The private
`bootstrap-receipt.json` records `license.source = "signed"`, the license id,
signing key and its status, terms, `managed_until`, the license file's SHA-256,
the trust registry's SHA-256 and whether the shipped registry or an override was
the trust root.

The trust root is `deploy/onprem/license-public-keys.json`. A different
registry (`--license-public-keys <file>`) replaces the vendor trust root, so
whoever writes that file can sign any seat count. The bootstrap refuses it
unless `--allow-custom-license-keys` is also passed; it then prints a warning
and records `trust_root = "override"`, the registry path and SHA-256 and the
warning text (`trust_root_warning`) in the receipt. Use it only for rehearsals
and vendor-supervised recoveries.

### Unsigned pilot terms

Typed terms remain for a time-boxed pilot only, and only with an explicit flag:

```sh
node scripts/deployment-bootstrap.mjs --deployment /srv/aidr --email owner@customer.example \
  --name "Pilot Customer" --seats 5 --license-expires-at 2026-12-31T00:00:00Z \
  --license-reference PILOT-2026-007 --unsigned-license-for-pilot
```

The command prints a prominent warning and the receipt records
`license.source = "unsigned-pilot"`. Do not use it for production or air-gapped
customers.

## Renewal, seat changes and importing a signed license

The bootstrap is a one-time action; it refuses to change the terms of a
completed bootstrap. Renewals, seat increases and true-ups are new signed
license files, applied with a two-person import that keeps the
[admission-operator](admission-operators.md) separation of duty:

1. **A workspace owner or admin stages the file.** Dashboard: **Settings ->
   License -> Import signed license**. The `license-admin` Edge function checks
   the signature against the deployment's trust registry
   (`AIDR_LICENSE_PUBLIC_KEYS_B64`, written by `deployment-prepare.mjs` from
   `deploy/onprem/license-public-keys.json`; Helm: `generate-secrets.mjs`) with
   the server clock. It refuses a tampered file, an unknown or revoked key, a
   license past its grace period and, when `AIDR_LICENSE_CUSTOMER_ID` is set, a
   license for another customer. An accepted file is stored as a **pending**
   import; seats and expiry do not change yet. A renewal that starts later
   (`not_before` in the future) may be staged early.
2. **A platform operator applies it.** Operator console (`/operator`):
   **Signed licence imports -> Load waiting licences -> Apply licence**, or
   **Apply a licence file** for the selected tenant. Air-gapped admins use the
   CLI, which verifies the file locally first and never sends a refused file:

   ```sh
   node scripts/operator-admin.mjs license-imports
   node scripts/operator-admin.mjs license-apply --tenant <tenant-id> \
     --license-file /secure-delivery/aidr-license.json [--import <import-id>]
   ```

   `operator-admin` verifies the document again at that moment (registry, key
   status and clock may have changed) and calls `operator_apply_license`, which
   reads seats, plan, license id and the admission end (`expires_at +
   grace_days`) from the stored signed payload and applies them through
   `operator_grant_license` -> `grant_licensed_tenant_admission`. That path
   still requires the operator's tenant-scoped `admission_operators` row and
   refuses an operator who is a member of the tenant. A license that is not yet
   valid or past its grace period is refused, and one license id can admit only
   one tenant.

Every step is audited (`license.import_submitted`, `license.applied`,
`operator.license_granted`, `admission.licensed_granted`) with the license id,
key id and the SHA-256 of the canonical JSON of the document
(`canonical_sha256`). Keep the license file with the change record. The
database stores the verified document; it does not re-verify signatures.

Manual terms through `grant_licensed_tenant_admission` (or `node
scripts/operator-admin.mjs grant`) remain available for contracts without a
signed file.

## Expiry warnings

- **Dashboard banner** (every member): 30 days and 7 days before the license
  end, during the grace period and after it. The banner says plainly that local
  detection on every device keeps enforcing. Without a stored signed license the
  admission end (which already includes grace) is used.
- **Prometheus** (`deploy/monitoring/prometheus-alerts.yml`, group
  `aidr-license`): `AIDRLicenseExpiresIn30Days` (warning),
  `AIDRLicenseExpiresIn7Days`, `AIDRLicenseInGracePeriod` and
  `AIDRLicenseExpired` (critical), and `AIDRLicenseEvidenceUnhealthy` when the
  evidence is failed or older than three hours. The hourly
  `deployment-maintenance.mjs` run writes `<deployment>/health/license.json`
  for the earliest-ending licensed admission; the dashboard publishes it as
  `aidr_license_*` gauges when `AIDR_LICENSE_HEALTH_FILE` is set
  (`deployment-prepare.mjs` sets it). License expiry is never a readiness check.

## Seats and device retirement

A seat is held by an enrolled installation (`agents` row, one per installation
id `iid`) until it is **retired**. Retired devices do not count against seats,
cannot write telemetry, and their enrollment-issued API keys are revoked. Local
detection on a retired device keeps enforcing; it only stops syncing with the
control plane.

- **Manual:** Agents page or agent detail -> **Retire** (owner/admin, MFA).
  A Browser Guard installation is also unlinked from its shared ingest key, so
  the key's install slot is free again.
- **Automatic:** Agents page -> **Automatic retirement**: retire devices not seen
  for 7..365 days (per workspace; off by default). The hourly maintenance run
  (Compose/Helm) or the `aidr-retention-agent-retirement` pg_cron job (Supabase
  Cloud) applies it in bounded batches and audits every retirement
  (`agent.retired`, reason `offline`).
- **Re-enrollment of the same machine:** an installation keeps its `iid` in the
  user profile (`~/.singularity-aidr/installation-id`). Enrolling again with the
  same `iid` reuses its row: an active device keeps its seat; a retired device
  gets a seat back only if one is free and is ranked as the newest device, so it
  never displaces a device enrolled in the meantime (`agent.reactivated`). A
  reimaged machine or a new user profile gets a new `iid` and therefore needs a
  seat; retire the old row or let automatic retirement free it.
- **Shared credentials:** a device that still holds a valid tenant-wide API key
  (not an enrollment-issued key) and reports again is treated like a
  re-enrollment: it returns only into a free seat. Revoke the shared key to stop
  it for good.

### VDI and non-persistent desktops

Non-persistent desktops lose the user profile at logoff, so each session gets a
new `iid` and a new seat. Either persist
`%USERPROFILE%\.singularity-aidr` (Windows) or `~/.singularity-aidr` (Linux) in
the profile solution (FSLogix, roaming profiles, a persistent home directory) so
the installation id survives, or set automatic retirement to the shortest period
the contract allows (7 days) and size seats for peak concurrent desktops plus
seven days of churn. Pooled desktops that share one image must not bake an
installation id into the image.

## Usage reports

`scripts/onprem-usage-report.mjs` produces the `aidr-usage-report-v1` report the
vendor imports per customer (counts only: no device names, users, iids or
events):

```sh
node scripts/onprem-usage-report.mjs /srv/aidr --license-file /secure-delivery/aidr-license.json
node scripts/onprem-usage-report.mjs --verify /srv/aidr/aidr-usage-report-2026-10-14.json
```

```json
{
  "format": "aidr-usage-report-v1",
  "customer_id": "example-ag",
  "license_id": "LIC-2026-0042",
  "generated_at": "2026-10-14T09:00:00.000Z",
  "seats_licensed": 250,
  "devices_enrolled": 180,
  "devices_active_30d": 150,
  "license_state": "valid",
  "updates_until": "2027-10-15T00:00:00.000Z",
  "deployment_version": "0.6.0+0123456789ab",
  "report_sha256": "<sha256 of the canonical JSON of the other fields>"
}
```

- `devices_enrolled` counts active (not retired) installations;
  `devices_active_30d` those seen in the last 30 days.
- `license_state` is `valid`, `grace`, `expired` or `not_yet_valid` for a
  verified license (the `--license-file`, otherwise the applied signed import);
  `unverified` when only typed admission terms exist; `unlicensed` without a
  licensed admission. `updates_until` is the end of the grace period, the last
  moment signed update packs are accepted.
- With several licensed workspaces pass `--tenant <id>`; Helm installs use
  `--from-env` like the maintenance job.
- Workspace owners and admins can download the same report from **Settings ->
  License -> Download usage report**.

**The report is customer-attested, not tamper-proof.** `report_sha256` detects
accidental edits and transport corruption; it is not a signature, and the
customer controls the hosts and database that produce it. True-up rests on the
report together with the contract's audit rights.

## Issuing licenses (vendor only)

`scripts/license-issue.mjs` runs only in the isolated license-signing
environment. The Ed25519 private key is read from an owner-only file
(`--private-key-file`, mode 0600) or from `AIDR_LICENSE_SIGNING_KEY_FILE` /
`AIDR_LICENSE_SIGNING_KEY`; it is never accepted as a command argument.

```sh
# one-time: create a key and publish its registry entry
openssl genpkey -algorithm ed25519 -out /secure/aidr-license-2026-1.pem && chmod 600 /secure/aidr-license-2026-1.pem
node scripts/license-issue.mjs --print-public-key-entry --key-id aidr-license-2026-1 \
  --private-key-file /secure/aidr-license-2026-1.pem --not-before 2026-09-24T00:00:00Z

# per customer
node scripts/license-issue.mjs --private-key-file /secure/aidr-license-2026-1.pem \
  --key-id aidr-license-2026-1 --license-id LIC-2026-0042 --customer "Example Customer AG" \
  --plan-id enterprise --seats 250 --features managed_policy,premium_intel \
  --deployment airgap --not-before 2026-10-01T00:00:00Z --expires-at 2027-10-01T00:00:00Z \
  --grace-days 14 --public-keys deploy/onprem/license-public-keys.json --out LIC-2026-0042.json
```

Add `--customer-id <id>` (for example `--customer-id example-ag`) when the
license goes into a per-customer installer: the
[customer packet](customer-builds.md) that carries it requires the id, and the
id is signed with the other terms.

The issuer validates every term, self-verifies the signature, checks that the
key is `active` in the registry passed with `--public-keys`, and never
overwrites an existing output file.

## Customer packets

A per-customer installer carries a vendor-signed customer packet
(`aidr-customer-packet-v1`) that embeds the license together with the
customer id, an optional control-plane URL, sensitivity preset and display
name. It is signed with a key from the same registry, under a separate
signature domain, so a license signature never verifies as a packet. Issue and
verify it with `scripts/customer-packet-issue.mjs` and
`scripts/customer-packet-verify.mjs`; the runbook is
[Per-customer builds](customer-builds.md).

## Limits

- A license is a commercial control, not DRM, and enforcement is operator-side
  (see [What the license can and cannot enforce](#what-the-license-can-and-cannot-enforce)).
  An administrator with root on the deployment host can replace the registry,
  change the clock or edit the database row; the signature proves what the
  vendor issued, and the receipt and admission audit log show which license was
  applied.
- The database does not re-verify license signatures.
- Revoking a license before its expiry is done by the admission operator
  (`revoke_licensed_tenant_admission`), not by the file.
- Disconnected endpoints learn about admission changes only when they reconnect;
  their local detection is unaffected either way.
