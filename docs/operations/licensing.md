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

This follows the product's enforcement default: a connector evaluates every tool
call locally, and managed features are an opt-in layer on top.

## License format

```json
{
  "format": "aidr-license-v1",
  "key_id": "aidr-license-2026-1",
  "payload": {
    "license_id": "LIC-2026-0042",
    "customer": "Example Customer AG",
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
- Unknown fields are refused, so a term this verifier does not understand is
  never silently ignored.

### States

| State | Condition | Managed features | Local detection |
|-------|-----------|------------------|-----------------|
| `not_yet_valid` | before `not_before` | not admitted | enforced |
| `valid` | `not_before` ≤ now < `expires_at` | enabled | enforced |
| `grace` | `expires_at` ≤ now < `expires_at + grace_days` | enabled, with warnings | enforced |
| `expired` | after the grace period | degraded | enforced |

## Trust root and key rotation

The verifier trusts only `deploy/onprem/license-public-keys.json`
(`aidr-license-public-keys-v1`). **The shipped file has no keys**, so every
license is refused until the vendor-published registry for your release is
installed (fail closed). Install the registry delivered with the signed customer
kit and compare its SHA-256 with the value in the release notes.

Each entry is `{ key_id, algorithm: "ed25519", public_key_pem, not_before,
not_after, status }`:

- `active`: signs new licenses.
- `retired`: no longer signs; still verifies licenses whose `issued_at` falls in
  its `not_before`..`not_after` window, so a rotation does not invalidate
  licenses already delivered.
- `revoked`: verifies nothing (use after a key compromise, then reissue).

A license names its `key_id`; a key that is unknown, revoked or outside its
window is refused. The registry never holds private keys, and the development
test keys used by the automated tests are generated in memory and never placed
in this file.

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
signing key, terms, `managed_until`, the license file's SHA-256 and whether the
shipped registry or an override (`--license-public-keys`) was the trust root.

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

## Renewal

The bootstrap is a one-time action; it refuses to change the terms of a
completed bootstrap. To extend an installed deployment, verify the renewed
license with `license-verify.mjs`, then have an admission operator apply its
seats, `expires_at + grace_days` and `license_id` through
`grant_licensed_tenant_admission` as described in
[admission operators](admission-operators.md). Keep the verified license file
and its `license-verify.mjs` output with the change record.

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

The issuer validates every term, self-verifies the signature, checks that the
key is `active` in the registry passed with `--public-keys`, and never
overwrites an existing output file.

## Limits

- A license is a commercial control, not DRM. An administrator with root on the
  deployment host can replace the registry or the database row; the signature
  proves what the vendor issued, and the receipt and admission audit log show
  which license was applied.
- Revoking a license before its expiry is done by the admission operator
  (`revoke_licensed_tenant_admission`), not by the file.
- Disconnected endpoints learn about admission changes only when they reconnect;
  their local detection is unaffected either way.
