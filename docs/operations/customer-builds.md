# Per-customer builds (vendor runbook)

Every customer receives the **same signed product**. What differs per customer
is a small vendor-signed **customer packet** that the per-customer installer
carries next to the product: who the build is for, their license, and optional
setup defaults. This page is the vendor runbook for producing and delivering
such a build, and an honest summary of what protects the product.

Audience: Singularity R&D release and licensing staff. Customer operators need
only [Licensing](licensing.md) (verify the license) and the installer they were
given.

## What the customer packet is

An `aidr-customer-packet-v1` document:

```json
{
  "format": "aidr-customer-packet-v1",
  "key_id": "aidr-license-2026-1",
  "payload": {
    "customer_id": "example-ag",
    "packet_id": "PKT-example-ag-2026-10",
    "issued_at": "2026-10-01T00:00:00Z",
    "license": { "format": "aidr-license-v1", "key_id": "aidr-license-2026-1", "payload": { "customer_id": "example-ag", "...": "..." }, "sig": "..." },
    "control_plane_url": "https://aidr.example-ag.internal/",
    "sensitivity": "balanced",
    "display_name": "Example AG"
  },
  "sig": "<base64 Ed25519 signature>"
}
```

| Field | Required | Rule |
|-------|----------|------|
| `customer_id` | yes | `^[a-z0-9][a-z0-9-]{1,31}$`; must equal the embedded license's `customer_id` |
| `packet_id` | yes | 1..128 characters of `[A-Za-z0-9._-]`, starting with a letter or digit |
| `issued_at` | yes | ISO-8601 UTC, inside the signing key's validity window |
| `license` | yes | A full `aidr-license-v1` document that verifies against the same registry and carries `customer_id` |
| `control_plane_url` | no | Absolute `https:` URL, no credentials, no fragment, at most 2048 characters |
| `sensitivity` | no | `paranoid`, `balanced` or `relaxed` |
| `display_name` | no | 1..60 printable characters, no surrounding whitespace |
| `licensing_public_keys_pem` | no | 1..8 Ed25519 SPKI public keys in PEM: the customer deployment's own signing keys (`endpoint-policy/licensing-public-keys.pem` from `deployment-prepare`). `aidr setup` adds them to `licensing.public_keys_pem`, so signed entitlements and runtime policy from that deployment verify and managed features turn on. Public keys only. A packet with this field is refused by `aidr` versions released before it. |

- The signature covers `aidr-customer-packet-v1\n` followed by the canonical
  JSON of `payload` (the same canonical form as the license). The first line is
  a domain separator: a license signature never verifies as a packet, and a
  packet signature never verifies as a license.
- It is signed by a key from the **same** public-key registry as licenses
  (`deploy/onprem/license-public-keys.json`, `aidr-license-public-keys-v1`),
  under the same `active` / `retired` / `revoked` rules. The document is at most
  64 KiB.
- Unknown fields are refused. **A packet never carries a secret**: there is no
  field for an enrollment code or API key. Enrollment codes travel separately
  (installer enrollment handoff), never inside the packet.
- A packet has no expiry of its own; the embedded license's terms apply. A
  packet whose license has expired still **verifies**, so the installer still
  installs local detection. The verifier reports the license state (`active`,
  `grace`, `expired`, `not_yet_valid`) separately.

On the endpoint, setup looks for the packet at
`<install prefix>/config/customer-packet.json`, then at the machine copy
(`%ProgramData%\Singularity AIDR\customer-packet.json` on Windows,
`/etc/singularity-aidr/customer-packet.json` on Linux). After a verified packet
is applied, `~/.singularity-aidr/license.json` holds the license and
`~/.singularity-aidr/customer.json` holds `customer_id`, `packet_id` and the
display name. A packet that does not verify (tampered, wrong key) is refused
with a plain message to the administrator, and local detection is still
installed.

## Runbook

> **Vendor admin panel.** The `/admin` console of the `aidr-landing` site does
> steps 1 to 3 from one screen: a company's name, device limit (`seats`), term,
> plan and server address are kept there; "issue license" signs the license and
> the packet with the same rules and byte format as the scripts below, and "build
> installers" dispatches this workflow with the packet inline. The panel's
> signing key is an online key: its public entry must be added to
> `deploy/onprem/license-public-keys.json` (the panel shows it) and released
> before any endpoint accepts what it signs. The offline scripts below stay the
> reference procedure and work without the panel.

All signing steps run in the isolated license-signing environment. The Ed25519
private key comes from an owner-only file (`--private-key-file`, mode 0600) or
from `AIDR_LICENSE_SIGNING_KEY_FILE` / `AIDR_LICENSE_SIGNING_KEY`; it is never
passed as a command argument and never printed.

### 1. Issue the license with a customer id

```sh
node scripts/license-issue.mjs --private-key-file /secure/aidr-license-2026-1.pem \
  --key-id aidr-license-2026-1 --license-id LIC-2026-0042 \
  --customer "Example AG" --customer-id example-ag \
  --plan-id enterprise --seats 250 --features managed_policy,premium_intel \
  --deployment airgap --not-before 2026-10-01T00:00:00Z --expires-at 2027-10-01T00:00:00Z \
  --grace-days 14 --public-keys deploy/onprem/license-public-keys.json --out LIC-2026-0042.json
```

Choose the customer id once per customer and keep it stable across renewals:
it appears in installer file names, in update-pack audiences and in leak
traces. See [Licensing](licensing.md#issuing-licenses-vendor-only) for every
license term.

### 2. Issue the customer packet

```sh
node scripts/customer-packet-issue.mjs --private-key-file /secure/aidr-license-2026-1.pem \
  --key-id aidr-license-2026-1 --license-file LIC-2026-0042.json \
  --customer-id example-ag --packet-id PKT-example-ag-2026-10 \
  --control-plane-url https://aidr.example-ag.internal/ --sensitivity balanced \
  --display-name "Example AG" \
  --licensing-public-key-file licensing-public-keys.pem \
  --public-keys deploy/onprem/license-public-keys.json --out customer-packet.json
```

- `--licensing-public-key-file` (optional, repeatable) embeds the public signing
  keys of the customer's own deployment. The customer sends
  `endpoint-policy/licensing-public-keys.pem` from their `deployment-prepare`
  output; check its fingerprint with them over a second channel. Without it,
  the same keys reach endpoints through the
  [machine policy](../installation/desktop-installers.md#machine-policy-every-user-of-a-computer).

- `--public-keys` is required: it is the registry the customer will ship. The
  signing key must be `active` there, and the embedded license must verify
  against it.
- `--customer-id` is optional; when given it must match the license.
- The issuer validates every term, signs, then runs the customer's own verifier
  on the result before writing it. It never overwrites an existing file. If the
  license is not `active` it still issues the packet and prints a warning.

Check the result exactly as the build pipeline will:

```sh
node scripts/customer-packet-verify.mjs --packet-file customer-packet.json \
  --public-keys deploy/onprem/license-public-keys.json --expect-customer-id example-ag
```

It prints a JSON summary (customer id, packet id, license id and state,
`updates_until`, document SHA-256). Exit `0` means the packet is authentic,
whatever the license state; exit `1` means it was refused (malformed, tampered,
wrong customer, unknown or revoked key, embedded license does not verify, or
no trusted keys installed). `--now <ISO>` exists for rehearsals.

### 3. Build the customer installer

Run the **customer installer** workflow (`.github/workflows/customer-installer.yml`,
manual dispatch) with the promoted release tag and the customer id, and supply
the packet as the workflow describes (a secret, an uploaded artifact, or inline
as `packet_b64` with `packet_source=input`). The
workflow verifies the packet with `scripts/customer-packet-verify.mjs` before
embedding it, reuses the already-signed release artifacts, signs the Windows
installer with the existing Authenticode flow and uploads files named
`SingularityAIDR-<CUSTOMER>-<version>-<arch>.<ext>`:

- Windows: MSI (and optionally a bootstrapper EXE wrapping it). The packet is
  installed under the install directory's `config\` and as a permanent machine
  copy under `%ProgramData%\Singularity AIDR\`, so a later generic
  `aidr update` keeps it.
  The install wizard names the customer (`display_name`; in the English pages
  Turkish letters are spelled in ASCII, since Windows-1252 has no `İ`), shows
  the packet's `control_plane_url` as the company address and the last update
  day ([the Windows install wizard](../installation/desktop-installers.md#the-windows-install-wizard)).
  The build fails when `control_plane_url` is not a plain
  `https://host[:port][/path]` address the installer can hand to setup.
- Linux: deb and rpm install it as `/etc/singularity-aidr/customer-packet.json`
  (a configuration file that upgrades do not overwrite); the tar.gz carries it
  at `config/customer-packet.json`.

The product inside is byte-for-byte the signed release; only the packet and the
installer wrapper differ.

### 4. Deliver

Deliver through the customer's agreed secure channel:

- the installers for their platforms and their SHA-256 values;
- the license file (`LIC-….json`) for the control-plane bootstrap or renewal
  ([Licensing](licensing.md#bootstrapping-with-a-license));
- the vendor-published public-key registry for the release, with its SHA-256.

Record in the customer file: license id, packet id, customer id, release tag,
installer SHA-256 values and the `customer-packet-verify.mjs` summary.

### Renewal

Issue a renewed license with the **same** `--customer-id`, then a new packet
(new `--packet-id`) and new installers. Endpoints that are not reinstalled keep
enforcing their installed rules; they only stop accepting new update packs once
the old license term has ended (see below).

## Updates follow the license

The value of the product is in continuous rule and intel updates. A signed
update pack can name an audience (`audience.customer_ids`, covered by the pack
signature). An endpoint with a license accepts a new pack only if:

- the pack's audience, when present, includes the license's `customer_id`; and
- the pack's signed `issued_at` is no later than the license's
  `expires_at + grace_days`.

Both comparisons use signed times only, never the endpoint clock, so a
customer cannot extend updates by changing a clock. An endpoint without a
license refuses packs that carry an audience and otherwise behaves as before.

On an air-gapped host the same check runs when a pack is imported:
`scripts/import-offline-pack.mjs` takes `--license <file>` (and
`--license-public-keys <registry>` to override the registry built into the
release). The local target falls back to the endpoint's installed
`~/.singularity-aidr/license.json`, so leaving out `--license` does not skip
the term check. The import summary prints the license id, customer id, license
state and `updates_until`.

**Local detection never stops or degrades because of license state, expiry or
a clock.** Rules and packs that are already installed keep enforcing for ever:
a pack past its own `expires_at` is reported as stale (logged, and listed in the
merged intel detail) but stays active, and an encrypted pack keeps the key it
was activated with after the managed entitlement ends. The only thing that can
still remove an installed pack is revoking its pack id or signing key. License state gates only accepting *new* packs and managed
control-plane features.

## What protects the product

Be accurate with customers about what each control does:

- **Signed license.** Seats, terms and customer id are Ed25519-signed; changing
  them breaks the signature. Enforcement on a self-hosted control plane is
  operator-side ([Licensing](licensing.md#what-the-license-can-and-cannot-enforce)).
- **License-bound updates.** New rule/intel packs are accepted only within the
  license term and only for the customers a pack names. A copied installer keeps
  its installed rules but receives no updates issued after its license term.
- **Leak-trace id.** The customer id is in the packet, the license, the
  installer file names and the endpoint's `customer.json`. A leaked installer or
  packet names the customer it was built for.
- **Integrity check.** Release builds verify their own signed artifacts before
  inspecting anything and refuse a tampered installation
  ([Integrity verification](../integrity.md)). Release bundles are minified and
  ship without source maps.
- **Contract.** The license agreement forbids redistribution and reverse
  engineering; the signed license, packet and leak-trace id are the evidence
  behind it.

What these controls are **not**: there is no obfuscation and no DRM. The
product runs on the customer's machines, and a determined party can read the
JavaScript. The controls make misuse attributable and stop updates outside the
license; they do not make the code secret.
