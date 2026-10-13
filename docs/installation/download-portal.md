# Installer download portal (operators)

Türkçe: [download-portal.tr.md](download-portal.tr.md)

Customers download the AIDR installer from the dashboard **Download** page
(`/downloads`, also step 1 of onboarding). The page detects the visitor's
operating system, highlights the matching installer, lists the other platforms
with size, SHA-256 and a copyable checksum command, and shows the Browser Guard
store links and the IT / MDM deployment notes.

Installers are offered for **Windows and Linux**. There is no macOS installer;
a macOS visitor sees a short note saying so, and Browser Guard (Chrome, Edge,
Firefox) still works on macOS. The platform list is data
(`INSTALLER_PLATFORMS` in `supabase/functions/_shared/installer-catalog.ts`,
`PLATFORMS` in `scripts/publish-installers.mjs` and the platform check in
`public.record_installer_download`), so a platform can be added later without
changing the page.

## How it fits together

```
release-promote ──► scripts/publish-installers.mjs ──► private bucket (aidr-installers)
                     verify signed release                 latest.json (+ .sig)
                     check SHA256SUMS                       <version>/manifest.json (+ .sig)
                     sign catalog, upload                   <version>/<platform>/<file>
                                                                 │
dashboard /downloads ──► installer-download Edge Function ──────┘
                          session + identity barrier + active membership
                          + ACTIVE admission (licence/trial/pilot)
                          verify catalog signatures, mint 30–900 s signed URL,
                          write audit row (installer.download)
```

- **Fail closed.** No session: 401. Not an active member of an active tenant:
  403. Expired, revoked or unentitled tenant: 403 `entitlement_required`. An
  unreadable admission, a storage error or a catalog whose signature or digest
  does not verify: 503 and nothing is listed. A URL is returned only after its
  audit row is written.
- **Audit.** Every URL writes `admin_audit_logs` action `installer.download`
  with tenant, user, version, platform, file name and SHA-256. No IP address or
  user agent is stored. Owners and admins see these rows in the audit trail and
  the audit export.
- **Rate limits.** Per user and tenant per minute: catalog 60 / 3000, download
  links 20 / 600 (`consume_tenant_rate_limit`, fails closed).
- **Managed enrollment.** For owners, admins and members the catalog includes
  the control plane's public URL, and the page shows the existing device-code
  flow (approve the code on `/verify`; manual enrollment tokens stay in the
  onboarding page's advanced section). No secret is created in the browser.

## Storage contract

Private bucket, default name `aidr-installers` (created by migration
`20261013000600_installer_download_portal.sql`; set `AIDR_INSTALLERS_BUCKET` to
use another name and create that bucket private, without client policies).

| Object | Content | Written |
|---|---|---|
| `<version>/<platform>/<file>` | installer bytes, exactly the signed release artifact | once, never replaced |
| `<version>/SHA256SUMS` | `<sha256>  <platform>/<file>` per installer | once |
| `<version>/release/aidr-release.manifest.json` / `.sig` | the signed release manifest the installers came from (chain of trust) | once |
| `<version>/manifest.json` | installer catalog: version, channel, `published_at`, `release_notes_url`, release tag/commit/sequence, signed-manifest digest and signer, and per file `platform`, `os`, `arch`, `file`, `path`, `size`, `sha256`, `minimum_os`, `format` | once |
| `<version>/manifest.json.sig` | Ed25519 signature over the exact `manifest.json` bytes | once |
| `latest.json` | `{ version, release_sequence, manifest_path, manifest_sha256, published_at }` | each publish, last |
| `latest.json.sig` | Ed25519 signature over the exact `latest.json` bytes | each publish, last |

Platforms: `windows-x64`, `windows-arm64`, `linux-x64`, `linux-arm64`.

Signatures use the release signature envelope of
`scripts/release-signing-lib.mjs` (`{ schema_version: 1, algorithm: "Ed25519",
key_id, signature_b64 }`) with a **dedicated installer-catalog key**, not the
release signing key (the promotion job never holds the release private key).
The catalog binds itself to the release by recording the signed release
manifest's SHA-256 and signer, and the release manifest is published next to it.

## Publishing (release promotion)

`scripts/publish-installers.mjs` republishes the installers of an already
promoted release. It:

1. verifies the release bundle with the trusted signer policy (signature, signer
   window, expiry, metadata/inventory bindings, every artifact digest and size),
   exactly like `scripts/release-verify.mjs`;
2. selects installers (`installers/<platform>/<file>` in the bundle, or explicit
   `--installer <platform>=<path>`), requires each to be a signed artifact and to
   appear in `SHA256SUMS` with the same digest, and hashes the bytes it uploads;
3. builds and signs `manifest.json` and `latest.json`;
4. uploads with the service-role key: versioned objects without upsert (an
   existing object is accepted only if byte-identical), `latest.json` last, and
   never back to a lower release sequence (`--allow-downgrade` overrides for a
   deliberate rollback).

Without the signing key, key id, `SUPABASE_URL` or `SUPABASE_SERVICE_ROLE_KEY`
it stops before uploading; nothing is ever published unsigned.

The coordinator wires this step into `.github/workflows/release-promote.yml`
(`promote` job, after "Publish final GitHub release from the same bundle"):

```yaml
      - name: Publish installers to the download portal
        shell: bash
        env:
          SUPABASE_URL: ${{ secrets.AIDR_DOWNLOADS_SUPABASE_URL }}
          SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.AIDR_DOWNLOADS_SERVICE_ROLE_KEY }}
          AIDR_INSTALLERS_BUCKET: ${{ vars.AIDR_INSTALLERS_BUCKET }}
          AIDR_INSTALLER_MANIFEST_KEY_ID: ${{ vars.AIDR_INSTALLER_MANIFEST_KEY_ID }}
          CATALOG_KEY_PEM: ${{ secrets.AIDR_INSTALLER_MANIFEST_SIGNING_KEY_PEM }}
          RELEASE_TAG: ${{ inputs.tag }}
        run: |
          set -euo pipefail
          [[ -n "${CATALOG_KEY_PEM}" && -n "${AIDR_INSTALLER_MANIFEST_KEY_ID}" ]] || { echo "Installer catalog signing key is required." >&2; exit 1; }
          key_path="${RUNNER_TEMP}/aidr-installer-catalog-key.pem"
          umask 077
          printf '%s\n' "${CATALOG_KEY_PEM}" > "${key_path}"
          node .trusted-release-verifier/scripts/publish-installers.mjs \
            --bundle release-output \
            --policy "${AIDR_RELEASE_SIGNER_POLICY_PATH}" \
            --signing-key "${key_path}" \
            --key-id "${AIDR_INSTALLER_MANIFEST_KEY_ID}" \
            --release-notes-url "https://<your release notes host>/${RELEASE_TAG}"
          rm -f "${key_path}"
```

`SHA256SUMS` is read from the bundle root by default (`--sha256sums <file>`
otherwise); the installer build must put it there. Minimum OS defaults follow
the bundled Node.js 22 runtime (Windows 10 / Server 2016, glibc 2.28) and can be
overridden with `--min-os <platform>=<text>`.

### Local dry run

```bash
node scripts/publish-installers.mjs --bundle release-output --policy signer-policy.json \
  --signing-key /secure/catalog-key.pem --key-id installer-catalog-1 --dry-run --out /tmp/portal
```

`--dry-run` makes no network request and stages the bucket tree in `--out`.
Without a signing key it stages an unsigned catalog for inspection only.

### Catalog signing key

Create an Ed25519 key once, outside any release directory:

```bash
openssl genpkey -algorithm ed25519 -out installer-catalog-key.pem
openssl pkey -in installer-catalog-key.pem -pubout -outform DER | base64 -w0   # AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64
```

Store the PEM as the `AIDR_INSTALLER_MANIFEST_SIGNING_KEY_PEM` secret of the
`production` environment and the base64 public key on the Edge Function. To
rotate, publish once with the new key after updating the function's public key
(the function serves nothing while the two disagree).

## Configuration

Edge Function `installer-download`:

| Variable | Required | Meaning |
|---|---|---|
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | yes | platform |
| `AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64` | yes | catalog public key (SPKI DER or raw 32 bytes, base64); missing or invalid answers 500 `server_misconfigured` |
| `AIDR_INSTALLERS_BUCKET` | no | bucket name, default `aidr-installers` |
| `AIDR_INSTALLER_URL_TTL_SECONDS` | no | signed URL lifetime, default 300, clamped to 30..900 |
| `AIDR_PUBLIC_API_ORIGIN` | when `SUPABASE_URL` is internal | public origin the browser downloads from (same rule as pack links) |

Dashboard build (all optional; an unset or non-https value hides that link):

| Variable | Meaning |
|---|---|
| `VITE_BROWSER_GUARD_CHROME_URL`, `VITE_BROWSER_GUARD_EDGE_URL`, `VITE_BROWSER_GUARD_FIREFOX_URL` | Browser Guard store listings |
| `VITE_BROWSER_GUARD_CHROME_EXTENSION_ID`, `VITE_BROWSER_GUARD_EDGE_EXTENSION_ID` | 32-letter IDs shown for IT policy (Firefox always uses `browser-guard@singularityrd.com`) |
| `VITE_AIDR_ADMIN_GUIDE_URL` | administrator guide linked from "IT / MDM deployment" |

Policy templates for force-installing Browser Guard are in
[`deploy/browser-guard/`](../../deploy/browser-guard/README.md).
