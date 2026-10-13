# Installer download portal (operators)

Türkçe: [download-portal.tr.md](download-portal.tr.md)

Customers download the AIDR installer from the dashboard **Download** page
(`/downloads`, also step 1 of onboarding). The page detects the visitor's
operating system, highlights the matching platform, lists the other platforms
with size, SHA-256 and a copyable checksum command, and shows the Browser Guard
store links and the IT / MDM deployment notes.

A platform can be published in several **formats**: Windows `.msi`; Linux
`.deb`, `.rpm` and `.tar.gz`. Each platform shows its recommended format first
and the others below it: `.msi` on Windows; on Linux `.deb` for Debian/Ubuntu,
`.rpm` for RHEL/Fedora and the `.tar.gz` tarball for any other distribution (and
when the browser does not name the distribution). Each format is labelled with
the distributions it is for.

Installers are offered for **Windows and Linux**. There is no macOS installer;
a macOS visitor sees a short note saying so, and Browser Guard (Chrome, Edge,
Firefox) still works on macOS. The platform list is data
(`INSTALLER_PLATFORMS` in `supabase/functions/_shared/installer-catalog.ts`,
`PLATFORMS` in `scripts/publish-installers.mjs` and the platform check in
`public.record_installer_download`), so a platform can be added later without
changing the page. The format list is data too (`INSTALLER_FORMATS` in
`_shared/installer-catalog.ts`, `FORMATS` in `scripts/publish-installers.mjs`;
for `aidr update` to install a new format, `KIND_FORMATS` in
`packages/cli/src/utils/update-installer.ts`).

## How it fits together

```
release-promote ──► scripts/publish-installers.mjs ──► private bucket (aidr-installers)
                     verify signed release                 latest.json (+ .sig)
                     check SHA256SUMS                       <version>/manifest.json (+ .sig)
                     sign catalog, upload                   <version>/<platform>/<file>  (one per format)
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
  with tenant, user, version, platform, format, file name and SHA-256. No IP address or
  user agent is stored. Owners and admins see these rows in the audit trail and
  the audit export.
- **Rate limits.** Per user and tenant per minute: catalog 60 / 3000, download
  links 20 / 600 (`consume_tenant_rate_limit`, fails closed).
- **Managed enrollment.** For owners, admins and members the catalog includes
  the control plane's public URL, and the page shows the existing device-code
  flow (approve the code on `/verify`; manual enrollment tokens stay in the
  onboarding page's advanced section). No secret is created in the browser.

- **Endpoint updates.** Enrolled endpoints reach the same catalog through
  the `installer-update` Edge Function with their tenant API key (no browser
  session): an active owner/admin/member key of an active tenant with an
  ACTIVE admission. It returns the exact signed `latest.json` and catalog
  bytes, which `aidr update` verifies again with its pinned catalog key, and
  then one signed URL for the current version, in the format the endpoint was
  installed with (`.msi`, `.deb`, `.rpm` or `.tar.gz`), with the same
  `installer.download` audit row (actor: the key's owner). Rate limits per key
  and tenant per minute: catalog 30 / 6000, download links 10 / 3000. See
  [Updating](desktop-installers.md#updating).

## Storage contract

Private bucket, default name `aidr-installers` (created by migration
`20261013000600_installer_download_portal.sql`; set `AIDR_INSTALLERS_BUCKET` to
use another name and create that bucket private, without client policies). The
audit function gained its optional `p_format` argument in
`20261013000610_installer_download_format.sql`; a caller that passes the six
original arguments still works.

| Object | Content | Written |
|---|---|---|
| `<version>/<platform>/<file>` | installer bytes, exactly the signed release artifact; one file per platform and format | once, never replaced |
| `<version>/SHA256SUMS` | `<sha256>  <platform>/<file>` per installer | once |
| `<version>/release/aidr-release.manifest.json` / `.sig` | the signed release manifest the installers came from (chain of trust) | once |
| `<version>/manifest.json` | installer catalog: version, channel, `published_at`, `release_notes_url`, release tag/commit/sequence, signed-manifest digest and signer, and per file `platform`, `os`, `arch`, `file`, `path`, `size`, `sha256`, `minimum_os`, `format` | once |
| `<version>/manifest.json.sig` | Ed25519 signature over the exact `manifest.json` bytes | once |
| `latest.json` | `{ version, release_sequence, manifest_path, manifest_sha256, published_at }` | each publish, last |
| `latest.json.sig` | Ed25519 signature over the exact `latest.json` bytes | each publish, last |

Platforms: `windows-x64`, `windows-arm64`, `linux-x64`, `linux-arm64`.
Formats: `msi` (Windows); `deb`, `rpm`, `tar.gz` (Linux). A file's extension
names its format.

### Catalog schema versions

| `schema_version` | Files | Written when |
|---|---|---|
| `1` | at most one per platform | every platform has a single file (as before formats existed) |
| `2` | one per platform **and** format; each file name ends in `.<format>` | at least one platform has more than one format |

The pointer (`latest.json`, `schema_version` 1) and the signature envelope are
unchanged, so a schema 1 catalog published earlier still verifies and parses.
Readers of schema 2 are the `installer-download` / `installer-update` functions
and `aidr update` from this release on. Endpoints with an older `aidr` read only
schema 1: until they are updated, either publish one file per platform (pass
`--installer` once per platform, which writes schema 1), or update them once
with the package manager or installer (`apt install ./….deb`, `dnf install
./….rpm`, the MSI). Deploy the migrations and Edge Functions before the first
schema 2 publish; an older function refuses a schema 2 catalog and lists
nothing.

### Choosing a format

The download request (`POST`) takes an optional `format`. It must be a format
the catalog lists for that platform, otherwise the answer is 404
`installer_not_found` and no URL is minted; a malformed value is 400
`invalid_request`. A request without `format` (the shape before formats existed)
gets the platform's only file, else its default format (`msi` on Windows,
`tar.gz` on Linux). The audit row records the format that was handed out.

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
2. selects installers by extension: every `installers/<platform>/<file>` in the
   bundle whose extension is a format of that platform (`.msi`; `.deb`, `.rpm`,
   `.tar.gz`; other files there are skipped and reported as `skipped`), or
   explicit `--installer <platform>=<path>` (repeat it once per format). Two files
   of the same platform and format stop the publish. It requires each to be a
   signed artifact and to appear in `SHA256SUMS` with the same digest, and hashes
   the bytes it uploads;
3. builds and signs `manifest.json` (schema 1 or 2, above) and `latest.json`;
4. uploads with the service-role key: versioned objects without upsert (an
   existing object is accepted only if byte-identical), `latest.json` last, and
   never back to a lower release sequence (`--allow-downgrade` overrides for a
   deliberate rollback).

Without the signing key, key id, `SUPABASE_URL` or `SUPABASE_SERVICE_ROLE_KEY`
it stops before uploading; nothing is ever published unsigned.

The promote job of `.github/workflows/release-promote.yml` runs this step
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

Edge Functions `installer-download` and `installer-update` (same variables):

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
