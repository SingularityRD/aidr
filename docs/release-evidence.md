# Release evidence and independent verification

`pnpm build:release` prepares unsigned artifacts. A portable installation
candidate can contain those real built bytes, inventories, SBOM and provenance
without a publisher signature. It must remain labelled unsigned: checksums do
not authenticate the publisher or authorize production. Commercial promotion
requires approved signatures and independent candidate-specific receipts.

The full operator sequence is in `docs/runbooks/portable-release-signing.md`,
delivered as `RELEASE-SIGNING.md` in the portable kit. Linux installation
instructions travel as `deploy/operations/PORTABLE-LINUX.md`.

## Evidence emitted

`pnpm build:release` creates per-artifact evidence under each `dist/`:

- `aidr-artifact.manifest.json` — sorted SHA-256 file inventory. Commercial
  preparation adds RC, commit, source, data, package, lockfile and SBOM digests
  plus the approved public signer identity and lineage.
- `aidr-sbom.cdx.json` and `.sha256` — deterministic CycloneDX 1.5 SBOM with
  SPDX-style license metadata and pnpm lockfile integrity hashes.

The build and `scripts/release-artifact-manifests.mjs` never sign manifests.
They reject private signing material and remove stale per-dist signatures.
Only the later isolated `scripts/sign-artifact-manifest.mjs` step adds
`aidr-artifact.manifest.sig`, an Ed25519 signature over the exact manifest bytes.

Commercial preparation creates unsigned aggregate evidence in
`.release-evidence/`. This preparation format differs from the portable delivery
bundle's `release-metadata.json` and `release-inventory.json`; do not pass it to
`release-sign.mjs` as a delivery bundle.

`scripts/build-release-candidate.mjs` packages existing outputs into the portable
candidate: ten npm archives, Claude plugin, both Cursor and VS Code VSIX files,
dashboard archive, SBOM/checksum and mandatory locally constructed provenance.
It records exact artifact hashes and source commit; it does not sign or approve
production. `.github/scripts/build-release-bundle.mjs` remains the signed-input
CI path, followed by `.github/scripts/package-vsix.mjs` to finalize its inventory.

The signed Claude Code endpoint additionally requires a package-root manifest at
`packages/claude-code/aidr-artifact.manifest.json` and its detached signature.
That exact file set covers `package.json`, `dist/`, and `resources/`; the
endpoint installer checks it before and after copying. Extract the Claude
plugin archive only from a publisher-verified release bundle, which also
authenticates plugin metadata and hook registration files outside the endpoint
package.

## In-toto/SLSA-style provenance

`scripts/generate-provenance.mjs` binds the released artifacts into one in-toto
statement (`predicateType` `https://slsa.dev/provenance/v0.2`): the `subject` is
the digest of every `aidr-artifact.manifest.json`, `materials` records the
`pnpm-lock.yaml` digest, and `byproducts` records the SBOM digest.
The candidate assembler and signed-input CI packager require all ten artifact
directories and the SBOM, then re-verify the written statement. The same
statement can be re-checked offline. When invoking it manually, supply all ten
`--artifact-dir` arguments and explicit `--lockfile` and `--sbom` paths.
The standalone generator's shorter default invocation is:

```powershell
node scripts/generate-provenance.mjs --output .release-evidence/aidr-provenance.intoto.json
node scripts/generate-provenance.mjs --verify-provenance --provenance .release-evidence/aidr-provenance.intoto.json
```

Verification fails closed when a manifest, the lockfile, or the SBOM no longer
matches the recorded digest, or when an artifact manifest is missing from the
statement. Without explicit directories it can skip missing default directories;
without an explicit SBOM it can generate a statement without that byproduct.
This predicate is unsigned and locally constructed: it carries no
publisher identity, no signature and no transparency-log entry, so it does not
replace signer key custody, registry publication, or the Ed25519 evidence above.

## Commercial preparation and signing inputs

Commercial preparation uses public metadata only:

- `AIDR_SIGNING_KEY_ID` — stable key identifier.
- `AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT` — SHA-256 SPKI fingerprint, written as
  `sha256:<64 lowercase hex characters>`.
- `AIDR_WATERMARK_ID` — non-sensitive release/customer lineage identifier.
- `AIDR_RC_VERSION` (or `AIDR_RELEASE_VERSION`) and `SOURCE_DATE_EPOCH` —
  stable release identity and timestamp.
- `AIDR_GIT_SHA` — the frozen source commit.
- For prebuilt SBOM reuse, `AIDR_PREBUILT_SBOM_PATH` and independently recorded
  `AIDR_EXPECTED_PREBUILT_SBOM_SHA256` — exact input file and expected digest.

Approved private keys enter only their isolated signing step, outside source,
bundle and customer kit. AIG data uses RSA; artifact and outer-release signatures
use Ed25519. Windows payloads require a separate approved Authenticode certificate
and independently pinned receipt. Never expose private signing inputs during
dependency installation, package assembly or customer-kit helper bundling.

If an image is shipped, set `AIDR_IMAGE_DIGEST` to its immutable digest. If
additional archives are shipped, provide repository-relative paths in
`AIDR_EXTRA_ARTIFACT_PATHS` separated by the platform path delimiter.
Declaring an image digest does not bundle the image.

## Independent verification

Verification must run in a clean checkout or artifact-only directory with the
public key, not the private signing key:

```sh
node scripts/verify-release-evidence.mjs \
  --public-key /opt/aidr-trust/artifact-signing-public.pem \
  --fingerprint "$APPROVED_ARTIFACT_FINGERPRINT" \
  --lockfile pnpm-lock.yaml \
  --dirs packages/core/dist packages/claude-code/dist packages/extension/dist \
  packages/openclaw/dist packages/opencode/dist packages/cli/dist \
  packages/sdk/dist packages/dashboard/dist packages/codex/dist \
  packages/mcp-gateway/dist packages/claude-code
```

Put every valued option before `--dirs`.

The verifier rejects missing or duplicate entries, manifest self-reference,
symlinks, source maps, secret-like filenames/content, host-path leaks,
invalid SBOM/license/integrity evidence, stale SBOM checksums, mismatched
provenance digests, bad release inventories, and invalid Ed25519 signatures.

An exit code of `0` is required for signed promotion. Missing approved signatures,
public key/fingerprint, SBOM or release provenance block that promotion; no
placeholder signature or synthetic dependency evidence is valid. Verification
requires no private key.

The outer delivery bundle is separately signed with `release-sign.mjs`. An
independent second machine must verify it using independently delivered
`release-verify.mjs`, `release-signing-lib.mjs`, public signer policy and persistent
anti-rollback state outside the bundle. Record real host identity and exercise
tamper, expiry, wrong-signer and rollback rejection on disposable copies.

An inner `artifacts/` signature authenticates only that directory. The customer
kit's signed outer envelope authenticates the complete archive, including helpers
and documents. `customer-kit-verify.mjs` checks extracted files and checksums;
its result alone does not authenticate the publisher. Repository tests, fixture
keys and local rehearsal results do not close independent Legal, Privacy,
Security, installation or production GO gates.

## Scanner regression check

The release scanner keeps executable strings and binary payloads strict. It
masks source comments only for generated documentation examples and relative
esbuild module metadata; absolute host paths, real token values, private-key
markers, source maps, and secret-looking filenames remain release blockers.
Run the focused regression before a release candidate build:

```powershell
node scripts/release-evidence-regression.mjs
```
