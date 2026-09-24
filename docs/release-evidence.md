# Release evidence and independent verification

Commercial artifacts are promoted only after each shipped byte has a signed
manifest, a CycloneDX SBOM, and an independently verifiable provenance tuple.
Developer builds may omit signatures, but they must not be presented as
commercial evidence.

## Evidence emitted

`pnpm build:release` creates per-artifact evidence under each `dist/`:

- `aidr-artifact.manifest.json` — sorted SHA-256 file inventory plus RC,
  commit, source-data, package, lockfile and SBOM digests.
- `aidr-artifact.manifest.sig` — Ed25519 signature over the exact manifest
  bytes (commercial mode only).
- `aidr-sbom.cdx.json` and `.sha256` — deterministic CycloneDX 1.5 SBOM with
  SPDX-style license metadata and pnpm lockfile integrity hashes.

Commercial mode also creates `.release-evidence/` with a signed
`release/bundle` manifest. Optional tarballs, VSIX files, plugin manifests,
Supabase function sources and configured container image digests are staged
there with `release-inventory.json`.

The Claude Code endpoint additionally has a signed package-root manifest at
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
`.github/scripts/build-release-bundle.mjs` runs it beside the SBOM copy and then
re-verifies the written statement before the bundle is assembled. The same
statement can be re-checked offline at any time:

```powershell
node scripts/generate-provenance.mjs --output .release-evidence/aidr-provenance.intoto.json
node scripts/generate-provenance.mjs --verify-provenance --provenance .release-evidence/aidr-provenance.intoto.json
```

Verification fails closed when a manifest, the lockfile, or the SBOM no longer
matches the recorded digest, or when an artifact manifest is missing from the
statement. This predicate is unsigned and locally constructed: it carries no
publisher identity, no signature and no transparency-log entry, so it does not
replace signer key custody, registry publication, or the Ed25519 evidence above.

## Required commercial inputs

Never commit these values or place private key material in an artifact:

- `AIDR_SIGNING_PRIVATE_KEY_PEM_PATH` — protected Ed25519 private key file.
- `AIDR_SIGNING_PUBLIC_KEY_PEM_PATH` — separately distributed public key PEM.
- `AIDR_SIGNING_KEY_ID` — stable key identifier.
- `AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT` — SHA-256 SPKI fingerprint, written as
  `sha256:<64 lowercase hex characters>`.
- `AIDR_WATERMARK_ID` — non-sensitive release/customer lineage identifier.
- `AIDR_RC_VERSION` (or `AIDR_RELEASE_VERSION`) and `SOURCE_DATE_EPOCH` —
  stable release identity and timestamp.

If an image is shipped, set `AIDR_IMAGE_DIGEST` to its immutable digest. If
additional archives are shipped, provide repository-relative paths in
`AIDR_EXTRA_ARTIFACT_PATHS` separated by the platform path delimiter.

## Independent verification

Verification must run in a clean checkout or artifact-only directory with the
public key, not the private signing key:

```powershell
$env:AIDR_SIGNING_KEY_ID = "aidr-release-2026"
node scripts/verify-release-evidence.mjs `
  --public-key C:\secure\aidr-release-2026.pub.pem `
  --fingerprint sha256:<64-hex-fingerprint> `
  --lockfile pnpm-lock.yaml `
  --dirs packages/core/dist packages/claude-code/dist packages/claude-code packages/cli/dist .release-evidence
```

The verifier rejects missing or duplicate entries, manifest self-reference,
symlinks, source maps, secret-like filenames/content, host-path leaks,
invalid SBOM/license/integrity evidence, stale SBOM checksums, mismatched
provenance digests, bad release inventories, and invalid Ed25519 signatures.

An exit code of `0` is required before publishing. A missing public key,
fingerprint, private signing key, SBOM, or release provenance is a hard
`NO-GO`; no placeholder signature or synthetic dependency evidence is valid.

## Scanner regression check

The release scanner keeps executable strings and binary payloads strict. It
masks source comments only for generated documentation examples and relative
esbuild module metadata; absolute host paths, real token values, private-key
markers, source maps, and secret-looking filenames remain release blockers.
Run the focused regression before a release candidate build:

```powershell
node scripts/release-evidence-regression.mjs
```
