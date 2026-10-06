# Portable candidate preparation and approved signing

This runbook prepares an unsigned portable installation package and describes
the separate approved signing path. It grants no production GO. Fixture keys,
historical host results and local rehearsal receipts do not establish publisher
ownership, independent acceptance or Legal approval. Release binaries embed
commercial integrity checks and remain blocked until their approved signatures
and public trust configuration are present. Signing only an outer archive does
not satisfy those runtime checks.

Readiness on 6 October 2026: Windows SDK signing tools are available, but the
inspected certificate stores have no certificate with an explicit code-signing
EKU and no approved publisher thumbprint was supplied. The 30 passing signing
tests include an artifact-only receiver and transfer-tamper rejection using
fixtures; they do not establish physical second-machine acceptance or approved
publisher identity. No certificate or key is selected by this runbook.

Assembly runs from the frozen source checkout. Customer installation runs from
the extracted kit with Node.js 24, Docker Engine with Compose v2 and tar; the
customer needs no Git, pnpm or source build. Installation instructions are in
`deploy/operations/PORTABLE-LINUX.md`. Container images require registry access
or a separately prepared and verified air-gap image delivery.

Commands below use POSIX shell syntax. Replace public placeholders with reviewed
values and stop on any failed command; use `set -eu` in a shell running a sequence.
Every output directory must be new. Private keys remain outside the snapshot,
candidate, kit and envelope throughout the process.

## 1. Assemble the unsigned portable package

The build owner first freezes a reviewed commit, creates a clean isolated snapshot
and produces complete `pnpm build:release` outputs with the frozen lockfile.
No private signing keys or certificate material may be exposed during build,
dependency installation or packaging. Preserve the commit, source-tree digest,
release version, prepared-input archive digest, SBOM digest and inventory digest
in the handoff record. Do not use `--allow-dirty` for this candidate.

Use a clean reviewed Supabase checkout at commit
`8c7a4d9dbbaf8b552893822e89d7bf06f33f9220`; its `docker` tree and `LICENSE` must
have no local changes. These separate output paths are ignored within the
isolated source snapshot:

```sh
node scripts/build-release-candidate.mjs \
  --output .tmp-test/portable-release/unsigned-candidate \
  --rc-version APPROVED_VERSION
node scripts/customer-kit.mjs \
  --output .tmp-test/portable-release/unsigned-kit \
  --upstream-dir /opt/aidr-inputs/supabase-upstream \
  --release-dir .tmp-test/portable-release/unsigned-candidate \
  --envelope-output .tmp-test/portable-release/unsigned-envelope
node scripts/customer-kit-verify.mjs --kit .tmp-test/portable-release/unsigned-kit
```

The candidate command packs existing outputs: ten npm archives, Claude plugin,
two VSIX files, dashboard archive, SBOM/checksum and provenance covering all ten
manifests. It uses installed locked `@vscode/vsce` 4.0.0 without installing
dependencies or rebuilding source. Kit assembly bundles the existing deployment
helpers with installed dependencies, so it also runs without private keys.

Deliver `unsigned-envelope` explicitly as an unsigned candidate. Its tar contains
the complete kit; metadata and inventory bind its bytes. Keep
`release_signed: false`, unsigned assurance and absent publisher signatures
truthful. Checksums detect changes and the portable verifier reports
`publisher_authenticated: false`.

Optional `node scripts/verify-customer-kit.mjs <kit-path>` is an engineering
preparation rehearsal using temporary local fixtures. It is neither approved
publisher verification nor a production installation receipt.

## 2. Sign the exact prebuilt inputs in isolation

Keep the unsigned delivery unchanged. Use a separate protected copy of its
frozen source commit and prepared package inputs; compare the independently
recorded digests before signing. The signing authority supplies the approved
Ed25519 artifact key ID, public SPKI fingerprint and public PEM; the AIG RSA
identity; Windows certificate thumbprint and timestamp service; and outer signer
policy, sequence and expiry. Match private keys to those approved public
identities using the custody checks in `.github/workflows/release-rc.yml`.
Do not generate a fixture key to satisfy this handoff.

The existing workflow separates unsigned preparation, Windows Authenticode,
AIG data signing, artifact signing and outer signing. Its Windows stage is new
and outside the source tree, bound to the prepared-input archive digest:

```sh
node .github/scripts/windows-authenticode-inputs.mjs prepare \
  --stage /opt/aidr-inputs/windows-signing-stage \
  --git-sha "$AIDR_GIT_SHA" \
  --unsigned-release-sha256 "$APPROVED_UNSIGNED_INPUT_ARCHIVE_SHA256"
```

On the controlled Windows signing host, use PowerShell 7, the approved certificate
under controlled custody and trusted Microsoft `signtool.exe`. Set `$stage`,
`$approvedThumbprint` and `$approvedTimestampServer` to the reviewed stage,
40-character certificate thumbprint and HTTPS timestamp service:

```powershell
./scripts/sign-windows-response-payload.ps1 `
  -FleetScriptRoot (Join-Path $stage 'fleet') `
  -ClaudeDist (Join-Path $stage 'claude') `
  -InputManifestPath (Join-Path $stage 'input-manifest.json') `
  -ExpectedThumbprint $approvedThumbprint `
  -TimestampServer $approvedTimestampServer `
  -ReceiptPath (Join-Path $stage 'authenticode-receipt.json')
```

This signs twelve fleet scripts and two Claude native copies. Independently hash
the returned complete stage archive and receipt. Verify Authenticode trust on
Windows using the same command with `-CheckOnly`, then consume the verified stage
before regenerating package manifests:

```sh
node .github/scripts/windows-authenticode-inputs.mjs consume \
  --stage /opt/aidr-inputs/verified-windows \
  --git-sha "$AIDR_GIT_SHA" \
  --unsigned-release-sha256 "$APPROVED_UNSIGNED_INPUT_ARCHIVE_SHA256" \
  --receipt-sha256 "$AIDR_EXPECTED_WINDOWS_AUTHENTICODE_RECEIPT_SHA256" \
  --thumbprint "$AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT" \
  --timestamp-server "$APPROVED_WINDOWS_TIMESTAMP_SERVER"
```

AIG uses a separately approved RSA key of at least 2048 bits. Scope private-key
access to its signing command, then remove that access before public verification:

```sh
AIG_SIGNING_PRIVATE_KEY_PATH=/secure/aig-data-private.pem \
  AIG_SIGNING_KEY_ID="$APPROVED_AIG_KEY_ID" node scripts/compile-aig-data.mjs
AIG_RELEASE=true AIG_REQUIRE_SIGNED=true \
  AIG_SIGNING_PUBLIC_KEY_PATH=/opt/aidr-trust/aig-data-public.pem \
  AIG_TRUSTED_SIGNING_KEY_ID="$APPROVED_AIG_KEY_ID" \
  AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256="$APPROVED_AIG_SPKI_SHA256" \
  node scripts/verify-aig-source.mjs
node packages/core/scripts/copy-generated.mjs
AIG_RELEASE=true AIG_REQUIRE_SIGNED=true \
  AIG_GENERATED_DIR="$PWD/packages/core/dist/generated" \
  AIG_SIGNING_PUBLIC_KEY_PATH=/opt/aidr-trust/aig-data-public.pem \
  AIG_TRUSTED_SIGNING_KEY_ID="$APPROVED_AIG_KEY_ID" \
  AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256="$APPROVED_AIG_SPKI_SHA256" \
  node scripts/verify-aig-source.mjs
```

Use the workflow's exact signed-data digest calculation for `AIDR_DATA_DIGEST`
before restoring tracked `packages/core/src/generated` to the frozen commit.
Keep the signed data in `packages/core/dist/generated`. Do not run a workspace
rebuild afterward: it would replace the approved prebuilt/signed bytes.

With all private-key environment variables cleared, set commercial preparation
metadata to the approved public values: `AIDR_RELEASE_MODE=commercial`,
`AIDR_RELEASE_VERSION`/`AIDR_RC_VERSION`, `AIDR_GIT_SHA`, `SOURCE_DATE_EPOCH`,
`AIDR_SIGNING_KEY_ID`, `AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT` (`sha256:` plus 64
lowercase hex characters), `AIDR_WATERMARK_ID` and the signed `AIDR_DATA_DIGEST`.
Set `AIDR_EXPECTED_PREBUILT_SBOM_SHA256` to the independently recorded original
SBOM digest, then run:

```sh
AIDR_PREBUILT_SBOM_PATH="$PWD/.release-evidence/aidr-sbom.cdx.json" \
  node scripts/release-artifact-manifests.mjs
```

Prebuilt validation checks the input against current source, locks, package
manifests, licenses and dependency coverage before rebinding signed data.
Preparation removes stale signatures; finish it before signing. Record the new
SBOM and manifest digests. Local handoffs leave GitHub-only builder/run variables
unset so provenance remains truthfully labelled local.

Sign all ten prepared manifests with the approved Ed25519 key. Generate the
Claude endpoint package-root manifest after its dist signature:

```sh
for artifact_dir in \
  packages/core/dist packages/claude-code/dist packages/extension/dist \
  packages/openclaw/dist packages/opencode/dist packages/cli/dist \
  packages/sdk/dist packages/dashboard/dist packages/codex/dist packages/mcp-gateway/dist
do
  node scripts/sign-artifact-manifest.mjs \
    --dir "$artifact_dir" --key /secure/aidr-artifact-private.pem || exit 1
done
node scripts/generate-artifact-manifest.mjs \
  --dir packages/claude-code --id claude-code/package \
  --version "$AIDR_RELEASE_VERSION" \
  --watermark-id "$AIDR_WATERMARK_ID" --channel commercial
node scripts/sign-artifact-manifest.mjs \
  --dir packages/claude-code --key /secure/aidr-artifact-private.pem
```

The version must match the frozen Claude `package.json`. Remove private-key access
through the signing authority's custody procedure. Verify with the independently
supplied public key; all valued flags precede `--dirs`:

```sh
node scripts/verify-release-evidence.mjs \
  --public-key /opt/aidr-trust/artifact-signing-public.pem \
  --fingerprint "$AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT" \
  --lockfile pnpm-lock.yaml --rc-version "$AIDR_RELEASE_VERSION" \
  --git-sha "$AIDR_GIT_SHA" \
  --dirs packages/core/dist packages/claude-code/dist packages/extension/dist \
  packages/openclaw/dist packages/opencode/dist packages/cli/dist \
  packages/sdk/dist packages/dashboard/dist packages/codex/dist \
  packages/mcp-gateway/dist packages/claude-code
```

## 3. Assemble and sign a new candidate and kit

With private keys inaccessible, repack the verified signed outputs into a new
candidate. This records SBOM/provenance and inventory for the final signed bytes;
it does not rebuild the workspace:

```sh
node scripts/build-release-candidate.mjs \
  --output .tmp-test/portable-release/signed-candidate \
  --rc-version "$AIDR_RELEASE_VERSION"
```

In the isolated outer-signing context, sign that candidate with the approved
publisher key. Sequences are positive integers for the product/channel. Expiry
must be canonical UTC (`YYYY-MM-DDTHH:mm:ss.sssZ`) within policy limits:

```sh
node scripts/release-sign.mjs \
  --bundle .tmp-test/portable-release/signed-candidate \
  --private-key /secure/aidr-release-private.pem --key-id APPROVED_RELEASE_KEY_ID \
  --sequence APPROVED_SEQUENCE --expires-at APPROVED_UTC_EXPIRY --channel stable
```

Remove private-key access before kit assembly. A signed inner bundle requires
the independently pinned Windows receipt and certificate thumbprint; the kit
copies the verified signed fleet bytes:

```sh
node scripts/customer-kit.mjs \
  --output .tmp-test/portable-release/signed-kit \
  --upstream-dir /opt/aidr-inputs/supabase-upstream \
  --release-dir .tmp-test/portable-release/signed-candidate \
  --windows-authenticode-receipt-sha256 "$AIDR_EXPECTED_WINDOWS_AUTHENTICODE_RECEIPT_SHA256" \
  --windows-code-signing-thumbprint "$AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT" \
  --envelope-output .tmp-test/portable-release/signed-envelope
node scripts/customer-kit-verify.mjs --kit .tmp-test/portable-release/signed-kit
```

Return the completed envelope to the isolated outer signer. Sign it on the
separate `customer-kit` channel with its approved sequence:

```sh
node scripts/release-sign.mjs \
  --bundle .tmp-test/portable-release/signed-envelope \
  --private-key /secure/aidr-release-private.pem --key-id APPROVED_RELEASE_KEY_ID \
  --sequence APPROVED_KIT_SEQUENCE --expires-at APPROVED_UTC_EXPIRY --channel customer-kit
```

Do not alter or finalize signed output afterward. A partial signing failure
requires rebuilding the bundle in a new directory. The inner signature covers
`artifacts/`; the outer signature covers the complete kit tar, including helpers
and documents. Signed kit assembly checks signature presence, not publisher
authorization, so independent verification is still required.

## 4. Verify on an independent second machine before extraction

Deliver public signer policy and trusted copies of `release-verify.mjs` and
`release-signing-lib.mjs` through an independent trusted channel. Policy,
persistent anti-rollback state and receipt stay outside the received bundle/kit.
The policy declares approved public Ed25519 signers, validity/revocations,
allowed channels, minimum sequence and maximum signature lifetime. It must allow
`customer-kit`; the inner release policy must allow `stable`. Never derive trust
from an unverified public key inside the delivery.

```sh
node /opt/aidr-trust/release-verify.mjs \
  --bundle /delivery/signed-envelope --policy /etc/aidr/customer-kit-policy.json \
  --state /var/lib/aidr/customer-kit-release-state.json \
  --receipt /var/log/aidr/customer-kit-verification.json
mkdir -m 0700 /srv/aidr-verified-kit
tar -xzf /delivery/signed-envelope/aidr-customer-kit.tar.gz -C /srv/aidr-verified-kit
node /srv/aidr-verified-kit/signed-kit/scripts/customer-kit-verify.mjs \
  --kit /srv/aidr-verified-kit/signed-kit \
  --release-policy /etc/aidr/artifact-release-policy.json \
  --release-state /var/lib/aidr/inner-release-state.json \
  --release-receipt /var/log/aidr/inner-release-verification.json
```

Stop before extraction if outer verification fails; the extraction directory
must not already exist. Initial verification omits `--record`, so it checks
rollback without advancing state. Record the actual second-machine identity,
manifest/inventory digests and positive/negative receipts. Exercise tamper,
expiry, wrong-signer and rollback rejection using disposable copies. Verifier
JSON alone does not attest that a separate machine was used.

Follow `deploy/operations/PORTABLE-LINUX.md` for the authorized installation.
After installation and acceptance succeed, reverify the unchanged outer envelope
with the same policy/state and `--record` to advance anti-rollback state. Do not
reset persistent state or reuse a sequence for different bytes. Signature and
portable checks do not replace live installation, restore, host enforcement,
Security/Privacy/Legal review or the named owners' exact-candidate decision.
Until those real receipts are approved, the deliverable remains a candidate and
production GO remains open.
