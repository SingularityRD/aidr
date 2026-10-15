# First release runbook: cutting and promoting v1.0.0

No release has been cut yet: the repository only has `v1.0.0-sprint*` tags,
which no release workflow accepts. This page lists, in order, every step only a
person can do to produce the first signed, promoted **v1.0.0** and the first
per-customer installers. The workflows do the rest.

How the pieces fit:

1. A PGP-signed, annotated, protected tag `v1.0.0-rc.N` on the default branch
   starts `release-rc.yml` (build, test, sign, attest, draft prerelease) and
   `release-images.yml` (container images, Helm chart, air-gap image bundle).
2. `release-promote.yml` (`action=promote`) promotes that one RC after a
   recorded production GO: npm packages, dashboard, the RC's GitHub release made
   final, and **the same signed files published again as the final `v1.0.0`
   release at the same commit**.
3. `customer-installer.yml` builds a customer's MSI/EXE/deb/rpm/tar.gz from
   `release_tag=v1.0.0` (or the promoted `v1.0.0-rc.N`). The installer file names
   and the product version are `1.0.0`; "-rc.N" never appears in what a customer
   receives.

## 0. Keys and accounts (once, before the first RC)

Generate every private key on an offline or hardened workstation, store the
private half only in the GitHub environment named below (and in the company's
offline backup), and record each fingerprint in a second place (password
manager, printed key ceremony record) so it can be checked independently.

| What | Who creates it | Where it goes |
|---|---|---|
| Release tag PGP key (signs `vX.Y.Z-rc.N` tags) | release manager | public key + fingerprint: secrets `RELEASE_TAG_PGP_PUBLIC_KEY`, `RELEASE_TAG_PGP_FINGERPRINT` in environments `release-candidate` and `release-images`; private key stays with the release manager (hardware token recommended) |
| Release signing key, Ed25519 (`docs/runbooks/portable-release-signing.md`) | release manager | `AIDR_SIGNING_PRIVATE_KEY_PEM`, `AIDR_SIGNING_PUBLIC_KEY_PEM`, `AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT` (`release-candidate`); variable `AIDR_SIGNING_KEY_ID` |
| Signer policy JSON (which keys may sign which release) | release manager | `AIDR_RELEASE_SIGNER_POLICY_JSON` (`release-candidate` and `production`) |
| AIG data signing key, Ed25519 | release manager | `AIG_DATA_SIGNING_PRIVATE_KEY_PEM`, `AIG_DATA_SIGNING_PUBLIC_KEY_PEM`, `AIG_DATA_SIGNING_PUBLIC_KEY_SHA256`; variable `AIG_DATA_SIGNING_KEY_ID` |
| Linux package GPG key | release manager | `AIDR_LINUX_PACKAGE_GPG_PRIVATE_KEY`, `AIDR_LINUX_PACKAGE_GPG_PASSPHRASE`, `AIDR_LINUX_PACKAGE_GPG_FINGERPRINT` (`release-candidate`) |
| Windows code-signing certificate (OV, HSM-held) | company officer buys it ([windows-code-signing.md](windows-code-signing.md)) | `AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT`, variable `AIDR_WINDOWS_TIMESTAMP_SERVER`, and the backend variables (`AIDR_WINDOWS_SIGNER` = `azure-key-vault` or `jsign`, …) |
| Installer catalog key, Ed25519 | release manager | private: `AIDR_INSTALLER_MANIFEST_SIGNING_KEY_PEM` (`production`); public: variable `AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_PEM`; variable `AIDR_INSTALLER_MANIFEST_KEY_ID` |
| Offline (air-gap) bundle key, Ed25519 | release manager | `AIDR_OFFLINE_BUNDLE_SIGNING_KEY_PEM` (`release-images`); variable `AIDR_OFFLINE_BUNDLE_KEY_ID` ([air-gapped install](../../deploy/README.md#disconnected-air-gapped-installation)) |
| License signing key | business owner + release manager | `deploy/onprem/license-public-keys.json` (public); private key offline (`docs/operations/licensing.md`) |
| Evidence keys for external acceptance runs | QA owner | `AIDR_EXTERNAL_E2E_EVIDENCE_PUBLIC_KEY_PEM`, `AIDR_OPENCLAW_HOST_EVIDENCE_PUBLIC_KEY_PEM` |
| Dashboard deploy hooks and smoke URLs | operations | `DASHBOARD_DEPLOY_HOOK_URL`, `DASHBOARD_ROLLBACK_HOOK_URL`, `DASHBOARD_SMOKE_BASE_URL`, `DASHBOARD_VERSION_URL` (`production`) |
| Download portal (optional) | operations | `AIDR_DOWNLOADS_SUPABASE_URL`, `AIDR_DOWNLOADS_SERVICE_ROLE_KEY`, variable `AIDR_INSTALLERS_BUCKET` (`production`) |
| Host API keys for the acceptance E2E | QA owner | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CURSOR_API_KEY`, `OPENCODE_API_KEY`, `OPENCLAW_GATEWAY_TOKEN` (`release-candidate`) |

GitHub settings, once:

- Environments `release-candidate`, `release-images` and `production` exist;
  `production` has required reviewers and is limited to the default branch.
- A tag ruleset protects `v*` tags: only release managers may create them,
  deletion and update are blocked. The promotion workflow creates the final
  `vX.Y.Z` tag through the release API at the RC's commit; if the ruleset does
  not let the workflow create it, push the signed final tag yourself first (step
  5) — the workflow then only checks it points at the same commit.
- Branch protection on the default branch (all release workflows refuse other refs).

## 1. Version bump

```bash
pnpm changeset          # select every shipped package, "major" for 1.0.0
pnpm run version        # bumps package.json files and the synced manifests to 1.0.0
pnpm ci:local:release   # strict local gates, including the full-history secret scan
```

Open a pull request, get it reviewed and merged.

## 2. Cut the release candidate

```bash
git switch <default branch> && git pull --ff-only
git tag -s -a v1.0.0-rc.1 -m "AIDR 1.0.0 release candidate 1"
git push origin v1.0.0-rc.1
```

`release-rc.yml` and `release-images.yml` start on the push. Watch them; a
failure is fixed on the default branch and released as `v1.0.0-rc.2` (RC tags
are never moved).

## 3. Acceptance on the exact candidate

- Run the protected real-host acceptance and, on Windows, the opt-in
  [Windows real-host workflow](../evidence/real-host/README.md#windows) against
  the candidate; record what a human checked by hand.
- Install the draft prerelease's MSI and `.deb`/`.rpm` on clean machines and
  check `Get-AuthenticodeSignature` / `rpm -K` / `dpkg-sig` equivalents.

## 4. Record the production GO

Update `docs/production-readiness/commercial-go-evidence-registry.json` on the
default branch: `decision: "GO"`, `releaseCandidate` = the SHA-256 of the RC's
`release-inventory.json`, closed hard-gate receipts bound to that digest, a fresh
`lastReviewed`. This is a business decision: the security owner and the business
owner sign it off in the pull request.

## 5. Promote

Optional, if the tag ruleset blocks workflow-created tags:

```bash
git tag -s -a v1.0.0 -m "AIDR 1.0.0" v1.0.0-rc.1^{commit}
git push origin v1.0.0
```

Then run **Release Promote, Rollback or Yank** with `action=promote`,
`tag=v1.0.0-rc.1`, `rc_run_id=<the successful release-rc.yml run>` and, for this
first promotion only, `genesis=FIRST_PROMOTION`. The production reviewers approve
the job. It publishes the RC release as final and the **final `v1.0.0` release**
with the same files.

## 6. First customer installers

Issue the customer packet (`scripts/customer-packet-issue.mjs`, see
[customer-builds.md](customer-builds.md)), then run **Customer Installer Build**
with `release_tag=v1.0.0`, the customer id and the packet. Deliver the artefacts
with their `SHA256SUMS` and the verification instructions.

## Needs a human (summary)

Every key and certificate in step 0, the GitHub environment and ruleset
settings, the version bump review, pushing the signed tags, the acceptance runs
and manual checks, the GO decision in the registry, approving the production
job, and issuing customer packets. None of these can be done by the workflows.
