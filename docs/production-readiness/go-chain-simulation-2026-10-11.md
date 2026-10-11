# GO chain rehearsal: promote → rollback, 2026-10-11

**Label: LOCAL SIMULATION. This is not a GitHub Actions run and not a production GO.** Every GO record in this
rehearsal is a synthetic fixture. It was written into a disposable git copy of the trusted verifier checkout under
the OS temp directory. The real `commercial-go-evidence-registry.json` and `commercial-gate-receipts.json` were
read and never written. The real registry is still `decision: "NO-GO"` with `releaseCandidate: null`. Nothing was
published, tagged, deployed or released.

This closes the last bullet of `PRODUCTION_READY_PROMPT-2026-10-11.md` §A.4: the "GO chain rehearsal".

**Harness:** `scripts/release-go-chain-simulation.test.mjs`. Run it with
`node --test scripts/release-go-chain-simulation.test.mjs` (about 50 s). It is part of the `commercial-readiness`
step of `pnpm ci:local`. Set `AIDR_GO_CHAIN_SIMULATION_KEEP=1` to keep the runs, workspaces and fake GO trees for
inspection.

## Why not `act`

`act` v0.2.82 was downloaded from the nektos/act GitHub release and checked against that release's
`checksums.txt`. `act_Linux_x86_64.tar.gz` has sha256
`76645c0bbe4bb69a8f0ba3caefa681b2f4c04babd4679c67861af9a276a3561f`. `act -n -j dry-run` against
`release-promote.yml` stopped at its first `uses:` step. It could not clone `actions/checkout` through this
environment's git proxy (`authentication required`). The jobs also need things `act` cannot provide even with
that fixed:

- `actions/download-artifact` with `run-id:` pulls the RC bundle and the protected state from **other**
  workflow runs through the GitHub API;
- `gh attestation verify` needs GitHub's attestation API and Sigstore trust roots;
- `verify-release-run.mjs` and `find-release-state-run.mjs` query the GitHub REST API for run identity;
- the jobs use the `production` / `release-candidate` environment secrets.

So the rehearsal uses a local runner instead.

## What the local runner executes

The runner parses `.github/workflows/release-promote.yml` and runs the `dry-run`, `promote` and `rollback` jobs
step by step, in workflow order:

- **Executed verbatim.** Every `run:` step except the four stubs below runs under
  `bash --noprofile --norc -eo pipefail` with its own `env:`, with `${{ }}` expressions resolved. Steps exchange
  values through `GITHUB_OUTPUT`/`GITHUB_ENV`/`GITHUB_PATH`. That includes the input validation,
  `find-release-state-run`, the signer-policy step, `verify-release-run` → `verify-release-promotion --record` →
  the stable-version tarball check → `candidate_digest`, `stage-verified-artifact-roots`,
  `verify-production-go --record`, the npm publication plan and publish, the dist-tag move and the rollback
  `verify-production-go --rollback`.
- **Fake GitHub.** A loopback HTTPS fake of the REST API (runs and artifacts) answers, with a throwaway
  self-signed CA passed through `NODE_EXTRA_CA_CERTS`. The trusted-API-origin check still runs.
- **Emulated actions.** `checkout` clones a fixture RC repository at the tag, and the trusted verifier
  repository at `github.workflow_sha`. `upload-artifact` and `download-artifact` use an artifact store keyed by
  run ID. The GO ledger therefore travels from the promote run to the rollback run through the same
  `aidr-promotion-anti-rollback-state` artifact as in production.
- **Stubbed publication.** `npm` is a PATH shim. It records every call and never contacts a registry.
  `npm view` answers E404, so every package counts as unpublished. Three steps are recorded and not performed:
  the dashboard deploy and smoke, the rollback retag, and the GitHub release.
- **Not simulated.** The pinned `gh` download and `gh attestation verify`.

**Fixtures.**

- The RC bundles are built and signed locally. Each has six npm tarballs plus a dist archive for every registry
  `artifactRoot`, a CycloneDX SBOM with sidecar, provenance bound to the RC lockfile, commit and run ID, and
  metadata and inventory. `scripts/release-sign.mjs` signs them with Ed25519 under a throwaway signer policy.
- There are three bundles: `v9.9.8-rc.0`, `v9.9.9-rc.0`, and a rebuilt `v9.9.9-rc.0` with the same tag and
  commit but a different inventory digest.
- The trusted verifier is a git copy of this working tree, without vendored subtrees or `dist/`.
- The fake GO overlay is a commit on top of that copy. It sets `decision: "GO"`, sets `releaseCandidate` to the
  digest, and closes every hard gate. Receipts, the SEC-EXT-001 assessment and the investor metrics are bound to
  that digest and point at `fixture-go-evidence/` files labelled as simulation fixtures. The real receipt verifier
  and the real `claim-check --mode=gate` then judge it.

## Result (all 9 scenarios pass)

| # | Scenario | Outcome |
|---|---|---|
| 1 | Coverage check | Every stubbed step still exists. Promote order is verify → stage → GO → persist → publish. Rollback order is verify → GO `--rollback` → retag. |
| 2 | `dry-run` job, 9.9.9 | Pass. The six `npm publish` calls all carried `--dry-run`. `verify-release-run` hit the fake run API. |
| 3 | `promote` 9.9.9, shipped **NO-GO** registry | Refused at "Require candidate-bound production GO". Verify and stage had passed. The reasons were `registry decision is "NO-GO"` and a failing claim-check. **Zero** mutations, no state artifact, no ledger. |
| 4 | `promote` 9.9.9, fake GO naming the **9.9.8 digest** | Refused at the GO step ("different candidate than this bundle"). Zero mutations. |
| 5 | `promote` 9.9.9, fake GO for the **exact digest** | GO passes. The state artifact holds `anti-rollback-state.json`, `verification-receipt.json` and `production-go-ledger.json`. The ledger is `aidr-production-go-ledger/v2` with one entry, chained to genesis, `entry_sha256` = head. The entry records the digest, version, tag and commit, plus the registry/receipt SHA-256 and the trusted verifier commit. All publish, dist-tag, deploy and release mutations came after the GO step. |
| 6 | `rollback` 9.9.9, registry back to **NO-GO** | Pass. The ledger was restored from the promote run's artifact, and only the stubbed retag ran. |
| 7 | `rollback` 9.9.8: authentic, signed, never promoted | Refused at the rollback GO step ("has no production GO record"). No retag. |
| 8 | `rollback` to the rebuilt 9.9.9 (**wrong digest**) | Refused. The signature and identity were valid, but there is no ledger entry for that digest. No retag. |
| 9 | **Tampered ledger.** The entry's digest was edited in the stored artifact. | Both rollbacks (rebuilt and genuine 9.9.9) were refused with "ledger entry 0 entry_sha256 does not match its contents". A new GO promote was refused with "could not record the GO decision", with zero mutations. |

`node scripts/ci-local.mjs --allow-dirty --only commercial-readiness,ci-local-drift,ci-workflows,actionlint --fetch-tools`:
PASS, with 7/7 steps including the guards and an unchanged working tree.

## Limits

- Build attestations and gh are not verified here. The Node runtime is the host's, not the pinned 22.12.0.
- Registry publication, dashboard deployment, rollback retag and the GitHub release are stubs.
- The fake GitHub API answers only the endpoints these jobs call.
- The ledger hash chain detects edits that do not recompute digests. It is not a signature: its authenticity still
  rests on the protected promotion artifact (see `scripts/verify-production-go.mjs`).
- A real Actions run of `release-promote.yml` is still outstanding. So is a real GO record.
