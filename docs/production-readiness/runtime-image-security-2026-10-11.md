# Runtime image security — first-party dashboard, landing and backup helper (AIDR-079, AIDR-082), 2026-10-11

Scope: the first-party images left `IMPLEMENTED_UNVERIFIED` by AIDR-079 (dashboard and landing runtime)
and AIDR-082 (backup/recovery Node helper). The upstream Supabase pins are covered separately by
`runtime-image-security-2026-10-07.md`, which this record does not change.

Run window: 2026-10-10T22:40Z – 23:20Z UTC, which is 2026-10-11 in the backlog's Europe/Istanbul timezone.
Host: Linux x86_64, Docker Engine 29.8.2 (containerd image store), Node v24.21.0 (official
nodejs.org tarball, verified against `SHASUMS256.txt`). Source: `a6aea1bb93dee0ed625d5817ca5fcfede9248d48`
plus the two-file guard fix below. Landing: `SingularityRD/aidr-landing` `e039be0b` (only branch: `main`).

## Scanner

- Trivy **0.73.0**, the same version as the 2026-10-07 record, from the GitHub release tarball checked
  against `trivy_0.73.0_checksums.txt`. The repo pins no local-image scanner: `scripts/scan-runtime-images.mjs`
  scans remote Docker Hub refs only, and these images are built locally.
- Vulnerability DB v2, updated **2026-10-10T18:59:50Z**, downloaded 22:46:22Z from `mirror.gcr.io/aquasec/trivy-db:2`.
- Command, run from an empty working directory with an empty ignore file and an empty config:
  `trivy image --input <docker save tar> --scanners vuln --pkg-types os,library --skip-db-update --ignorefile empty.trivyignore --config empty-trivy.yaml --format json`.
  No `.trivyignore`, no VEX and no severity filter. Each occurrence of a package/target pair counts once.
- Compact results: `evidence/runtime-image-scan-2026-10-11/summary.json`.

## Base image provenance

Docker Hub rejected anonymous manifest requests with `429 Too Many Requests` for the whole run. The pinned
base `node:24.21.0-alpine3.24@sha256:ebfe2f90…ec1c1` was therefore pulled from `mirror.gcr.io/library/node`.
That pull returned exactly the same content-addressed index digest, `sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1`,
and was tagged locally under the official name. The bytes are identical. Only the transport differs.

For the same reason, the CI command `docker build --pull` (ci-local step `onprem-dashboard-image`) failed on
the 429 before building anything. The same step was then run by hand with `--pull=false` against the
digest-identical cached base:

```bash
pnpm -C packages/dashboard build
node scripts/deployment-prepare.mjs --output <tmp>/aidr-deploy --development \
  --dashboard-url http://127.0.0.1:8080 --supabase-url http://127.0.0.1:8000 --region self-hosted --tenant-region self-hosted
docker build --pull=false --tag aidr-dashboard:ci <tmp>/aidr-deploy/dashboard
node -e 'import("./scripts/lib/node-helper-image.mjs").then(m => console.log(m.buildNodeHelperImage()))'
```

## Results (CRITICAL / HIGH, no ignores)

| Image | Image config ID | OS | CRITICAL | HIGH | Other |
|---|---|---|---:|---:|---|
| Stock `node:24.21.0-alpine3.24` (reference) | `sha256:c10884952bb8…` | Alpine 3.24.2 | 0 | **8** | 13 MEDIUM, 1 LOW |
| **Dashboard** `aidr-dashboard:ci` (`deploy/dashboard/Dockerfile`) | `sha256:9060947615…` (image `sha256:29755bee33530d73…`) | Alpine 3.24.2 | **0** | **0** | 1 MEDIUM |
| **Backup helper** (`scripts/lib/node-helper.Dockerfile`) | `sha256:744c473f135d…` | Alpine 3.24.2 | **0** | **0** | 1 MEDIUM |
| Landing runner base, stock `node:20-slim` (unpinned, Node 20 is EOL) | `sha256:2cf067cfed83…` | Debian 12.13 | **7** | **84** | lower bound; the runner also copies the full build `node_modules` |

- All 8 stock-base HIGH findings are in npm's bundled packages: `brace-expansion` ×4, `http-cache-semantics`,
  `ip-address`, `tar` and `undici`. The dashboard and the helper delete npm, npx, Corepack, Yarn, pnpm and
  pnpx, so those packages are not in the image and Trivy finds no Node.js language target at all.
- The only residual in both first-party images is `zlib` CVE-2026-85091 (MEDIUM, Alpine 3.24.2 OS package).
  Clearing it needs a new base build. A MEDIUM finding is outside both acceptance criteria. Nothing is accepted here.
- Coverage limits: Trivy does not inventory the `node` binary itself (Node 24.21.0, which embeds OpenSSL 3.5.8;
  the DTLS vendor-patch question in AIDR-082's `remainingExternal` is still open). It also does not
  inventory the dashboard's pre-bundled static frontend under `/app/public`. The supply chain for those
  assets is covered by the `pnpm audit` gates, not by this scan.
- Compared with the backlog's original measurement (dashboard 3 CRITICAL / 49 HIGH, helper on Node 24.12 /
  Alpine 3.23 with 3 CRITICAL / 49 HIGH): those figures used an older scanner, an older DB and the old base,
  so they are not directly comparable. The within-run comparison is stock base 8 HIGH against first-party 0.

## Dashboard runtime checks (AIDR-079)

The image was confirmed by inspection: `USER node` (uid 1000), `CMD ["node","server.mjs"]` and the `/readyz`
image HEALTHCHECK. `/usr/local/lib/node_modules` is empty, `/opt/yarn-*` is gone, and `npm`, `npx`, `corepack`,
`yarn`, `yarnpkg`, `pnpm` and `pnpx` are all absent from PATH. `node -v` reports v24.21.0, and `tar` and `sh`
are present.

Two containers ran with the compose hardening: `--read-only --cap-drop ALL --security-opt no-new-privileges:true
--memory 256m --pids-limit 128 --cpus 0.5`, with the health directory bind-mounted read-only.

| Case | Result |
|---|---|
| Startup with a non-public Supabase key | Refused: `Only an anonymous or publishable key may be exposed` (fail-closed) |
| Production defaults, all 7 readiness checks, upstreams unreachable | `/livez` 200; `/readyz` **503** (`database`/`storage`/`functions`/`certificate` failed; `signing`/`backup`/`queue` ok from files); image HEALTHCHECK → `unhealthy` as designed |
| Compose-equivalent development mode (`AIDR_DEVELOPMENT_MODE=true`, file-backed checks) | `/livez` 200, `/readyz` **200** `ready`, compose `/livez` healthcheck → `healthy` |
| Both | `/` serves the SPA (200) with CSP, X-Frame-Options and X-Content-Type-Options; `/metrics` 401 without token, 200 with it |
| Process hardening inside both | uid 1000, `CapEff: 0000000000000000`, `NoNewPrivs: 1`, writes to `/app` and `/tmp` fail with read-only filesystem, 0 restarts |

Repo tests, all run on Node 24.21.0:

- `node --test deploy/dashboard/server.test.mjs scripts/dockerfile-context.test.mjs scripts/deployment-prepare.test.mjs scripts/customer-kit-verify.test.mjs`: **58/58** before the fix below.
- `scripts/deployment-prepare.test.mjs` after the fix: **25/25**.

### Landing: not verified, and not remediated in any reachable source

The backlog's AIDR-079 evidence describes "exact replacements" for landing built on Node 24.21/Alpine 3.24.
Public `SingularityRD/aidr-landing` has a single branch, `main` at `e039be0b`, which is the same commit as
`latestVerification.source.landingBaselineCommit`. Its `Dockerfile` still uses `FROM node:20-slim` in all
three stages with no digest, runs `corepack enable`, and copies the full builder `node_modules` (dev
dependencies included) into the runner. The stock runner base alone has 7 CRITICAL / 84 HIGH. The landing
replacement therefore exists in no source this verification could reach, and **AIDR-079 cannot be closed**.

## Backup helper and encrypted backup/recovery (AIDR-082)

**Helper build.** `buildNodeHelperImage()` writes only the reviewed `node-helper.Dockerfile` into a fresh
`mkdtemp` context, which is fixed and public-only. It builds with `--pull=false --network=none` and returns
`sha256:…`. Three builds returned different IDs (`8f0379d8…`, `7f20ac43…`, `849b19d7…`) because each build has
its own attestation manifest. All three have an identical `RootFS.Layers` list and the same config. The
backup manifest records the exact returned ID used (`helper_image`). A `--progress=plain` rebuild shows the
base metadata resolved from the local store in 0.0s, while Docker Hub was returning 429 for the same digest,
so the build needs no registry. An uncached base digest fails the build. The helper runs `--network none`.
It runs as root only to preserve volume ownership.

**Real drill.** A clean clone of `a6aea1bb` was used, with `source_has_changes: false`. The main tree has
other agents' uncommitted edits, and backup correctly refuses a dirty source. Steps:

1. The prepared kit was run against real `supabase/postgres:17.6.1.136`. A 5000-row sentinel table was
   created, and a storage volume was seeded with a 1 MiB random object owned by uid 1000.
2. `backup/deployment-backup.mjs keygen`, then `backup --maintenance`, wrote three AES-256-GCM entries and an
   HMAC manifest. db was stopped, a clean `pg_controldata` shutdown was confirmed, and db was restarted. None
   of the archives starts with gzip magic, and none contains plaintext table or `PG_VERSION` strings.
3. `verify` passed. With a wrong key: `Backup manifest authentication failed` (exit 1). With one bit flipped
   in the ciphertext: `Backup file integrity check failed` (exit 1).
4. `recover --runtime <reviewed clean install>` created a new project `aidr-recovery-4b6f2665a55ebd94` with
   new db and storage volumes, and left its services stopped. After starting the recovered db, the sentinel
   matched exactly (`5000:70b880b450bbc39abfdd304166b3eec1`). The storage file-digest inventory matched
   exactly (`82baf981…`), and so did ownership (1000:1000). The installation tree differed only in
   `deployment.json` and `.env`, which the recovery rewrites with the new project name. The source and
   recovered projects were then removed with their volumes.

**Defect found and fixed.** `deployment-prepare` and `customer-kit` ship `deployment-backup.mjs` as an
esbuild bundle that inlines `deployment-restore-drill.mjs` and `deployment-backup-offsite.mjs`. Inside the
bundle, each module's main-guard `import.meta.url === argv[1]` was true. As a result, every backup command
also ran the restore-drill and offsite CLIs with the backup's own arguments. Before the fix this printed
`AIDR restore drill failed …` and `AIDR offsite backup failed …` and set `process.exitCode = 1`. The
`backup`, `verify` and `keygen` commands hid this because they call `process.exit(0)`. A **fully successful
`recover` exited 1**, which would mark `aidr-backup-recover.service` as failed.

The fix: both guards now also require the module's own file name. A regression check in
`scripts/deployment-prepare.test.mjs` runs the prepared bundle's `keygen` and asserts exit 0 with no foreign
CLI output. With the re-bundled fixed tool, the full backup → verify → recover sequence ran with exit 0 and
no stray output. Custody and archive boundaries are unchanged: `pnpm verify:backup-offsite` passes **69/69**.

**Not run.** The automated off-host drill (`deployment-restore-drill.mjs`) was not run. It needs an offsite
S3 or separate-mount target, a signed release-candidate inventory and a signer policy. Off-host recovery and
operator custody stay external gates in AIDR-082's `remainingExternal`. No Windows helper was built or scanned.

## Other gates run

- `pnpm verify:upgrade`: 43 checks passed.
- `pnpm verify:onprem-config-reference`: 4/4.
- `pnpm verify:bootstrap`: 23/24. The failure is an IPv6 `::1` loopback case: `EAFNOSUPPORT` on this host,
  which has no IPv6. `onprem-extra` failed only on the same IPv6 case in `deployment-offboarding.test.mjs`
  (82/83). Both are environment failures, not image-related.
- The `deploy/upstream` submodule was initialised (sparse `docker`, shallow) so these gates could run.

## Status decision

- **AIDR-082 → VERIFIED_CLOSED** locally. The external gates remain in `remainingExternal`: Node OpenSSL
  DTLS applicability, physical off-host recovery and operator custody.
- **AIDR-079 stays IMPLEMENTED_UNVERIFIED.** The dashboard half meets acceptance (supported pinned base,
  tools removed only from the runner, nonroot read-only startup and readiness, 0 CRITICAL / 0 HIGH without
  ignores). The landing half is unremediated in its only published source.

## Reproduce

```bash
node scripts/ci-local.mjs --only onprem-dashboard-image     # needs Docker Hub; on 429 use the manual --pull=false sequence above
trivy image --input <saved.tar> --scanners vuln --pkg-types os,library --ignorefile <empty> --config <empty> --format json
node --test scripts/deployment-prepare.test.mjs deploy/dashboard/server.test.mjs
pnpm verify:backup-offsite
```

A rerun with a newer DB will produce different counts. Compare only within a single run.
