# Upstream image triage — self-hosted Supabase pins (AIDR-080), 2026-10-11

Scope: every upstream image the self-hosted kits deploy. That means the Compose kit (`deploy/upstream/docker/docker-compose.yml`
at submodule `8c7a4d9d`, plus the tag@digest overrides in `scripts/deployment-prepare.mjs`) and the Helm chart
(`deploy/helm/aidr/values.yaml` and the `edge-functions` base in `deploy/helm/images/edge-functions.Dockerfile`).
This record follows on from `runtime-image-security-2026-10-07.md`, whose findings and pins it keeps unchanged as
history. First-party images (dashboard, landing, helpers, bridge) are out of scope. Nothing here is a risk acceptance.

Result in one paragraph: no newer upstream tag of any Compose service removes a CRITICAL or HIGH finding in this run.
The Compose set therefore stays at **33 CRITICAL / 727 HIGH**. One Compose pin did move: Storage `v1.80.0` → `v1.80.2`.
The scan findings are identical, but v1.80.2 adds a vendor authorization fix that callers can reach. The Helm chart
had fallen behind the Compose pins, and aligning it reduces its upstream set from **5 CRITICAL / 213 HIGH to
5 CRITICAL / 172 HIGH** without adding any finding. Native acceptance ran for Storage v1.80.2 only (19/19 checks,
upgrade and fresh install). AIDR-080 stays **BLOCKED_EXTERNAL**.

## Method

- **Scanner:** Trivy **0.73.0**, from the GitHub release tarball `trivy_0.73.0_Linux-64bit.tar.gz`. Its sha256
  `2edd39da…547b` matches `trivy_0.73.0_checksums.txt`, and the binary in use is byte-identical to the one in the tarball.
- **Vulnerability DB:** v2, UpdatedAt **2026-10-11T01:13:45Z**, pulled from `mirror.gcr.io/aquasec/trivy-db:2`. All
  20 scans used this one DB version. The first four (studio, auth, storage v1.80.0, rest) ran from an earlier
  download of the same DB version, because that cache was deleted mid-run. The scan window was 02:29:40Z – 02:42:31Z UTC.
- **Command:** each scan ran from an empty working directory with an empty `--config` and an empty `--ignorefile`, with no VEX and no
  severity filter:
  `trivy image --image-src remote --platform linux/amd64 --scanners vuln --pkg-types os,library --skip-db-update --format json`.
  The full JSON reports, with every severity, are kept outside the repo. The compact evidence keeps CRITICAL/HIGH with package, installed
  version, fixed version, target and, for language packages, `PkgPath`. Counting matches the 2026-10-07 record:
  every package/target occurrence counts once (`scripts/scan-runtime-images.mjs` `compactFindings`/`countFindings`).
- **Image identity:** Docker Hub's registry rate-limits anonymous manifest reads, so every image was resolved and
  scanned through `mirror.gcr.io`. The manifest digest that `mirror.gcr.io` returned for each tag was checked against
  the `hub.docker.com` tag API digest, and all 20 matched (`plan.json`). Digests are content addresses, so only the
  transport differs.
- **Candidates:** the tags newer than each pin were taken from the `hub.docker.com` tag listings on 2026-10-11. Release
  content was taken from the vendor git history: `supabase/storage` and `supabase/realtime`, cloned anonymously. GitHub's
  REST API and postgresql.org were not reachable from this host.
- **Compatibility anchor:** upstream `supabase/supabase` `master:docker/docker-compose.yml` still pins the same set
  as our submodule. Its `versions.md` was last updated 2026-09-09, so upstream has published no newer "supported self-host" set.
- **Evidence:** `docs/production-readiness/evidence/upstream-image-triage-2026-10-11/`. It holds one record per image,
  `summary.json` (with DB metadata and comparisons), `plan.json`, the Storage acceptance probe and its outputs.

## Compose kit — current pins vs newest candidates (same run)

| Service | Pin on 2026-10-11 | CRIT / HIGH (fix available) | Newest candidate(s) | Candidate CRIT / HIGH | Decision |
|---|---|---:|---|---:|---|
| studio | `supabase/studio:2026.10.05-sha-94b8b06` | 17 / 321 (14 / 55) | none newer (next weekly not yet published) | — | Keep |
| auth | `supabase/gotrue:v2.197.0` | 0 / 9 (0 / 8) | only `v2.198.0-rc.*` (pre-release) | — | Keep (no RC pins) |
| storage | `supabase/storage-api:v1.80.0` | 1 / 57 (1 / 56) | `v1.80.2`, `v1.81.0` | 1 / 57 each, identical ids | **Bump to v1.80.2** (vendor auth fix, see below) |
| meta | `supabase/postgres-meta:v0.100.0` | 8 / 89 (7 / 36) | none newer | — | Keep |
| functions | `supabase/edge-runtime:v1.77.4` | 4 / 58 (3 / 5) | none newer | — | Keep |
| realtime | `supabase/realtime:v2.134.10` (submodule) | 3 / 141 (3 / 56) | `v2.143.3` | 3 / 141, identical ids | Keep (see below) |
| api-gw | `envoyproxy/envoy:v1.39.2` | 0 / 0 | `v1.39.3` | 0 / 0 | Keep (no reduction) |
| imgproxy | `darthsim/imgproxy:v4.0.17` | 0 / 4 (0 / 4) | none newer | — | Keep |
| rest | `postgrest/postgrest:v14.17` | 0 / 0, **no packages recognised** | `v14.18` | 0 / 0, no packages recognised | Keep |
| db | `supabase/postgres:17.6.1.136` | 0 / 48 (0 / 48) | `17.11.0.004` (reference only) | 0 / 23 | **Not changed by policy** |

Compose deployed set: **33 CRITICAL / 727 HIGH** both before and after. The 2026-10-07 record's 33 / 709 used an
older DB. In this run the extra HIGH findings come from findings published since then (for example auth 5 → 9 and
imgproxy 0 → 4). They are not regressions in the pins.

**Storage v1.80.0 → v1.80.2.** This is the smallest available step, and it does not change the scan: Trivy reports
the same findings and installed versions. The reason for the bump is code. `v1.80.1` (`ba73b08`, "fix: hardening for iceberg buckets")
enforces the service role on S3 requests to Iceberg buckets. `v1.80.2` (`db42280`, "fix: hardening for tus signed")
moves the signed resumable-upload check, `verifySignedUploadRequest`, out of a `req.url` prefix test and binds it to
the route that was registered as signed. The vendor commits are labelled hardening. No advisory or CVE was located, so this record
does not claim a vulnerability. The routes are reachable: `/storage/v1/` is proxied unconditionally by the Compose
Envoy (`volumes/api/envoy/lds.template.yaml`), and the reference nginx proxies every API-host path to it.
`git diff v1.80.0 v1.80.2` touches only `src/` (13 files): no `migrations/`, `package.json` or lockfile change. `v1.81.0`
was rejected as a larger step. It adds bucket versioning, a new tenant migration (`0074-unlock-object-versioning.sql`)
and edits to existing migrations, and its scan is again identical.

**Realtime stays at v2.134.10.** v2.143.3 is 178 commits ahead. It moves private-channel authorization to a Postgres
function (`e600189`), adds migrations and runs the container as `nobody` (`2e96b64`). The scan is identical, with the
same 3 CRITICAL / 141 HIGH ids, so there is no scanner benefit to set against a behaviour change that needs a full
RLS and broadcast acceptance. The move to non-root is real hardening and should be weighed for a later functional bump.

## Helm chart — aligned with the Compose pins

The chart still pinned the 2026-09-09 upstream set. Those are the same versions the 2026-10-07 record had already
replaced in Compose.

| Chart image | Before | CRIT / HIGH | After | CRIT / HIGH | Ids removed / added |
|---|---|---:|---|---:|---|
| `api-gw` | `envoyproxy/envoy:v1.39.1` | 0 / 2 | `v1.39.2` (Compose pin) | 0 / 0 | 1 / 0 |
| `auth` | `supabase/gotrue:v2.196.0` | 0 / 30 | `v2.197.0` | 0 / 9 | 20 / 0 |
| `storage` | `supabase/storage-api:v1.74.0` | 1 / 72 | `v1.80.2` | 1 / 57 | 8 / 0 |
| `functions` base | `supabase/edge-runtime:v1.76.2` | 4 / 61 | `v1.77.4@sha256:ad45164b…` | 4 / 58 | 3 / 0 |
| `rest`, `db` | unchanged | 0 / 0, 0 / 48 | unchanged | — | — |

The chart's upstream set goes from **5 / 213 to 5 / 172**, and every pair passes `compareImages`: fewer
CRITICAL+HIGH and no new CRITICAL. The chart keeps tag-only references. Its documented air-gap flow (`docker load` →
retag → push) does not preserve the multi-arch index digest, so a values digest would break mirrored installs. The
`edge-functions` base is built on a connected host, so it is digest-pinned in the Dockerfile. The posture-scanner and
dashboard images are first-party and were not touched.

## Residual CRITICAL / HIGH — classification

The categories below come from `PkgPath`, the image `Cmd`/`Entrypoint`/`User` (read from the registry config blob) and
the gateway routes. "Not loaded" means the code is outside the service process's start path. It is **not** evidence
that the code could never run inside the container. Nothing below is accepted.

| Image | CRIT | HIGH | Breakdown |
|---|---:|---:|---|
| studio | 17 (8 ids) | 321 | CRIT: Debian `perl*` ×12 (3 ids, fix `5.36.0-7+deb12u4`), `linux-libc-dev` ×1, `zlib1g` CVE-2023-45853, `libsqlite3-0` CVE-2025-7458 (no Debian fix), app `simple-git` CVE-2026-102828 and `@simple-git/argv-parser` CVE-2026-102829 (fixed 4.0.1/2.0.1). HIGH: `linux-libc-dev` 192, other OS 110 (37 fixable), npm/pnpm-bundled 15, app 4 (`simple-git` ×2, `@modelcontextprotocol/sdk` CVE-2026-104850, `next` CVE-2026-94483 fixed 16.3.8) |
| auth | 0 | 9 | Go `stdlib` 1.27.0 ×3 (fixed 1.27.2), `grpc` ×2, `x/net` ×1, `pgproto3/v2` CVE-2026-32286 (no fix), Alpine `libcrypto3`/`libssl3` CVE-2026-14456 (fix 3.5.8-r0) |
| storage v1.80.2 | 1 | 57 | CRIT `tar` CVE-2026-59873 is in `usr/local/lib/node_modules/npm` (npm CLI, not loaded by `node dist/start/server.js`). HIGH: npm-bundled 12, app 32 (`fast-uri` 11, `brace-expansion` 9, `fastify` 4, `undici` 3, `@fastify/busboy` 2, `@grpc/grpc-js`, `ip-address`, `propagator-jaeger`), Alpine 13 (`python3*` 12, `libexpat`). 56/57 have a fixed version |
| meta | 8 | 89 | CRIT: Debian `perl-base` ×3 (fixable), `zlib1g` CVE-2023-45853; app `tinypool` ×2 (under runtime dependency `oxfmt`), `piscina` CVE-2026-102992 (direct runtime dependency), `proxy-addr` CVE-2026-90711 (fastify). HIGH: app 22 (`fast-uri` 16, `fastify` 4.29.1 ×5, `find-my-way`), npm-bundled 11, Debian 56 (52 unfixed util-linux/ncurses/gnutls/systemd/openssl 3.0.x) |
| functions | 4 | 58 | OS only: Debian `perl-base` ×3 (fixable), `zlib1g` CVE-2023-45853; HIGH 53 of 58 have no Debian fix |
| realtime | 3 | 141 | OS only: Debian 13 `perl-base` ×3 (fixed `5.40.1-6+deb13u1`); HIGH 56 fixable (util-linux 2.41.5, expat, python3.13, openssl 3.5.7, …), 85 not |
| imgproxy | 0 | 4 | Go `stdlib` 1.27.1 ×3 (fixed 1.27.2), `golang.org/x/net` 0.59.0 (fixed 0.60.0), in `opt/imgproxy/bin/imgproxy` |
| db 17.6.1.136 | 0 | 48 | Alpine `curl`/`libcurl` 20, `libcrypto3`/`libssl3` 4, `c-ares` 1; Go `stdlib` 1.26.1 in `usr/local/bin/gosu` 23 |

Primary evidence behind each classification:

- **`zlib1g` CVE-2023-45853 (studio, meta, functions; `1:1.2.13.dfsg-1`).** The CVE is in MiniZip
  (`zipOpenNewFileInZip4_64`). The `libz.so.1` copied from the pinned postgres-meta image exports 88 functions and
  **no** `zip*` symbol (`nm -D --defined-only`). The vulnerable MiniZip code is not in the shared library. This was checked
  in the meta image only; studio and functions ship the same Debian package version.
- **npm/pnpm-bundled packages** (studio 15 HIGH, storage 1 CRIT + 12 HIGH, meta 11 HIGH) sit under
  `usr/local/lib/node_modules/{npm,pnpm}`. The services start with `node apps/studio/server.js`,
  `node dist/start/server.js` and `node dist/server/server.js`, so these packages are not loaded by the service. The vendor can
  remove them, as AIDR does for its own images (`runtime-image-security-2026-10-11.md`).
- **`linux-libc-dev` (studio, 193 findings)** are kernel UAPI headers. The container runs on the host kernel, so these are not the
  running kernel.
- **Go `stdlib` findings (auth, imgproxy, db/gosu)** are linked into the shipped binaries, so they are present at run time and are
  **not** build-time-only. Reachability per CVE was not analysed, because no symbol-level tool was run. `gosu` runs only
  in the postgres entrypoint, to drop privileges. Fixing any of these needs a vendor rebuild with Go 1.27.2 (auth, imgproxy) or a newer gosu (db).
- **Application dependencies in reachable services** are the findings most likely to be exploitable, and they are
  vendor-fixable, not reclassifiable. They are storage `fastify`/`fast-uri`/`undici`/`@fastify/busboy` (anon-key
  reachable via `/storage/v1/`), meta `fastify`/`proxy-addr`/`piscina`/`tinypool` (via `/pg/`, which Envoy RBAC limits to
  the service-role key) and studio `next`/`simple-git`/MCP SDK.
- **Studio exposure (correction).** The 2026-10-07 record said Studio "should stay off the public ingress". In the
  Compose kit as shipped it is **on** the public API host. The Envoy route `/` → `studio` is behind HTTP basic auth
  only (`DASHBOARD_USERNAME`/generated `DASHBOARD_PASSWORD`), `/mcp` and `/api/mcp` are RBAC-denied, and
  `deploy/ingress/nginx.onprem.reference.conf` proxies every `api.` path (`location /`) to the gateway. Studio's
  CRITICAL/HIGH findings are therefore reachable by anyone who can reach the API host, up to the basic-auth prompt.
  The Helm chart does not deploy Studio.
- **Recognition gaps (not clean results).** Trivy found no OS and no packages at all in `postgrest/postgrest` (a static
  Haskell binary), so its 0/0 means not inventoried. The same applies to the Deno/Rust `edge-runtime` binary, Realtime's
  Erlang/Elixir release, Envoy's statically linked BoringSSL and the PostgreSQL server built under `/nix/store`. For those,
  only the OS layer is covered.

## PostgreSQL (classification only, no pin change)

`17.6.1.136` has 0 / 48, all with a fixed version. `17.11.0.004`, the newest vendor tag, scanned as a reference only,
has 0 / 23. Its Alpine findings are gone and only the `gosu` Go stdlib findings remain. The PostgreSQL server version itself
(17.6) is not inventoried by Trivy, and the PostgreSQL project's advisory list could not be fetched from this host.
The backlog's statement that 17.6 is below advisory fixed floors therefore stands unverified by this run. A move to
17.11.x is a stateful major-image change: it needs the backup/restore and migration drill, and it was not attempted.

## Native acceptance run here

Storage v1.80.2 was tested against the prepared development kit from this tree (`deployment-prepare.mjs --mode self-hosted
--development`). It ran with real `supabase/postgres:17.6.1.136`, `darthsim/imgproxy:v4.0.17` and the Compose storage
service. The probe ran inside the Compose network and talked to storage directly, not through Envoy.

| Run | Result |
|---|---|
| Baseline: v1.80.0 seeded (bucket, object, 24 h signed URL), then probe | 4/4 seed, 19/19 probe |
| **Upgrade:** same volumes, storage replaced by `v1.80.2@sha256:95b217a9…` | healthy; `storage.migrations` unchanged (74 rows, last `revoke-grants-to-unused-operations`); **19/19** |
| **Fresh install** on new volumes with v1.80.2 | 74 migrations applied; 4/4 seed, **19/19** probe |

The 19 checks: `/status`, pre-upgrade object and signed URL still valid, tampered signed URL rejected, anon and
no-token reads rejected, anon listing of a private bucket empty, authenticated upload and delete without a policy denied
(RLS) with the object surviving, bad-signature and expired JWTs rejected, signed upload URL accepted and bound to its
path, TUS `/upload/resumable/sign` without `x-signature` rejected, TUS create by an authenticated user without a policy
rejected (403), TUS create by the service role accepted (201), and an imgproxy render via storage.

**Not run:** AIDR's own bucket policies and pack/audit-export flows (these need the full bootstrap with AIDR migrations),
any check through Envoy, and the dashboard `/storage/v1/status` readiness probe. The Helm changes are render-verified only:
no Kubernetes install or `edge-functions` image build was done. The auth v2.197.0, meta v0.100.0, edge-runtime
v1.77.4 and studio acceptance listed in the 2026-10-07 record is still outstanding. A full self-hosted smoke
(`scripts/deployment-smoke.mjs`) was not run: it needs the whole image set, and this host's disk filled during the run.

## Repo changes

- `scripts/deployment-prepare.mjs` and its test: the storage pin is now `supabase/storage-api:v1.80.2@sha256:95b217a9c59e0ac06c6dcb539df3189a1668a2445fb43dbf29660d6968ffd7d2`.
- `deploy/helm/aidr/values.yaml`: envoy `v1.39.2`, gotrue `v2.197.0`, storage-api `v1.80.2`.
  `deploy/helm/images/edge-functions.Dockerfile` now uses `FROM supabase/edge-runtime:v1.77.4@sha256:ad45164b7548bf5820ed7be714789c17ac2865edce79a09cfb4c3756c3d365a8`.
  `deploy/helm/chart.test.mjs`, the chart README and `docs/operations/kubernetes.md` are updated to match.
- The air-gap image lists are derived from the rendered Compose/Helm images, so they follow the pins automatically and no list file changed.
- The `deploy/upstream` gitlink and its source are unchanged. No image was repacked.

Gates run on the edited tree: `node --test scripts/deployment-prepare.test.mjs scripts/scan-runtime-images.test.mjs`
30/30. `pnpm verify:airgap-images` 11/11. `node scripts/ci-local.mjs --allow-dirty --only onprem-contracts,onprem-compose,helm
--fetch-tools`: 6/6 steps PASS, with the helm step at 38 pass and 1 skip (kubeconform not installed).

## Decisions that still need a named Security owner

1. **Studio on the public API host.** Either drop `/` → studio from the shipped ingress/gateway (operator-only
   access through a tunnel) or accept the residual findings behind basic auth. Recommended: exclude it from the public ingress.
2. **Vendor escalations** (all fixable upstream, with no AIDR-side fix short of an unreviewed repack):
   - Supabase Studio: Debian perl rebuild; `simple-git` ≥ 4.0.1; `next` ≥ 16.3.8; MCP SDK ≥ 1.31.0.
   - storage-api: `fastify` 5.12.2, `fast-uri`, `undici`, `@fastify/busboy`; remove the bundled npm.
   - postgres-meta: `fastify` 4 → 5 line, `proxy-addr`, `piscina`, `tinypool`; Debian perl.
   - edge-runtime: Debian perl rebuild.
   - realtime: Debian 13 point-release rebuild.
   - gotrue and imgproxy: Go 1.27.2, grpc, x/net.
   - postgres: Alpine curl/openssl/c-ares and gosu rebuild.
3. **Risk acceptance or explicit non-applicability** for findings with no vendor fix: Debian `linux-libc-dev`,
   util-linux/ncurses/gnutls/systemd, `zlib1g` CVE-2023-45853 (MiniZip absent from `libz.so.1`, verified in one image),
   and `pgproto3/v2`.
4. **Recognition gaps:** decide what evidence replaces a scanner result for PostgREST, edge-runtime (Deno), Realtime
   (BEAM) and the PostgreSQL server version, for example a vendor SBOM or a version-to-advisory check.
5. **PostgreSQL 17.6 → 17.11.x**, scheduled behind the backup/restore and migration drill.

## Reproduce

```bash
# per image (resolved digests in evidence/upstream-image-triage-2026-10-11/plan.json)
trivy image --image-src remote --platform linux/amd64 --scanners vuln --pkg-types os,library --skip-db-update \
  --config <empty {}> --ignorefile <empty> --format json mirror.gcr.io/<repo>:<tag>@<index digest>
# storage acceptance: prepared development kit, db + imgproxy + storage up, probe on the Compose network
docker run --rm --network <project>_default -e SERVICE -e ANON -e SECRET -e RUN -v <evidence dir>:/work \
  node:24.21.0-alpine3.24 node /work/storage-acceptance.mjs seed|verify
```

Rerunning with a newer DB will produce different counts. Compare only within a single run.
