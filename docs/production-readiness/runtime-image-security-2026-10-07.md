# Runtime image security — upstream Supabase pins (AIDR-080), 2026-10-07

Scope: the upstream runtime images the self-hosted kit deploys (`deploy/upstream/docker/docker-compose.yml`
at submodule commit `8c7a4d9d`, plus the tag@digest overrides in `scripts/deployment-prepare.mjs`).
Supavisor is removed from the self-hosted kit and was not scanned. First-party images (dashboard, landing,
helpers) are out of scope here.

## What was run

- Tool: `scripts/scan-runtime-images.mjs` (tracked; test `scripts/scan-runtime-images.test.mjs`).
  - `resolve`: anonymous Docker Hub registry API (`auth.docker.io` token + `registry-1.docker.io` manifest),
    records the multi-arch index digest and the linux/amd64 manifest digest.
  - `scan`: `trivy image --image-src remote --platform linux/amd64 --scanners vuln --severity CRITICAL,HIGH`,
    empty `--ignorefile` and empty `--config`, run from an empty temp directory (no ambient `.trivyignore`/`trivy.yaml`).
- Scanner: Trivy **0.73.0** (local WinGet install), vulnerability DB v2 updated **2026-10-07T07:38:55Z**,
  downloaded fresh for this run. Run window 2026-10-07T13:38:03Z – 13:39:48Z. All 17 scans succeeded.
- Evidence: `docs/production-readiness/evidence/runtime-image-scan-2026-10-07/`
  - `plan-input.json` (tags), `plan.json` (resolved digests), `summary.json` (scanner/DB metadata, counts, comparisons),
  - one compact `<service>-<current|candidate>.json` per image (CVE id, package, installed, fixed, severity, status, target).
- Counting: "findings" = every package/target occurrence Trivy reports (the same CVE in `perl` and `perl-base`
  counts twice); unique-id counts are in `summary.json`. "fix" = findings with a `FixedVersion`.
- Comparability: the 2026-10-06 baseline (36 CRITICAL / 893 HIGH) used Trivy 0.75.0, an older DB and
  locally cached image archives across a different service set. Its numbers are **not** directly comparable
  with this run. Every before/after comparison below is current vs candidate in this single run (same scanner,
  same DB, same flags).
- Decision rule (applied mechanically by `compareImages`): bump only if candidate CRITICAL+HIGH findings are
  strictly fewer than current **and** the candidate introduces no CRITICAL id absent from current.
  No candidate introduced any new vulnerability id of either severity.

## Results

| Service | Current pin | CRIT / HIGH (fix) | Candidate | CRIT / HIGH (fix) | Action |
|---|---|---:|---|---:|---|
| studio | `supabase/studio:2026.09.07-sha-7996410` | 21 / 415 (18 / 131) | `2026.10.05-sha-94b8b06` (newest dated tag on 2026-10-07) | 17 / 318 (14 / 34) | **Bumped** |
| auth | `supabase/gotrue:v2.196.0` | 0 / 26 (0 / 25) | `v2.197.0` | 0 / 5 (0 / 4) | **Bumped** |
| storage | `supabase/storage-api:v1.74.0` | 1 / 72 (1 / 71) | `v1.80.0` | 1 / 57 (1 / 56) | **Bumped** |
| meta | `supabase/postgres-meta:v0.99.0` | 9 / 93 (8 / 42) | `v0.100.0` | 8 / 87 (7 / 36) | **Bumped** |
| functions | `supabase/edge-runtime:v1.76.2` | 4 / 59 (3 / 8) | `v1.77.4` | 4 / 56 (3 / 5) | **Bumped** |
| realtime | `supabase/realtime:v2.134.10` | 3 / 141 (3 / 59) | `v2.142.0` | 3 / 141 (3 / 59) | Not bumped (identical findings) |
| api-gw | `envoyproxy/envoy:v1.39.2` (existing override) | 0 / 0 | `v1.39.3` | 0 / 0 | Not bumped (no reduction) |
| imgproxy | `darthsim/imgproxy:v4.0.17` (existing override) | 0 / 0 | — | — | Keep |
| rest | `postgrest/postgrest:v14.17` | 0 / 0 | — | — | Keep |
| db | `supabase/postgres:17.6.1.136` | 0 / 45 (0 / 45) | not evaluated | — | **Not bumped by policy** (stateful; needs migration drill) |

Deployed set (10 scanned services) before: **38 CRITICAL / 851 HIGH** findings. After the five bumps:
**33 CRITICAL / 709 HIGH**. Removed vulnerability ids: studio 100, auth 20, storage 8, meta 7, functions 3.

Digests pinned (index digests, verified by registry API; the existing envoy v1.39.2 and imgproxy v4.0.17
digests re-resolved to exactly the values already pinned):

```
supabase/studio:2026.10.05-sha-94b8b06@sha256:d878dcd9dba73b66d1c2c19aeaf53d07704e71604d93013225be1d1c51475237
supabase/gotrue:v2.197.0@sha256:1736a63078f5922b198c4cbe50f80ab9a2d3b54fe8b7b6cfb2e9dc5dbbc12c6b
supabase/storage-api:v1.80.0@sha256:15aa712fdda0dab83d6345c79b54230c1466c41161f1f3756651778b22c3b292
supabase/postgres-meta:v0.100.0@sha256:145325b7e39f8ef4931d6e8cfd3f6f4d655de09d72a2ccc96d9513542c2202bd
supabase/edge-runtime:v1.77.4@sha256:ad45164b7548bf5820ed7be714789c17ac2865edce79a09cfb4c3756c3d365a8
```

## Remaining CVEs per image (vendor escalation / risk acceptance)

None of these images is AIDR-built; every remaining finding needs either an upstream vendor fix or an
explicit, owner-signed risk acceptance. Nothing below is accepted by this document.

- **studio (candidate)** — 17 CRITICAL / 318 HIGH. CRITICAL: Debian `perl`/`libperl5.36`/`perl-base`/`perl-modules-5.36`
  CVE-2026-13221, CVE-2026-42496, CVE-2026-8376 (fixed in `5.36.0-7+deb12u4`, vendor rebuild needed);
  `zlib1g` CVE-2023-45853, `libsqlite3-0` CVE-2025-7458, `linux-libc-dev` CVE-2026-43185 (no Debian fix);
  npm `simple-git` CVE-2026-102828 and `@simple-git/argv-parser` CVE-2026-102829 (fixed upstream, needs
  Studio dependency bump). HIGH is dominated by `linux-libc-dev` (190 findings, kernel headers, no fix —
  risk-acceptance candidate as not executed in the container) and Python 3.11 / perl. The `next` CRITICALs
  present in the current pin are gone. Studio is an operator-only admin UI; it should stay off the public
  ingress regardless. Escalate: Supabase Studio (base image rebuild, simple-git).
- **auth (candidate)** — 0 / 5. `libcrypto3`/`libssl3` CVE-2026-14456 (fixed `3.5.8-r0`), Go `google.golang.org/grpc`
  CVE-2026-84304 / CVE-2026-84445 (fixed in 1.83.x), `github.com/jackc/pgproto3/v2` CVE-2026-32286 (no fix).
  Escalate: supabase/auth.
- **storage (candidate)** — 1 / 57. CRITICAL npm `tar` CVE-2026-59873 (fixed 7.5.19). HIGH: npm `fast-uri`, `brace-expansion`,
  `fastify`, `undici`, `@fastify/busboy` and Alpine `python3` — all 56 HIGH have a fixed version. Escalate: supabase/storage.
- **meta (candidate)** — 8 / 87. CRITICAL: Debian `perl-base` (3 ids, fix available), `zlib1g` CVE-2023-45853 (no fix),
  npm `tinypool` (2), `piscina`, `proxy-addr` (all fixed upstream). HIGH: `fast-uri`, `brace-expansion`, `fastify`
  plus unfixed Debian util-linux family. Escalate: supabase/postgres-meta.
- **functions (candidate)** — 4 / 56. CRITICAL: Debian `perl-base` (3, fix available) and `zlib1g` CVE-2023-45853 (no fix).
  HIGH: mostly unfixed Debian util-linux/ncurses. Note: Trivy found only Debian OS packages — the Deno/Rust edge-runtime
  binary itself is not inventoried, so this is OS-layer coverage only. Escalate: supabase/edge-runtime.
- **realtime (current, unchanged)** — 3 / 141. CRITICAL: Debian 13 `perl-base` (3 ids, fixed `5.40.1-6+deb13u1`).
  HIGH: util-linux family, `libexpat1`, Python 3.13 (59 of 141 fixable). Trivy inventoried only Debian packages —
  the Elixir/Erlang release dependencies are not covered. v2.142.0 ships the same OS layer findings, so there is
  no security reason to bump. Escalate: supabase/realtime (base image rebuild).
- **db (current, not bumped)** — 0 / 45, all fixable: Alpine `curl`/`libcurl` (20), `libcrypto3`/`libssl3`, `c-ares`, and Go
  `stdlib` in `usr/local/bin/gosu` (20). A Postgres image change is a stateful upgrade: it needs a backup/restore and
  migration drill before any pin change. Escalate: supabase/postgres.
- **api-gw, imgproxy, rest** — 0 CRITICAL / 0 HIGH with this scanner and DB.

## Native acceptance still required for the bumped services — NOT yet run

This change is scan-gated only. No container was started, no compose stack was brought up, and none of the
following functional checks have been executed against the new images. Each must pass on a prepared
self-hosted kit before these pins are released to a customer:

- **studio 2026.10.05** — operator login, table editor/SQL editor against the AIDR schema, no public ingress exposure.
- **auth / gotrue v2.197.0** — GoTrue schema migrations apply cleanly on an existing database; password sign-in,
  recovery mail template (`GOTRUE_MAILER_TEMPLATES_RECOVERY`), JWT issuance and verification by PostgREST,
  storage and functions (role claims, expiry), SSO paths in use.
- **storage-api v1.80.0** — storage schema migrations; bucket RLS (tenant isolation on read/write/delete),
  signed URL issue/expiry, imgproxy transforms, `/storage/v1/status` readiness probe used by the dashboard.
- **postgres-meta v0.100.0** — Studio metadata endpoints, TypeScript type generation output diff against the
  current AIDR schema.
- **edge-runtime v1.77.4** — all AIDR Edge Functions dispatch (incl. `packs-manifest` readiness probe and
  `device-start`), JWT/JWKS verification, `.env.functions` secrets loading, Ed25519 policy envelope signing.

Realtime was not bumped; if it is bumped later for a non-security reason it needs broadcast, presence and
Postgres-changes-with-RLS acceptance.

## Reproduce

```bash
node scripts/scan-runtime-images.mjs resolve --plan docs/production-readiness/evidence/runtime-image-scan-2026-10-07/plan-input.json --out plan.json
node scripts/scan-runtime-images.mjs scan --plan plan.json --output out/ --engine trivy   # or --engine docker
node --test scripts/scan-runtime-images.test.mjs scripts/deployment-prepare.test.mjs
```

A rerun on a later date uses a newer vulnerability DB and will produce different counts; compare within a run.
