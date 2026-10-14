# Runtime image security — dashboard re-scan and release gate (AIDR-079, AIDR-080), 2026-10-14

Scope: the first-party dashboard image (`deploy/dashboard/Dockerfile`), re-measured
with a newer scanner and vulnerability database than the 2026-10-11 record, and the
new release gate that keeps it clean. The landing image (other repository) and the
upstream Supabase images (AIDR-080) are not changed by this record.

## Measurement

- Source: `dec0222cf8489549231165a5e05346ca9de3cf87`; `deploy/dashboard/Dockerfile` unchanged
  (base `node:24.21.0-alpine3.24@sha256:ebfe2f90…ec1c1`, npm/npx/Corepack/Yarn/pnpm removed).
- Base pulled by digest from `mirror.gcr.io/library/node` (Docker Hub rate limit); same
  content-addressed index digest as the pin.
- Build: the context `scripts/deployment-prepare.mjs` assembles (deploy/dashboard,
  `deploy/saml-config.mjs`, `supabase/templates`, `packages/dashboard/dist`),
  `docker build --pull=false --network=none`. Image `sha256:24ba16f85837…`.
- Scanner: Trivy **0.75.0** (the release tarball, SHA-256 equal to the `TRIVY_SHA256` pin
  of `release-images.yml`), vulnerability DB v2 updated **2026-10-14T19:14:58Z**.
- `trivy image --input <docker save tar> --scanners vuln --pkg-types os,library
  --skip-db-update --ignorefile <empty> --config <empty> --format json`. No ignore
  file, no VEX, no severity filter.
- Compact results: `evidence/runtime-image-scan-2026-10-14/summary.json`.

| Image | OS | CRITICAL | HIGH | Other |
|---|---|---:|---:|---|
| Stock `node:24.21.0-alpine3.24` (reference) | Alpine 3.24.2 | 0 | **8** | 13 MEDIUM, 1 LOW |
| **Dashboard** (`deploy/dashboard/Dockerfile`) | Alpine 3.24.2 | **0** | **0** | 1 MEDIUM |

- The 8 HIGH findings of the stock base are all in npm's bundled packages
  (`brace-expansion` ×4, `http-cache-semantics`, `ip-address`, `tar`, `undici`); the
  dashboard image does not contain npm, and Trivy finds no Node.js language target in it.
- The one residual is `zlib` CVE-2026-85091 (MEDIUM; fixed in Alpine `zlib 1.3.2-r1`),
  which needs a newer base build. `node:24.22.0-alpine3.24` was published on the day of
  this record; it is not adopted until it has been public for two weeks and re-scanned.
- Coverage limits are unchanged from the 2026-10-11 record: Trivy does not inventory the
  `node` binary (OpenSSL 3.5.8 embedded) or the pre-bundled static frontend.

Runtime check of the same image with the Compose hardening (`--read-only --cap-drop ALL
--security-opt no-new-privileges:true --memory 256m --pids-limit 128`, no network): uid
1000, `CapEff` 0, `NoNewPrivs` 1, writes to `/app` fail (read-only), no package manager
on PATH, `/livez` 200, `/` 200 with Content-Security-Policy, `/readyz` 503 because no
database, storage or functions upstream exists in the isolated run (as designed).

The original 3 CRITICAL / 49 HIGH measurement (older scanner, DB and base) stays in the
backlog as history; it is not comparable to this one.

## Release gate

`release-images.yml`, job `airgap-bundle`: the `aidr-dashboard:<version>` image that goes
into the vendor-signed air-gap bundle is scanned with the pinned Trivy before anything is
signed; any CRITICAL or HIGH finding, fixed or not, fails the job (no ignore file, no
VEX). The GHCR images keep the existing gate of the `build-sign` job (fixable CRITICAL).

## Still open

- Landing image (AIDR-079, other repository): not remediated in any reachable source.
- Upstream Supabase images (AIDR-080): unchanged; the vendor air-gap bundle carries the
  same reviewed pins and therefore the same recorded upstream findings.
- Independent Security review of these results.
