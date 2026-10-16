# Runtime image security — landing image from merged `main` and dashboard re-check (AIDR-079), 2026-10-11

This record adds to [runtime-image-security-2026-10-11.md](./runtime-image-security-2026-10-11.md).
It does not rewrite that record. The earlier record verified the dashboard half of AIDR-079 and left
the landing half open because the remediation was in no reachable source. That remediation was merged in
[SingularityRD/aidr-landing#1](https://github.com/SingularityRD/aidr-landing/pull/1). This run rebuilds
both images from merged sources, scans them and repeats the runtime checks.

Run window: 2026-10-11T10:55Z – 11:05Z UTC. Host: Linux x86_64, Docker Engine 29.8.2 with the
`mirror.gcr.io` registry mirror. Compact evidence:
[`evidence/runtime-image-scan-2026-10-11-landing/summary.json`](./evidence/runtime-image-scan-2026-10-11-landing/summary.json).

## Sources

| Image | Source | Dockerfile |
|---|---|---|
| Landing | `SingularityRD/aidr-landing` `origin/main` @ `12750cab55c3e72ff61b886c081aece6f9f414f6` (merge of PR #1) | `Dockerfile`, sha256 `c138eb48…0657a` |
| Dashboard | `SingularityRD/aidr` @ `b8b36459` (`master` `eca71088` plus one docs-only commit) | `deploy/dashboard/Dockerfile` via `deployment-prepare` |

Both Dockerfiles use `node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1`.
The base came through the registry mirror under the same content-addressed digest.

## Landing build: proxy CA added for this run only (not committed)

The unmodified `Dockerfile` failed at `deps` → `pnpm install --frozen-lockfile` with
`SELF_SIGNED_CERT_IN_CHAIN`. The sandbox egress proxy re-terminates TLS, and its CA is not trusted
inside build containers. This is a property of the sandbox, not of the Dockerfile.

To build anyway, a **scratch copy** of the Dockerfile was used. It lived only in the session
scratchpad, sha256 `065c22a5…cced544`, and was never committed to any repository. Only two `RUN`
lines changed: `pnpm install --frozen-lockfile` in `deps` and `pnpm build` in `builder`, which
re-downloads pnpm through corepack. Each gained
`--mount=type=secret,id=proxyca NODE_EXTRA_CA_CERTS=/run/secrets/proxyca`. The CA was passed as
`--secret id=proxyca,src=/root/.ccr/ca-bundle.crt`.

The runner stage is byte-identical to the committed file. BuildKit does not persist secret mounts, and
`docker history --no-trunc` of the final image has no `proxyca` reference.

```bash
docker build --pull=false --secret id=proxyca,src=/root/.ccr/ca-bundle.crt -f <scratch copy> -t aidr-landing:verify .
```

The build succeeded in about 2 minutes (`next build` included). Image manifest list:
`sha256:5c5bab32…3fd3b2a`. Config: `sha256:22f21f50…b711c076a9`. Size: 331,883,902 bytes.

## Dashboard build

Command: `node scripts/ci-local.mjs --allow-dirty --only onprem-dashboard-image`.

- The step **passed** on Node v24.21.0 in 10 s. `docker build --pull` resolved the pinned base through
  the mirror. Image manifest list: `sha256:ef82c4e6…6de90`. Config: `sha256:ff5a6e7b…b4fda`.
- The run as a whole exited 1. The only failure was the trailing `guard-tree-unchanged` guard. Other
  agents were editing already-modified files at the same time (`docs/product/features`,
  `packages/extension`, `packages/core`), and the step writes only to its runner temp directory.
  `packages/dashboard` and `deploy/dashboard` had no changes when the build ran.

## Scanner

- Trivy **0.73.0**, run as container `mirror.gcr.io/aquasec/trivy:0.73.0@sha256:7cced7ca…1045c`.
- Vulnerability DB v2, updated **2026-10-11T07:05:14Z**, downloaded 10:57:58Z from `mirror.gcr.io/aquasec/trivy-db:2`.
- Each image was scanned from its `docker save` tar. The scanner container ran with `--network none` from an
  empty read-only working directory, with an empty ignore file and an empty config:
  `trivy image --input <tar> --scanners vuln --pkg-types os,library --skip-db-update --ignorefile empty.trivyignore --config empty-trivy.yaml --format json`.
- No `.trivyignore`, no VEX and no severity filter. Each occurrence of a package/target pair counts once.

## Results (no ignores)

| Image | OS | CRITICAL | HIGH | Below HIGH |
|---|---|---:|---:|---|
| Stock `node:24.21.0-alpine3.24` (reference) | Alpine 3.24.2 | 0 | **8** | 13 MEDIUM, 1 LOW; all HIGH are in npm's bundled packages |
| **Landing** `aidr-landing:verify` | Alpine 3.24.2 | **0** | **0** | 4 MEDIUM: `zlib` CVE-2026-85091 (OS); `protobufjs` 8.5.0 CVE-2026-54269, CVE-2026-59876, CVE-2026-59877 |
| **Dashboard** `aidr-dashboard:ci` | Alpine 3.24.2 | **0** | **0** | 1 MEDIUM: `zlib` CVE-2026-85091 |

- Landing Node.js target: 116 packages, including `@grpc/grpc-js@1.14.6` (the PR #1 override) and
  `next@16.3.8`. The image contains no npm, corepack or yarn package.
- Dashboard: no Node.js language target, same as the previous record.
- Residual MEDIUM findings fall outside AIDR-079's acceptance criterion (0 CRITICAL / 0 HIGH). They are
  listed here so they stay visible, but **this record does not accept them**:
  - `zlib` needs a new base build.
  - `protobufjs` 8.5.0 has fixes in 8.6.0 / 8.6.5 / 8.6.6. A landing dependency bump is a follow-up.
- Coverage limits from the previous record still apply: Trivy does not inventory the `node` binary
  (24.21.0) or pre-bundled client assets.

## Landing runtime checks

Flags: `--read-only --tmpfs /tmp --tmpfs /app/.next/cache:uid=1000,gid=1000 --cap-drop ALL --security-opt no-new-privileges:true --memory 512m --pids-limit 128`
(the hardening documented in `DEPLOYMENT_CLOUD_RUN.md`).

| Case | `/api/health` | `/api/ready` | `/` | Image HEALTHCHECK |
|---|---|---|---|---|
| Production defaults, nothing configured | 200 `application/json`, `Cache-Control: no-store, max-age=0`, `"status":"ok"` | **503** `application/json`, `no-store, max-age=0`, `not_ready`. The four required checks report `not_configured` (`database`, `auth_config`, `auth_provider`, `agent_token_secret`) | 200 HTML | `healthy` |
| `AIDR_DEMO_MODE=1` plus a random 48-character `AIDR_AGENT_TOKEN_SECRET`, generated in the shell and not recorded | 200 JSON, `no-store` | **200** JSON, `no-store`, `ready`. Dependency checks `skipped: demo_mode`; `agent_token_secret` ok | 200 HTML | `healthy` |

Process hardening inside both containers:

- uid 1000 (`node`).
- `CapEff`, `CapPrm` and `CapBnd` are all `0000000000000000`. `NoNewPrivs: 1`.
- Writes to `/app` and `/` fail with `Read-only file system`. `/tmp` and `/app/.next/cache` (tmpfs) are writable.
- `/usr/local/lib/node_modules` is empty, and `npm`, `npx`, `corepack`, `yarn`, `yarnpkg`, `pnpm` and `pnpx` are not on PATH.
- `node -v` reports v24.21.0. 0 restarts.

The readiness responses contain only check names, statuses and reason codes, with no hostnames and no
secret values. The demo-mode case shows that the endpoint can report `ready`. It is not evidence that
production dependencies (Firestore, Clerk) are reachable. That needs real credentials, and those are
outside AIDR-079.

## Dashboard runtime checks

Flags: `--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true --memory 256m --pids-limit 128`.
Environment: a placeholder publishable Supabase URL and key.

- `/livez` returned 200 JSON.
- `/readyz` returned **503** `not_ready` because all seven checks failed with the upstreams unreachable.
  This is the expected fail-closed result.
- `/` served the SPA with 200.
- Inside the container: uid 1000, `CapEff: 0000000000000000`, `NoNewPrivs: 1`, `/app` read-only, no package
  managers, 0 restarts.

This run did not repeat the development-mode `/readyz` 200 case. The previous record covers it with the
same Dockerfile.

## Firestore grpc-js override smoke (re-run)

The landing override `@grpc/grpc-js@<1.14.5 → ^1.14.5` was re-checked against the Firestore emulator
`cloud-firestore-emulator-v1.22.0.jar` (sha256 `9b6498b7…5166c`, fetched by firebase-tools 15.31.0).

- Dependencies came from a `pnpm install --frozen-lockfile` checkout of `12750cab`.
- Both SDKs resolve grpc-js **1.14.6**: the client `@firebase/firestore` and the admin `google-gax`.
- The client SDK ran `setDoc`, `getDoc`, a `where` query and `onSnapshot`. The admin SDK ran `set`, `get`
  and `runTransaction` (update 2 → 3).
- Every operation returned the expected values on Node v22.22.0 and on Node v24.21.0 (exit 0 both).

Limits: this ran on the host against a local emulator, with the same lockfile as the image. It did not run
inside the runner image and did not touch production Firestore.

## Status decision

**AIDR-079 → VERIFIED_CLOSED (local evidence).** Both first-party images built from merged sources meet
the acceptance criterion:

- supported pinned Node 24.21 / Alpine 3.24 base;
- package managers removed from the runner only;
- 0 CRITICAL / 0 HIGH in a full OS and language scan without ignores;
- nonroot, read-only, `cap-drop ALL`, no-new-privileges startup;
- JSON `no-store` liveness and readiness responses.

Still open, not closed by this record:

- independent Security review and customer acceptance of the images;
- the fresh compiled customer-kit dashboard bytes;
- the residual MEDIUM findings above;
- a landing CI or registry build that does not depend on this sandbox's proxy workaround.

## Cleanup

After the run the following were removed: `aidr-landing:verify`, `aidr-dashboard:ci`, the Trivy image,
the BuildKit cache, the saved tars, the Trivy DB cache and the emulator jar.

## Reproduce

```bash
git -C aidr-landing checkout 12750cab && docker build -t aidr-landing:verify aidr-landing   # outside a TLS-intercepting proxy
node scripts/ci-local.mjs --only onprem-dashboard-image
docker save <image> -o img.tar
trivy image --input img.tar --scanners vuln --pkg-types os,library --ignorefile <empty> --config <empty> --format json
docker run --read-only --tmpfs /tmp --tmpfs /app/.next/cache:uid=1000,gid=1000 --cap-drop ALL \
  --security-opt no-new-privileges:true -p 8080:8080 aidr-landing:verify   # then curl -i /api/health /api/ready
```

A rerun with a newer DB will produce different counts. Compare only within a single run.
