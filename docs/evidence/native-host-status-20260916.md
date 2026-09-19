# Native host acceptance — what is proven, what is not

**Date:** 2026-09-18
**Gate:** `18-native-host`
**Decision:** `NO_GO` — and it stays `NO_GO` until a person outside this
repository signs a record. Nothing below changes that.

## What was actually run

Real installed hosts, real packaged artifacts, isolated profiles. Not fixtures.

| Host | Executable | Version | Result | Exit |
|---|---|---|---|---|
| Cursor | `%LOCALAPPDATA%\Programs\cursor\Cursor.exe` | 3.19.7 | **8/8 cases pass** | 0 |
| VS Code | `%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe` | 1.137.0 | **8/8 cases pass** | 0 |
| OpenClaw | isolated Node 24.20 runtime | 2026.9.4 | packed contract, offline install, runtime inspect, gateway startup and health all pass — **no compatibility shims** | 0 |
| OpenCode | `opencode-ai` 1.18.30 | 1.18.30 | plugin loaded and ran in the real host; host logs show the AIDR scan starting and completing | 0 |
| Claude Code | isolated CLI install | 2.1.273 | plugin discovered as `aidr@inline`, 3 hooks registered, MCP connected; strict manifest validation passes with 0 errors and 0 warnings | — |
| Codex | `codex-cli` 0.141.0 | 0.141.0 | packaged hook denies `rm -rf /` as `critical` and allows `ls -la` | 0 |

Raw results: `cursor-host-e2e-results.json`, `vscode-host-e2e-results.json`,
`codex-hook-packaged-results.json`, and `native-host-acceptance-run-20260916.md`
in this directory.

## What this proves

The packaged extension loads, activates, registers its commands and settings,
writes and removes its managed hooks, and returns a blocking decision for a
dangerous Write payload — in two real IDE extension hosts, at the versions above.
The OpenClaw plugin is installable by the official host from a packed tarball
without the compatibility shims an earlier run required. The OpenCode plugin runs
in the real host. Claude Code discovers the plugin and its hooks. The Codex hook
makes the correct decision on real payloads.

## What this does not prove, and why the gate stays open

**1. No model-driven agent turn was observed.** Every result above is at the hook
level or the host-load level. `dangerous-write-blocked` exercises the hook
decision path with a fixture payload — it is hook-decision evidence, not evidence
that a live agent's side effect was prevented. Proving that needs a provider-
authenticated model turn, and no provider is authenticated on this machine.

**2. The scenario manifest cannot be filled in from here.** The gate runs seven
cases per host — `denied_side_effect`, `benign_allow`, `disabled_hook`, `crash`,
`timeout`, `offline`, `restart` — and each case must observe three independent
things: that the host attempted the call, that the connector was invoked, and
whether the side effect occurred. Its driver injects `AIDR_NATIVE_TEST_SENTINEL`,
`AIDR_NATIVE_TEST_RECEIPT` and `AIDR_NATIVE_TEST_CASE_NONCE` for the connector to
write. **No connector on this repository reads those variables**; they appear only
in the gate and in its own tests, which drive Node as a stand-in host. So the
manifest mechanism is wired for fixture hosts, not for the six real ones, and
running it against a real host would report `ATTEMPT_UNPROVEN` or `HOOK_UNPROVEN`
for every case regardless of how well the connector works.

Making that real is a genuine engineering task — teaching each connector to emit
the three observations, then running all seven cases per host on every sold
OS/architecture — and it is not a matter of filling in digests.

**3. The named acceptance record cannot be produced by this repository.**
`qa_owner`, `endpoint_owner` and `support_owner` must be named accountable people
outside the team that wrote the code. The README is explicit that the best a local
run can reach is `LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN`, and that `GO` requires
"a real host run per sold OS/architecture plus named external acceptance". There
is no way to write those names that is not a fabrication.

## What would actually close it

1. Extend the six connectors to emit the gate's three observation variables, so
   the seven cases can run against a real host instead of a Node stand-in.
2. Run all seven cases per host, on each OS/architecture the product is sold for.
3. Have a named QA owner, endpoint owner and support owner sign the acceptance
   record for that specific candidate.

Step 3 is the one that cannot be automated, delegated, or inferred. It is a
person taking responsibility for a result.
