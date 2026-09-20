# `@singularityrd/aidr-sdk`

Universal SDK for integrating Singularity AIDR security checks into AI agent
frameworks (LangChain, LlamaIndex, AutoGen, CrewAI, Express, Next.js, or any
custom runtime).

## Verdict enforcement is fail-closed

Every adapter and middleware in this package shares **one** enforcement rule,
implemented in [`src/enforcement.ts`](./src/enforcement.ts):

> A wrapped function, tool, agent message, or HTTP request proceeds to execution
> **only** when the security check returns `decision: "allow"`.

| Check result                                                      | What the SDK does                                                                                             |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `allow`                                                           | Executes.                                                                                                      |
| `deny`                                                            | Never executes. Never approvable, even with an `onAsk` callback configured.                                     |
| `ask`, `onAsk` callback configured and returns `true`             | Executes — a real human approved this specific result.                                                          |
| `ask`, no `onAsk` callback (default)                              | Blocks with a message explaining that explicit human approval is required.                                      |
| `ask`, `onAsk` returns `false` / throws                           | Blocks.                                                                                                        |
| Indeterminate — the check failed after all retries, or the result is internally inconsistent (`allowed` disagrees with `decision`) | Blocks. **Not approvable by default**, even with `onAsk` configured.                                            |

### Why an indeterminate check is not approvable

`AIDRClient.check()` retries failed checks and, when every attempt fails, returns

```ts
{ allowed: false, decision: "ask", confidence: 0.5,
  reason: "Check failed after N attempts: ...",
  metadata: { indeterminate: true, attempts: N } }
```

A failed check carries **no security signal at all**. If that were routed to an
approval prompt, a broken (or attacker-degraded) engine would train operators to
click "yes" on unevaluated actions. `indeterminate` results are therefore
blocked outright. Callers who knowingly accept that risk can opt in per adapter:

```ts
const middleware = createMiddleware(client, {
  onAsk: askHuman,
  allowApprovalOfIndeterminateResults: true, // explicit, documented opt-in
});
```

### Supplying human approval

`onAsk` is always **caller-supplied** and is never invented by the SDK. It must
route to a real human through a channel the *model cannot invoke itself* — a CLI
prompt, a host UI dialog, an out-of-band ticket/console, a Slack approval, etc.
It receives the full `CheckResult`, so it can inspect `metadata.indeterminate`
and `threatId` before deciding, and it must return `true` only for an explicit
approval.

If no such out-of-band channel exists, do not configure `onAsk`: the `ask`
verdict stays blocking, which is the correct (and safe) outcome.

> **Never wire `onAsk` to an agent-callable tool, prompt, or model output.** An
> approval must be an action the policed agent cannot perform. See the
> "Agent self-approval" note below.

## Usage

```ts
import { AIDRClient, createMiddleware } from "@singularityrd/aidr-sdk";

const client = new AIDRClient({ apiKey: process.env.AIDR_API_KEY! });

// 1. Wrap a function. `ask` blocks unless a human approves it.
const middleware = createMiddleware(client, {
  onAsk: async (result) => await askOperatorInTerminal(result), // caller-supplied
});

const safeRun = middleware.wrap(runShellCommand, (cmd) => ({
  action: "execute",
  resource: cmd,
}));

// 2. Express / Next.js: non-allow results become HTTP 403 with an explicit
//    `reason` (including "requires explicit human approval" for `ask`).
app.use(middleware.express());
```

Framework adapters accept the same `onAsk` / `allowApprovalOfIndeterminateResults`
options:

| Adapter              | Entry point                                    | Blocking behaviour for `ask` / indeterminate                                             |
| -------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Core middleware      | `createMiddleware(client, options)`            | `wrap()` throws; `express()`/`nextjs()` return 403 with the enforcement message.          |
| Generic middleware   | `createGenericMiddleware(client, options)`     | Throws `AIDRMiddlewareError` (also used by the sync-compatible variant).                  |
| LangChain            | `withAIDR(tool, client, options)`              | Returns `allowed: false` + `[DENIED] …`, or throws when `throwOnAsk` is set.              |
| LlamaIndex           | `withAIDRLlamaIndex(engine, client, options)`  | Throws `AIDRLlamaIndexError` unless `throwOnDeny: false` (then a `[BLOCKED]` result).     |
| AutoGen              | `createAIDRSpeaker(client, options)`           | Returns `{ allowed: false, verdict }` (never a synthesized allow), or throws.             |
| CrewAI               | `withCrewAIDR(tool, client, options)`          | Throws `AIDRCrewSecurityError` unless `throwOnDeny: false` (then `{ blocked: true }`).    |
| CrewAI delegation    | `wrapCrewAgentWithAIDR(agent, client, options)`| Throws `AIDRCrewSecurityError`.                                                           |

## SDK command

The SDK's optional command-line helper is installed as `aidr-sdk` (the documented
`aidr` command belongs exclusively to `@singularityrd/aidr-cli`):

```bash
npx aidr-sdk --help
```

## Tool output inspection before model consumption

The Generic, LangChain, LlamaIndex, AutoGen, and CrewAI adapters inspect returned
text and structured results with the core output scanner before returning them to
the framework. The default limit is 256 KiB of UTF-8 data. A finding, an oversized
result, a circular value, binary data, or another unsupported value blocks delivery
by default; none of those states is reported as clean.

Use the standalone API when integrating a framework-specific result path:

```ts
import { guardToolOutput } from "@singularityrd/aidr-sdk";

const guarded = guardToolOutput(toolResult, {
  maxBytes: 256 * 1024,
  findingAction: "redact",
});

if (guarded.delivery === "block") {
  throw new Error(guarded.inspection.reason);
}
return guarded.output;
```

`inspection.status` is one of `clean`, `findings`, `oversize`, or `unavailable`.
Redaction replaces the complete result with a fixed marker so matched secrets or
instructions cannot survive in an uninspected field. Hosts that return binary or
streaming values must decode them to bounded text before calling the guard.

### AutoGen note

`AIDRSpeaker.onMessage()` used to fall through to a synthesized
`{ allowed: true, decision: "allow" }` ("All checks passed") even when a
sub-check returned `ask`. That synthesis only happens now when every check
either returned an explicit `allow` or was approved through `onAsk`; the
combined verdict records `ask verdict approved by onAsk` in its reason when that
happened.

### LlamaIndex note

`throwOnDeny: false` on the *source-URL validation leg* annotates the result
(`metadata.aidrUrlWarnings`) instead of throwing, matching the pre-existing
opt-out for `deny`. The primary query verdict is always blocking.

## Agent self-approval is not a thing in this SDK

The SDK's `onAsk` is a host-side callback, not an agent tool. The bundled
connectors follow the same rule: an agent must never be able to approve its own
blocked action. `packages/openclaw` and `packages/opencode` therefore expose
**no** approval tool — see their READMEs for the operator-facing approval paths
and the current limitation.

## Rule data: where the SDK loads threats and allowlists from

`AIDRClient.init()` loads the YAML threat rules and trusted-domain allowlists
that detection runs on. `@singularityrd/aidr-core` publishes only `dist/**` (no
data), and `process.cwd()` is *your* working directory rather than the SDK's, so
the SDK **ships its own copy** of the rule data under `resources/` (generated by
`scripts/sync-assets.mjs` during the build, exactly like the CLI and connector
packages) and resolves it relative to the running module.

Resolution order — the first usable directory wins, per kind:

| # | Candidate | Use case |
| - | --------- | -------- |
| 1 | `AIDR_THREATS_DIR` / `AIDR_ALLOWLISTS_DIR` | Explicit override (managed deployments, customer rule stores). An override that is set but unusable is a **hard error** — the SDK never silently ignores a configured path. |
| 2 | `<moduleDir>/resources/<kind>` | Resources next to the runtime bundle. |
| 3 | `<moduleDir>/../resources/<kind>` | Packaged install: `<pkg>/dist/index.mjs` + `<pkg>/resources/`. |
| 4 | Walk up (≤ 6 levels) to a directory holding **both** `threats/` and `allowlists/` | Monorepo source tree / workspace build without `sync-assets`. |
| 5 | `<cwd>/<kind>` | Legacy cwd-relative layout, kept last so apps that vendor their own rules keep working. |

`~/.singularity-aidr/threats` is deliberately **not** a candidate: loading a
partial user overlay *instead of* the shipped rules would silently reduce
detection to those few rules.

### Missing or unusable rule data fails `init()` loudly

A client without rules cannot inspect anything, and "inspected nothing" is not a
clean result. `init()` therefore throws:

- `AIDRDataDirError` — no usable directory was found. The message lists every
  path that was searched, in order.
- `AIDRInitError` — the directory exists but could not be read/parsed, or it
  loaded **zero** rules.

`check()` propagates that failure instead of returning a result. Because
enforcement is fail-closed, a client that "worked" with no rules would answer
`ask` forever and detect nothing — which is why this is an error rather than a
warning. If `AIDR_THREATS_DIR` is a typo, you get a failure naming the path, not
a quieter product.

`client.getDataDirs()` (and the exported `resolveDataDirs()` /
`getBundledDataDirs()`) report the directories actually used and which candidate
produced them, for health checks and diagnostics.

### Configuration is validated in the constructor

`new AIDRClient(config)` runs `SDKConfigSchema.parse`, so schema defaults apply
(`retries: 2`, `timeout: 5000`, `cache: true`, `cacheTtl: 300000`,
`environment: "production"`) and out-of-range or missing values are rejected
instead of silently disabling behaviour. `updateConfig()` re-validates too.

## Tests

`packages/sdk/src/__tests__/fail-closed-enforcement.test.ts` locks in the table
above with one test per adapter, including "the wrapped function is not called
for `ask`", "a failed check never executes", and "an `onAsk` approval still
works".

`packages/sdk/src/__tests__/data-dir-resolution.test.ts` covers rule-data
resolution from the monorepo source tree, the documented fallback order, the
`AIDR_*_DIR` overrides, and every "cannot initialise" failure mode.

`packages/sdk/src/__tests__/packaging.test.ts` packs the real tarball with
`pnpm pack`, extracts it into a temp directory **outside the repository**, and
runs `init()` + checks through both the ESM and CJS entry points from a different
cwd: a known-malicious command must come back `deny` (proof the rules loaded) and
a benign one `allow`. It also re-runs against a `dist`-only extraction to prove
the missing-data case fails loudly instead of reporting results.
