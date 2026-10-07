# `@singularityrd/aidr-sdk`

Small SDK for integrating Singularity AIDR security checks into Express,
Next.js, or any runtime through the generic middleware adapter.

This is an application-owned check boundary, not an AI-host connector. It only
checks requests the application passes to it; wrapping a tool does not provide
the native connectors' tool normalization or package/manifest inspection.

The client also honors an operator-installed local response worker. A verified
pause or unavailable required control state returns `deny` before cached allows
or provider requests; a pause applied during provider I/O prevents a new allow.
The installed endpoint's credential and issuer roots establish that authority.
The SDK caller's remote `apiKey` and request context cannot replace it or bypass
the pause. Without an installed or required worker, caller-owned SDK checks keep
their existing scope; configuring an SDK API key does not enroll the host.

## Mandatory privacy and final text sends

The installed core configuration may require `{"privacy":{"required":true}}`.
In that mode, ordinary `check()` operations and both middleware families deny
caller-owned execution, including raw provider callbacks. A local threat still
keeps its denial; no cache or external reputation lookup authorizes the route.
Mandatory denials emit a fixed withheld request instead of raw input. Malformed
or unreadable installed configuration blocks execution. Approvals and request
metadata cannot bypass the requirement. Wrappers recheck installed controls
after asynchronous approval/hooks, immediately before the caller operation.
The mandatory profile also suppresses raw observer hooks, custom request
extractors, `.use` callbacks and composed stages before they receive input;
normal-mode callbacks keep their existing behavior. Low-level composition
still needs a detector middleware in normal mode to inspect tools.
Generic and `wrap()` results are also withheld if mandatory routing is enabled
while their operation or provisioned output scan is pending; the already-started
operation may have completed. Express/Next middleware owns its continuation
decision and does not intercept the later host response.

`sendText()` owns one bounded final text request through the operator-installed
private `@singularityrd/aidr-privacy/platform` package's real `TextGatewayClient`.
Install that approved private package beside this SDK and run its configured
service with approved model, broker, tenant policy, durable state and mTLS.
The second constructor argument is trusted host configuration; it is separate
from the SDK/reputation settings and remains private to the client. Provider
credentials belong on the service. Keep device private keys and session tokens
in the approved OS credential vault, with enrolled certificate/CA files owned
by the host operator.

```ts
const client = new AIDRClient(
  { apiKey: sdkCredential },
  { privacyGateway: {
    origin: approvedPrivacyServiceOrigin,
    destinationId: approvedDestinationId,
    tls: { ca: approvedCa, cert: enrolledCertificate, key: deviceKeyFromVault },
    credentials: loadBoundSessionCredentialsFromVault,
  } },
);
const requestId = crypto.randomUUID(); // Persist before dispatch for reconciliation.
const outputText = await client.sendText(prompt, { requestId });
```

The SDK copies TLS buffers at construction, runs fresh local detection without
reputation/cache, and checks current installed controls before dispatch and
after asynchronous credential resolution. Only the service's sanitized
`outputText` is returned. Input is nonempty text up to 500,000 UTF-8 bytes;
the gateway's 512 KiB serialized request bound also applies. Returned text is
bounded to 2 MiB. Streaming, files, images and destination overrides are
unsupported and rejected. This path emits no SDK input/output events or raw
credential errors. Only `requestId`, an approved `reviewCaseId`, and an
`AbortSignal` may be supplied per send.

A blocked/review/unknown receipt, withheld response, missing package, invalid
configuration, failed authentication/TLS or installed pause stops delivery.
There is no raw provider fallback and SDK retry settings never resend a model
request. A failed/aborted send can already have committed at the provider;
retain the explicit `requestId` and reconcile its service record before any
operator-approved retry. Do not automatically create a fresh request ID or
replace unavailable output with the original prompt.

This enforces the SDK's owned text route. Separate host processes, browser
clients and arbitrary unwrapped network calls require the institution's
actual egress restrictions and removal of direct provider credentials. The
privacy service's defense model/broker qualification and customer host
acceptance remain separate requirements; local tests do not approve a model.

## Verdict enforcement is fail-closed

Both middleware surfaces in this package share **one** enforcement rule,
implemented in [`src/enforcement.ts`](./src/enforcement.ts):

> A wrapped function, tool invocation, or HTTP request proceeds only for
> `decision: "allow"`, or when a caller-supplied `onAsk` explicitly approves an
> `ask` result (including a separate opt-in for indeterminate results). `deny`
> never proceeds.

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

### Input coverage is chosen by the caller

`createMiddleware(client).wrap(fn, requestFactory)` runs one SDK
`AIDRClient.check()` on the `CheckRequest` returned by `requestFactory`. The
caller must set its `action` and `resource` to the specific command, URL, or
file path being checked; the SDK does not infer all security-relevant artifacts
from arbitrary function arguments. The Express/Next.js helpers check the request
URL/path. Express passes body and headers as context; Next.js passes headers but
does not read the body. Neither extracts them as separate artifacts.

`wrapToolWithMiddleware()` retains the serialized arguments and, for structured
inputs, also adds typed artifacts extracted from common field names such as
`command`, `path`, `url`, and `content`. Positional arguments have no universal
meaning, so their fields are not inferred; the SDK wrapper also does not call
the native connectors' shared evaluator or package checker. For those guarantees,
map arguments explicitly with `createMiddleware(client).wrap(fn, requestFactory)`
or use and verify a supported native connector. Do not treat a generic wrapper
as equivalent to native connector coverage.

The tool wrapper executes a JSON snapshot of the inspected arguments. Custom
prototypes, `toJSON` methods, and caller mutations cannot replace that checked
snapshot with a different value before the tool runs.

### URL reputation and data sharing

The SDK keeps URL reputation requests **off by default**. Fetch URLs are still
checked by local heuristics; because remote reputation was not consulted, a
fetch that would otherwise be allowed returns `ask` and requires review. To
share eligible URLs with the configured reputation provider, explicitly enable
it:

```ts
const client = new AIDRClient({
  apiKey: process.env.AIDR_API_KEY!,
  urlReputationEnabled: true,
});
```

URL user-info and fragments are never sent. Query parameters are withheld by
default; enabling `includeUrlQueryParameters: true` separately opts in to
sending them. URLs withheld for these reasons are reported as unavailable,
not clean. Avoid putting secrets in a URL even when reputation lookups are
enabled.

Set `baseUrl` to your reputation service's HTTPS API base (for example,
`https://aidr.example.com/functions/v1`); the SDK calls its `/url-check` route
with `apiKey` as a bearer credential. Configuration updates clear existing
verdicts so a changed service or credential takes effect on the next check.

Both middleware surfaces accept the same `onAsk` /
`allowApprovalOfIndeterminateResults` options:

| Adapter              | Entry point                                    | Blocking behaviour for `ask` / indeterminate                                             |
| -------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Core middleware      | `createMiddleware(client, options)`            | `wrap()` throws; `express()`/`nextjs()` return 403 with the enforcement message.          |
| Generic middleware   | `createGenericMiddleware(client, options)`     | Throws `AIDRMiddlewareError` (also used by the sync-compatible variant).                  |

## Tool output inspection before model consumption

The generic adapter inspects returned text and structured results with the core
output scanner before returning them to the caller. The default limit is 256 KiB
of UTF-8 data. A finding, an oversized
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

For a host serving a locally provisioned connector profile, set
`createGenericMiddleware(client, { agentRuntime: "cursor" })` to include that
profile's signed tenant output DLP. Choose the runtime the host actually serves.
The runtime is fixed when middleware is created; tool input and metadata cannot
select or change it. Each result revalidates the local signed policy and managed
entitlement before delivery. This also applies to the sync-compatible middleware
and generic tool wrappers. The SDK API key does not select this local tenant
profile, and the standalone synchronous guards continue to use the fixed output
rules.

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
above for both retained middleware surfaces, including "the wrapped function is
not called for `ask`", "a failed check never executes", and "an `onAsk`
approval still works".

`packages/sdk/src/__tests__/data-dir-resolution.test.ts` covers rule-data
resolution from the monorepo source tree, the documented fallback order, the
`AIDR_*_DIR` overrides, and every "cannot initialise" failure mode.

`packages/sdk/src/__tests__/packaging.test.ts` packs the real tarball with
`pnpm pack`, extracts it into a temp directory **outside the repository**, and
runs `init()` + checks through both the ESM and CJS entry points from a different
cwd: a known-malicious command must come back `deny` (proof the rules loaded) and
a benign one `allow`. It also re-runs against a `dist`-only extraction to prove
the missing-data case fails loudly instead of reporting results.
