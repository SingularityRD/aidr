# @singularityrd/aidr-openclaw

**Singularity AIDR** - AI Agent Detection & Response plugin for [OpenClaw](https://openclaw.dev).

Singularity AIDR intercepts tool calls (shell commands, URL fetches, file writes) and checks them against URL reputation services, local heuristic threat rules, and package supply-chain checks before they execute.

## Installation

For customer installs, configure the private registry as described in
[Package Installation](../../docs/package-installation.md) and install the
exact approved release version:

```bash
openclaw plugins install npm:@singularityrd/aidr-openclaw@VERSION
```

Replace `VERSION` with the version in the approved release record.

## What It Does

- Intercepts `exec`, `web_fetch`, `write`, `edit`, `read`, and `apply_patch` tool calls
- Checks URLs against cloud-based malware/phishing detection
- Matches commands and file paths against YAML-based threat definitions
- Validates npm/PyPI packages against supply-chain risks
- Scans installed plugins for threats at session start
- Inspects tool output and outbound model responses with a bounded 256 KiB text budget
- Quarantines risky tool output before the model receives it (OpenClaw 2026.9+ embedded runner; see below)
- Replaces risky persisted tool output and risky outbound text with a safe, non-echoing notice
- Blocks `ask` verdicts until a human approves them out of band (see below)
- Inspects the user's prompt before the model reads it (prompt protection, see below)

## Prompt protection

The `before_agent_run` gate inspects the current user input after prompt construction
and before model submission (`prompt_protection` in `~/.singularity-aidr/config.json`:
secrets `block`, personal data such as TC Kimlik, IBAN, email and phone numbers `warn`
by default; a provisioned tenant DLP policy also applies and blocks on any action other
than `allow`).

- **block**: returns `{ outcome: "block", reason, message, category: "prompt_protection" }`.
  OpenClaw keeps only the replacement `message` (which names the kind of data, never the
  value) in the transcript; the internal `reason` is a static code.
- **warn**: the gate passes. `before_prompt_build`, which runs before the gate on the
  same request, prepends a notice asking the model not to repeat or copy the data and
  to tell the user. It inspects `currentUserMessage` when the host supplies it.
- The gate always returns an explicit decision. A prompt that cannot be inspected, or
  whose inspection is still running after 10 s (`AIDR_PROMPT_INSPECTION_DEADLINE_MS`,
  100–13000; the host fails closed at 15 s), is blocked while secrets are in `block` mode.
  If the plugin fails to initialise, prompts get the same uninspected-prompt policy.
- Audit entries use `tool_name: "before_agent_run"` and record kinds and counts only.

Boundaries: OpenClaw implements `before_agent_run` in its embedded and CLI runners only;
it is not an input gate for the Codex or Copilot harnesses, and a host without the hook
ignores the registration. A non-bundled plugin needs conversation access for both
hooks:

```json
{ "plugins": { "entries": { "aidr-openclaw": { "hooks": { "allowConversationAccess": true } } } } }
```

Real-host acceptance of the prompt gate and of the pre-model tool-output quarantine
(OpenClaw 2026.9.6 embedded runner, scripted mock model, linux/x64) is recorded in
[`docs/evidence/real-host/openclaw.json`](../../docs/evidence/real-host/openclaw.json).

## Output protection boundaries

OpenClaw exposes different guarantees at each output hook, so the connector
labels them explicitly:

- **Pre-model tool-result quarantine** (`api.registerAgentToolResultMiddleware`,
  OpenClaw 2026.9 and later). OpenClaw's embedded runner awaits this middleware
  after the tool executed and **before** its result enters the model context. The
  connector inspects the result's `content` and, when it is risky or cannot be
  fully inspected (non-text blocks, the 256 KiB budget), returns a fresh text-only
  result: `Singularity AIDR quarantined this tool output before it reached the
  model`, the rule identifiers, nothing of the original. An inspection error, an
  integrity failure or an initialisation failure also quarantines; the original
  is never handed back on error (a middleware that throws is replaced by OpenClaw
  with its own "Tool output unavailable" error result). The tool side effect has
  already happened; what is contained is what the same-turn model reads. Flow and
  canary records are fed from the original output here, because `after_tool_call`
  then sees only the notice.
  Requirements and scope:
  - `openclaw.plugin.json` declares `contracts.agentToolResultMiddleware: ["openclaw"]`,
    and OpenClaw accepts the middleware from an installed plugin only when it is
    **explicitly enabled** (`plugins.entries.aidr-openclaw.enabled: true`).
    Otherwise OpenClaw drops the registration with a registry diagnostic; the
    connector logs `pre-model tool-output quarantine is not enforced` with
    `enforced: false` when it can see that (host without the API, a refused
    registration, or config that does not enable the plugin).
  - Only the `openclaw` runtime (the embedded runner) is claimed. OpenClaw's Codex
    native-hook relay runs tool-result middleware but forwards the result only to
    `after_tool_call`, not to the model, so the Codex harness is not covered.
  - `details` is not inspected at this boundary because OpenClaw strips it before
    provider replay; the transcript boundary below still inspects the whole message.
- `after_tool_call` observes the result after the tool has executed. A finding is
  recorded and correlated with the run when OpenClaw supplies a run or session
  identifier. This hook cannot undo the call or change what the same-turn model
  already received. When the same tool call reaches `tool_result_persist`, the
  recorded finding is carried into that transcript rewrite.
- `tool_result_persist` synchronously replaces risky text before OpenClaw writes
  it to its transcript, including text that only `after_tool_call` observed for
  the same tool call. This protects later transcript reuse; on its own it is a
  **post-execution transcript boundary** (the pre-model quarantine above is the
  same-turn boundary).
  If the host does not deliver this hook (or registering it fails), the connector
  records the transcript boundary as **not enforced** instead of implying the
  observed output was contained.
- `message_sending` scans outbound text and replaces a risky or incompletely
  inspected response before channel delivery. The replacement includes only rule
  identifiers and safe metadata; it never repeats detected content or secrets.
- `reply_payload_sending` applies the same decision to the complete normalized
  reply. A risky payload becomes a fresh text-only notice, so attached media,
  presentation data, and delivery actions cannot bypass the text decision.

The scanner visits at most 256 KiB of primitive text with explicit node and
depth ceilings. Output beyond those limits is reported as incompletely inspected
and is withheld at the delivery boundary instead of being declared clean.

These output boundaries also apply the output rules in a provisioned, signed
tenant DLP policy. A matching policy action withholds the complete payload using
the existing safe notice; this connector does not selectively redact fields.
Asynchronous hooks refresh policy trust before inspection. Synchronous transcript
persistence uses the validated snapshot initialized after artifact verification,
and withholds output when that snapshot is unavailable, expired, or changed.

## Verdicts

| Verdict | Behaviour                                                                 |
| ------- | ------------------------------------------------------------------------- |
| `allow` | Tool call passes through.                                                  |
| `deny`  | Tool call is blocked and reported to the model.                            |
| `ask`   | Tool call is **blocked**. The model is told to hand the approval reference (`actionId`) to the user; nothing the model can call can approve it. |
| paranoid sensitivity | `ask` is promoted to `deny` (no approval path at all).      |

## Provisioned tenant detector policy

An operator can deliver a signed tenant detector policy (DLP and behavioural
detectors) for this connector at a fixed location under the local AIDR state
directory:

```
~/.singularity-aidr/detectors/openclaw.json
```

The bundle is accepted only when it is signed by a key listed in
`licensing.public_keys_pem` (ed25519), is inside its validity window, and is
bound to the same tenant as the verified managed entitlement. Provisioning is
opt-in: with no bundle and no `runtime_detectors` module on the signed
entitlement, the plugin evaluates exactly as it does without a tenant policy.
A bundle that is present but invalid — or required by the signed entitlement and
missing — blocks the tool call rather than being treated as an empty policy.

The policy's labels and rules are whatever the tenant's signed bundle defines;
this connector ships no customer label taxonomy and assumes none.

## Behavioral baseline status

A signed policy can provision behavioral and novelty detectors, but this
connector does not provide a trusted, input-bound post-execution success receipt
to promote baseline samples. Product preflight therefore starts cold and does
not persist or restore learned baselines. Baseline-dependent detection is
unavailable and asks by default; a signed policy may explicitly select
`behavioral.unavailable_action: "skip"`, which remains a visible
`behavioral_unavailable` warning rather than a clean result. Do not treat
behavioral baseline detection as production-ready until a verified feedback
path and independent efficacy evaluation are available.

## Approving a flagged action

**The agent cannot approve its own actions.** Singularity AIDR deliberately does
not register an approval tool. An earlier version exposed an agent-callable
`aidr_approve` tool; because the block message necessarily contains the
`actionId`, a prompt-injected model could approve its own blocked call and then
re-issue it (and make the bypass permanent through `aidr_allowlist_add`). That
tool has been removed.

Approval is therefore an **out-of-band, human-only action**. The supported paths
are:

1. **Operator approval of one retry (`aidr approve`).** Every `ask` is recorded in
   the operator approval store (`~/.singularity-aidr/approvals.json`). In their own
   terminal the user runs `aidr pending` to review it and
   `aidr approve <actionId>` to approve it; the CLI shows the call and requires an
   interactive confirmation. The approval is HMAC-protected, bound to the exact
   tool and artifact set, expires after 15 minutes by default and is spent by the
   first identical retry. `aidr approve <actionId> --permit-allowlist` additionally
   lets `aidr_allowlist_add` turn that one artifact into a permanent entry once.
2. **Permanently allowlist the exact artifact** with `aidr allowlist add
   <url|command|file_path> <value>` (also interactive). Any later tool call with
   that exact artifact evaluates to `allowlisted`.
3. **Managed mode: dashboard approval.** On an enrolled installation every `ask`
   is also submitted to the AIDR dashboard, and the block reason says
   `Approval requested in the AIDR dashboard: <request_id>`. An administrator — a
   different, MFA-authenticated person on another device — approves it there, and
   the next identical call is released once by a control-plane-signed token that
   is verified against the approval keys in the signed entitlement and whose nonce
   is spent locally. The agent cannot mint, re-bind or replay such a token. With
   `operator_approvals.dashboard_only: true` this is the only channel (path 1 is
   then ignored). See
   [dashboard approvals](../../docs/configuration.md#managed-mode-dashboard-approvals).
   In local mode nothing is sent anywhere and only paths 1 and 2 apply.

### Honest limitation

OpenClaw's plugin API does not (yet) expose a host-native confirmation dialog the
plugin can drive, so approval happens in a separate terminal rather than inside
the session: the model reports the `actionId`, the user approves it with the CLI,
and the user then asks the model to retry. The approval channel is not a boundary
against code running as the same OS user with full shell access (see
[docs/configuration.md](../../docs/configuration.md#operator-approvals)); the
self-defense rules `CLT-SELF-007`..`009` deny the agent running `aidr approve`
(however it is quoted or wrapped) or touching the AIDR state directory and the
approval key, which lives in the OS credential vault. Blocking is the safe failure mode: a blocked
action is recoverable, a self-approved one is not.

## Configuration

Commercial releases verify their signed package before registering any hook. An
operator must provision the independently distributed artifact signing public
key in `~/.singularity-aidr/config.json`:

```json
{
  "sensitivity": "balanced",
  "integrity": { "public_keys_pem": ["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"] },
  "url_check": { "enabled": true },
  "file_check": { "enabled": true }
}
```

## Links

- [Source & documentation](https://github.com/singularityrd/aidr)
- [OpenClaw platform guide](https://github.com/singularityrd/aidr/blob/main/docs/platform-guides/openclaw.md)
- [Privacy policy](https://github.com/singularityrd/aidr/blob/main/docs/privacy.md)

## License

The first-party OpenClaw integration is proprietary and distributed under the
commercial terms in the repository [LICENSE](../../LICENSE) and the applicable
Order Form. Threat resources retain the [Detection Rule License 1.1](dist/resources/threats/LICENSE).
Third-party components retain their original terms listed in
[THIRD_PARTY_NOTICES](../../THIRD_PARTY_NOTICES). Legal approval of the
current Release Candidate remains open.
