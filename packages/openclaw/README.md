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
- Replaces risky persisted tool output and risky outbound text with a safe, non-echoing notice
- Blocks `ask` verdicts until a human approves them out of band (see below)

## Output protection boundaries

OpenClaw exposes different guarantees at each output hook, so the connector
labels them explicitly:

- `after_tool_call` observes the result after the tool has executed. A finding is
  recorded and correlated with the run when OpenClaw supplies a run or session
  identifier. This hook cannot undo the call or change what the same-turn model
  already received. When the same tool call reaches `tool_result_persist`, the
  recorded finding is carried into that transcript rewrite.
- `tool_result_persist` synchronously replaces risky text before OpenClaw writes
  it to its transcript, including text that only `after_tool_call` observed for
  the same tool call. This protects later transcript reuse, but it is still a
  **post-execution transcript boundary**, not a pre-consumption tool-result gate.
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

Approval is therefore an **out-of-band, human-only action**. Today the supported
paths are:

1. **Permanently allowlist the exact artifact.** Add the URL/command/file path to
   the allowlist file (`~/.singularity-aidr/allowlist.json` by default) — e.g.
   with the Claude Code connector's allowlist flow, or by editing the file. Any
   later tool call with that exact artifact evaluates to `allowlisted`.
2. **Out-of-band `ApprovalStore` approval** for hosts that wire their own human
   approval channel: the process that owns the `ApprovalStore` can
   `setPending(actionId, …)` + `approve(actionId)` (see `approveAction` in
   `@singularityrd/aidr-core`) and the retry is then allowed.

### Honest limitation

OpenClaw's plugin API does not (yet) expose a host-native confirmation dialog the
plugin can drive, so **this connector has no in-session approval path**. The
practical consequence: an `ask` verdict cannot be approved while the session is
running — it stays blocked, and the user must allowlist the artifact or answer
the model's report with an alternative action. Blocking is the safe failure mode:
a blocked action is recoverable, a self-approved one is not. When OpenClaw
exposes a host confirmation primitive, wire it to `ApprovalStore` **without**
exposing it as a model-callable tool.

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
