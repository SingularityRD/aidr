# @singularityrd/aidr-claude-code

Singularity AIDR connector for **Claude Code**, shipped as hook entry points plus
a bundled MCP server.

The plugin registers a `PreToolUse` hook (the decision point), a `PostToolUse`
hook (tool-output inspection), a `UserPromptSubmit` hook (prompt protection), a
`SessionStart` hook (installed-plugin scan and version check) and a `health`
command used by the endpoint installer and the release consumer gate. Every hook
reads its event from stdin and writes a verdict to stdout. Caught internal errors
produce an explicit **deny** (or block); a hook process killed before it writes a
verdict lets the call run (fail-open, observed on Claude Code 2.1.282).

Real-host acceptance ([`docs/evidence/real-host/claude-code.json`](../../docs/evidence/real-host/claude-code.json),
`pnpm test:e2e:real-host`) covers Claude Code 2.1.282 on linux/x64 with the
development build and a scripted mock model: a malicious Bash call and a
credential read were refused with no side effect, a prompt carrying a token never
reached the model, and a token in Bash output reached the model only as AIDR's
quarantine notice. Other host versions, platforms, a signed release and a real
model are not covered.

## What it does

- Extracts commands, URLs, file paths and package installs from the tool input
  and evaluates them against the shared detection core (`@singularityrd/aidr-core`)
  using the local YAML threat corpus in `resources/`.
- Inspects supported PostToolUse result shapes after the tool has already run.
  Unsafe or uninspectable recognized MCP result envelopes are replaced by a
  text-only MCP error result; supported built-in results use shape-preserving
  replacements.
  Unknown shapes or oversized hook input are reported as coverage-unavailable
  rather than claimed as quarantined. Live Claude-host acceptance of replacement
  outputs covers a Bash result only (see above); MCP and other result shapes are
  not host-accepted, and PostToolUse cannot undo tool execution.
- Records decisions in the local audit log and, when a managed control plane is
  configured, forwards scoped telemetry.
- Approvals: an `ask` opens Claude Code's native confirmation dialog. In managed
  mode the ask is also submitted to the AIDR dashboard (the dialog shows
  `Approval requested in the AIDR dashboard: <request_id>`); once an administrator
  approves it there, the identical retry is released once without the dialog by a
  control-plane-signed, single-use token (the request id and the spent nonce are
  persisted, since every hook call is its own process). With
  `operator_approvals.dashboard_only: true` the dialog is replaced by a block so
  only the dashboard can release the call. See
  [dashboard approvals](../../docs/configuration.md#managed-mode-dashboard-approvals).
- Loads the pinned native AMSI addon from `dist/vendor/koffi` on Windows so file
  and buffer reputation can use the host antimalware interface. The installer
  refuses to register hooks when that payload is missing.

## Behavioral baseline status

The shared core includes behavioral and novelty scoring, but this connector does
not yet provide a trusted, input-bound success receipt to promote baseline
samples after execution. A cold or unavailable baseline is fail-closed (`ask`)
by default. A signed tenant policy may explicitly select
`behavioral.unavailable_action: "skip"`; that produces a visible
`behavioral_unavailable` warning verdict rather than a clean result, and the
independent known-threat model and other configured detectors still run. Treat
behavioral baseline detection as not production-ready until a verified
post-execution feedback path and independent efficacy evaluation are available.

## Installation

Install only from an approved release whose publisher signature and artifact
hashes have been verified. The Claude plugin archive is part of that verified
release bundle; do not treat the archive by itself as proof of publisher
identity. Either give the extracted package to the endpoint installer, or add
the verified plugin directory as a local Claude Code marketplace. Do not add
the Git repository directly; generated connector bundles are deliberately not
tracked. Commercial builds require the separately provisioned integrity
public key before they register hooks or start protection.

```bash
node scripts/endpoint-install.mjs --package-dir packages/claude-code --config /secure/path/agent-config.json
```

For source development, build the checkout before loading it:

```bash
pnpm install
pnpm build
claude --plugin-dir /absolute/path/to/aidr
```

A fresh install enforces locally with no account or network access. Managed
features are an opt-in layer on top of local enforcement.

## Entry points

| Artifact | Purpose |
| --- | --- |
| `dist/pre-tool-use.cjs` | `PreToolUse` decision hook |
| `dist/post-tool-use.cjs` | Tool-output inspection hook |
| `dist/session-start.cjs` | Session scan and version check |
| `dist/mcp-server.cjs` | Bundled MCP server |
| `dist/health.cjs` | `aidr-claude-code --json` health probe (declared `bin`) |

## Licence

Proprietary. See `LICENSE` in this package.
