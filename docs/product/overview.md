# Singularity AIDR — product overview

Singularity AIDR (AI Agent Detection & Response) puts a policy check between AI tools and
the things they touch: the commands, files and URLs of AI coding agents, the MCP tool
results those agents read, and the prompts people paste into AI chat products. This page
describes what each product line does, where it runs and where its boundaries are. The
current release decision is in
[first-customer-ready.md](../production-readiness/first-customer-ready.md) (not yet
released for customer use); nothing here replaces that record.

## Product lines at a glance

| Product line | Runs where | Main components |
| --- | --- | --- |
| AIDR for AI coding agents | Developer endpoint, inside the agent host's hook | `packages/core`, connectors, `packages/mcp-gateway`, `packages/sdk`, `packages/cli` |
| AIDR Browser Guard | The user's browser (Chrome, Edge, Firefox) | `packages/browser-guard` |
| AIDR Privacy engine | In the browser (rule layer), optional endpoint native host, optional server gateway | `packages/privacy` |
| AI Security Posture | Developer or operator machine (CLI), optional loopback deep-scan service, dashboard Posture view | `packages/core` posture scanners, `packages/cli` (`scan`, `discover`, `collect`), `threats/skill-scan.yaml`, `packages/dashboard` |
| Control plane | Cloud (SaaS) or customer-operated (on-prem) | `supabase/`, `packages/dashboard` |

## 1. AIDR for AI coding agents

Each connector hands observed tool calls to one shared local decision engine
(`@singularityrd/aidr-core`), which returns `allow`, `deny` or `ask`.

| Connector | Hook boundary | Guide |
| --- | --- | --- |
| Claude Code | `PreToolUse`, `PostToolUse`, `SessionStart` plugin hooks | [claude-code.md](../platform-guides/claude-code.md) |
| Cursor / VS Code | Extension (`aidr-cursor`) with host hooks | [cursor.md](../platform-guides/cursor.md) |
| OpenClaw | In-process `before_tool_call` plugin | [openclaw.md](../platform-guides/openclaw.md) |
| OpenCode | `tool.execute.before` plugin | [opencode.md](../platform-guides/opencode.md) |
| Codex CLI | Native `PreToolUse` command hook for `Bash` and `apply_patch` | [codex.md](../platform-guides/codex.md) |

**Detection.** 494 YAML threat rules in 29 files under [`threats/`](../../threats/)
cover dangerous commands, credential access, persistence, obfuscation, crypto-mining,
supply-chain and LLM-specific patterns for Linux, macOS and Windows. The rules are data,
not code, and customers can add their own under `~/.singularity-aidr/threats/`. Package
supply-chain checks, session-start plugin scanning and optional URL/file/package
reputation lookups add further signals. A signed tenant detector policy can add DLP and
behavioural detectors.

**Verdicts.** `deny` asks the host to stop the call. `ask` is a block pending
out-of-band human approval: the model sees an action ID in the block reason, and no
connector exposes an approval tool to the agent, so a prompt-injected agent cannot
approve its own block. When several signals fire the stricter one wins
(`deny > ask > allow`). Sensitivity presets are paranoid (0.70), balanced (0.85) and
relaxed (0.95).

**Session, safety and governance layers.** On top of the per-call rules:
[toxic-flow detection](../toxic-flow.md) holds the call that would combine private data,
untrusted content and an outbound channel in one session;
[canary credentials](../canary-tokens.md) catch an agent that touches decoy keys;
[agent permission profiles](../agent-profiles.md) restrict each agent to its tools, paths,
domains and MCP servers; [AI safety guardrails](../agent-safety.md) pause runaway loops and
hold test sabotage, autonomy escalation and irreversible actions;
[poisoning protection](../poisoning-protection.md) guards instruction, memory and MCP
configuration files; [model supply-chain](../ai-supply-chain-safety.md) and
[secure-code](../secure-code-guardrails.md) rules check the code an agent writes (secure-code
findings warn by default). `aidr simulate`, `aidr aibom` and `aidr coverage` provide a
defensive self-test, a CycloneDX AI-BOM and the OWASP / MITRE ATLAS coverage matrix; the
dashboard adds approvals, an AI asset register, four-eyes change control and a governance
scorecard ([ai-governance.md](../ai-governance.md)).

**Failure behaviour, per layer:**

- Connector entry points fail closed: an internal error becomes a deny.
- Detection internals skip a failing signal, log it and continue. The skip is visible;
  it is never reported as a clean result.
- Security controls (authentication, tenant isolation, approvals, webhook signatures)
  fail closed.
- The host decides what happens when a hook is disabled, untrusted or killed. Codex, for
  example, proceeds in those cases. AIDR is a guardrail at the hook boundary, not
  endpoint isolation.

**MCP Gateway** ([README](../../packages/mcp-gateway/README.md)). A loopback HTTP
gateway, plus a stdio bridge, that sits between an MCP client and its servers. It
requires a bearer token per client, an explicit per-tenant tool allowlist and an
Ed25519-signed server manifest. It buffers and scans tool results before the model sees
them. New or changed toolsets are quarantined until an operator approves them with a
command-line tool; approval is never an MCP tool. Clients that can still reach the
upstream server directly are outside its boundary.

**SDK** ([README](../../packages/sdk/README.md)). Express, Next.js and generic
middleware that applies AIDR checks to calls your own application makes. Only
`allow`, or an `ask` that your `onAsk` callback explicitly approves, proceeds; `deny`
and indeterminate results block.

**CLI** (`@singularityrd/aidr-cli`, binary `aidr`). `setup`, `status`, `config`,
credential rotation/revocation, and `scan`/`collect` for AI-infrastructure posture (see
section 4).

## 2. AIDR Browser Guard

A browser extension for Chrome, Edge and Firefox
([README](../../packages/browser-guard/README.md)) for the people in an organisation who
use AI chat products directly.

- **Sites.** ChatGPT, Gemini, Claude, Copilot, Perplexity, DeepSeek, Mistral and Grok
  through per-site adapters, plus a generic adapter for other pages.
- **What it detects.** Turkish and English personal data: T.C. kimlik numbers (checksum),
  IBANs (mod-97), phone numbers, email addresses, payment cards (Luhn), addresses and
  labelled fields. Also secrets and API keys (cloud, Git hosting and AI provider tokens,
  JWTs, private keys, credentials in URLs), administrator-defined custom terms, and
  exact-data-match datasets. Optional signals flag prompt-injection patterns and
  source-code pastes with coaching text.
- **Exact data match.** An administrator distributes HMAC-SHA256 fingerprints of
  sensitive records (for example customer name + account number) through managed policy.
  The extension compares fingerprints and never receives the plaintext dataset. The
  per-dataset keys come from the optional native host, not from browser policy, and
  datasets of guessable values (below 64 bits of estimated entropy) are refused.
- **Channels.** Typed prompts, pastes and file uploads. Text-based files (plain text,
  source, CSV/TSV, JSON/JSONL, `.env`) are masked and replaced before upload, with
  spreadsheet formula cells neutralised. Binary files such as PDF, DOCX, XLSX or images
  cannot be inspected in the browser: `block` mode stops them, other modes let them
  through with a warning and record them as unscanned. Administrators can also block or
  allow every upload, and oversized files are blocked.
- **Reversible placeholders.** Values are replaced with numbered placeholders such as
  `[EMAIL_1]` or `[TCKN_2]` before sending. The mapping lives only in the page's
  content-script memory; it is never written to extension storage or sent over the
  network, so a reload forgets it and earlier placeholders stay as placeholders.
  Placeholders in the AI's response are shown with the originals restored on the page.
  Types such as secrets can be set to never restore.
- **Modes.** `auto` (mask and send), `confirm`, `block` and `monitor`.
- **Managed policy.** Administrators push settings through the browser's enterprise
  policy ([`managed_schema.json`](../../packages/browser-guard/static/managed_schema.json)).
  Managed keys are locked in the user interface.
- **Telemetry.** Optional, and counts only: site, action, channel and per-type counts,
  as defined in [privacy-telemetry.md](../contracts/privacy-telemetry.md). No text,
  masked text, values or page URLs are sent.
- **Optional native host.** An endpoint process from the AIDR Privacy package can add
  named-entity recognition for names and addresses without cue words. It ships without
  model weights; see [native-host.md](../../packages/browser-guard/docs/native-host.md).

**Boundaries.** Browser Guard sees only what happens in pages it is injected into. It
does not cover desktop AI apps, API clients or other browsers. A site redesign can
require an adapter update. The content script fails closed: if the policy is missing,
the editor cannot be read, or a scan errors or is incomplete, the send is blocked (except
in `monitor` mode, which never blocks).

## 3. AIDR Privacy engine

`@singularityrd/aidr-privacy` 0.6.0 ([README](../../packages/privacy/README.md)) is the
TR/EN detection and masking engine. Its browser-safe rule layer is what Browser Guard
runs. Optional parts:

- a **native messaging host** for NER and screenshot OCR on the endpoint;
- an **enterprise gateway / control plane** (`/platform`) with signed policy and tool
  controls (`/enterprise`).

The optional parts are integration building blocks. They are not switched on by
installing AIDR and need the customer's identity provider, device management and
provider accounts before acceptance. The package's status table lists what is tested and
what is not. Tests run with `pnpm test:privacy`.

## 4. AI Security Posture

Singularity AIDR's AI Security Posture shows where the AI stack around your agents is
exposed. It is detection, not enforcement: three local, deterministic scanners report
findings, and runtime `allow`/`ask`/`deny` decisions are unchanged
([AI Security Posture](../ai-security-posture.md)).

- **AI infrastructure vulnerability scanning.** `aidr scan --target <url>` (or
  `--file targets.txt`) fingerprints AI services such as inference servers, agent
  frameworks and AI apps (146 AI component fingerprints), extracts their versions and
  matches them against 2,000+ CVE rules. Each finding carries a CVE/GHSA id, severity
  and CVSS score. Only loopback and private targets are scanned unless `--allow-public`
  is given; a target that could not be reached or identified is reported as *not
  scanned*, never as clean. Critical or high findings exit `2` for CI use.
  `aidr collect` keeps a tenant-scoped inventory of scanned targets.
- **MCP server risk analysis.** `aidr discover` reads local MCP configuration files and
  reports each server's transport, risk indicators (remote URL, shell wrapper, broad
  filesystem access), tool-manifest attestation status and the 14 MCP risk categories
  (`mcp-01` to `mcp-14`, such as token exposure, tool poisoning, command injection and
  tool shadowing). The categories map onto AIDR's MCP enforcement policy.
- **Skill and plugin scanning.** `aidr scan --skill <dir>` and the session-start plugin
  scan check skill and plugin packages against the T01–T09 taxonomy (instruction
  hijacking, memory poisoning, remote payload execution, embedded malicious code,
  privilege escalation, persistence, tool hijacking, insecure dependencies, insecure
  coding practices) as reviewable rules in `threats/skill-scan.yaml`.
- **Dashboard posture view.** With `--upload`, findings reach the managed control plane
  and appear on the dashboard's **Posture** page: CVEs by severity and CVSS, MCP servers
  with their risk categories, skill/plugin findings and a 30-day trend. An empty posture
  is never shown as a clean environment.
- **Identifiers only.** Uploads carry identifiers and digests (CVE id, severity, CVSS,
  component and version, risk category codes, rule ids, SHA-256 digests). Target URLs and
  hostnames, file paths, matched text, MCP commands, arguments and credentials never
  leave the machine.

Optional deep scans run through a separate bridge service that listens on loopback by
default. A scan target can contain user-controlled text, so check where the bridge runs
before scanning customer systems.

## 5. Control plane and deployment

| Option | What you get | Guide |
| --- | --- | --- |
| Local mode (free) | Agent connectors and Browser Guard with local settings. No account or network needed for detection. | [configuration.md](../configuration.md) |
| Cloud (SaaS) | Hosted dashboard, device enrollment, central policy for agents and Browser Guard, telemetry, audit export, SSO/SCIM | [saas.md](../deployment/saas.md) |
| On-premises | The same control plane, customer-operated on Docker Compose or Kubernetes (Helm); air-gapped with a signed offline license and signed packs | [onprem.md](../deployment/onprem.md) |

The control plane is multi-tenant with row-level security. API keys are stored as
hashes, devices enroll through a short-lived device-code flow, and enforcement always
stays local. If the control plane is unreachable, enrolled endpoints keep enforcing with
signed cached state.

## 6. Plans

Free (local mode), Team, Business and Enterprise. Pricing is by quote through
anil@singularityrd.com; edition contents are listed in the
[product catalog](../sales/catalog/README.md).

## Related

- [Security FAQ](../sales/security-faq.md)
- [Privacy and telemetry data flow](../privacy.md)
- [Architecture](../architecture.md)
- [Threat rules](../threat-rules.md)
