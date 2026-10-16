# Singularity AIDR

### AI Agent Detection & Response — policy enforcement for AI coding agents and AI chat

---

## The problem

AI coding agents run shell commands, write files and fetch URLs on developer machines,
with developer credentials, following instructions the model derived from content it
read. A README, a web page, a dependency's docs or a tool result can steer the agent.
The agent is not compromised; it is obeying.

At the same time, people across the company paste customer records, IBANs, national ID
numbers and API keys into ChatGPT, Gemini, Claude and Copilot, often without noticing.

Existing layers see different parts of this:

- **SAST/SCA** analyse code you already wrote; they are not in the execution path.
- **EDR** observes operating-system behaviour; its agent context depends on the product.
- **Model guardrails** sit at the model boundary and may not see an endpoint action or a
  paste into a web chat.

## What Singularity AIDR does

**AIDR for AI coding agents.** Six connectors pass observed tool calls to one local
decision engine before the host acts: Claude Code, OpenClaw and OpenCode, Cursor and
VS Code (preview — no real-host acceptance evidence yet), and Codex CLI (preview;
outside the first general-availability scope, which is the other five). The engine returns `allow`, `deny` or `ask`, naming the matched rule and
artifact. The MCP Gateway inspects MCP tool results before the model reads them; the SDK
applies the same checks inside your own applications.

**AIDR Browser Guard.** A Chrome, Edge and Firefox extension that replaces personal data
and secrets with placeholders such as `[IBAN_1]` before a prompt, paste or file reaches
ChatGPT, Gemini, Claude, Copilot, Perplexity, DeepSeek, Mistral or Grok, and shows the
originals again in the response, on the user's screen only. It covers Turkish and English
data (T.C. kimlik, IBAN, phones, emails, cards), secrets and API keys, custom terms and
exact-data-match fingerprints of your own records.

**AI Security Posture.** Find the weak spots in the AI stack around your agents.
`aidr scan --target` fingerprints AI services (146 AI component fingerprints) and matches
them against 2,000+ CVE rules with severity and CVSS; `aidr discover` maps local MCP
servers to 14 MCP risk categories; skill and plugin packages are scanned against the
T01–T09 taxonomy. The dashboard's Posture view collects the results, and uploads carry
identifiers and digests only, never target URLs, file paths or matched text.

**AI safety and governance.** Session-level toxic-flow detection holds the step that
would combine private data, untrusted content and an outbound channel. Guardrails pause
runaway loops and hold test sabotage and irreversible actions (database drops, cloud
deletions, publishing) for a person. The dashboard adds an AI asset register, an intake and
exception workflow, four-eyes policy change and a governance scorecard; `aidr simulate`
tests defanged attacks against your settings without executing anything.

## How it works

```
AI agent tool call                     Prompt / paste / file in an AI chat
        │                                           │
        ▼                                           ▼
  connector hook  ─▶ local engine          Browser Guard (in the browser)
                    ├─ 521 YAML rules        ├─ TR/EN PII + secrets detection
                    ├─ command-chain and     ├─ custom terms + exact-data match
                    │  obfuscation analysis  └─ reversible placeholders
                    ├─ package/plugin checks          │
                    └─ allowlist + cache              ▼
        │                                   masked text is sent; originals
        ▼                                   restored locally in the reply
  host enforces allow | deny | ask
```

- **Local first.** Detection runs on the device in both products. The default mode is
  `local`; no account is needed.
- **Counts, not content.** Managed telemetry sends redacted agent verdicts (hashed by
  default) and Browser Guard per-type counts. Prompts, file contents and masked values
  are not sent.
- **Fails closed where it matters.** Connector entry points and Browser Guard's content
  script block on an internal error. A hook the host disabled, did not trust or killed
  gives no verdict, and the host then decides. Detection internals skip a failing signal visibly;
  a skipped check is never a clean result.
- **No self-approval.** `ask` blocks until a human approves out-of-band. No connector
  gives the agent an approval tool.

## Deployment

| Local mode (free) | Cloud (SaaS) | On-premises |
| --- | --- | --- |
| Connectors and Browser Guard, no account | Hosted dashboard, enrollment, central policy, audit export, SSO/SCIM. **Not live yet**: no hosted region is deployed | Docker Compose or Kubernetes (Helm); air-gapped with a signed offline license and signed packs. Not yet accepted on a customer host; the Helm chart has not run on a live cluster |

## Plans

Free (local mode) · **Team** (minimum 3 developers) · **Business** (minimum 25
developers) · **Enterprise** (on-premises and air-gapped). Pricing and quotes:
anil@singularityrd.com.

## Who it's for

Engineering-led companies with **15–80 developers** where AI coding agents are in daily
use, and organisations (including Turkish companies with KVKK obligations) whose staff
use public AI chat products with customer data.

- **The user** wants to move fast and not be nagged.
- **The buyer** (Head of Engineering, CISO, DPO) wants to know what agents are doing,
  **which installed agents are not covered**, and what personal data is going to AI
  sites, as counts per type.

## What makes it different

- **Position.** Agent hooks see a tool request before the host acts, when the host
  invokes the hook. Browser Guard sees the prompt before it leaves the page.
- **Reversible masking.** Users keep working with real names and numbers on screen;
  the AI provider sees placeholders.
- **Turkish data first.** Checksum-validated T.C. kimlik and IBAN, Turkish phone and
  address patterns, Turkish and English in-page messages and coaching.
- **Deployment choice.** Local mode, cloud or on-prem, including air-gapped.
- **Candour.** We publish rule counts because they are countable, and we list what is
  not ready (appendix).

---

## Appendix — current status and what is not ready yet

Singularity AIDR is not yet released for live pilots or production; the release record is
[first-customer-ready.md](../production-readiness/first-customer-ready.md). Use the
[controlled demo runbook](../production-readiness/controlled-demo-runbook.md) and the
[demo script](demo-script.md) for any session.

**Working in this repository today**

- Local engine with 521 YAML threat rules in 31 files; `aidr setup` refuses to report
  success if zero rules load or the self-test does not match.
- Connector code for Claude Code, Cursor, VS Code, OpenClaw, OpenCode and Codex CLI,
  with cross-connector parity tests. Cursor and VS Code are a preview — no real-host acceptance evidence yet.
  Claude Code, OpenClaw, OpenCode and Codex have one real-host record each (linux/x64,
  development build, scripted mock model). Codex is outside the first GA scope.
- Browser Guard engine, reversible vault, site adapters, file sanitisation, managed
  policy, counts-only telemetry and a real-browser E2E harness against hermetic site
  fixtures. It has not been verified on the live AI sites.
- AIDR Privacy 0.6.0 engine with its own test suite (`pnpm test:privacy`).
- Control plane with tenancy/RLS, device enrollment, policy, audit export, SSO/SCIM.

**Not ready yet**

- **No certifications or independent assessment.** No SOC 2, ISO 27001 or penetration
  test. None in progress.
- **No customers.** No case studies, testimonials or references.
- **No measured efficacy.** Detection rate, false-positive rate and evasion resistance
  have not been measured on a real workload, for agents or for Browser Guard.
- **No publisher-signed release.** No approved code-signing identity; Windows warnings or
  policy blocks depend on the device. Browser Guard is not yet published to the Chrome,
  Edge or Firefox stores.
- **Cloud and on-prem are not accepted.** The hosted app hostname does not resolve yet,
  the public website's API routes return errors, and no EU, US or APAC region is
  deployed; both deployment paths still need the FCR installation, recovery and scale
  rehearsals. There is no desktop application; endpoints run the CLI, hooks and
  extensions.
- **Real-host acceptance is open** for each connector, OS and host version, and for each
  browser and AI site. A returned `deny` is not proof that a side effect was prevented.
- **Known coverage edges.** If a hook is disabled, untrusted or killed, the host
  proceeds; Codex fails open in those cases. Browser Guard uploads Word, Excel and
  PowerPoint files as masked copies but cannot rewrite PDFs (a PDF with findings is
  blocked; scanned or encrypted PDFs are uploaded with a warning unless the mode is
  `block`), and a site redesign can require an adapter update. Names and addresses without
  cue words need the optional NER host, which ships without a model.
- **Commercial terms open.** Legal terms and DPA, billing, support and regions still await
  approval. The EULA, DPA and SLA in `docs/legal` are drafts; the 99.9% monthly
  availability figure is a draft target for contract discussion, not an SLA in force.

*This document contains no customer names, certifications or efficacy claims, because
none exist. It will be updated when they do.*
