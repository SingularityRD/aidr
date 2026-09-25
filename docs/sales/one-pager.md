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

**AIDR for AI coding agents.** Connectors for Claude Code, Cursor, VS Code, OpenClaw,
OpenCode and Codex CLI pass observed tool calls to one local decision engine before the
host acts. The engine returns `allow`, `deny` or `ask`, naming the matched rule and
artifact. The MCP Gateway inspects MCP tool results before the model reads them; the SDK
applies the same checks inside your own applications.

**AIDR Browser Guard.** A Chrome, Edge and Firefox extension that replaces personal data
and secrets with placeholders such as `[IBAN_1]` before a prompt, paste or file reaches
ChatGPT, Gemini, Claude, Copilot, Perplexity, DeepSeek, Mistral or Grok, and shows the
originals again in the response, on the user's screen only. It covers Turkish and English
data (T.C. kimlik, IBAN, phones, emails, cards), secrets and API keys, custom terms and
exact-data-match fingerprints of your own records.

**AI Security Posture.** AI Infra Guard-based scans check AI services against 2,000+ CVE
rules for 146 AI components, map MCP risk categories and scan agent skills and plugins.

## How it works

```
AI agent tool call                     Prompt / paste / file in an AI chat
        │                                           │
        ▼                                           ▼
  connector hook  ─▶ local engine          Browser Guard (in the browser)
                    ├─ 386 YAML rules        ├─ TR/EN PII + secrets detection
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
  script block on an internal error. Detection internals skip a failing signal visibly;
  a skipped check is never a clean result.
- **No self-approval.** `ask` blocks until a human approves out-of-band. No connector
  gives the agent an approval tool.

## Deployment

| Local mode (free) | Cloud (SaaS) | On-premises |
| --- | --- | --- |
| Connectors and Browser Guard, no account | Hosted dashboard, enrollment, central policy, audit export, SSO/SCIM | Docker Compose or Kubernetes (Helm); air-gapped with a signed offline license and signed packs |

## Plans

Free · **Team** $20 per developer per month billed annually ($24 monthly, minimum 3) ·
**Business** $45 per developer per month (minimum 25) · **Enterprise** custom. List
prices, subject to COM-001 approval. Details in [pricing.md](pricing.md).

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

The release decision is **NO-GO**; see
[first-customer-ready.md](../production-readiness/first-customer-ready.md). Use the
[controlled demo runbook](../production-readiness/controlled-demo-runbook.md) and the
[demo script](demo-script.md) for any session.

**Working in this repository today**

- Local engine with 386 YAML threat rules in 24 files; `aidr setup` refuses to report
  success if zero rules load or the self-test does not match.
- Connector code for Claude Code, Cursor, VS Code, OpenClaw, OpenCode and Codex CLI,
  with cross-connector parity tests.
- Browser Guard engine, reversible vault, site adapters, file sanitisation, managed
  policy, counts-only telemetry and a real-browser E2E harness against hermetic site
  fixtures.
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
- **Cloud and on-prem are not accepted.** The hosted app hostname does not resolve yet;
  both deployment paths still need the FCR installation, recovery and scale rehearsals.
- **Real-host acceptance is open** for each connector, OS and host version, and for each
  browser and AI site. A returned `deny` is not proof that a side effect was prevented.
- **Known coverage edges.** If a hook is disabled, untrusted or killed, the host
  proceeds; Codex fails open in those cases. Browser Guard cannot inspect binary files
  such as PDF or DOCX in the browser (blocked in `block` mode, otherwise let through with
  a warning), and a site redesign can require an adapter update. Names and addresses
  without cue words need the optional NER host, which ships without a model.
- **Commercial gates open.** Prices, legal terms and DPA, billing, support and regions
  (COM-001 to COM-013) await approval.

*This document contains no customer names, certifications or efficacy claims, because
none exist. It will be updated when they do.*
