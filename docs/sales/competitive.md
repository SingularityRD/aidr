# Competitive notes

**Internal sales reference. Handle with care.** The competitor descriptions below are a
summary of how these vendors publicly position themselves, written from general market
knowledge as of September 2026. They have **not** been verified hands-on, and product
scope, ownership and pricing change often. Before quoting anything to a prospect, check
the vendor's current public material and cite it. Never state a competitor's weakness as
fact unless you can link a public source. Never claim AIDR outperforms anyone: we have no
measured efficacy data and no head-to-head evaluation (see
[pricing.md](pricing.md) §6 for the honesty constraints).

---

## Where AIDR sits

AIDR covers two surfaces with one control plane:

1. **AI coding agents at the tool-call boundary.** Connectors inside Claude Code,
   Cursor, VS Code, OpenClaw, OpenCode and Codex CLI evaluate commands, file writes and
   URLs before the host acts, plus an MCP Gateway for MCP tool results.
2. **People using AI chat products.** Browser Guard masks personal data and secrets
   before prompts, pastes and files reach ChatGPT, Gemini, Claude, Copilot, Perplexity,
   DeepSeek, Mistral and Grok, and restores them locally in the reply.

Most vendors below focus on one of these surfaces, or on LLM applications a company
builds itself.

## Vendor summaries

| Vendor | Public positioning (verify) | Overlap with AIDR |
| --- | --- | --- |
| **Lakera** | Runtime protection for LLM applications (Lakera Guard): prompt-injection and jailbreak detection, data-leakage checks, delivered as an API in front of the model. Check current ownership before citing. | Low to moderate. They protect LLM apps you build; AIDR's agent product protects the agent host's actions, and Browser Guard protects employee prompts. The MCP Gateway and SDK are where the overlap is. |
| **Protect AI** | AI/ML supply-chain and model security: model-file scanning, AI red-teaming and runtime LLM protection. Reported to be part of Palo Alto Networks; verify. | Low. Model scanning is a different problem. AIDR's AI Security Posture (CVE scanning of AI infrastructure components, MCP risk analysis, skill/plugin scanning) is adjacent. |
| **Prompt Security** | GenAI security across employee AI use (browser extension), homegrown apps and AI coding assistants. Reported to be part of SentinelOne; verify. | High on both surfaces: employee AI use and coding assistants. The most direct comparison. |
| **Harmonic Security** | Data protection for employee GenAI use: browser-based detection of sensitive data sent to AI tools, shadow-AI visibility, coaching users. | High for Browser Guard. No overlap with the agent connectors. |
| **Nightfall** | AI-native DLP across SaaS apps, browsers, endpoints and GenAI tools; detection of PII, PCI, secrets. | Moderate for Browser Guard (GenAI data leakage). Broader DLP scope than AIDR. |

## Talking points (true, and checkable)

- **Enforcement before the action.** Agent connectors run at the host's pre-tool hook, so
  a `deny` is returned before the host acts, when the host invokes the hook. Name the
  hook boundary for each host; do not claim more.
- **Reversible masking, restored locally.** The AI provider sees `[IBAN_1]`; the user
  sees the real value in the reply. The mapping never leaves the page.
- **Turkish data depth.** Checksum-validated T.C. kimlik and IBAN (mod-97), Turkish phone
  and address patterns, Turkish and English in-page messages.
- **Exact data match without sharing the data.** Administrators distribute HMAC
  fingerprints of sensitive records; the plaintext dataset is never shipped to browsers.
- **Deployment choice.** Free local mode, cloud, on-prem Docker Compose or Helm, and
  air-gapped with a signed offline license.
- **Rules as data.** 494 YAML threat rules the customer can read and extend, each mapped to
  OWASP LLM, OWASP Agentic and MITRE ATLAS with per-item coverage (including what is not
  covered).
- **Agent behaviour, not only malware.** Session toxic-flow chains, runaway and sabotage
  guardrails, and an AI asset register with four-eyes change control.
- **Counts-only telemetry.** Browser Guard reports per-type counts, not content.

## Where competitors are ahead (say so if asked)

- **Maturity and references.** The vendors above have paying customers, case studies
  and security teams. AIDR has none of these yet.
- **Assurance.** Established vendors typically hold third-party attestations. AIDR has no
  certification or independent assessment.
- **Breadth.** Full DLP suites cover SaaS, email and endpoints; AIDR does not.
- **Measured efficacy.** Some vendors publish benchmark or evaluation data. AIDR has not
  measured detection or false-positive rates.
- **Distribution.** Browser Guard is not yet in the browser stores, and AIDR has no
  publisher-signed release.

## Handling "why not just use X?"

1. Ask which surface they worry about: agents acting on machines, or people pasting
   data into AI chat. Many prospects need both, and AIDR covers both with one policy
   plane.
2. If they need on-prem or air-gapped deployment, or Turkish identifiers, lead with
   those.
3. If they need a certified vendor with references today, say plainly that AIDR cannot
   meet that yet.

Do not use competitor names or logos in public material without Legal review.
