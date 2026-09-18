# Singularity AIDR

### AI Agent Detection & Response — inline enforcement for AI coding agents

---

## The problem

AI coding agents execute shell commands, write files, and fetch URLs. That is
what they are for. Claude Code, Cursor, VS Code, Codex CLI, OpenCode, OpenClaw —
all of them act on your machine, with your credentials, on instructions the
model derived from content it read.

That content is attacker-controllable. A README, a web page, a dependency's
docs, a tool result — any of it can steer the agent. The agent is not
compromised; it is *obeying*. And the only thing between that instruction and
your filesystem is whether a human clicked "approve" fast enough.

**Existing tooling does not cover this gap:**

- **SAST/SCA (Snyk, Semgrep, Dependabot)** analyze code you already wrote.
  They are not in the execution path.
- **EDR** watches the operating system, after the fact, with no understanding
  of agent intent.
- **Model guardrails** live in the model provider's boundary, not on your
  endpoint, and do not see the tool call.

Nothing asks *"should this specific command be allowed to run?"* before it runs.

---

## What Singularity AIDR does

AIDR is a **hook that sits inside the agent**. It intercepts the tool call —
the shell command, the file write, the URL fetch — evaluates it against a local
detection engine, and returns `allow`, `deny`, or `ask` **before execution**.

- A denied call **never runs**. It is not logged after the fact and not
  sandboxed retroactively.
- Every verdict carries the **matched rule and the artifact** that triggered it,
  so the developer sees exactly what was blocked and why.
- `ask` is a **block pending out-of-band human approval**. There is deliberately
  no tool the agent can call to approve its own block — otherwise a
  prompt-injected agent would simply approve itself.

---

## How it works

```
Agent is about to call a tool
        │
        ▼
  PreToolUse hook  ──▶  extract artifacts (command / path / URL / package)
        │                        │
        │                        ▼
        │              local decision engine
        │              ├─ 351 YAML threat rules
        │              ├─ obfuscation & command-chain analysis
        │              ├─ URL / package indicators (when configured)
        │              └─ allowlist + verdict cache
        │                        │
        ▼                        ▼
  host enforces  ◀──  allow | deny | ask  (+ matched rule, artifact, severity)
```

**Local-first by design.** The default mode is `local`: every tool call is
evaluated with **no account and no network access**. AIDR does not send your
source code or file contents. Depending on configuration it may send
privacy-preserving indicators (for example URL or package hashes) to
first-party reputation endpoints.

**One engine, six hosts.** Claude Code, Cursor, VS Code, OpenClaw, OpenCode,
and Codex CLI all consume the same detection core. Teams with mixed tooling do
not need multiple security products.

**Failure behavior is per-layer, and we state it precisely rather than calling
the product simply "fail-open" or "fail-closed":**

- *Connector entry points* fail **closed** — an internal error returns a deny
  rather than silently allowing the call.
- *Detection internals* skip a failing signal, log it, and continue. A skipped
  signal is **never** reported to the user as a clean result.
- *Security controls* (auth, tenant isolation, approvals) fail closed.

---

## Who it's for

Engineering-led software companies with **15–80 developers** where AI coding
agents are already in daily use, that have a security-minded engineering leader
but are too small to justify enterprise agent-security tooling.

- **The user** is a developer who wants to move fast and not be nagged.
- **The buyer** is their Head of Engineering, who wants to know what every
  agent on the team is doing — and, critically, **which installed agents are
  not covered**.

Typical trigger: an agent did something nobody expected, and there was no
control in place to stop it.

---

## What makes it different

| | AIDR | SAST/SCA | EDR |
|---|---|---|---|
| In the agent's execution path | **Yes** | No | No |
| Blocks *before* the action runs | **Yes** | N/A | Sometimes, after |
| Understands agent tool semantics | **Yes** | No | No |
| Works with no account or network | **Yes** | No | Varies |
| Same engine across agent hosts | **Yes** (6 hosts) | N/A | N/A |

The honest differentiator is **position**, not raw detection volume: being
inside the agent and in front of the call is a place no scanner occupies.

---

## Current status

**Read this before evaluating.** This is a one-person product and these are the
real limitations:

**Working today**

- Local detection engine with 351 shipped YAML threat rules across 23 files.
- Connectors for Claude Code, Cursor, VS Code, OpenClaw, OpenCode and Codex CLI.
- Verified enforcement: the repo's `verify-enforcement.mjs` suite passes all
  72 cases — destructive commands blocked (`curl … | bash`, reverse shells,
  `rm -rf /`, download-and-execute, credential writes) and benign commands
  allowed, across default, managed-mode and commercial build configurations.
- `aidr setup` self-tests detection and **refuses to report success** if zero
  rules load or nothing matches.
- Local audit log, allowlist management, verdict caching.

**Not ready**

- **No certifications.** No SOC 2, no ISO 27001, no penetration test, no
  third-party assessment. None in progress.
- **No customers.** No case studies, no testimonials, no references. AIDR has
  not been deployed in production at any organization.
- **No verified efficacy measurement.** We have not measured detection rate,
  false-positive rate, or evasion resistance on any real workload. We quote
  rule counts because they are countable; we do not quote block percentages.
- **Windows builds are unsigned.** Expect a SmartScreen warning on install.
- **The team control plane is not deployed.** Team dashboard, remote policy
  distribution, audit export, DLP, legal hold and billing are implemented but
  require a live cloud deployment that does not yet exist. **Local enforcement
  does not depend on it.**
- **Real-host acceptance is open.** Correct behavior is verified against built
  artifacts locally; it has not been independently accepted on every supported
  host/OS/version combination.
- **Known coverage edges.** Coverage depends on the host's hook system. If a
  hook is disabled, unavailable, or its process is killed, the action proceeds —
  Codex in particular fails open when an untrusted or crashed hook is involved.
  This is a **strong guardrail, not endpoint isolation.** Reputation checks
  require configured first-party feeds; with none deployed those checks are
  inert and are reported as such, not as "clean."

---

## Getting started

**Local enforcement is free, requires no account, and needs no network.**

```bash
# Claude Code
/plugin marketplace add https://github.com/singularityrd/aidr.git
/plugin install aidr@aidr

# Then verify your installation
aidr status
```

`aidr status` reports the real bundled rule count, runs a detection self-test,
and tells you which connectors are actually installed — and explicitly
distinguishes *registered* from *enforced*.

**Try to break it.** That is a more useful evaluation than a sales call, and
the tool is built to be honest even when the news is bad.

**For a deeper look:** the architecture, threat-rule format, and full
limitations are documented in the repository. Security reviews are welcome;
we will tell you plainly what we cannot yet provide.

---

*Singularity AIDR · AI Agent Detection & Response*
*This document contains no customer names, certifications, or efficacy claims,
because none exist. It will be updated when they do.*
