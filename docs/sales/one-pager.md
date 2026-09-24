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

Different security layers observe different parts of this workflow:

- **SAST/SCA (Snyk, Semgrep, Dependabot)** analyze code you already wrote.
  They are not in the execution path.
- **EDR** observes operating-system behavior; its timing and agent context
  depend on the product and configuration.
- **Model guardrails** operate at a different boundary and may not observe an
  endpoint tool action.

An agent-host hook can ask *"should this observed tool call be allowed?"* before the host acts, if that host invokes and honors the hook.

---

## What Singularity AIDR does

AIDR provides connectors that pass observed tool calls to a shared local
decision engine, which returns `allow`, `deny`, or `ask`. Enforcement depends
on the host invoking and honoring the connector at its documented boundary.

- A pre-action `deny` requests that the host prevent the observed call. A
  returned verdict alone is not proof that a side effect was prevented.
- A matched threat verdict can name the rule and inspected artifact; not every
  `allow` or unavailable signal has a matched rule.
- `ask` requests host-managed confirmation where the connector supports it;
  it is not an independently verified human-approval workflow.

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

**Local evaluation is available without an account.** The default mode is
`local`. URL, file, and package reputation checks are disabled by default;
an operator can enable them with configured endpoints. When enabled, requests
can include URLs, package names/versions, and metadata. This is not a blanket
no-egress or no-content promise: verify actual outbound traffic before
describing a particular installation as offline. See the
[privacy inventory](../privacy.md).

**One core, six implemented connectors.** Claude Code, Cursor, VS Code,
OpenClaw, OpenCode, and Codex CLI have connector code. Supported host/OS/version
rows, side-effect prevention and failure behavior remain subject to real-host
acceptance; these are not six approved production integrations.

**Failure behavior is per-layer, and we state it precisely rather than calling
the product simply "fail-open" or "fail-closed":**

- *Invoked connector entry points* return a deny on internal error. A host that
  never invokes the connector, or drops a crashed hook, can still proceed.
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
| Can receive an observed agent tool request | **Yes, when the host invokes its connector** | Product-dependent | Product-dependent |
| Can request a pre-action deny | **Yes, for documented pre-action hooks** | Product-dependent | Product-dependent |
| Shared local evaluation core | **Yes** (six implemented connectors; host acceptance open) | Product-dependent | Product-dependent |

The proposed differentiator is **position**, not raw detection volume: a
connector can observe selected tool requests at agent hook boundaries. Actual
coverage and side-effect prevention depend on host invocation and require the
per-host acceptance described below.

---

## Current status

**Read this before evaluating.** This is a one-person product and these are the
real limitations:

**Working today**

- Local detection engine with 351 shipped YAML threat rules across 23 files.
- Connector implementations for Claude Code, Cursor, VS Code, OpenClaw, OpenCode and Codex CLI; no six-host production acceptance claim.
- The repo's `verify-enforcement.mjs` defines 72 destructive/benign command
  checks across default, managed-mode and commercial configurations. It needs a
  release bundle to run; no signed candidate-bound or real-host acceptance
  record is held yet.
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
- **Publisher-authenticated release is not available.** The current portable engineering envelope has no approved publisher signature; Windows warnings or policy blocks depend on the customer device.
- **The team control plane is not production-accepted.** A pilot deployment and
  disposable-stack tests do not establish a signed cloud GA release or field
  acceptance for dashboard, remote policy, audit export, DLP, legal hold, or
  billing. **Local enforcement does not depend on it.**
- **Real-host acceptance is open.** Correct behavior is verified against built
  artifacts locally; it has not been independently accepted on every supported
  host/OS/version combination.
- **Known coverage edges.** Coverage depends on the host's hook system. If a
  hook is disabled, unavailable, or its process is killed, the action proceeds —
  Codex in particular fails open when an untrusted or crashed hook is involved.
  This is a **strong guardrail, not endpoint isolation.** Reputation checks
  require reachable configured feeds; unavailable checks must not be described
  as "clean." Enabled lookups may still attempt outbound requests.

---

## Getting started

**Local evaluation needs no account; a free-forever commercial licence and an
offline installation are not yet approved promises.** A controlled evaluation
must use an agreed scope and configuration.

No approved publisher-signed customer installer is available yet. Do not
send a source-checkout or unsigned engineering bundle as a supported release.
On a controlled internal candidate, `aidr status` can report the bundled rule
count and detection self-test, but registration is not host enforcement proof.

Use the [first-customer evaluation gate](../production-readiness/first-customer-ready.md)
and [controlled demo runbook](../production-readiness/controlled-demo-runbook.md)
before offering an installation or live trial. The current decision is NO-GO.

**For a deeper look:** the architecture, threat-rule format, and full
limitations are documented in the repository. Security reviews are welcome;
we will tell you plainly what we cannot yet provide.

---

*Singularity AIDR · AI Agent Detection & Response*
*This document contains no customer names, certifications, or efficacy claims,
because none exist. It will be updated when they do.*
