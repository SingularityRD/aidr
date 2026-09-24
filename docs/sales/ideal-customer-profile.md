# Ideal Customer Profile (Beachhead)

> **Historical snapshot — not current sales qualification (archived 2026-09-23).**
> This 2026-09-13 small-team hypothesis predates the BMC enterprise/on-prem
> objective and the cloud pilot. Its enterprise/defense exclusions, free-tier
> language and pricing assumptions are not current policy or a readiness
> decision. A BMC conversation may be limitations-first; a supported PoC or
> sale still needs the [current buyer handoff](../production-readiness/first-customer-buyer-handoff-2026-09-23.md)
> and its open technical, security, legal and commercial gates. This snapshot
> does not assert certification or defense-sector acceptance.

**Status:** Superseded working hypothesis. Zero customers validated it. Every
claim about buyer behavior below was reasoning, not a won-deal finding.
**Snapshot date:** 2026-09-13
**Owner:** Founder

> **The honest framing:** a one-person company cannot pursue a market. It can
> pursue roughly 50 named accounts and hope to close 3. This document exists to
> make those 50 obvious and to make everyone else a deliberate "no" for now.

---

## 1. The beachhead, in one sentence

**Engineering-led software companies with 15–80 developers where AI coding
agents are already in daily use, that have a security-minded engineering leader
but are too small to justify enterprise agent-security tooling.**

The whole thesis: these companies have **already** accepted the risk of letting
agents run shell commands and write files, they have **already** felt a moment
of "wait, it can do *that*?", and they have **no product** that governs it.
They are past the "should we use AI agents" debate and stuck on "how do we let
people use them without getting burned."

---

## 2. Firmographics

| Dimension | Target | Why this range |
|---|---|---|
| **Headcount (eng)** | **15–80 developers** | Below ~15 there's rarely budget or a security owner. Above ~80 you're competing with a funded vendor's enterprise motion, procurement, and a security questionnaire we cannot yet pass. |
| **Total company size** | 20–300 employees | Big enough to have a budget line, small enough that the Head of Eng answers email. |
| **Industry** | B2B SaaS, fintech/payments, healthtech, developer tools, AI/ML products, e-commerce infrastructure | All ship software continuously, all have real secrets and customer data in reach of a shell command, and all have compliance pressure that makes "we govern our agents" a useful internal story. |
| **Geography** | English-speaking, US/UK/EU first | Founder sells in English; support hours are one person's. |
| **Stage** | Seed → Series B | Post product-market-fit, pre-formal-security-org. Budget exists but isn't locked behind a committee. |
| **Regulatory exposure** | Light-to-moderate: SOC 2 aspirations, GDPR, PCI-adjacent | Enough to care about evidence and audit trails; not so much that we fail an enterprise review we can't pass. |

**Sweet spot: ~40 developers, Series A, B2B SaaS, shipping daily, has a
"Head of Engineering" or "VP Engineering" who also owns security because
nobody else does.**

---

## 3. Techno-graphic signals (the strongest qualifiers)

These are observable before you ever talk to the company. Prioritize accounts
showing **three or more**:

- **AI coding agents in daily use** — Claude Code, Cursor, VS Code with Copilot
  or Claude, Codex CLI, OpenCode, OpenClaw. Look for these in job posts,
  engineering blogs, conference talks, and public dotfiles/configs.
- **Multiple agents, multiple hosts** — evidence that different developers
  picked different tools and nobody governs the mix. This is our wedge: we
  cover six hosts with one engine.
- **A real secrets surface** — `.env` files, cloud credentials, CI/CD tokens,
  production database access reachable from a developer machine.
- **Fast deploy cadence** — daily or on-merge deploys. Speed is what makes
  humans rubber-stamp agent actions, which is exactly the failure mode we stop.
- **Production access from dev machines** — engineers with credentials that
  matter. Without this, the blast radius story doesn't land.
- **Modern stack** — TypeScript/Node, Python, Go; GitHub/GitLab; containers.
  Our threat rules and connector coverage are strongest here.
- **Existing security spend that is *not* agent-specific** — they already pay
  for Snyk/Semgrep/Dependabot, so the "add one more security line item"
  conversation has a precedent and a budget category.
- **A named security owner** — even if it's a staff engineer with 20% time.
  No owner means no buyer.

---

## 4. The trigger event (why they buy *now*)

Nobody buys agent security on a Tuesday for no reason. Sell into a trigger.
Ranked by how reliably they convert:

1. **A near-miss or incident.** An agent deleted something, force-pushed,
   rewrote config, exfiltrated a file, or ran a destructive command that a
   human caught. This is the strongest trigger and it is common.
2. **A prompt-injection scare.** Someone read about (or experienced) an agent
   being steered by content it fetched — a malicious README, a poisoned web
   page, a compromised dependency. The "the agent did what the *page* said"
   realization.
3. **Onboarding agents broadly.** They just told 40 engineers "use Claude Code"
   and someone asked "what's stopping it from `rm -rf`ing prod?" and there was
   no answer.
4. **A customer security questionnaire.** An enterprise prospect asked "how do
   you govern AI agents in your SDLC?" and they had nothing.
5. **Compliance/audit prep.** SOC 2 or a similar audit is coming and they need
   to show control over automated change.
6. **A departing employee.** Offboarding raised the question of what agent
   access still exists on their machine.

**Listen for these phrases:** "we told everyone to use Cursor and…", "one of
our engineers accidentally…", "it ran a command I didn't expect", "our
security person asked about this", "we have no idea what the agents are
doing."

**If none of these have happened, they are not ready.** Log them and revisit
in 90 days — do not try to manufacture urgency.

---

## 5. Buyer vs. user vs. budget

| Role | Who | What they care about | What to lead with |
|---|---|---|---|
| **User / champion** | Individual developer using Claude Code or Cursor | Not being slowed down; not having a tool that cries wolf; seeing what the agent is about to do | The block is instant, local, no account, no latency, and explainable — "it tells you *which rule* fired" |
| **Buyer (Team tier)** | Head of Engineering / VP Engineering / Eng Manager | Speed without an incident; not becoming the person who has to explain a breach; coverage across a team using mixed tools | Fleet visibility — *especially* "which installed agents are not covered" |
| **Buyer (Business tier)** | CISO / Head of Security / VP Eng at a larger account | Evidence, policy control, audit trail, offboarding, answering the board | Policy distribution, audit export, DLP, offboarding workflows, SIEM |
| **Blocker / influencer** | The security-minded staff engineer | Whether it actually works and whether it's honest about limits | Will read the limitations section and *trust you more* for it |
| **Budget authority** | Team: eng manager's tooling budget (card, no PO). Business: CISO/VP Eng with annual budget | — | Keep Team under the approval threshold; see `pricing.md` §5 |

**Critical asymmetry:** the **user is a developer, the buyer is their manager.**
Adoption must be bottom-up (free tier, individual install) and monetization
top-down (manager buys Team when they want fleet visibility). Never pitch the
dashboard to a developer; never pitch CLI speed to a CISO.

---

## 6. Anti-personas — who NOT to sell to yet

Each of these will consume founder time and not close. The reason matters more
than the exclusion.

| Anti-persona | Why not yet |
|---|---|
| **Enterprise (500+ employees)** | Requires SOC 2, pen-test reports, a security questionnaire, legal redlines, and a sales team. We have none of these — `commercial-gate-receipts.json` records no certification, no signing certificate, no real-host acceptance. Pursuing them now burns the founder's only resource for zero revenue. |
| **Regulated / FedRAMP / gov / defense / healthcare-with-PHI** | Requires certifications and attestations we cannot produce. A conversation here ends in "come back with SOC 2." |
| **Pure-security-tooling buyers looking for a scanner** | We are not a scanner and are not a SAST/SCA replacement. If they want to compare rule counts and CVE databases, we lose and waste the call. |
| **Companies with no AI coding agent usage** | There is no problem to solve. Educating the market is a funded company's job, not a solo founder's. |
| **Individual hobbyist developers / students** | They will use the free tier (good!) but will never pay. Do not spend sales time; optimize the docs and install path for them instead. |
| **Enterprises demanding on-prem / air-gapped today** | Self-hosted deployment exists but has no real-host acceptance and no signed artifacts. Selling it now creates a support obligation we cannot meet. |
| **Companies whose blocker is "we just need a checkbox for the audit"** | They want a PDF, not enforcement. We cannot provide attestation, and pretending otherwise is the exact dishonesty this package forbids. |
| **Very early startups (<10 devs, pre-seed)** | Not enough seats to matter; a $60/month floor is real money to them; churn risk is high. Let them use free. |
| **Anyone requiring 24/7 support or an SLA today** | One person. `pricing.md` §7 lists this as a gating gap. |
| **Windows-heavy fleets right now** | Builds are unsigned, so SmartScreen will warn on install. Sellable with disclosure, but expect friction and support load — treat as a second-wave segment until signing is in place. |

---

## 7. How to find these companies

### 7.1 Job-posting signals (highest-yield, lowest-cost)

Search job boards (Greenhouse, Ashby, Lever, LinkedIn, Wellfound, HN Who's
Hiring) for postings containing:

- **"Claude Code"**, **"Cursor"**, **"AI coding agents"**, **"agentic
  development"**, **"AI-native engineering"** — a company listing these in a
  job description has standardized on them and has an owner who cares.
- **"AI Developer Experience"**, **"Developer Productivity Engineer"**,
  **"Platform Engineer, AI tooling"** — these roles *are* our buyer or report
  to them.
- **"Head of Engineering" + "security"** in the same posting at a 20–300 person
  company — that's the person who owns this and has no tooling.
- **"SOC 2"** in a benefits/requirements block — they're in audit prep (trigger
  #5).

### 7.2 Community and social listening

- **r/ClaudeAI, r/ChatGPTCoding, r/cursor, r/ExperiencedDevs** — look for
  threads about agents doing destructive things, prompt injection, or "is it
  safe to let Claude Code run commands." The people in those threads are
  pre-qualified by trigger #1/#2.
- **Hacker News** — search past threads for "Claude Code", "Cursor", "agent
  security", "prompt injection". Commenters describing their own setup are
  leads.
- **Local AI/eng meetups and Discord/Slack communities** for the above tools.
  Be a helpful participant first; mention the free local tier only when
  directly relevant.
- **GitHub** — search for public dotfiles/configs referencing these agents
  (`claude code` in code search), and for internal-tooling repos at target-size
  companies. Also valuable: watch stars/forks on agent-security and
  agent-framework repos.
- **Conference talks** — anyone presenting "how we rolled out AI agents at
  <company>" is a lead with a named owner.

### 7.3 Technographic discovery

- **BuiltWith / Wappalyzer-style lookups** on target companies to confirm stack
  fit (modern JS/Python, cloud infra).
- **Public engineering blogs** — "we use Cursor/Claude Code at <company>"
  posts are explicit, self-declared signals.
- **Crunchbase / LinkedIn** to filter for 20–300 employees, Seed–Series B,
  B2B SaaS/fintech/healthtech, US/UK/EU.

### 7.4 Inbound (build this in parallel)

- **The free local tier is the top of funnel.** Ship it with excellent docs.
  Every install is a signal, and every `aidr status` output is a conversation
  starter. (Note: this only works once telemetry/enrollment exists — the free
  local tier is *intentionally* anonymous, so inbound must come from the docs,
  the repo, and community presence, not from tracking users.)
- **An honest "how it works / current limitations" page.** In this category,
  publishing real limitations is a differentiator and attracts exactly the
  staff-engineer influencer described in §5.

### 7.5 Qualification checklist (use before every call)

Score 1 point each; **6+ is a real conversation, under 4 is a polite no:**

- [ ] 15–80 developers
- [ ] AI coding agents in daily use, named specifically
- [ ] More than one agent/host in use
- [ ] Real secrets or production access reachable from dev machines
- [ ] A named security owner or eng leader who owns it
- [ ] One of the §4 triggers has actually happened
- [ ] Existing per-seat dev-security spend (Snyk/Semgrep/etc.)
- [ ] US/UK/EU, English-speaking
- [ ] Not gated on a certification we don't have

---

## 8. What I'd validate in the first 10 conversations

This ICP is a hypothesis. Before writing more GTM material, test:

1. **Is "too small for enterprise tooling" real, or do they just not care?**
   If they don't care, the problem is education, not price.
2. **Does the buyer actually want fleet visibility,** or only the local block?
   If only the local block, the paid tier has no value and pricing needs a
   rethink.
3. **Per-developer vs. per-organization** — do they push back on seat
   counting? (Genuinely unknown; see `pricing.md` §8.)
4. **Does the mixed-host story sell** (one engine, six hosts) or confuse?
5. **How much does the missing SOC 2 actually block** at 20–80 developers?
   This determines whether we can sell at all before certification.

**TODO:** replace this section with real findings after 10 discovery calls, and
revise §2–§5 accordingly.
