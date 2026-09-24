# Singularity AIDR — Pricing Model (Proposal)

**Status:** Superseded internal pricing hypothesis for founder review. The proposed developer-seat unit and dollar amounts below conflict with the current connected-agent metering decision; neither proposal is an offer, approved licence, published tier, quote, or entitlement schedule. The [Commercial Release Manifest](../production-readiness/commercial-release-manifest-template.md) is the approval template, and COM-001 remains open.
**Last updated:** 2026-09-13
**Owner:** Founder (single-person company)

> **Read this first.** Every dollar figure below is a *proposal* based on public
> competitor list pricing, not on measured willingness-to-pay, because no
> customer has paid for this product yet. The "How I chose these numbers"
> section is the actual reasoning and is the part most likely to need revision
> after the first three real sales conversations. Sections marked **TODO** are
> deliberate placeholders — fill them in with real data, not estimates.

---

## 1. What we are pricing

Singularity AIDR is an **AI Agent Detection & Response (AIDR) layer**. It
intercepts what an AI coding agent is about to do — shell commands, file
writes, web fetches — and blocks dangerous actions *before* they execute. It
runs as a hook/plugin inside the agent (Claude Code, Cursor, VS Code, OpenClaw,
OpenCode, Codex CLI), built on a shared detection core: 351 YAML threat rules,
URL reputation checks, and a local decision engine returning `allow` / `deny` /
`ask`.

The structural fact that drives the entire pricing model:

**Local evaluation can run without an account or control-plane dependency;
"free forever" is a proposed commercial decision, not an approved licence.**
`ConfigSchema.mode` defaults to `"local"`, but enabled URL/file reputation
checks can make outbound requests. An offline pilot must disable optional
egress and verify traffic. "Managed" mode is a separately configured layer
that adds a control plane, team dashboard, entitlement/licensing, audit logs,
DLP, legal hold, and billing.

This is not a pricing gimmick — it is the product's actual architecture, and it
means we cannot (and should not) try to meter the detection engine. Anyone can
copy the artifacts. We therefore sell the things that genuinely require a
server and a relationship: **visibility, policy control, evidence, and
support.**

---

## 2. Units of measure

Getting the unit right matters more than the number, because the unit decides
what a customer expects to grow and what they think they're buying.

| Unit | Definition | Used for |
|---|---|---|
| **Protected developer (seat)** | One human developer whose agent hosts run AIDR and who is covered by team policy. | Primary paid unit. |
| **Agent instance** | One enrolled AIDR installation id (`iid`) connecting to the control plane. | Internal metering / abuse ceiling, *not* the headline price. |
| **Organization** | One tenant in the control plane. | Minimum commitment, feature gating. |

**Recommendation: price on protected developers, and use agent instances only
as a fair-use ceiling.** Rationale: our beachhead buyer thinks in headcount
("we have 12 engineers"), not in agent count. One developer may run Claude Code
*and* Cursor on two machines; billing them twice for the same human produces a
support argument on every invoice, and that argument is fatal for a founder
with no support team. Seat-based pricing is also the norm our comparables use
(see §5), so it needs no explanation.

---

## 3. The three tiers

### Tier 1 — Local (Free, forever)

**Proposed $0.** No account, signup, or email for local evaluation; licence and
distribution terms still require approval.

- Full local detection: all 351 shipped YAML threat rules, obfuscation and
  command-chain analysis, credential/supply-chain/persistence patterns.
- Full local decision engine: `allow` / `deny` / `ask` with confidence scoring.
- Write interception (file writes/edits) and URL analysis of tool calls.
- Local allowlist management and local JSONL audit log.
- One connector from an explicitly accepted host/OS/version scope.

**Why propose free, and why uncrippled:** the free tier would be the distribution strategy.
A local-first security tool is adopted bottom-up by an individual developer who
is curious and skeptical; a paywall before they see a block destroys that. It
is also honest — the engine genuinely runs offline, so any attempt to
license-check it locally would be both circumventable and a lie about how the
product works. We give away the enforcement engine to create the population
that later needs the dashboard.

**What the proposed free tier excludes:** anything requiring a server — team
dashboard, cross-fleet visibility, remote policy distribution, audit export,
DLP label management, SSO, legal hold, support SLA.

### Tier 2 — Team (self-serve)

**Proposal only; not purchasable or deployable today.** The managed control
plane, payment provider, distribution, support and commercial approvals remain
open.

**$20 per protected developer / month, billed annually ($240/developer/year).
Monthly billing at $24/developer/month.**

Minimum: **3 developers** (~$60/month, ~$720/year entry point).

Includes everything in Local, plus:

- Control-plane tenant: multi-tenant isolated team dashboard.
- Fleet visibility — which developers/agents are covered, what fired, on which
  hosts, and critically *which installed agents are not covered*.
- Central policy management with versioning, targeted rollout, and rollback.
- Audit log retention and export (JSONL/CSV).
- SSO (OIDC/SAML), MFA, RBAC.
- Offboarding workflow: revoke a departing employee's agent access.
- DLP and legal hold (subject to the caveats in §7).
- Email support, best-effort, no SLA.

**Why consider self-serve:** the founder cannot run a sales team. This tier would need to be
buyable with a credit card, priced below the threshold where a VP needs to
attend a procurement meeting, and installable without a call. $20/developer/
month sits under the "expense it on a personal card" line for most engineering
managers while still being real money at fleet scale.

### Tier 3 — Business (sales-assisted, founder-led)

**$45 per protected developer / month, billed annually ($540/developer/year).**
Minimum: **25 developers** (~$13,500/year).

Everything in Team, plus:

- Self-hosted / private-cloud deployment option.
- Signed policy and intel pack distribution for the customer's tenant.
- Durable SIEM export to Splunk / Sentinel / Elastic plus native RED and duration telemetry.
- Named support contact and a response-time commitment.
- Security questionnaire support and architecture review calls.
- Deployment assistance for rollout.

**Why a minimum and a higher price:** this tier is where the founder's own
calendar is the scarce resource. Onboarding, security review, and deployment
help are unbounded time sinks, so the minimum exists to ensure the deal is
worth the hours. Do not discount below the minimum — shrink the seat count
instead, or move the customer to Team.

> **Do not sell any proposed paid tier yet.** See §7 — both deployment paths,
> signed customer distribution, live billing and supported operations remain
> unaccepted. Tier names and prices here are hypotheses only.

---

## 4. Self-serve vs. sales-assisted

| | Local | Team | Business |
|---|---|---|---|
| Proposed motion | None (approved download) | Self-serve target | Founder-led target |
| Proposed purchase | — | Card only after live provider acceptance | Invoice / PO only after Finance approval |
| Typical buyer | Individual dev | Eng manager / Head of Eng | CISO / VP Eng |
| Sales cost we can afford | $0 | **$0** | A few hours |

**The single-founder constraint:** a deal that requires a demo, a security
review, a legal redline, and a procurement cycle costs more calendar time than
one person can sustain across many deals. So the model is deliberately shaped
so that **revenue can exist without any sales motion at all**: free tier →
individual developer adopts → their manager buys Team on a card. Only
exceptional deals escalate to Tier 3, and only once the founder has spare
capacity.

**The proposed annual-first Team term is a hypothesis.** Monthly self-serve billing creates
churn-handling and dunning work that a solo founder cannot absorb. Annual
upfront also generates the cash that funds the next year of building.

**Concession policy (founder's own guardrails):**
- One discount lever only: annual commitment. No "startup discount," no
  "first customer discount" — a discounted first price anchors every renewal.
- Never discount below $15/developer/month. Below that, support costs more than
  the seat earns.
- Nonprofits/OSS maintainers: free Team, capped at 10 seats, in exchange for a
  public reference **only if they choose to give one** (see §6 — never imply a
  customer relationship that doesn't exist).

---

## 5. How I chose these numbers

I anchored on **public list pricing for adjacent developer-security products**,
then adjusted for our specific situation. Verified figures (fetched
2026-09-13):

| Product | Free tier | Entry paid | Scale tier | Source |
|---|---|---|---|---|
| **Snyk** | $0, 5 projects | **$25/dev/mo** (Team) | **$1,260/dev/yr** (Ignite) | [snyk.io/plans](https://snyk.io/plans/) |
| **Semgrep** | $0 up to 10 contributors | **$30/contributor/mo** (Teams, Code or Supply Chain); Secrets $15 | Custom (Enterprise) | [semgrep.dev/pricing](https://semgrep.dev/pricing/) |
| **Endor Labs** | Free developer tools tier | Custom ("Book a Demo") | Custom | [endorlabs.com/pricing](https://www.endorlabs.com/pricing) |
| **Socket.dev** | Free for OSS | Not verifiable — pricing page is JS-rendered, no public figure obtainable | Custom | [socket.dev/pricing](https://socket.dev/pricing) — **could not verify** |
| **Pillar Security** | — | No public pricing (`/pricing` returns 404) | Custom, demo-gated | [pillar.security](https://www.pillar.security/) — **could not verify** |

**Verified against the live pages:** Snyk's $25/dev/mo Team and $1,260/dev/yr
Ignite, and Semgrep's $0/10-contributor free tier and $30/contributor/mo
Teams tier. **I could not verify public pricing for Socket.dev, Pillar
Security, Invariant Labs, or Endor Labs** — those pages are demo-gated or
JavaScript-rendered and expose no dollar figure to a plain fetch. I have
listed them as unverified rather than guessing. **TODO:** confirm Socket.dev,
Invariant Labs, and Pillar Security pricing from a sales conversation or a
rendered page before using them in any external comparison.

Reasoning from those anchors:

1. **$20 sits deliberately below Snyk's $25 and Semgrep's $30.** We are a
   single-founder product with no certifications, no auditors, and no
   reference customers. A buyer comparing us to a funded vendor with SOC 2 and
   a support org will not pay parity — and asking for it invites a comparison
   we lose. Pricing ~20–35% under the incumbents converts that gap into our
   actual advantage: it makes "just try it" easy.

2. **$20 is also under the informal approval threshold.** In most companies
   below ~50 engineers, a per-seat software cost around $20/month can be
   approved by an engineering manager without finance or procurement. That is
   the difference between a self-serve sale and a stalled deal.

3. **The $60/month Team floor is the honest minimum.** A 1-seat "team" has no
   team to give visibility into — the entire value of the paid tier is
   cross-developer. A floor of 3 seats keeps the tier coherent and avoids
   supporting single-seat tenants that generate cost without insight.

4. **$45 for Business reflects real marginal cost.** Self-hosted deployment,
   SIEM integration, security-review support, and a response-time commitment
   each consume founder hours on an ongoing basis. The 2.25× multiple over
   Team is the price of that time, and the 25-seat minimum is what makes those
   hours affordable.

5. **Free-forever local tier mirrors the comparables, not a marketing choice.**
   Snyk gives 5 projects free; Semgrep gives 10 contributors free. Free
   individual tiers are the established on-ramp in this category. Ours is
   uncrippled because the architecture makes local enforcement free to
   operate — near-zero marginal cost to us, and real adoption value.

6. **I did not price on agent instances, despite the existing
   `docs/pricing.md`.** That earlier draft proposed $2/additional agent/month
   metered by `iid`. I recommend superseding it: per-agent metering produces
   invoice disputes (one dev, two hosts), penalizes the exact multi-tool
   behavior we want to encourage, and yields ~$24/dev/year — an order of
   magnitude below what the comparables sustain, on a unit the buyer does not
   think in.

**Explicitly not assumed:** no efficacy statistics, no conversion-rate or
churn assumptions, no LTV/CAC model. Those require real customer data.
**TODO:** revisit all three prices after 10 paid Team tenants or the first
Business deal, whichever comes first.

---

## 6. Honesty constraints on what sales may claim

These are binding on any quote, deck, or email:

- **Do not claim any certification or audit.** No SOC 2, no ISO 27001, no
  penetration test, no third-party assessment has been performed. The repo's
  own `commercial-gate-receipts.json` records "No official code-signing
  certificate, notarization or publisher identity is held" and lists
  real-host acceptance as open. If a prospect requires SOC 2, the honest answer
  is that we do not have it and cannot provide a date.
- **Do not cite customer names, logos, testimonials, or case studies.** There
  are none. Every customer-reference field in our materials must stay empty
  until a real customer consents in writing.
- **Do not state efficacy numbers.** We have not measured detection rate,
  false-positive rate, or evasion resistance. "351 rules" is a countable fact
  about shipped content; "blocks 99% of attacks" is a fabrication. Never
  convert the former into the latter.
- **Do not describe the product as blanket "fail-open" or "fail-closed."**
  The real behavior is per-layer: detection internals skip a failing signal and
  log it; connector entry points fail closed; security controls fail closed.
- **Do not present reputation checks as verified protection.** Enabled
  URL/file/package lookups can make outbound requests by default; unavailable
  endpoints or stale evidence must not be described as "clean." Disclose the
  configured destinations and verify them for each candidate.

---

## 7. Current status and what blocks paid selling

Honest readiness, from the repo's own audit records
(`PRODUCTION_SALES_GAPS.json`, `FEATURE_INVENTORY.json`,
`commercial-gate-receipts.json`):

**Working today (verified locally on 2026-09-13 by running the built
artifacts):**

- `node scripts/verify-enforcement.mjs` passes the full matrix: destructive
  commands blocked and benign commands allowed, including under un-enrolled
  managed-mode and commercial-build configurations.
- The built Claude Code hook demonstrably blocks `curl … | bash` and `rm -rf /`
  (`deny`, with the real matched rule title), allows `ls -la` (empty output),
  and returns `ask` for credential-file reads.
- `aidr status` reports the real bundled rule count (351) and a passing
  detection self-test, and correctly refuses to claim host enforcement.

**Not ready — do not sell against these:**

| Gap | Impact on pricing |
|---|---|
| **No approved publisher signature** for a customer release | Do not offer the unsigned engineering bundle as a supported Windows or Team installation. Device warnings or blocks vary by policy. |
| **No accepted cloud production deployment.** A Free pilot exists, but it is not a signed, supported GA candidate. | **Blocks selling Team and Business today.** A live pilot does not establish paid-service acceptance. |
| **Signed release artifacts / trusted delivery not performed** | Blocks a supported customer installation in either deployment path. Private-registry acceptance remains open for a paid production offer. |
| **Real-host E2E acceptance open** for each connector; Codex can fail open if the hook process is unavailable | Limits what we can promise about coverage; disclose per-connector. |
| **No real-host side-effect acceptance** for advertised connectors | Cannot claim verified enforcement on a customer's specific OS/host combination. |
| **Reputation intel feed freshness/latency unvalidated** | Do not sell reputation as a working feature yet. |

**Net position: none of these tiers is approved for a supported customer
release.** Local component evaluation and design-partner conversations can be
discussed with explicit limitations, but customer installation requires the
[first-customer-ready gate](../production-readiness/first-customer-ready.md).
Team and Business additionally need a deployed, accepted control plane and
the applicable commercial gates; this draft cannot authorize invoicing.

**TODO (founder):**
1. Confirm Socket.dev / Invariant Labs / Pillar Security pricing from rendered
   pages or sales calls.
2. Decide the Windows code-signing budget and vendor.
3. Stand up the control plane, then re-price with real data.
4. Replace every figure in §3 once 10 paid tenants exist.

---

## 8. Open questions for the founder

1. **Should Team include a small free agent-instance allowance** to defuse the
   two-hosts-one-developer argument, or is "per developer, unlimited hosts"
   cleaner? (Recommendation: unlimited hosts per developer.)
2. **Is annual-only too aggressive** for the first 10 customers, given it
   front-loads trust we haven't earned? (Recommendation: hold annual-only, but
   allow the first three design partners a 90-day paid pilot credited to
   annual.)
3. **Does the free tier need a seat cap** (e.g. free below 5 developers, paid
   above)? A cap is enforceable only via the control plane, which local mode
   does not use — so a cap would be unenforceable and is probably not worth
   pretending otherwise.
