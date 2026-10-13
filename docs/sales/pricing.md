# Singularity AIDR — Editions and quote-based pricing (internal)

**INTERNAL — not customer-facing.** Prices are **not published**. Product-owner decision
(2026-09-25, "Fiyat lanse etmeyelim"): no price, currency or per-seat / per-month figure
appears on the dashboard, the public Editions page (`/pricing`), the README, product
docs, the catalog, the brochure or any other customer-facing material. Every paid
edition is sold by a written quote; customers request one from
**anil@singularityrd.com**. This page is the internal sales reference for edition names,
packaging and quoting. It is not a quote, licence or entitlement schedule. Edition terms
are recorded in the plan catalog (`public.plans`, seeded by
`supabase/migrations/20260925000010_plan_catalog.sql`, mirrored without prices on the
public Editions page and documented in [docs/pricing.md](../pricing.md)). Orders go
through an approved written quote and invoice; self-service checkout stays disabled
until the payment provider, entitlement reconciliation and Finance approval are accepted
(COM-001, COM-004). The
[Commercial Release Manifest](../production-readiness/commercial-release-manifest-template.md)
is the approval template.
**Last updated:** 2026-09-25
**Owner:** Founder

---

## 1. What we are pricing

Singularity AIDR has four product lines that share one control plane:

- **AIDR for AI coding agents** — connectors for Claude Code, OpenClaw, OpenCode and
  Codex CLI, Cursor and VS Code as a preview — no real-host acceptance evidence yet, plus the MCP Gateway, SDK and CLI. The local engine evaluates
  tool calls against 507 YAML threat rules and returns `allow` / `deny` / `ask`.
- **AIDR Browser Guard** — Chrome/Edge/Firefox extension that masks TR/EN personal data,
  secrets, custom terms and exact-data-match records before prompts reach AI chat
  products, and restores them locally in responses.
- **AIDR Privacy engine** — the TR/EN detection engine behind Browser Guard, with an
  optional native host and enterprise gateway.
- **AI Security Posture** — AI infrastructure vulnerability scanning (146 AI component
  fingerprints, 2,000+ CVE rules with severity and CVSS), MCP server risk analysis (14
  risk categories), skill and plugin scanning (T01–T09) and a dashboard posture view.

The structural fact behind the model: **local enforcement needs no server.** The
default mode is `local`; a fresh install evaluates every tool call on the device. We do
not meter the detection engine. We charge for what needs a server and a relationship:
**visibility, central policy, evidence, deployment options and support.**

## 2. Unit of measure

| Unit | Definition | Used for |
| --- | --- | --- |
| **Protected developer / user (seat)** | One person whose agent hosts or browser run AIDR under team policy | Primary paid unit |
| **Agent instance** | One enrolled installation id (`iid`) | Admission count (one per seat in the catalog) and the cloud trial limit, not the headline price |
| **Organization** | One tenant in the control plane | Minimums and feature gating |

One seat covers the same person's browser and one protected agent installation; the
catalog admits one `iid` per seat today. Pricing per person keeps the headline price on
a unit the buyer thinks in. Whether a seat should admit more than one agent host (for a
developer who runs Claude Code and Cursor on two machines) is an open question for
COM-001.

## 3. Plans

Edition terms match the plan catalog. Paid editions are quoted per developer seat, and
each seat admits one protected agent installation (`iid`); the control plane enforces
the admitted count. This table is safe to share with a customer; the internal quote
reference in §4 is not.

| | **Free** | **Team** | **Business** | **Enterprise** |
| --- | --- | --- | --- | --- |
| Price | Free | By quote | By quote | By quote |
| Minimum | 1 protected agent | 3 developers | 25 developers | By agreement |
| Deployment | Local mode; cloud dashboard | Cloud | Cloud or on-prem (Docker Compose) | On-prem (Docker Compose or Helm) or air-gapped |
| Event retention | 7 days | 90 days | 365 days | Contractual |
| Catalog features | Local detection, dashboard | + Browser Privacy Guard, Entra ID SSO | + SIEM export, SCIM, AI security posture | + air-gapped deployment, dedicated support |
| Motion | Download | Quote now; self-serve once checkout is accepted | Founder-led | Founder-led |

### Free — one protected agent

- Agent connectors with the full local engine: 507 threat rules, obfuscation and
  command-chain analysis, package and plugin checks, local allowlist and JSONL audit log.
  Local detection needs no account, signup or email.
- Browser Guard with local settings: masking and local restore on the supported AI
  sites.
- The Free catalog plan adds a cloud dashboard for one protected agent with 7-day event
  retention. No central policy, no team fleet view, no support commitment.

### Team

Everything in Free, plus:

- Cloud control plane tenant with row-level security, dashboard and device enrollment.
- Fleet visibility: which people and agents are covered, what fired, and which
  installed agents are **not** covered.
- Central policy for agent connectors and Browser Guard managed policy (custom terms,
  modes, sites).
- Counts-only Browser Guard telemetry and redacted agent verdict events; 90-day event
  retention.
- Audit export (JSONL/CSV), SSO (Microsoft Entra ID, OIDC/SAML), MFA, roles, offboarding.
- Email support in business hours, no SLA.

### Business

Everything in Team, plus:

- On-prem control plane on Docker Compose; 365-day event retention.
- Exact-data-match datasets for Browser Guard, tenant DLP detector policy.
- Signed policy and intel packs, SIEM delivery (Splunk / Sentinel / Elastic formats).
- SCIM provisioning and IdP group mapping.
- AI Security Posture: infrastructure CVE scans, MCP risk analysis, skill/plugin scanning and the dashboard posture view.
- MCP Gateway deployment assistance.
- Named support contact with published response targets; security questionnaire and
  architecture review support.

### Enterprise

Everything in Business, plus:

- Kubernetes (Helm) and air-gapped installation with a signed offline license and
  signed offline rule/intel packs.
- Contractual event retention and dedicated support.
- Optional AIDR Privacy enterprise gateway integration. The native host for NER/OCR ships
  without a model and is not part of the first-release scope; it is not sold until model
  acceptance closes.
- Custom terms, data-processing agreement and support schedule.

**Cloud trial:** 14 days, one agent. Paid cloud plans have no trial cap.

**Lapsed subscription:** local enforcement keeps working; cloud features stop. Turning
off detection because an invoice is late would be a safety regression.

## 4. Internal quote reference (do not publish)

Quotes start from the internal per-seat reference below. It is **not** a published
price: never put it on a website, deck, brochure, catalog, public page or email
signature, and never describe it to a customer as a list price. The per-seat
reference is held in the `public.plans` seed (server-side only) and in the Stripe
prices named by `AIDR_STRIPE_PRICE_MAP`; a card checkout shows its amount only on the
Stripe page. Adjusting a quote does not change this reference.

| Edition | Internal annual reference | Monthly option |
| --- | --- | --- |
| Team | USD 20 per developer / month, billed annually | USD 24 per developer / month |
| Business | USD 45 per developer / month, billed annually | Not offered |
| Enterprise | Scoped per deployment | Not offered |

The reference was anchored on public list pricing for adjacent developer-security
products (fetched 2026-09-13):

| Product | Free tier | Entry paid | Scale tier | Source |
| --- | --- | --- | --- | --- |
| **Snyk** | $0, 5 projects | **$25/dev/mo** (Team) | **$1,260/dev/yr** (Ignite) | [snyk.io/plans](https://snyk.io/plans/) |
| **Semgrep** | $0 up to 10 contributors | **$30/contributor/mo** (Teams) | Custom | [semgrep.dev/pricing](https://semgrep.dev/pricing/) |
| **Endor Labs** | Free developer tools | Custom | Custom | [endorlabs.com/pricing](https://www.endorlabs.com/pricing) |
| **Socket.dev** | Free for OSS | Not verifiable | Custom | [socket.dev/pricing](https://socket.dev/pricing) |

1. **$20 sits below Snyk's $25 and Semgrep's $30.** We have no certifications and no
   reference customers; buyers will not pay parity with a funded vendor.
2. **$20 is under the informal approval threshold** in most companies below ~50
   engineers, so an engineering manager can approve it without procurement.
3. **The 3-seat Team minimum** keeps the tier coherent: a one-person "team" has no
   cross-developer visibility to buy.
4. **$45 for Business** pays for self-hosting, SIEM, security-review and response-time
   work. The 25-seat minimum makes those hours affordable.
5. **Free local mode** mirrors the category (Snyk and Semgrep both have free tiers) and
   matches the architecture: local enforcement costs us nothing to run.
6. **Browser Guard is priced on the same seat.** It serves the same buyer (security or
   engineering leadership) and the same control plane. A separate browser-only SKU is an
   open question (§7).

No efficacy statistics, conversion rates, churn or LTV/CAC are assumed.

## 5. Concession policy

- One discount lever: annual commitment. No "first customer" discount; it anchors every
  renewal.
- Never below $15 per developer per month.
- Nonprofits and OSS maintainers: free Team up to 10 seats. A public reference only if
  they choose to give one.

## 6. Honesty constraints on what sales may claim

Binding on any quote, deck or email:

- **No published prices.** Prices go only into a written quote addressed to one
  customer. Public copy says "pricing by quote" and points to anil@singularityrd.com.
- **No certification or audit claims.** No SOC 2, ISO 27001, penetration test or
  third-party assessment has been completed. Say so plainly and give no date.
- **No customer names, logos, testimonials or case studies.** There are none.
- **No efficacy numbers.** "507 rules" is a countable fact; "blocks 99% of attacks" is a
  fabrication. Browser Guard masking accuracy has not been measured on customer data.
- **Failure behaviour is per layer**, not blanket "fail-open" or "fail-closed": connector
  entry points and Browser Guard's content script fail closed, detection internals skip
  a failing signal visibly, security controls fail closed, and the host decides what
  happens when a hook is disabled, untrusted or killed.
- **Reputation checks are optional** and need a configured endpoint; an unavailable
  check is never "clean".
- **Compliance wording:** "designed to support KVKK/GDPR obligations", never
  "certified" or "compliant".

## 7. What blocks paid selling today

The release decision is **NO-GO** ([first-customer-ready.md](../production-readiness/first-customer-ready.md)).
Before any plan is sold: a signed customer candidate, real-host acceptance for each
offered connector and browser, an accepted cloud and on-prem deployment, legal terms
and DPA (COM-002/003), Finance approval of the internal quote reference (COM-001), live billing and
entitlement (COM-004), and an independent security review (SEC-EXT-001).

Open questions for the founder:

1. Separate Browser Guard-only seat for non-developer users (support, finance, HR)?
2. Annual-only Team for the first ten customers, or a 90-day paid pilot credited to
   annual?
3. Quote currency: USD only at launch, or TRY for Turkish customers?
