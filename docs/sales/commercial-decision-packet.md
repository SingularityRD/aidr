# Commercial decision packet

**Purpose:** every open commercial gate in
`docs/production-readiness/commercial-go-evidence-registry.json` needs a value
that a person decides, not a value a tool can derive. This packet lists those
decisions with the options, the consequence of each, and a recommendation, so
one founder can work through them in an afternoon instead of discovering them
one at a time during a sales call.

**Status:** no decision below has been made. Nothing in this file is a commitment,
a price, or an approval. Every "Recommendation" is a proposal to accept or
reject. Where a value is genuinely unknown, it says so.

**How to use it:** work top to bottom. The first four blocks (A–D) are blocking:
without them the product cannot be invoiced at all. Block E is blocking only for
large customers. Block F is what a first design partner will ask you.

---

## Block A — What you are selling, exactly

The single most expensive ambiguity in this product is that the free tier is
genuinely useful. That is deliberate and should stay. But it means "what does a
customer pay for" must be answered in one sentence before any price is quoted.

| # | Decision | Options | Recommendation |
|---|---|---|---|
| A1 | Is the local detection engine permanently free? | (a) Free forever, uncrippled. (b) Free with a seat cap. (c) Time-limited trial. | **(a).** The architecture makes local enforcement zero-marginal-cost, and any local licence check is both trivially circumventable and a false claim about how the product works. |
| A2 | What exactly does a paid seat unlock? | (a) Team dashboard + remote policy + audit export. (b) Everything in (a) plus SSO/MFA/RBAC, DLP, legal hold, offboarding. (c) Support only. | **(a) for Team, (b) for Business.** These are the features that genuinely require a server, which is the honest dividing line. |
| A3 | Is self-service checkout offered at launch? | (a) Yes, card, no sales contact. (b) No, invoice/quote only. | **(a).** A one-person company cannot afford a sales-assisted motion for small deals, and the registry already excludes self-service from the *enterprise* scope only. |
| A4 | Minimum seat count for the paid tier | (a) 1. (b) 3. (c) 10. | **(b) three.** A one-seat "team" buys no cross-developer value and will churn; three is the smallest number where the dashboard shows something the buyer could not see before. |

**Blocking gate:** COM-001 (Commercial Release Manifest).

---

## Block B — Price, currency, tax, term

`docs/sales/pricing.md` proposes $20/developer/month annual and $45 for Business,
anchored below Snyk and Semgrep. Those numbers are a proposal with cited
comparables, not measured willingness-to-pay.

| # | Decision | Options | Recommendation |
|---|---|---|---|
| B1 | Accept the proposed price points? | (a) Accept $20 / $45. (b) Raise. (c) Lower to remove friction. | **Decide after three real conversations.** Do not publish a number you have never said out loud to a buyer. |
| B2 | Currency of record | (a) USD only. (b) TRY for Turkish customers, USD elsewhere. (c) EUR for EU. | **(a) USD at launch.** Multi-currency invoicing adds tax and reconciliation work that a single founder should not take on before the first renewal. |
| B3 | Tax handling | (a) You invoice and remit. (b) A merchant-of-record handles VAT/sales tax. | **(b) if self-service; (a) if invoice-only.** Selling digital services into the EU with self-service checkout without a MoR creates VAT registration obligations in every member state. This is the most common expensive mistake for a first-time SaaS founder. |
| B4 | Minimum term and renewal | (a) Monthly, cancel anytime. (b) Annual prepay. (c) Annual with auto-renew. | **(b) annual prepay for Team, monthly available.** Annual prepay is what makes a one-person company's cash flow survivable. |
| B5 | Cancellation and refund policy | (a) Pro-rata refund. (b) No refund, access to period end. (c) 30-day money-back. | **(b) with a stated 30-day remedy window for defects.** Pro-rata refunds create a monthly reconciliation chore; a defect remedy is what buyers actually want. |
| B6 | What happens to detection when a subscription lapses | (a) Local keeps working; cloud features stop. (b) Everything stops. | **(a).** Turning off local detection because an invoice is late is a safety regression and would be indefensible in an incident review. |

**Blocking gates:** COM-001, COM-004 (billing and entitlements).

---

## Block C — Support and availability promises

Everything in this block is a promise you personally have to keep. A one-person
company should promise less than it can do.

| # | Decision | Options | Recommendation |
|---|---|---|---|
| C1 | Public SLA target | (a) 99.9% monthly. (b) 99.5%. (c) No SLA at launch. | **Start at (c) or (b).** The registry's direct-GA scope names 99.9%, which is a real engineering commitment with no on-call rotation behind it today. A missed 99.9% with service credits attached is a contractual breach; a published 99.5% is survivable. |
| C2 | Support hours | (a) Business hours, one timezone. (b) 24/7. (c) Best effort. | **(a), stated explicitly with the timezone.** 24/7 is not deliverable by one person. |
| C3 | Severity definitions and response targets | (a) None. (b) Published severity table with response (not resolution) targets. | **(b).** Buyers accept a slow response; they do not accept not knowing what to expect. |
| C4 | Security contact and disclosure path | (a) A monitored address. (b) A published security.txt with a PGP key. | **(b).** This is cheap and it is the first thing a security reviewer checks. |
| C5 | Status page | (a) None. (b) A hosted status page. | **(b) before the first paid customer.** Without one, every outage becomes a support conversation. |

**Blocking gates:** COM-005 (support operations), COM-013 (SLA).

---

## Block D — Legal and privacy documents

None of these exist yet. `LICENSE` is present but the licence itself is marked
proprietary without a full EULA, and there is no DPA, privacy notice, or
subprocessor list.

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Licence model for the paid product | (a) Proprietary EULA. (b) Source-available. (c) Open core. | **(a) for the paid tiers, with the local engine's terms stated plainly.** The registry already records `Proprietary`. |
| D2 | Are you willing to sign a customer DPA? | (a) Yes, your own template. (b) Yes, theirs. (c) No. | **(a), with a reviewed template.** Refusing a DPA disqualifies you from most B2B deals; accepting the customer's template unconditionally means accepting terms you have not read. |
| D3 | Subprocessor list | (a) Publish it. (b) Provide on request. | **(a).** You already depend on named infrastructure; hiding it delays every security review. |
| D4 | Data residency at launch | (a) Single region, stated. (b) EU/US/APAC as the registry's GA scope names. | **(a) single region, with the region named.** COM-011's three-region scope requires routing, residency, transfer, backup and deletion models that do not exist yet. Promising them now is a commitment you cannot meet. |
| D5 | Retention and deletion commitments | (a) State a default and honour it. (b) No commitment. | **(a).** A stated retention period is a feature; silence reads as "forever". |

**Blocking gates:** COM-002 (licensing/IP), COM-003 (privacy), COM-011 (regions).

---

## Block E — Enterprise-only commitments

These gate large customers specifically. They are safe to leave open while you
sell to the beachhead segment (15–80 developers), because those buyers do not
ask for them.

| # | Decision | Recommendation |
|---|---|---|
| E1 | Signed artifacts through an authenticated private registry (COM-012) | **Defer.** Requires signing infrastructure that does not exist yet — see `docs/sales/code-signing-guide.md` for the certificate path. |
| E2 | Invoice-based ordering for enterprise procurement (COM-012) | **Defer until first asked.** |
| E3 | Air-gapped and offline entitlement procedures | **Defer.** |
| E4 | Independent penetration test (SEC-EXT-001) | **Budget for it before the first enterprise deal, not before the first sale.** A design partner at 40 developers will not ask; a 500-person enterprise will. |

---

## Block F — What a design partner will ask you

These are not registry gates, but they are what actually comes up in the first
conversations, and having no answer stalls the deal.

| # | Question | Honest answer today |
|---|---|---|
| F1 | "Do you have SOC 2?" | No. No certification, audit, or penetration test has been performed. |
| F2 | "Who else uses this?" | Nobody yet. This is the first cohort. |
| F3 | "What happens if you disappear?" | The local engine keeps working with no account and no network; that is a deliberate architectural property. The cloud layer would stop. Say this plainly — it is a strong answer, not a weak one. |
| F4 | "How do I know it actually blocks things?" | 351 shipped rules and a verification suite that exercises allow/deny/ask behaviour. There is no independent efficacy measurement, and you should not imply one. |
| F5 | "Why is my installer unsigned?" | Currently true and being fixed; see the code-signing guide. Do not let this be discovered by the customer. |
| F6 | "Can I see your data processing terms?" | Not yet written — this is Block D. |

---

## What this packet does not do

It does not approve anything, and it does not close a single gate. Each gate
closes when a named person records a decision against a specific release
candidate, which is what `commercial-gate-receipts.json` exists to hold. This
packet is the input to those decisions; the decisions themselves are yours.

It also does not tell you which decisions are *commercially* right. It tells you
which ones are *outstanding*, which is the part that was previously discoverable
only by opening a registry file and reading a JSON array.
