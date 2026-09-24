# Commercial decision packet

**Purpose:** every open commercial gate in
`docs/production-readiness/commercial-go-evidence-registry.json` needs a value
that a person decides, not a value a tool can derive. This packet lists those
decisions with the options, the consequence of each, and a recommendation, so
one founder can work through them in an afternoon instead of discovering them
one at a time during a sales call.

**Status:** historical decision worksheet. The current product decision is both
online cloud sales and enterprise/on-prem invoice, with a 14-day / one-agent
cloud trial and no trial cap for paid cloud. Provider-of-record, settlement,
tax, pricing, and legal acceptance remain open. Nothing here approves selling.

**How to use it:** work top to bottom as a decision worksheet. The requirements
for even a scoped first-customer evaluation are in the
[first-customer-ready gate](../production-readiness/first-customer-ready.md).
Do not treat any block here as permission to bypass a release, privacy,
distribution, support, or independent-review requirement.

---

## Block A — What you are selling, exactly

The single most expensive ambiguity in this product is that the free tier is
genuinely useful. That is deliberate and should stay. But it means "what does a
customer pay for" must be answered in one sentence before any price is quoted.

| # | Decision | Options | Recommendation |
|---|---|---|---|
| A1 | Is the local detection engine permanently free? | (a) Free forever, uncrippled. (b) Free with a seat cap. (c) Time-limited trial. | **Propose (a), subject to licence and Finance approval.** Local evaluation needs no control plane; this does not establish distribution rights or a permanent price. |
| A2 | What exactly does a paid seat unlock? | (a) Team dashboard + remote policy + audit export. (b) Everything in (a) plus SSO/MFA/RBAC, DLP, legal hold, offboarding. (c) Support only. | **(a) for Team, (b) for Business.** These are the features that genuinely require a server, which is the honest dividing line. |
| A3 | Which sales channels are in scope? | (a) Online cloud payment. (b) Enterprise/on-prem invoice. (c) Both. | **Decision: (c) both.** Checkout remains disabled until provider-of-record, payment/entitlement reconciliation, Finance approval and support acceptance. |
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
| B3 | Tax handling | (a) Vendor invoices. (b) A merchant-of-record handles collection and tax. | **No recommendation without qualified tax/legal review.** Record jurisdictions, provider responsibilities and approved terms before quoting. |
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
| C1 | Public SLA target | (a) 99.9% monthly. (b) 99.5%. (c) No SLA at launch. | **No SLA promise now.** Choose a target only after measured service availability, named operations, approved exclusions/credits and Legal review. |
| C2 | Support hours | (a) Business hours, one timezone. (b) 24/7. (c) Best effort. | **(a), stated explicitly with the timezone.** 24/7 is not deliverable by one person. |
| C3 | Severity definitions and response targets | (a) None. (b) Published severity table with response (not resolution) targets. | **(b).** Buyers accept a slow response; they do not accept not knowing what to expect. |
| C4 | Security contact and disclosure path | (a) A monitored address. (b) A published security.txt with a PGP key. | **(b).** This is cheap and it is the first thing a security reviewer checks. |
| C5 | Status page | (a) None. (b) A hosted status page. | **(b) before the first paid customer.** Without one, every outage becomes a support conversation. |

**Blocking gates:** COM-005 (support operations), COM-013 (SLA).

---

## Block D — Legal and privacy documents

Draft privacy, licence and contract templates exist, but the customer-specific
terms, distribution rights, DPA/subprocessor scope and counsel/Privacy approval
are still open. A template is not a signed customer agreement.

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

These are not automatically "large-customer-only" gates. The first-customer
evaluation requires trusted distribution and scoped independent review before
handling real customer data; any paid production offer needs its applicable
commercial hard gates regardless of the buyer's size.

| # | Decision | Recommendation |
|---|---|---|
| E1 | Signed artifacts through an authenticated private registry (COM-012) | **Open for a paid production offer.** An AIDR-owned controlled evaluation still needs a trusted signed candidate; see the release gate. |
| E2 | Invoice-based ordering for enterprise procurement (COM-012) | **Open if invoicing is offered.** Do not call `pending_finance` an invoice or paid entitlement. |
| E3 | Air-gapped and offline entitlement procedures | **Exclude unless explicitly sold and tested.** |
| E4 | Independent security assessment (SEC-EXT-001) | **Open for customer-data handling and a production offer.** Scope, findings and retest must match the sold candidate. |

---

## Block F — What a design partner will ask you

These are not registry gates, but they are what actually comes up in the first
conversations, and having no answer stalls the deal.

| # | Question | Honest answer today |
|---|---|---|
| F1 | "Do you have SOC 2?" | No. No certification, audit, or penetration test has been performed. |
| F2 | "Who else uses this?" | Nobody yet. This is the first cohort. |
| F3 | "What happens if you disappear?" | Local evaluation does not require a control-plane account, but optional reputation checks can use external services and updates/support would stop. Any continuity promise needs approved licence, package custody and an offline rehearsal. |
| F4 | "How do I know it actually blocks things?" | 351 shipped rules and a verification suite that exercises allow/deny/ask behaviour. There is no independent efficacy measurement, and you should not imply one. |
| F5 | "Why is my installer unsigned?" | No approved publisher-signed customer installer is available yet. Do not send the engineering bundle as a supported release; see the code-signing guide. |
| F6 | "Can I see your data processing terms?" | Draft templates exist, but no customer-specific DPA, subprocessor schedule or counsel/Privacy approval is held. |

---

## What this packet does not do

It does not approve anything, and it does not close a single gate. Each gate
closes when a named person records a decision against a specific release
candidate, which is what `commercial-gate-receipts.json` exists to hold. This
packet is the input to those decisions; the decisions themselves are yours.

It also does not tell you which decisions are *commercially* right. It tells you
which ones are *outstanding*, which is the part that was previously discoverable
only by opening a registry file and reading a JSON array.
