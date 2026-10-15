# Windows Code Signing — Purchase Guide for Singularity AIDR

**For:** one-person Turkish startup, limited budget, needs enterprise procurement credibility
**Product:** Singularity AIDR — Node.js SEA `.exe` + VS Code/Cursor `.vsix` + npm packages
**Research date:** 2026 (all sources fetched live; URLs cited inline)
**Author's note on method:** `web_search` was unavailable in this session (missing API key), so every claim below comes from a direct `web_fetch` of the cited URL. Where a price could not be retrieved, it is marked **NOT VERIFIED** rather than estimated.

---

## 1. Recommendation

### Recommendation: **Turkey is not the blocker.** Buy an **SSL.com IV code signing certificate (~$129/yr)** if you have no registered company, or **Certum OV via a Turkish reseller (≈₺4,500–7,500)** if you have a registered limited şirket. In both cases, do **not** chase EV and do **not** count on Azure Artifact Signing.

**Runner-up: Azure Artifact Signing** — but it is *not available to you* (see §3). That is the one firm exclusion in this document.

**The finding that matters most:** the real dividing line for a Turkish one-person startup is **entity type, not country**. Turkey is absent from every CA restricted-country list I could find, and SSL.com explicitly names Turkish government registries (MERSIS, Ticaret Sicil Gazetesi) as acceptable validation sources. What actually blocks solo founders is that most CAs sell only to registered *organizations*, and GlobalSign has retired its individual product entirely. **Read §5 before you assume you are excluded — you probably are not.**

### Why OV, specifically

The decisive fact is that **EV no longer buys you anything for SmartScreen**. Microsoft states this outright:

> "EV certificates no longer bypass SmartScreen. Years ago, signing files with an Extended Validation (EV) code signing certificate would result in positive SmartScreen reputation by default, but this behavior no longer exists. EV certificates may matter for enterprise procurement, but they no longer impact SmartScreen behavior. **Paying a premium for EV solely to avoid SmartScreen warnings is no longer justified.**"
> — <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation>

Microsoft's own comparison table confirms it — the SmartScreen column is literally identical for OV and EV:

| Certificate type | First-download SmartScreen behavior |
| --- | --- |
| Valid Certificate (OV/EV) | ⚠️ Warning — app flagged as unrecognized until reputation accumulates; verified publisher name is displayed |
| No signature | ⚠️ Warning — "Windows protected your PC"; user must choose "Run anyway". **Enterprise policy can prevent continuation entirely.** |
| Self-signed Certificate | ⚠️ Warning — same behavior as no signature |

Same source. Note the last clause on the unsigned row: *"Enterprise policy can prevent continuation entirely."* That is precisely your procurement blocker. **Signing does not remove the warning — it removes the "Unknown Publisher" state and stops enterprise policy from blocking you outright.** That is the thing you are actually buying, and OV delivers it at roughly a third of the EV price.

EV priced at **$349–$608/yr** versus OV at **$129–$434/yr** (§4) buys you a marginal procurement signal and zero SmartScreen benefit. For a one-person startup with a limited budget, that premium is not defensible.

### Why not Azure Artifact Signing (the "obvious" cheap answer)

At **$9.99/month (~$120/year)** it looks like a slam dunk, and it is Microsoft's own recommendation for non-Store distribution. **But you are very likely ineligible**, and this is not the commonly-cited "3+ years of business history" rule. See the next section.

---

## 2. The single most important finding: Azure Artifact Signing eligibility

**Your brief assumed the gate was "3+ years of verifiable business history." That is out of date, and the real gate is worse for you: it is geographic, and Turkey is not on the list.**

Azure Trusted Signing has been **renamed to Azure Artifact Signing**. The current prerequisites state:

> "Public Trust certificates are available to **organizations** in the United States, Canada, the European Union, the United Kingdom, Australia, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway, and Israel. **Individual developers must be located in the United States or Canada.** These geographic restrictions do not apply to Private Trust certificates."
> — <https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart> (also mirrored in the source Markdown: <https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/main/articles/artifact-signing/quickstart.md>)

Microsoft's developer-facing comparison page restates it plainly:

> "**Geographic limitation:** Azure Artifact Signing is available to organizations in the USA, Canada, the European Union, and the United Kingdom. Individual developers are currently limited to the USA and Canada."
> — <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options>

**Turkey is not in the EU, not in the EEA, and not the US or Canada.** So:

| Path | Turkey eligible? |
| --- | --- |
| Public Trust as an **individual developer** | ❌ **No** — individuals limited to US/Canada |
| Public Trust as an **organization** | ❌ **No** — country list excludes Turkey |

**Conclusion: a brand-new one-person Turkish startup does not qualify for Azure Artifact Signing Public Trust.** There is no "3 years of history" workaround to chase, because the blocker is the country list, not business age. Do not budget for this.

Two further confirmations that this is a dead end for you, and one escape hatch that is not worth taking:

- **No EV available, ever.** "No, Artifact Signing doesn't issue Extended Validation (EV) certificates. There's no plan to issue EV certificates in the future." — <https://learn.microsoft.com/en-us/azure/artifact-signing/faq>
- **No free/trial subscriptions.** "Artifact Signing doesn't support free, trial, or sponsored Azure subscriptions... you must have a paid Azure subscription." — same FAQ.
- **The escape hatch (don't).** Private Trust certificates *are* exempt from the geographic restriction, but Private Trust is explicitly **not** publicly trusted: "The CA hierarchy that's used for Artifact Signing Private Trust resources isn't default-trusted in any root program and in Windows." — <https://learn.microsoft.com/en-us/azure/artifact-signing/concept-trust-models>. It is for WDAC/internal app control only. It will not help you with SmartScreen or procurement.

**One action to take anyway:** the country dropdown in the Azure portal is the authoritative live check. The FAQ says: "Check Pre-requisites to get the list of supported countries/regions for onboarding." — <https://learn.microsoft.com/en-us/azure/artifact-signing/faq>. If you have 10 minutes, open the portal, attempt an identity validation, and see whether Turkey appears. Treat a "no" as confirmation, not as a failure. Everything else in this guide assumes a "no."

### What Azure Artifact Signing actually costs (for completeness)

Verified from Microsoft's own retail pricing API (not a marketing page):

> `https://prices.azure.com/api/retail/prices?$filter=contains(serviceName,'Signing')`

| SKU | Price | Signature quota / month | Overage |
| --- | --- | --- | --- |
| **Basic** | **$9.99 / month** | 5,000 | $0.005 per signature |
| **Premium** | **$99.99 / month** | 100,000 | $0.005 per signature |

Corroborated by <https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-change-sku>. Note also: "The pricing isn't calculated on a pro rata basis. The invoice is generated with the full amount for the SKU that you selected." — <https://learn.microsoft.com/en-us/azure/artifact-signing/faq>.

**Relevant to you if you ever relocate or incorporate in the EU:** Artifact Signing needs **no hardware token**, is FIPS 140-3 Level 3, and integrates with GitHub Actions and Azure DevOps. Certificates are short-lived (72 hours, renewed daily) so **timestamping is mandatory** — the timestamp is what keeps old signatures valid. If you ever set up an EU entity (e.g. Estonia e-Residency → EU company), this becomes the cheapest and best option by a wide margin. That is a legitimate strategic consideration, but it is a company-formation decision, not a purchasing decision.

---

## 3. The three certificate types, and what actually differs

### 3.1 Hardware key storage is still mandatory — this is confirmed current

Your brief asked me to verify that the CA/Browser Forum hardware requirement (since June 2023) is still true. **It is**, and it has been reinforced since.

From the CA/Browser Forum [Code Signing Baseline Requirements v3.11.0 (16 June 2026)](https://cabforum.org/working-groups/code-signing/requirements/), the "Relevant Dates" table:

| Compliance | Section | Requirement |
| --- | --- | --- |
| **2023-06-01** | 6.2.7.4.2 | "Effective June 1, 2023, for Code Signing Certificates, CAs SHALL ensure that the Subscriber's Private Key is generated, stored, and used in a suitable **Hardware Crypto Module** that meets or exceeds the requirements specified in section 6.2.7.4.1" |
| 2026-03-01 | 6.3.2 | "For Code Signing Certificates issued on or after March 1st, 2026, the **validity period MUST NOT exceed 460 days**" |
| 2026-09-15 | 7.1.6.4 | Subscriber certificates must contain exactly one reserved policy OID |

Vendor confirmation, verbatim from Sectigo's store: *"May 2023 — All new code signing certificate keys are mandated to be stored on an HSM or compliant hardware token."* — <https://sectigostore.com/code-signing/sectigo-code-signing-certificate>

Microsoft restates it for developers: "As of June 2023, the CA/Browser Forum requires private keys for OV certificates to be stored on a hardware security module (HSM) or hardware token. Most CAs provide a compatible USB token or cloud HSM option." — <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options>

**Practical consequences for you, and they are not small:**

1. **You cannot hold a `.pfx` file.** Every option is either a physical USB token shipped to you in Turkey (international shipping, customs delay) or a cloud-signing service. This is the main reason your build pipeline will need rework.
2. **A USB token is a physical single point of failure for CI.** A token plugged into a machine cannot be used by a hosted CI runner. For automation you want a **cloud signing service** (SSL.com eSigner, DigiCert KeyLocker, or similar), not a token.
3. **The 460-day cap (effective 1 March 2026)** means annual renewal is unavoidable. GlobalSign: "the last date to order 2 and 3 year validity certificates was the 26th December 2025... We are only issuing 1 year (366 day) certificates now." — <https://www.globalsign.com/en/blog/code-signing-validity-changes>. Budget for a renewal every year, and note that multi-year purchases are now mostly a prepayment discount, not a longer certificate.

### 3.2 The comparison you asked for

| | **OV** (Organization Validation) | **EV** (Extended Validation) | **Azure Artifact Signing** |
| --- | --- | --- | --- |
| **Cost/year** | $129–$434 (see §4) | $349–$608 (see §4) | $119.88 (Basic, $9.99/mo) |
| **SmartScreen: immediate?** | ❌ No — "reputation builds over time; initial warnings expected" | ❌ **No — identical to OV since 2024** | ❌ No — "reputation accumulates over time based on download volume and behavior" |
| **Hardware token/HSM required?** | ✅ **Yes** (CA/B Forum CSBR 6.2.7.4.2, since 2023-06-01). CA supplies token or cloud HSM. | ✅ **Yes** (same rule) | ❌ **No** — keys held in Microsoft's FIPS 140-3 Level 3 HSMs; "No hardware token required" |
| **Turkey eligible?** | ✅ Yes (see §5) | ✅ Yes (see §5) | ❌ **No** (see §2) |
| **Available to a solo founder with no company?** | ⚠️ **Only at SSL.com (IV, ~$129) and Certum.** DigiCert/Sectigo are org-only; GlobalSign retired its individual product. | ⚠️ Same, plus notarization and business-listing requirements | n/a |
| **Issues EV certs?** | n/a | n/a | ❌ "No plan to issue EV certificates in the future" |
| **Enterprise credibility** | Verified publisher name shown | Same + heavier vetting | Verified publisher name shown |

Sources: <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options>, <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation>, <https://learn.microsoft.com/en-us/azure/artifact-signing/faq>, <https://cabforum.org/working-groups/code-signing/requirements/>

### 3.3 How SmartScreen reputation actually behaves — the part that changes your sales pitch

This is operationally the most useful thing in this document:

> "When a file is **not signed**, SmartScreen reputation must build for **each new version** of your files, starting with zero reputation. Reputation cannot transfer from previous versions **unless both were signed using the same publisher identity**."
> — <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation>

And:

> "The prompt will stop appearing once the file hash has sufficient download history. **There is no exact threshold, but it can take several weeks and hundreds of clean installs from a wide audience.**"
> — same source

Three consequences:

1. **Signing changes the shape of the problem.** Unsigned, every release restarts at zero. Signed, *publisher* reputation accumulates across releases and only the *hash* reputation restarts — so release N+1 inherits trust from release N. This is the real ROI of signing, more than the first-download warning.
2. **Never change your signing identity.** "Use a consistent signing identity — changing your signing certificate affects the publisher trust signal." Same source. Pick your certificate subject name carefully; a rebrand later costs you accumulated reputation.
3. **Do not sign anything questionable.** "Do not sign potentially unwanted applications — ...or the certificate may develop **negative** reputation." Same source. For a *security* tool this is a genuine risk worth naming: AIDR blocks things, and security tooling is routinely flagged as PUA. A false-positive reputation hit on your signing certificate is materially worse than being unsigned.

Also relevant to a security tool: "On Windows 11 devices, the Smart App Control feature may supersede SmartScreen Application Reputation. Smart App Control will **block execution of unsigned files** unless the file has a positive reputation." Same source. Smart App Control is on by default on new Windows 11 installs — this makes signing more urgent than SmartScreen alone suggests.

---

## 4. Vendor comparison with sources

> **Price caveat, stated plainly.** CA list prices are mostly behind JavaScript configurators that a text fetch cannot read. The verified figures below fall into two tiers, and I label which is which. **Treat every number as a starting quote to confirm at checkout, not a contract price.** Where I could not verify, I say so.

| Vendor | Product | Price / year | Source tier | SmartScreen | Token / HSM | Turkey? |
| --- | --- | --- | --- | --- | --- | --- |
| **Certum** (via Turkish reseller) | Standard Cloud OV | **≈₺7,500** | Turkish reseller (kodimza.com) | Builds over time | SimplySign cloud | ✅ Yes |
| **SSL.com** | **IV Code Signing** | **$129.00** | Aggregator + SSL.com product page | Builds over time | eSigner cloud | ✅ Yes (no company needed) |
| **SSL.com** | OV Code Signing | **$129.00** | Aggregator (SSL Shopper) | Builds over time | eSigner cloud | ✅ Yes |
| **Sectigo** | OV Code Signing | $313.50 (list $379) | Reseller storefront | Builds over time | **Token = paid extra** | ✅ Yes |
| **DigiCert** | OV Code Signing | $434.00 | Aggregator / reseller | Builds over time | KeyLocker / eToken / BYO | ✅ Yes (**org only**) |
| **Certum** (direct) | Code Signing | **NOT VERIFIED** | — | Builds over time | Card or SimplySign cloud | ✅ Yes |
| **GlobalSign** | OV / EV | **NOT VERIFIED** | — | Builds over time | USB token **included** | ✅ Yes (**org only; individual product retired**) |
| **SSL.com / Sectigo / DigiCert** | EV Code Signing | $349 / $410.85 / $608 | Aggregator + reseller | **Identical to OV** | Token or cloud | ✅ Yes |
| **Azure Artifact Signing** | Basic | $119.88 ($9.99/mo) | ✅ **Microsoft pricing API** | Builds over time | **None** | ❌ **NOT ELIGIBLE** |

**Source URLs:**
- SSL.com OV `$129` / DigiCert OV `$434` / Sectigo OV `$313`: <https://www.sslshopper.com/cheap-code-signing-certificates.html>
- SSL.com EV `$349` / DigiCert EV `$608` / Sectigo EV `$410`: <https://www.sslshopper.com/ev-code-signing-certificates.html>
- Sectigo storefront detail (list prices, discounts, token options): <https://sectigostore.com/code-signing/sectigo-code-signing-certificate>
- DigiCert key-storage options (KeyLocker / provided token / BYO token), and "DigiCert does not publish prices": <https://www.digicert.com/signing/code-signing-certificates>
- GlobalSign "USB Token... Included in the price of the certificate" and "can be issued in the name of a legally registered organization only": <https://shop.globalsign.com/en/code-signing>
- Azure pricing (authoritative): `https://prices.azure.com/api/retail/prices?$filter=contains(serviceName,'Signing')` → serviceName `"Trusted Signing"`, Basic $9.99/mo, Premium $99.99/mo, overage $0.005/signature

### The SSL.com/DigiCert/Sectigo prices are reseller prices, not list

Important honesty note: the SSL Shopper table is an **affiliate-funded comparison page** (it discloses this: "SSL Shopper is a free service because we may collect referral fees"), and its "Get Pricing" links point to resellers. So `$129` for SSL.com OV is a **street price**, not SSL.com's own list price. SSL.com's own product pages render prices via JavaScript and returned no figure to a text fetch. **Verify at checkout.**

### GlobalSign is probably closed to you

> "Please note: GlobalSign Code Signing Certificates can be issued in the name of a **legally registered organization only**."
> — <https://shop.globalsign.com/en/code-signing>

If you operate as a sole trader rather than a registered company, GlobalSign is out. They also instruct buyers to order from the region matching the certificate holder's country, which for Turkey means the "Middle East" or "Europe and Africa" storefront — confirm with sales. **GlobalSign price is NOT VERIFIED**; the live page and the 2026 Wayback snapshot both render the literal placeholder `From • / year`, with the number injected by a currency selector.

### Certum — the honest gap

**Certum's prices are NOT VERIFIED.** This matters because Certum (Asseco Data Systems, Poland) is widely cited as the best-value option for individual European developers, and your brief specifically flagged it as likely the cheapest for individuals.

What I *did* confirm, from Certum's own search-result descriptions and support pages:
- Certum sells a **"Standard Code Signing"** product, and describes it as a normal publicly-trusted cert: *"The certificate is trusted by Microsoft and supports building the Microsoft SmartScreen Filter reputation."* — <https://shop.certum.eu/standard-code-signing-electronic-code.html>
- Certum sells an **Open Source Code Signing** variant (relevant only if AIDR were open source — it is not, so this likely does not apply).
- Certum's storage options are a **Starcos 3.5 cryptographic card** or **Certum SimplySign cloud** ("Code Signing in the cloud"), and Certum actively pushes cloud for EV: *"more and more Users are choosing the cloud solution, which eliminates the need for a card, especially in its highest version Code Signing EV."* — <https://shop.certum.eu/buy-a-code-signing-certyficate>

**Why I could not get the price:** Certum's storefronts (`shop.certum.eu`, `certum.store`, `sklep.certum.pl`) are Magento stores whose category and product pages return only navigation chrome to a text fetch, with prices below the retrieval cut-off. Their support KB (`support.certum.eu`) is fully JavaScript-rendered — even direct article URLs return only a page title. I tried product-slug guesses, catalog search pages, and Wayback snapshots of both the category page and the live store.

**Action for you:** open <https://shop.certum.eu/code-signing.html> in a real browser. If Certum's "Code Signing in the cloud" (SimplySign, no physical card) comes in meaningfully under SSL.com's $129, **buy Certum instead** — it is a European CA (no transcontinental token shipping, EUR invoicing) and is the CA most experienced with individual-developer code signing. This is the one open question worth 10 minutes of your own browser time.

### On the "country restrictions" question

I could not find a per-CA published country blocklist, and I want to be explicit rather than imply one exists. What is verifiable:

- **Microsoft/Azure Artifact Signing is the only vendor with a published, explicit geographic restriction, and Turkey is outside it** (§2). That finding is solid.
- For commercial CAs (SSL.com, Sectigo, DigiCert, GlobalSign, Certum), the constraint is **not a country list but a validation process**: the CA must verify your legal identity and address using documentation from a government agency or reliable third-party database, per CA/B Forum CSBR §3.2.2.1.1 ("A government agency in the jurisdiction of the Applicant's legal creation, existence, or recognition; A third party database...; A site visit...; or an Attestation Letter").
- **Consequence:** Turkish company registration (MERSIS / Ticaret Sicil Gazetesi) and tax number (VKN) are the documents that matter, and they must be legible to the CA's validation team, often in English. Where solopreneurs most often fail is the **verifiable business phone number / directory listing** step — a one-person company with no landline and no third-party directory entry is a common rejection cause. Getting a **D-U-N-S number** and a listing that shows your business name and address is the standard mitigation.

**NOT VERIFIED:** whether any of these CAs formally refuse Turkey, and the exact document checklist each one applies. **Do not assume you will be rejected, and do not assume you will be approved.** The efficient move is to start the *validation* conversation with two CAs in parallel (see §8) — the application is free and only the certificate costs money.

---

## 5. Turkey eligibility and documents

**Bottom line: yes, this is possible, and Turkey is not the blocker.** Turkey is absent from every CA restricted-country list located in this research. Where a blocker exists it is **entity type** — most CAs sell only to registered organizations — not nationality.

### 5.1 Country eligibility, per CA

| CA | Turkey eligible? | Evidence |
| --- | --- | --- |
| **SSL.com** | ✅ **Yes — and Turkey is named explicitly** | `Turkey / TR` appears on SSL.com's accepted-country list. Its Restricted Countries Listing is exactly four: **Cuba, Iran, North Korea, Syria**. Turkey is not among them. <https://www.ssl.com/country_codes/> |
| **DigiCert** | ✅ Not restricted | Embargoed-country list (SO101120141837, rev. 04/2026): Cuba, Iran, North Korea, Syria, Crimea/Donetsk/Luhansk, Russia, Venezuela, Belarus. Turkey absent. <https://knowledge.digicert.com/solution/embargoed-countries-and-regions> |
| **Sectigo** | ✅ Not restricted | No restricted-country list found; international token shipping supported (customer pays customs). <https://www.sectigo.com/knowledge-base/detail/EV-Document-Signing-Certificate-Token-FAQ> |
| **GlobalSign** | ✅ Not restricted (but see §5.2 — org-only) | Sanctions policy names no Turkey exclusion. <https://www.globalsign.com/en/repository/GlobalSign-sanctions-policy-v2.pdf> |
| **Certum** | ✅ No exclusion found | See the caveat in §9 — their CPS PDFs could not be retrieved. |
| **Azure Artifact Signing** | ❌ **NOT ELIGIBLE** | See §3. Geographic restriction, not a country blocklist. |

**The strongest single piece of evidence:** SSL.com's published QIIS (Qualified Independent Information Source) list names **`MERSIS (https://mersis.gtb.gov.tr/)`** and **`Turkish Trade Registry Gazette (www.ticaretsicil.gov.tr)`** as acceptable validation sources, listed for **both OV and EV** certificates.
— <https://www.ssl.com/blogs/acceptable-business-listings-for-validation/> and <https://www.ssl.com/how-to/validation-process-for-document-signing-code-signing-and-ev-code-signing-certificates/>

This matters because it means your Turkish registry record *is* the validation evidence, in place of a D-U-N-S number (see §5.4). **Caveat:** SSL.com's own pages could not be re-fetched for this document — their mega-menu consumed the fetch budget. These specific quotes come from a delegated research pass, not from my own re-verification. Spot-check them yourself before relying on them.

### 5.2 Individual vs organization — this is the real gate

The CA/B Forum Code Signing BRs **v3.11.0 (16 June 2026)** do define and permit an "Individual Applicant" (§3.2.3, verified by government photo ID plus a QIIS address) — <https://cabforum.org/working-groups/code-signing/requirements/>. **Most CAs simply choose not to sell it:**

- **DigiCert — organization only.** The required validation type is literally "CS — Code Signing **Organization** Validation". <https://docs.digicert.com/en/certcentral/manage-certificates/code-signing-certificates/order-a-code-signing-certificate.html>
- **Sectigo — organization only, emphatically.** "EV Code Signing certificates are issued only to verified organizations... **They cannot be issued to individuals.**" <https://www.sectigo.com/knowledge-base/detail/extended-validation-ev-code-signing-certificates-what-to-expect-during-validation>. Note this quote is specifically about **EV** — whether Sectigo's **OV** is open to natural persons is **NOT VERIFIED**.
- **GlobalSign — its individual product was RETIRED.** Verified via Wayback CDX status codes: `.../code-signing-for-individual-developers/` → **301** (April 2021); the buy page → **404**. Current KB (May 2026) mentions only "standard organization validation"; "individual" and "sole proprietor" appear nowhere.
- **Certum — ✅ sells to individuals.** Their product table lists the Standard tier as "Code signing for an individual **or** a company" (the EV tier is company-name only), and their FAQ states OV certificates "can also be issued to individuals." <https://www.certum.eu/en/code-signing-certificates/>

**✅ SSL.com IV Code Signing — ~$129/yr — the answer if you have no registered company.** SSL.com's own product description reportedly states the IV tier "gives solo developers access to Authenticode signing **without a business entity**" and requires "**no business registration**". <https://www.ssl.com/products/software-integrity/code-signing/iv/>
- Constraint to note: **Windows-only** (macOS would need a separate Apple Developer ID), no immediate SmartScreen reputation, and **not** eligible for kernel-mode driver signing. For AIDR — a Windows `.exe` and a VSIX — this is sufficient.
- Same caveat as §5.1: I could not re-fetch this page's body text myself; treat the quoted wording as delegated-research findings to spot-check.

**SSL.com Sole Proprietor EV** (<https://www.ssl.com/guide/sole-proprietor-ev-application/>) also needs no registered entity, but requires a **notarized / CPA-sealed / attorney-signed** Personal Identity Verification Form, and states that EV applicants "must appear in a qualified independent business listing service such as Dun & Bradstreet." **Given that EV buys no SmartScreen benefit (§1), IV is the cleaner solo path.**

### 5.3 Document checklist for a Turkish applicant

**Path A — SSL.com IV (no company required).** Per <https://www.ssl.com/faqs/ssl-ov-validation-requirements/>:
1. Front of government photo ID or passport ID page — name, address, DOB and photo visible (the ID number may be obscured). **Turkish T.C. kimlik kartı or passport both work.**
2. Back of the same ID.
3. A selfie holding the ID beside your face, ≥5 megapixels (automated AI identity verification is offered as an alternative).
4. **A successful callback to a verified phone number is still required.**

**Path B — OV (registered company).** You supply a link to a Reliable Data Source showing name, address and phone — **Ticaret Sicil Gazetesi or MERSIS are accepted**. Registration Number and Registered Country are required fields.
> ⚠️ **Watch this clause:** "if the business or organization is less than three years old, a scan of the certificate requestor's government-issued ID is also required." This will apply to most new one-person Turkish firms. It is a paperwork step, not a rejection — just have the ID scan ready.

**Path C — EV.** Signed EV Subscriber Agreement and EV Authorization Form; Articles of Incorporation **or** a government-website link; and one of D-U-N-S / ZoomInfo / Crunchbase / OpenCorporates / an attorney-CPA-notary attestation letter. Requires naming a Contract Signer (an officer), a Requester, and an Approver. **Not worth it for SmartScreen reasons (§1), and burdensome for a one-person company.**

**Documents NOT required (contrary to common assumption):** articles of association (EV only, and only as an alternative), a separate proof-of-address utility bill, and **domain whois** — code signing does not use whois; that is SSL/TLS domain validation.

### 5.4 The directory / phone problem — real, but it is about the PHONE, not D-U-N-S

This is where one-person applicants most often stall, so it is worth being precise:

- **The phone callback is mandatory.** SSL.com: "This process is **mandatory for OV and EV certificates**", and you need "an approved contact number provided for by any Qualified Independent Information Source." **But there is a relief clause:** "In case that an independent source of your number does not appear on our list, **you may provide a link to a listing that you do appear in** to your validation contact for potential approval."
- **DigiCert** must obtain an "independently verified telephone number for the organization (e.g. using reliable online telephone directories) and call that number."
- **Sectigo rejects virtual addresses outright:** "**PO Boxes, virtual offices, mail forwarding addresses, or registered agent addresses are not accepted.**" ← A Turkish virtual office will not satisfy this.
- **D-U-N-S is NOT mandatory at any CA.** It is consistently framed as an *expediter*, not a requirement. SSL.com accepts MERSIS / Trade Registry Gazette in its place.

**If you do want a D-U-N-S number:** **CRIF Türkiye is the sole authorized Dun & Bradstreet representative in Turkey** — "D&B Worldwide Network üyesi ve Türkiye'deki tek yetkili DUNS Numarası sağlayıcı olan CRIF Türkiye'ye **dunstalep@crif.com** e-posta adresinden başvuruda bulunabilirsiniz." — <https://www.crif.com.tr/duns-numarasi> (verified directly). It is **paid**, and CRIF's request-reason dropdown offers only Google Developer, Apple Developer, FDA-SAM, tender participation, supplier/customer request, or update — **there is no "code signing" option**, so select "Diğer" (Other) and explain in the message field.

**Recommendation: skip D-U-N-S initially.** Use IV (no organization directory needed at all), or satisfy the phone requirement via your MERSIS / Ticaret Sicil Gazetesi listing, which is free, official, and already on SSL.com's accepted QIIS list. Only pay CRIF if a specific CA rejects your Turkish registry listing.

### 5.5 Turkish resellers — the cheapest verified route

Domestic resellers sell the same certificates in TRY with local invoicing. Live 2026 pricing found at **kodimza.com**:

| Product | TRY price |
| --- | --- |
| **Certum Standard Cloud OV** | **₺7,500** |
| **Certum Open Source Cloud** | ₺4,500 |
| Certum Cloud EV | ₺13,250–15,250 |
| Sectigo OV | ₺20,000 |
| Sectigo EV | ₺25,000 |
| GlobalSign OV | ₺30,000 |
| GlobalSign EV | ₺41,000 |
| DigiCert EV | ₺33,750 |

Other active Turkish resellers: **elektronikssl.com.tr**, **kodimzalama.com**, **ihs.com.tr**, **nettrust.com.tr**, **globalsign.com.tr** (GlobalSign Turkey, +90 212 266 8930), **tr.comodo.com**. Documents they ask for: **ticaret sicil gazetesi, vergi levhası, and photo ID of the authorized person.** (`isimtescil.net` does **not** sell code signing — verified.)

> ⚠️ **Two cautions.** (1) These prices come from a delegated research pass and were not independently re-verified by me — **get a written quote before budgeting.** (2) **No Turkish reseller sells SSL.com IV or Sole Proprietor EV.** If you have no registered company, you must buy those direct from SSL.com in USD.

### 5.6 Turkish domestic CAs do NOT solve this — verified, not assumed

This is worth stating because it is a natural assumption for a Turkish founder:

- **Kamu SM (TÜBİTAK BİLGEM) — ❌ not usable for Authenticode.** Microsoft's authoritative code-signing report (`MicrosoftCodeSigningCSV` via CCADB, <https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=MicrosoftCodeSigningCSV>) lists **69 rows across 18 CA owners — zero Turkish CAs.** Kamu SM's root *is* in the Microsoft Trusted Root Program, but **only for TLS**: it is named "TUBITAK Kamu SM SSL Kok Sertifikasi" with EKUs "Server Authentication; Client Authentication" only, its e-imza intermediate is marked **"Not Trusted"**, and there is **no Code Signing EKU anywhere in the hierarchy.** So a Turkish e-imza / nitelikli elektronik sertifika is fine domestically but worthless for signing your `.exe`.
- **E-Tuğra — ❌ distrusted, and no longer sells code signing.** Browser status: Chrome "Removed", Mozilla "Removed", Apple "Not Included", legacy root "Disabled". Microsoft set NotBefore = **15 September 2025**, so anything signed after that date is untrusted. Its live site now sells only E-İmza, KEP, SSL and Zaman Damgası — no code signing product.

### 5.7 Payment

- SSL.com accepts "Visa/Mastercard, American Express, Discover and Paypal", plus **USD wire to JPMorgan Chase (SWIFT CHASUS33, routing 021000021)**, and — usefully for a Turkish company that needs an invoice before paying — **accepts purchase orders and quotes** via Sales@SSL.com. <https://www.ssl.com/purchase-orders/>
- A Turkish card works for USD purchases at your issuer's TCMB FX rate plus commission; wire transfer is the fallback. **Physical tokens shipped to Turkey incur customs duty and VAT, and Sectigo confirms the customer pays them.** SSL.com's eSigner cloud signing avoids shipping a token entirely — another reason to prefer cloud signing.
- **NOT VERIFIED:** current Turkish foreign-currency payment restrictions. Turkish government sites (hmb.gov.tr, tcmb.gov.tr, mevzuat.gov.tr) returned empty or navigation-only content, and **no evidence of any actual prohibition was found.** Confirm with your accountant or bank.

---

## 6. Signing your artifacts — real commands

### 6.1 The `.exe` (Node.js SEA) — with a traditional OV certificate

SignTool ships with the Windows SDK (e.g. `C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe`). The `/fd` and `/td` options are now **required**, not optional:

> "The SignTool `sign` command requires the file digest algorithm option (`/fd`) and the time stamp digest algorithm option (`/td`) during signing and time stamping... **If the `/fd` option isn't specified while signing, the command generates an error.**"
> — <https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool>

**Signature — always timestamp.** An unsigned-timestamp signature becomes worthless when your certificate expires (which is now every ≤460 days). `signtool` only *warns* if timestamping fails, so a silently untimestamped release is a real hazard:

```powershell
# OV/EV cert in a PFX file (only possible if your CA gave you a software key;
# under the 2023+ HSM rule most CAs will NOT — see the token/cloud variants below)
signtool sign `
  /f  "C:\certs\aidr-ov.pfx" `
  /p  "$env:CERT_PASSWORD" `
  /fd SHA256 `
  /tr "http://timestamp.digicert.com" `
  /td SHA256 `
  /d  "Singularity AIDR" `
  /du "https://aidr.example.com" `
  "dist\aidr.exe"
```

```powershell
# Certificate already installed in the Windows cert store with a hardware key
# (the typical USB-token case). This is the form that works with an HSM-backed key.
signtool sign /n "Your Legal Company Name" /fd SHA256 `
  /tr "http://timestamp.digicert.com" /td SHA256 "dist\aidr.exe"
```

**Always verify what you just signed:**

```powershell
signtool verify /v /pa "dist\aidr.exe"
```

Microsoft's own FAQ notes that not every file type shows a **Signature** tab in Explorer's Properties dialog, so `verify` is the reliable check — not the GUI: *"run this command: `.\signtool.exe verify /v /debug /pa fileName`"* — <https://learn.microsoft.com/en-us/azure/artifact-signing/faq>.

### 6.2 The `.exe` — with Azure Artifact Signing (for reference / if you ever relocate)

Included because the command shape differs meaningfully (`/dlib` + `/dmdf`), and because you may hand this to a future EU entity.

Install client tools: `winget install -e --id Microsoft.Azure.ArtifactSigningClientTools` — <https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations>

Create `metadata.json` (the endpoint must match your account **region**):

```json
{
  "Endpoint": "https://neu.codesigning.azure.net",
  "CodeSigningAccountName": "<account name>",
  "CertificateProfileName": "<profile name>",
  "CorrelationId": "aidr-release-1.4.2"
}
```

Sign:

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" sign `
  /v /debug /fd SHA256 `
  /tr "http://timestamp.acs.microsoft.com" /td SHA256 `
  /dlib "C:\tools\Azure.CodeSigning.Dlib\bin\x64\Azure.CodeSigning.Dlib.dll" `
  /dmdf "C:\tools\metadata.json" `
  "dist\aidr.exe"
```

Notes from the same page: signing via Artifact Signing needs the **Artifact Signing Certificate Profile Signer** role; certificates are valid only 72 hours, so **timestamping is mandatory** ("time stamping is critical for continued successful validation of a signature beyond that three-day validity period"); and a region/endpoint mismatch "commonly causes a 403 Forbidden error and an internal `SignerSign()` failure."

### 6.3 The `.vsix`

**Be precise about what a `.vsix` is, because there are two incompatible meanings and Microsoft documents the trap.** The `.vsix` container format is shared between **Visual Studio IDE extensions** (installed by `VSIXInstaller.exe`) and **Azure DevOps / VS Code packages**. Microsoft's FAQ:

> "Both ship as `.vsix` files but they aren't interchangeable, and `VSIXInstaller.exe` only supports IDE extensions — running it against the Artifact Signing package fails with a misleading `SignatureState: InvalidSignature` and `System.NullReferenceException`. **The signing certificate is valid; the installer is the wrong tool.**"
> — <https://learn.microsoft.com/en-us/azure/artifact-signing/faq>

**Your `.vsix` is a VS Code/Cursor extension**, produced by `vsce`:

```bash
vsce package        # produces aidr-cursor-<version>.vsix
```

From the VS Code publishing docs (<https://code.visualstudio.com/api/working-with-extensions/publishing-extension>), a `.vsix` is installed with `code --install-extension my-extension-0.0.1.vsix`, and **a `.vsix` is a ZIP archive** — which is why you can run `signtool` over it directly, since SignTool supports "all file types that SignTool supports" and Authenticode applies to any file format.

```powershell
# Sign the VSIX as an opaque blob (valid, and what most pipelines do)
signtool sign /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 `
  "dist\aidr-cursor-1.4.2.vsix"
signtool verify /v /pa "dist\aidr-cursor-1.4.2.vsix"
```

**Untested claim, flagged as such:** signing the `.vsix` container signs the *archive*, not the individual files inside it. Whether VS Code/Cursor surfaces or enforces a VSIX Authenticode signature on install is **NOT VERIFIED**, and I found no Microsoft or VS Code documentation stating that a signed VSIX produces a different install experience. **Do not promise this to customers.** The `.vsix` signature is worth doing for supply-chain integrity (it lets a customer verify the file came from you and was not tampered with), not because it will suppress a SmartScreen prompt. Your customer-facing credibility comes from the signed `.exe`, the Marketplace listing, and publisher verification.

**Related, and worth knowing:** VS Code's Publisher **verified badge** is a separate, arguably more valuable trust signal for enterprise buyers than a VSIX signature. Requirements: "a publisher must have one or more extensions on the VS Marketplace for a **minimum of 6 months**, and the registration of the domain must also be at least 6 months old." — <https://code.visualstudio.com/api/working-with-extensions/publishing-extension>. **Start this clock now** — see §8.

### 6.4 npm packages

npm has its own **provenance/sigstore** mechanism, which is independent of Authenticode. Publishing via GitHub Actions with provenance gives you a verifiable attestation link on the npm package page. That is the correct tool for your npm artifacts, **not** `signtool`. Note that `.exe` files distributed *inside* an npm package still need Authenticode signing separately.

### 6.5 Pipeline shape

Recommended structure for a one-person shop:

```
build (SEA .exe, vsce package)
  └─> sign .exe    (signtool + cloud HSM, or token on a self-hosted runner)
  └─> sign .vsix   (signtool)
  └─> verify       (signtool verify /pa  — FAIL THE BUILD on non-zero exit)
  └─> sha256sum    (publish alongside release)
  └─> publish
```

Two non-negotiables:
1. **`signtool verify` must gate the release.** Signing that silently failed is worse than not signing, because you will believe it worked.
2. **Never modify a signed artifact.** "Do not modify signed files — Avoid modifying files after signing as doing so can break the signature." — <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation>. Never re-zip, re-timestamp, or patch a signed binary; rebuild and re-sign.

**Realistic constraint to plan around:** with a **USB token**, hosted CI (GitHub Actions) **cannot** sign. You need either a self-hosted Windows runner with the token attached, or a **cloud signing service** (SSL.com eSigner, DigiCert KeyLocker). For a one-person startup, choose a CA that offers cloud signing rather than a physical token — it is the difference between automated releases and manually signing on your laptop each time.

**Implemented:** the release and customer-installer workflows no longer need an exportable PFX. `AIDR_WINDOWS_SIGNER` selects `azure-key-vault` (AzureSignTool, GitHub OIDC, no stored secret) or `jsign` (eSigner, DigiCert ONE, Google Cloud KMS, AWS KMS, Azure, PKCS#11 tokens including Certum cryptoCertum); `pfx` remains for local test builds. Every signed file is checked against the pinned certificate thumbprint whatever the backend. Configuration and the Certum purchase steps: [Windows code signing with an HSM-held certificate](../operations/windows-code-signing.md).

---

## 7. Timeline: purchase → first signed build

| Option | Realistic elapsed time | Dominated by |
| --- | --- | --- |
| **Azure Artifact Signing** | **N/A — ineligible** | (If eligible: identity validation "takes from 1 to 20 business days") |
| **OV from a commercial CA** | **1–3 weeks** | Organization validation + **physical token shipping to Turkey + customs** |
| **OV with cloud signing (no token)** | **~3–10 business days** | Validation only — no shipping. **Fastest realistic path.** |
| **EV** | **1–4 weeks** | Heavier validation (§3.2.2.2: legal existence, physical presence, operational existence) + token shipping |

Source for the Artifact Signing figure: "Processing your identity validation request takes from **1 to 20 business days** (possibly longer if we need to request more documentation from you)." — <https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart>. Commercial CAs quote similar or faster issuance *once documentation is complete* — SSL Shopper lists "Within 1 day after all documentation is received" for DigiCert and SSL.com, and "Less than 2 days" for Sectigo (<https://www.sslshopper.com/cheap-code-signing-certificates.html>) — but that excludes the validation queue and, critically, **token shipping**.

**The honest bottleneck is not the CA, it is you.** Validation stalls on documentation mismatch. Have the documents in §5 ready and consistent *before* you order.

**And the timeline to *warning-free* downloads is much longer than the timeline to signing:**

> "It can take **several weeks and hundreds of clean installs from a wide audience**" before the SmartScreen prompt stops.
> — <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation>

So: signed in ~2 weeks; no first-download warning in maybe **2–6 months** of steady distribution. **Sell the former to procurement now; do not promise the latter.**

---

## 8. What to do this week

### Do now, before spending anything (all free)

1. **Test Azure Artifact Signing eligibility — 10 minutes.** Open the Azure portal → Artifact Signing → Identity validation and check whether Turkey appears in the country dropdown. The FAQ points at the prerequisites list as the authority. My research says **no**, but this is the one test that could overturn the entire recommendation. If Turkey *is* available, **stop and buy Artifact Signing Basic at $9.99/month instead** — it is cheaper, token-free, and CI-native.
2. **Fix your naming consistency.** Make your legal entity name identical across: Turkish trade registry, tax records, your website, invoice templates, and the certificate application. Mismatches here cause most validation delays.
3. **Start the VS Code publisher-verification clock.** You need 6 months of extension history **and** a 6-month-old domain. If your extension is not yet published under your final publisher ID, publish it this week — the clock only starts when it is live. (Domain age is likely already satisfied.)

### Buy (this week)

4. **Decide which entity form you are buying as — this determines the whole path.**
   - **No registered company → SSL.com IV Code Signing, ~$129/yr, direct from SSL.com in USD.** No business registration needed; needs your T.C. kimlik kartı or passport, a selfie, and a phone callback. <https://www.ssl.com/products/software-integrity/code-signing/iv/>
   - **Registered limited şirket (or A.Ş.) → get quotes both ways:** Certum Standard Cloud OV via a Turkish reseller (≈₺7,500, TRY invoicing, no token shipping) **and** SSL.com OV direct in USD. Pick on price and on whether you want TRY or USD invoicing.
5. **Ask two CAs these four specific questions** (applications cost nothing — only issuance does):
   - Will you issue to a **Turkish-registered company**, and is a **şahıs şirketi** acceptable as an "organization"?
   - Is **MERSIS / Ticaret Sicil Gazetesi** acceptable as my Reliable Data Source / QIIS listing?
   - Can I use **cloud signing (SSL.com eSigner / Certum SimplySign)** so no physical token ships to Turkey?
   - What is the exact document checklist, and will the **<3-year-old business ID requirement** apply to me?
6. **Skip D-U-N-S for now.** It is an expediter, not a requirement. Your MERSIS / Ticaret Sicil Gazetesi listing is free, official, and already on SSL.com's accepted list. Only pay CRIF Türkiye (dunstalep@crif.com) if a CA specifically rejects your Turkish registry listing.
7. **Do not buy EV.** Per Microsoft, the premium buys no SmartScreen benefit, and it adds notarization and business-listing requirements.

### Build (this week, in parallel — do not wait for the certificate)

7. **Get the signing path working with a self-signed certificate.** Produce a test cert, wire `signtool sign` + `signtool verify /pa` into your build, and make the build **fail** when verification fails. This is the highest-value work you can do before the real certificate arrives, and it means day one with a real cert is a config change, not a project.
8. **Publish SHA-256 checksums for every release** and add a `checksums.txt` + `SHA256SUMS` to your GitHub release. Free, and it is a genuine supply-chain control that enterprise security reviewers ask for.
9. **Write a short "Why you may see a Windows warning" page** on your install docs. Microsoft explicitly recommends this: "**Communicate with early adopters** — for new apps, let beta users know they may see a SmartScreen prompt on first download, and that they should only proceed after verifying the publisher and confirming they trust the download source." Include the expected publisher name, the SHA-256, and a reporting address. This converts a scary prompt into a documented step, and it is exactly what a procurement reviewer wants to see.

### Do not expect these to work (verified dead ends)

10. **Building SmartScreen reputation without a certificate: not possible for a `.exe`.** Microsoft is unambiguous: "When a file is not signed, SmartScreen reputation must build for each new version of your files, starting from zero reputation. Reputation cannot transfer from previous versions unless both were signed using the same publisher identity." There is no mechanism to accumulate reputation unsigned.
11. **Submitting to Microsoft for reputation review: not available to you.** "**There is no need (or mechanism) to manually submit a file for SmartScreen reputation review for consumer endpoints.** Reputation builds organically through download volume." The one exception is enterprise-managed fleets: "Enterprise IT administrators may optionally submit files for review via the Microsoft Security Intelligence portal. This can accelerate trust for internal or managed deployments." — <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation>. **This is still worth doing**, just not for the reason you might think: submit your *signed* build to <https://www.microsoft.com/en-us/wdsi/filesubmission> as a **software developer** — the portal has a dedicated "Software developer — Software providers wanting to validate detection of their products" persona. Its real value is **clearing false-positive malware detections**, which a security tool will hit. It is not a reputation shortcut.
12. **Do not ship a self-signed certificate.** "Not trusted by Windows by default and will trigger a strong SmartScreen block for any user who hasn't manually installed the certificate as a trusted root." Strictly for dev/test.

### The one alternative distribution route

13. **Consider the Microsoft Store (MSIX).** It is free, and "Store-distributed apps are signed by a Microsoft certificate and are **never subject to SmartScreen download warnings**." For a security/dev tool that needs CLI access this is usually impractical, and MSIX packaging has real constraints — but if AIDR ever gains a GUI component, this is the only route to genuinely warning-free installation. MSI/EXE Store submissions are **not** re-signed by Microsoft, so that path still requires your own certificate.

---

## 9. What I could NOT verify

Stated explicitly so you can judge the confidence of each claim:

| Item | Status |
| --- | --- |
| **Certum's own prices** | ❌ **NOT VERIFIED** (direct). Storefronts return only nav chrome; support KB is JS-rendered. A Turkish reseller price (₺7,500) was found instead — get a written quote. |
| **Certum's formal country list / CPS text** | ❌ **NOT VERIFIED.** All `certum.eu/servlet/...` CPS PDF paths 404'd. The Turkey claim rests on their live product table plus active Turkish resale, **not** policy text. |
| **SSL.com OV/Sectigo/DigiCert eligibility for a Turkish applicant** | ✅ **Substantially resolved.** SSL.com names Turkey explicitly and accepts MERSIS / Ticaret Sicil Gazetesi. DigiCert/Sectigo/GlobalSign have no Turkey restriction, but see the row below. |
| **Whether MERSIS / Ticaret Sicil Gazetesi are accepted by DigiCert, GlobalSign or Sectigo** | ❌ **NOT VERIFIED** — only SSL.com names them; the others use generic "official government registry databases" phrasing. |
| **Whether a Turkish *şahıs şirketi* counts as an "organization"** at DigiCert/Sectigo/GlobalSign | ❌ **NOT VERIFIED.** No CA page addresses Turkish entity types. **Ask the CA directly.** This determines whether you need Path A or Path B in §5.3. |
| **Whether SSL.com IV is explicitly available in Turkey** | ⚠️ **NOT VERIFIED verbatim.** The product page and accepted-country list are both satisfied, but no page says so in those words. Confirm with sales. |
| **Sectigo OV for natural persons** | ❌ **NOT VERIFIED.** Sectigo's "cannot be issued to individuals" statement is specifically about **EV**. |
| **GlobalSign and SSL.com own-site list prices** | ❌ **NOT VERIFIED** (JS-rendered). SSL.com/DigiCert/Sectigo figures in §4 are **reseller/aggregator** prices. |
| **Turkish reseller TRY prices** | ⚠️ **Single-source** (kodimza.com), from a delegated research pass. Get written quotes. |
| **Exact CRIF Türkiye D-U-N-S fee** | ❌ **NOT VERIFIED** — paid service, price on application. |
| **Turkish foreign-currency payment restrictions** | ❌ **NOT VERIFIED.** No evidence of a prohibition found; government sites returned empty content. Confirm with your accountant. |
| **Whether a signed `.vsix` changes install behavior in VS Code/Cursor** | ❌ **NOT VERIFIED.** No documentation found. Do not make customer claims about it. |
| **Exact per-CA document checklist** | ⚠️ **PARTIAL.** §5.3 derives from SSL.com's published requirements plus CA/B Forum rules, not a per-CA published list. |
| **SSL.com QIIS / IV page wording** | ⚠️ **Delegated, not re-verified.** SSL.com's pages could not be re-fetched (mega-menu consumed the fetch budget). Spot-check the quotes in §5.1–§5.2 yourself. |
| **Azure Artifact Signing's 3-year-business-history rule** | ⚠️ **Could not find this rule in current sources.** The documented gates are geography, identity validation, and a paid subscription. Moot regardless — geography already excludes you. |
| **`web_search`** | ❌ Unavailable all session (missing API key). All findings come from direct URL fetches, so secondary-source coverage is narrower than a full search would give. |

---

## 10. Bottom line

| Decision | Answer |
| --- | --- |
| **Is it even possible from Turkey?** | ✅ **Yes.** Turkey is absent from every CA restricted-country list found, and SSL.com accepts MERSIS / Ticaret Sicil Gazetesi as validation evidence. The real gate is **entity type**, not country. |
| **Buy — no registered company** | **SSL.com IV Code Signing, ~$129/yr**, direct in USD. No business registration required. |
| **Buy — registered limited şirket** | **Certum Standard Cloud OV via a Turkish reseller (≈₺7,500)** *or* **SSL.com OV direct (~$129)**. Get both quotes. |
| **Runner-up** | **Azure Artifact Signing** ($9.99/mo) — cheaper and better, but **Turkey is not on the eligible country list** |
| **Don't buy** | **EV.** Microsoft: the SmartScreen bypass was removed; the premium "is no longer justified". Also adds notarization/business-listing requirements. |
| **Don't bother with** | **Kamu SM / e-imza** (no Code Signing EKU — verified against Microsoft's CCADB report), **E-Tuğra** (distrusted since 15 Sept 2025), **D-U-N-S** (an expediter, not a requirement) |
| **Budget** | **~$129/yr**, or ~₺7,500 via a Turkish reseller. Cloud signing avoids token shipping and customs. |
| **Time to first signed build** | **~1–3 weeks** (faster with cloud signing; slower if a token must ship to Turkey) |
| **Time to warning-free downloads** | **Weeks to months** of real download volume — signing does not make the warning disappear |
| **What signing actually buys you** | A **named publisher** instead of "Unknown Publisher", a signature that **survives expiry** (with timestamping), **publisher reputation that carries across versions**, and — the real win — **enterprise policy that no longer blocks you outright** |
| **Do this week** | Test Azure eligibility (expect no) · decide entity path · get Certum-reseller and SSL.com quotes · start VS Code publisher-verification clock · build the signing path with a self-signed cert · publish checksums · write the warning-expectation page |

**The blunt version:** you are not excluded by your country — you are excluded by Azure's geographic list and, at some CAs, by not being a registered organization. Buy **SSL.com IV** if you have no company, or **Certum OV via a Turkish reseller** if you do. Skip EV, skip D-U-N-S, and skip Turkish domestic CAs for Authenticode. Then start the reputation clock as early as possible — the certificate is quick, but the reputation that removes the warning takes months, and it only starts accumulating once you are signing.
