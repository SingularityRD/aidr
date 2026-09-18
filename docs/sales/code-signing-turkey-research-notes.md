# Publicly-Trusted Code Signing Certificate for a One-Person Turkish Software Company (2026)

**Research date:** 2026 · **Method:** `web_fetch` + PowerShell `Invoke-WebRequest` (JS-render bypass) + Wayback Machine CDX API. `web_search` was **unavailable** (API key error) for the entire session; all findings come from direct page fetches.

---

## HEADLINE ANSWER

**YES — a Turkey-based one-person software company CAN buy a publicly-trusted code signing certificate in 2026.**

- **Turkey is not restricted by any CA examined.** It is absent from every embargoed/restricted country list found.
- **SSL.com is the strongest fit and explicitly supports Turkish applicants**: it publishes Turkey (TR) on its accepted-country list, and it names **both** `MERSIS` and the **Turkish Trade Registry Gazette** as acceptable validation data sources.
- **SSL.com IV Code Signing ($129/yr) requires no business entity at all** — only the founder's government photo ID. This is the single most important finding for a solo founder.
- The widely-feared "Turkey problem" does **not** exist at the country level. Where a blocker does exist, it is **entity type** (DigiCert/Sectigo/GlobalSign sell only to registered organizations), not nationality.

---

## 1. COUNTRY ELIGIBILITY, PER CA

### SSL.com — ✅ TURKEY SUPPORTED AND EXPLICITLY NAMED

**Official accepted-country list includes Turkey:**
- Source: https://www.ssl.com/country_codes/ — table entry `Turkey | TR`.
- The page states: *"SSL.com complies with U.S. law and therefore accepts the following two-letter ISO-3166 country codes."*
- The same page's **"Restricted Countries Listing"** is exactly four countries: **Cuba (CU), Iran (IR), North Korea (KP), Syria (SY)**. Turkey is **not** among them.

**Turkish registry sources are named as valid validation evidence (this is the decisive find):**
- Source: https://www.ssl.com/blogs/acceptable-business-listings-for-validation/
- The QIIS list includes verbatim:
  - **`MERSIS (https://mersis.gtb.gov.tr/#)`**
  - **`Turkish Trade Registry Gazette (www.ticaretsicil.gov.tr)`**
- These appear under **"For OV and EV Certificates"** — i.e. accepted for both OV and EV code signing, not merely the weaker tiers.
- Source: https://www.ssl.com/how-to/validation-process-for-document-signing-code-signing-and-ev-code-signing-certificates/ — the organization-validation tab lists **"Turkish Trade Registry Gazette"** among acceptable Reliable Data Sources, alongside Dun & Bradstreet, Hoovers, Companies House, etc.

### DigiCert — ✅ NOT RESTRICTED
- Source: https://knowledge.digicert.com/solution/embargoed-countries-and-regions (SO101120141837, last modified 04/26/2026): *"Due to U.S.-imposed sanctions, DigiCert is legally prohibited or restricted from offering its products and services to specific countries or regions."*
- Full list: Cuba, Iran, North Korea, Syria (embargoed); Crimea/Donetsk/Luhansk (regions); Russia, Venezuela, Belarus (sectoral/high-risk). **Turkey appears nowhere.**
- ⚠️ But DigiCert is **organization-only** — see §2.

### GlobalSign — ✅ NOT RESTRICTED
- No per-country sell list is published. Only an internal sanctions policy exists: https://www.globalsign.com/en/repository/GlobalSign-sanctions-policy-v2.pdf ("GMO GlobalSign Public Sanctions Policy", © 2023) — defines "restricted territory/restricted party" but **does not enumerate Turkey**.
- ⚠️ GlobalSign is **organization-only in 2026** — its Individual Code Signing product was retired. See §2.

### Sectigo — ✅ NOT RESTRICTED (no list found)
- No published restricted-country list located in the Sectigo knowledge base (searched the 442-article index, the 25-article Code Signing category, and the 15-article Code & Document Signing category).
- International shipping **is** supported: https://www.sectigo.com/knowledge-base/detail/EV-Document-Signing-Certificate-Token-FAQ (updated 08/08/2026): *"**What happens if my token is held at customs?** If your token is held at customs, you are responsible for paying any required duties, taxes, or customs fees before the shipment can be released."*
- ⚠️ Sectigo is **organization-only** — see §2.

### Certum (Poland, Asseco) — ✅ Sells to individuals AND companies; no Turkey exclusion found
- Source: https://www.certum.eu/en/code-signing-certificates/ — Certum's own comparison table states the **Standard** tier's purpose is *"Code signing for an individual **or** a company"*, with certificate data being *"First and Last Name / Company Name"*. The **EV** tier is org-only: *"Company Name"*.
- Certum's FAQ on the same page: *"EV Code Signing differs from OV primarily in the scope and rigor of the validation process... the certificate is available only to registered companies. **OV certificates involve a simpler validation process and can also be issued to individuals.**"*
- **NOT VERIFIED: Certum publishes no country-by-country sell list I could retrieve.** I attempted the Certum CPS PDFs (multiple `certum.eu/servlet/...` and `upload_module` paths → all 404), the resellers map (fetch failed), and the documents/repository pages (intermittent). I did **not** find any page excluding Turkey. Certum has a **Turkish reseller network** actively selling its code signing products (see §5), which is strong practical evidence Turkey is served.

### Summary table

| CA | Turkey restricted? | Individual / sole-proprietor SKU? | Publicly trusted Authenticode? |
|---|---|---|---|
| **SSL.com** | ✅ No — on accepted list | ✅ **YES — IV ($129/yr)** and Sole Proprietor EV | ✅ Yes |
| **DigiCert** | ✅ No | ❌ No — organization only | ✅ Yes |
| **GlobalSign** | ✅ No | ❌ **Retired ~April 2021** | ✅ Yes |
| **Sectigo** | ✅ No | ❌ No — organization only | ✅ Yes |
| **Certum** | ✅ No exclusion found | ✅ **YES — Standard/OV to individuals** | ✅ Yes |
| Kamu SM (TÜBİTAK) | N/A (domestic) | — | ❌ **NO** (see §5) |
| E-Tuğra | N/A (domestic) | — | ❌ **NO** — distrusted (see §5) |

---

## 2. INDIVIDUAL vs ORGANIZATION

### The legal framework permits individuals; most CAs choose not to sell it
- **CA/Browser Forum Code Signing Baseline Requirements v3.11.0 (June 16, 2026)**, https://cabforum.org/working-groups/code-signing/requirements/:
  - *"**Individual:** A natural person."*
  - *"**Individual Applicant:** An Applicant who is a natural person and requests a Certificate that will list the Applicant's legal name as the Certificate's Subject."*
  - §3.2.3: *"Prior to issuing a Code Signing Certificate to an **Individual Applicant**, the CA MUST verify the Subject's Identity..."*
  - §3.2.3.1 requires government photo ID (passport / driver's licence / national ID) plus address verification via *"a government-issued photo ID, a QIIS or QGIS, or an access code"*.
- So the "organization **or** verified individual" branch is real in the BRs — **but DigiCert and Sectigo sell no such product, and GlobalSign retired its individual product.**

### SSL.com IV — the best option for a Turkish solo founder
- Product page: https://www.ssl.com/products/software-integrity/code-signing/iv/
- **Price: $129.00/yr.** (Token/validation fee included; the page shows a $599.00 priority-validation option elsewhere on the page.)
- **No business registration required.** Verbatim from the page:
  - *"Independent developers shipping tools, utilities, command-line apps, and personal projects under a verified individual name: the IV tier gives **solo developers access to Authenticode signing without a business entity**."*
  - *"Put your verified personal name on every installer: **no business registration required, issued in minutes**."*
- *"Trusted on all Windows versions — IV certificates are trusted for Microsoft Authenticode executable signing across Windows 11, Windows 10, Windows Server 2025, Server 2022, Server 2019, and every earlier supported Windows release."*
- Issued under *"current CA/Browser Forum Code Signing Baseline Requirements with all ballot resolutions applied. Hardware-backed private keys per the June 2023 key storage mandate."*
- ⚠️ **Limitation:** IV covers **Windows Authenticode only**. The FAQ states macOS signing requires Apple Developer ID. IV also does **not** grant immediate SmartScreen reputation and is **not** eligible for kernel-mode driver signing (that needs EV).

### SSL.com Sole Proprietor EV — EV trust without a registered entity
- Guide: https://www.ssl.com/guide/sole-proprietor-ev-application/
- Verbatim: *"Most Sole Proprietors do not register their companies with a government entity. This practice creates a validation problem. Without proof of existence... Sole Proprietorships will not meet the requirements for Extended Validation."*
- *"SSL.com's remedy is to add a **Personal Identity Verification Form** which, along with the other standard EV requirements, will enable a sole proprietorship to meet the requirements for an EV certificate. **This form requires either a notary seal with a currently registered notary, a registered CPA seal, or an active attorney signature.**"*
- ⚠️ **Important caveat from the same page:** *"All entities that apply for an EV code signing certificate must appear in a qualified independent business listing service such as Dun & Bradstreet and government business listings."* So **Sole Proprietor EV still requires a QIIS listing** — a Turkish sole trader would use MERSIS / Trade Registry Gazette. The plain **IV product does not carry this requirement.**

### GlobalSign — ⚠️ INDIVIDUAL PRODUCT RETIRED
- Wayback CDX status codes prove retirement:
  - `globalsign.com/en/code-signing-certificate/code-signing-for-individual-developers/` → **20210420053610, statuscode 301**
  - `.../buy-code-signing-for-individual-developers` → **20210420053604, statuscode 404**
- Current KB is organization-only: https://support.globalsign.com/code-signing/general-information/code-signing-faq (dated **May 25, 2026**): *"**Standard Code Signing Certificates undergo standard organization validation.** EV Code Signing Certificates undergo strict Extended Validation vetting requirements set by the CA/B Forum."* The words "individual" and "sole proprietor" appear nowhere in the current Code Signing FAQ.
- Conclusion: **GlobalSign is not a route for a natural person in 2026.**

### DigiCert — organization only
- https://docs.digicert.com/en/certcentral/manage-certificates/code-signing-certificates/order-a-code-signing-certificate.html (last modified Aug 4, 2026): *"The organization must be active and validated for code signing in your account."* / *"For Code Signing certificates, the required validation type is **CS — Code Signing Organization Validation**."*
- https://knowledge.digicert.com/general-information/code-signing-certificate-faqs (INFO1119): *"a Code Signing certificate is tied to your **Organization Name** only."*

### Sectigo — organization only, stated emphatically
- https://www.sectigo.com/knowledge-base/detail/extended-validation-ev-code-signing-certificates-what-to-expect-during-validation (updated **May 29, 2026**): *"**EV Code Signing certificates are issued only to verified organizations, such as registered businesses, private organizations, international organizations, and government entities. They cannot be issued to individuals.**"*

---

## 3. DOCUMENT CHECKLIST FOR A TURKISH APPLICANT

### Path A — SSL.com IV Code Signing (recommended for a solo founder, no company needed)
Source: https://www.ssl.com/faqs/ssl-ov-validation-requirements/ (IV Documentation section)
1. Scan of the **front** of a valid government-issued photo ID card or passport ID page — *"The ID number may be obscured, but we must be able to see your name, address, year of birth, and photograph."* → **Turkish national ID (T.C. kimlik kartı) or passport both work.**
2. Scan of the **back** of the ID / passport ID page.
3. A **selfie holding the ID next to your face**, *"at least 5 megapixels."*
4. Automated AI identity verification (SSL.com's tool) is offered as an alternative to manual submission.
- Note: a **successful callback to a verified telephone number is still required** — *"A successful contact via a verified telephone number is required to issue an OV or IV certificate."*

### Path B — SSL.com OV Code Signing (registered company)
Source: https://www.ssl.com/how-to/validation-process-for-document-signing-code-signing-and-ev-code-signing-certificates/
- **A link to a Reliable Data Source** showing the organization's **name, address, and telephone number**. Accepted Turkish sources include:
  - **Turkish Trade Registry Gazette** — https://www.ticaretsicil.gov.tr
  - **MERSIS** — https://mersis.gtb.gov.tr
  - (or Dun & Bradstreet, ZoomInfo, Crunchbase, OpenCorporates, etc.)
- *"In most cases, businesses and organizations will not need to upload documents to their order, but can simply provide a URL."*
- **⚠️ For OV Code Signing specifically: *"if the business or organization is less than three years old, a scan of the certificate requestor's government-issued ID is also required."*** → **This applies to most new one-person Turkish companies.**
- Registration Number, Registered Country, Company, Address, City, Postal Code are required ordering fields.

### Path C — SSL.com EV Code Signing (registered company, highest tier)
- Signed **EV Subscriber Agreement** + signed **EV Authorization Form**.
- **One of:** Articles of Incorporation/Registration **or** a link to a government website listing the organization.
- **One or more of:** D-U-N-S number; a business profile from another QIS such as ZoomInfo, Crunchbase, OpenCorporates; **or an attestation letter from a licensed professional** (attorney, accountant, or civil-law/Latin notary) — SSL.com publishes sample legal-opinion and CPA letters.
- Roles must be named: **Contract Signer** (must be an officer — CEO, President, Director, Managing Member, etc.), **Certificate Requester**, **Contract Approver**. For a one-person company these can all be the same person ("Same as Contract Signer" checkbox).
- Identity verification of those individuals via SSL.com's **AI Identity Verification**.

### Path D — Turkish company documents demanded by Turkish resellers
Per Turkish reseller guidance (see §5): **ticaret sicil gazetesi** (Trade Registry Gazette extract), **vergi levhası** (tax plate/certificate), and the authorized person's **photo ID**. The **VKN** (Vergi Kimlik Numarası, tax number) is the company tax identifier; **TCKN** is the personal one.

### Documents NOT confirmed as required
- **Articles of association** — only requested by SSL.com for **EV**, and only as an alternative to a government-website link. Not required for IV or OV.
- **Proof of address as a separate utility bill** — SSL.com relies on the ID itself (IV) or the registry/QIIS record (OV), not a separate utility bill.
- **Domain whois** — the standard documents list for **code signing** does not mention whois. Domain validation requirements (whois/email/DNS/CSR-hash) apply to **SSL/TLS** certificates, not to code signing identity validation. (NOT VERIFIED that a whois record is ever requested for code signing specifically.)
- **Passport specifically** — not required; Turkish national ID is acceptable since it shows name, address, DOB and photo.

---

## 4. THE PHONE NUMBER / DIRECTORY LISTING (QIIS) PROBLEM

### Is it real? Yes — but it is about the **phone number**, not the D-U-N-S number.

**SSL.com** (https://www.ssl.com/blogs/acceptable-business-listings-for-validation/):
- *"As a primary method to perform CA validations is over the phone... This process is **mandatory for OV and EV certificates**."*
- *"In order to successfully complete a call back, you will need to have an **approved contact number provided for by any Qualified Independent Information Source**."*
- *"**Dun & Bradstreet is regarded as the primary source for a contact number** because it is highly reputable as a QIIS."*
- ⚠️ **Critical relief clause:** *"In case that an independent source of your number does not appear on our list, **you may provide a link to a listing that you do appear in to your validation contact for potential approval**."*

**DigiCert** (https://knowledge.digicert.com/general-information/ssl-tls-order-validation-faq, INFO1572, 04/26/2026):
- *"**DigiCert must obtain an independently verified telephone number for the organization (e.g. using reliable online telephone directories) and calling that number** to ensure that we can get through to the Organizational Contact. If we are unsuccessful in obtaining a valid third-party telephone number for the organization, we will send an e-mail to the Organizational Contact with alternate options."*

**Sectigo** (https://www.sectigo.com/knowledge-base/detail/extended-validation-ev-code-signing-certificates-what-to-expect-during-validation, 05/29/2026):
- *"A verified, working business phone number and/or email address listed in reliable third-party public data sources or government sources."*
- Also: *"**PO Boxes, virtual offices, mail forwarding addresses, or registered agent addresses are not accepted.**"* → a home address used as a registered office is a risk; a virtual office is explicitly disqualified.

**Why it bites a small Turkish company:** a newly formed one-person Turkish company will typically **not** yet appear in Dun & Bradstreet, and may have no landline listed anywhere public. The CA cannot complete the mandatory callback.

### Do you need a D-U-N-S number?
**No — a D-U-N-S is not strictly required, but it is the path of least resistance.**
- **No CA examined states a D-U-N-S number is mandatory.** It is consistently described as a convenient/expediting option. In SSL.com's words, entering it *"helps SSL.com expedite validation and certificate issuance."*
- **SSL.com accepts Turkish government registries instead**: MERSIS and the Turkish Trade Registry Gazette are both on the published QIIS list, accepted for **OV and EV**.

### How to get a D-U-N-S number in Turkey (if you choose that route)
- **CRIF Türkiye is the sole authorized Dun & Bradstreet representative in Turkey.** Source: https://www.crif.com.tr/duns-numarasi — *"Türkiye'deki tek yetkili DUNS Numarası sağlayıcı olan CRIF Türkiye"* ("CRIF Turkey, the sole authorized DUNS Number provider in Turkey"). Applications via **dunstalep@crif.com**.
- The route is **paid**. CRIF's own request-form dropdown for reason ("Talep Nedeni") lists Google Developer, Apple Developer, FDA-SAM, tender participation, supplier/customer request, update, other — **there is no "code signing" option**.
- Dun & Bradstreet's global free request form is https://www.dnb.com/duns-number/get-a-duns.html (page title confirmed via Wayback: "Claim Your Free D-U-N-S Number"), **but**:
  - **NOT VERIFIED: whether that free form serves Turkey end-to-end** or redirects to CRIF. `dnb.com` returns **HTTP 403** to direct requests from this environment, and its JS bundle contains no "Turkey" string.
  - **NOT VERIFIED: the exact CRIF fee** — no public price list found.
- Commercial brokers (duns.com.tr, dunshelp.com, dunsturkiye.com) are **paid intermediaries, not official**. No Turkish government body (TOBB, TÜİK, chambers) issues D-U-N-S numbers.

### ✅ The practical recommendation for the phone problem
1. **Use SSL.com IV** — for the individual route there is **no organization directory listing requirement at all**; only your personal ID plus a callback to a verified number you control.
2. If you go the OV route, **register the company's phone number through MERSIS / Ticaret Sicil Gazetesi** (free, official, and already on SSL.com's QIIS list), and use a **real landline or a mobile number published on your own domain and registry record**. Do **not** rely on a virtual office (Sectigo explicitly rejects them).
3. Only pay CRIF for a D-U-N-S if a specific CA rejects your Turkish registry listing.

---

## 5. TURKEY-SPECIFIC RESELLERS AND DOMESTIC CAs

### Turkish resellers — the market is real and active
Turkish resellers publish live TRY prices for exactly the brands discussed above:

| Reseller | Notes |
|---|---|
| **kodimza.com** | Publishes TRY prices: Sectigo OV ₺20,000; Sectigo EV ₺25,000; GlobalSign OV ₺30,000; GlobalSign EV ₺41,000; DigiCert EV ₺33,750; **Certum Standard Cloud OV ₺7,500**; **Certum Open Source Cloud ₺4,500**; Certum Cloud EV ₺13,250–15,250 |
| **elektronikssl.com.tr** | Same brand set; DigiCert OV ₺26,500; GlobalSign HSM ₺27,000 |
| **kodimzalama.com**, **kodimza.com** | Code-signing specialists |
| **ihs.com.tr**, **nettrust.com.tr**, **atakdomain.com** | General SSL/security resellers |
| **globalsign.com.tr** | GlobalSign Turkey, +90 212 266 8930 |
| **tr.comodo.com** | Sectigo/Comodo Turkey |
| **sslsertifikasi.com.tr** | SSL reseller |

- **Required documents per Turkish reseller guidance:** **ticaret sicil gazetesi** (Trade Registry Gazette), **vergi levhası** (tax plate), and photo ID of the authorized signatory. EV requires more.
- **isimtescil.net does NOT sell code signing** — only SSL/TLS. Verified by live page check and a Wayback CDX sweep. (It is a common assumption that it does; it doesn't.)

### ❌ Kamu SM (TÜBİTAK BİLGEM) — NOT publicly trusted for Authenticode — VERIFIED
This was **verified from primary data, not assumed**:
- Microsoft's authoritative code-signing trust list — `MicrosoftCodeSigningCSV` from the CCADB reports (`https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=MicrosoftCodeSigningCSV`) — parses to **69 rows, 18 CA owners, and ZERO Turkish CAs.**
- Kamu SM's root **is** in the Microsoft Trusted Root Program, but only for TLS: the root is literally named **"TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1"** ("SSL Root Certificate") with EKUs **"Server Authentication; Client Authentication"** only. Its e-imza intermediate is marked **"Not Trusted"**.
- **There is no Code Signing EKU anywhere in the Kamu SM hierarchy.**
- **Conclusion: Kamu SM e-imza / "nitelikli elektronik sertifika" certificates are NOT publicly trusted for Windows Authenticode code signing.** They remain valid for domestic Turkish legal e-signature purposes (e-Devlet, KEP, official documents) — that is a different trust domain from the Microsoft Authenticode program.

### ❌ E-Tuğra — DISTRUSTED and no longer sells code signing — VERIFIED
- Chrome: **"Removed"**; Mozilla: **"Removed"**; Apple: **"Not Included"**; legacy root: **"Disabled"**.
- Microsoft: both v3 roots (RSA v3, ECC v3) have status **"NotBefore"**, and Microsoft's 27 Aug 2025 deployment notice sets **NotBefore = 15 September 2025** — i.e. certificates issued after that date are not trusted.
- Cause: security disclosures at https://ian.sh/etugra; Chrome's Q2 2023 summary confirms they *"distrusted the e-Tugra root certificates after a researcher discovered significant security issues in their systems."*
- E-Tuğra's live site (e-tugra.com.tr, fetched 2026) sells only **E-İmza, KEP, SSL, Zaman Damgası** — **no code signing product at all**.
- **E-Tuğra is not an option.**

### ✅ Practical reseller conclusion
Turkish resellers can sell you a **Certum** or **Sectigo/DigiCert/GlobalSign** code signing certificate with Turkish-language support and TRY invoicing — and Certum's OV tier (**"org **or** individual"**) is the cheapest organization/individual-flexible legitimate route at roughly **₺4,500–7,500**. **No Turkish reseller sells SSL.com's IV or Sole Proprietor EV products**, so those must be bought directly from SSL.com in USD.

---

## 6. PAYMENT / BILLING

### SSL.com — payment methods (verified from their own page)
Source: https://www.ssl.com/purchase-orders/
- *"We currently accept **Visa/Mastercard, American Express, Discover and Paypal**. We also accept the following **wire transfer**: JPMorgan Chase Bank, N.A. Routing: 021000021, Account: 786679550, **SWIFT: CHASUS33**."*
- **Purchase Orders and quotes are accepted** — PO can be emailed to Sales@SSL.com or faxed to 832-201-7706; an RFQ form is provided. This matters for a Turkish company that needs an invoice before paying.
- SSL.com prices in **USD**.

### Practical considerations for paying a foreign CA from Turkey
- A **Turkish-issued credit card can generally be used for USD purchases**, but expect the card issuer to apply the **TCMB (Central Bank) foreign-exchange rate plus a commission**, and to enforce any FX/installment restrictions the issuer applies to foreign-currency transactions.
- A **wire transfer in USD** via SWIFT (as SSL.com publishes) is the fallback and works from Turkish banks, but carries correspondent-bank fees and requires the bank to process a foreign-currency transfer for a services import.
- Turkish companies importing services normally handle this through the standard **service-import (hizmet ithali)** flow; a Turkish accounting firm can advise on the exact documentation.
- ⚠️ **NOT VERIFIED:** I could **not** verify the specific current Turkish foreign-currency payment restrictions or the exact TCMB/HMB rules that might apply, because the relevant regulator pages did not yield retrievable text within scope (`hmb.gov.tr` returned an effectively empty page; `tcmb.gov.tr` returned only navigational content; `mevzuat.gov.tr` returned a 4,273-line index without the relevant regulation body). **This should be confirmed with a Turkish accountant or the applicant's bank.** No evidence of an actual *prohibition* on paying a foreign CA was found — only ordinary FX mechanics.
- ⚠️ **Also note:** physical USB tokens shipped to Turkey are subject to **customs duties/VAT**. Sectigo states the customer bears these: *"If your token is held at customs, you are responsible for paying any required duties, taxes, or customs fees."* **SSL.com's eSigner cloud signing avoids shipping a token entirely** — relevant if customs friction matters.

---

## RECOMMENDED PATH FOR A TURKISH ONE-PERSON SOFTWARE COMPANY

| If you are… | Best option | Why |
|---|---|---|
| **Solo founder, no company registered** | **SSL.com IV Code Signing, $129/yr** | No business registration required; only government photo ID + selfie; issued in minutes; explicitly accepted for Turkey |
| **Solo founder, wants EV / kernel drivers / instant SmartScreen** | **SSL.com Sole Proprietor EV** | No registered entity needed, but requires a **notarized/CPA/attorney-sealed Personal ID Form** *and* a QIIS listing |
| **Registered Turkish company (limited şirket), cheapest** | **Certum Standard OV via a Turkish reseller (~₺4,500–7,500)** | Real Microsoft code-signing participant; OV tier accepts individuals or companies; TRY invoicing; Turkish-language support |
| **Registered Turkish company, want a US CA direct** | **SSL.com OV Code Signing** | Turkey on accepted-country list; MERSIS + Trade Registry Gazette on the QIIS list; note the **<3-year-old company ID requirement** |
| **Registered Turkish company, brand-name CA** | **DigiCert / Sectigo / GlobalSign OV or EV** | Turkey not restricted — but **organization only**, and you must satisfy a directory + callback requirement |

**Avoid:** Kamu SM (no Code Signing EKU), E-Tuğra (distrusted, no product).

**Universal 2026 constraints:** certificates are capped at **~458–460 days** (CA/B Forum Ballot CSC-31, effective ~1 March 2026; SSL.com began enforcing 458 days on 27 Feb 2026) and **private keys must be hardware-backed or in a cloud signing service**. Budget for the token customs cost or use cloud signing.

---

## COULD NOT VERIFY

1. **Turkish-language documentation specifically about QIIS mechanics** for code signing — no Turkish source found that discusses QIIS/directory-listing requirements in depth.
2. **The exact CRIF Türkiye fee** for a D-U-N-S number — no public price list located.
3. **Whether dnb.com's free D-U-N-S request form serves Turkey end-to-end** or redirects to paid CRIF. `dnb.com` returns **HTTP 403** to direct requests here, and its JS bundle contains no "Turkey" string.
4. **Whether a Turkish chamber of commerce (TOBB/İTO) offers any D-U-N-S route** — no evidence found; TOBB appears to run only the Trade Registry Gazette.
5. **Certum's current published country list / CPS applicant-eligibility text.** Multiple CPS PDF URLs (`certum.eu/servlet/...`, `upload_module/...`) returned 404; the resellers-map and repository pages failed intermittently. No Turkey exclusion was found, and Certum products are actively resold in Turkey, but the policy text itself was not retrieved.
6. **GlobalSign's current (2026) sanctions policy PDF** — only a 2023 Wayback capture was retrievable; the domain blocks direct fetch.
7. **GlobalSign per-country document checklist for Turkey** — no public table exists.
8. **Sectigo's country-by-country accepted-documents table** — its KB link now redirects to a generic blog post; the historical table survives only in old Wayback captures.
9. **D-U-N-S as a hard requirement at any CA** — no CA page states it is mandatory; searched DigiCert's full 827-URL KB sitemap and found no such article.
10. **Whether MERSIS / Trade Registry Gazette are accepted by DigiCert, GlobalSign, or Sectigo** — only **SSL.com** names them explicitly. The other three use generic phrasing such as *"official government registry databases"* and *"the Incorporating or Registration Agency in the Applicant's Jurisdiction."*
11. **Whether a Turkish *şahıs şirketi* (sole proprietorship) is treated as an "organization"** by DigiCert/Sectigo/GlobalSign — no CA page addresses Turkish entity types. **This must be asked of the CA directly.**
12. **Current Turkish foreign-currency payment restrictions** applicable to buying a foreign digital service — regulator pages did not yield retrievable text in scope.
13. **Whether SSL.com's IV Code Signing is available to applicants in every accepted country** — the product page confirms no business entity is needed and Turkey is on the accepted-country list, but **no page explicitly states "IV is available in Turkey."** Confirm with SSL.com sales before purchase.
14. **Sectigo's OV tier and natural persons** — Sectigo's explicit "cannot be issued to individuals" quote is specifically about **EV**. Whether its **OV** tier accepts a natural person is **NOT VERIFIED**; its product page frames OV as "Organization Validation."
