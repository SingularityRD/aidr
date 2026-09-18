# Windows Code Signing — Purchase Guide for Singularity AIDR

**For:** one-person Turkish startup, limited budget, needs enterprise procurement credibility
**Product:** Singularity AIDR — Node.js SEA `.exe` + VS Code/Cursor `.vsix` + npm packages
**Research date:** 2026 (all sources fetched live; URLs cited inline)
**Author's note on method:** `web_search` was unavailable in this session (missing API key), so every claim below comes from a direct `web_fetch` of the cited URL. Where a price could not be retrieved, it is marked **NOT VERIFIED** rather than estimated.

---

## 1. Recommendation

### Recommendation: buy an **OV (Organization Validation) code signing certificate** — do not chase EV, do not count on Azure Artifact Signing.

**Runner-up: Azure Artifact Signing** — but almost certainly *not available to you*, which is the single most important finding in this document. Read §3 before you spend anything.

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

| Vendor | Product | Price / year | Source tier | SmartScreen | Token / HSM | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| **SSL.com** | OV Code Signing | **$129.00** | Aggregator (SSL Shopper "Price For 1 Year") | Builds over time | Token or eSigner cloud | Cheapest verified OV. Houston, TX. Sells internationally. |
| **SSL.com** | EV Code Signing | **$349.00** | Aggregator | **Same as OV** | Token or eSigner cloud | Only worth it if a specific customer demands EV |
| **Sectigo** | OV Code Signing | **$313.50** (list $379) | Reseller storefront | Builds over time | **Token = separate paid line item** | Standard Validation "Available for organizations and for individual developers" |
| **Sectigo** | EV Code Signing | **$410.85** (list $498) | Reseller storefront | **Same as OV** | Token = separate line item | |
| **DigiCert** | OV Code Signing | **$434.00** | Aggregator / reseller | Builds over time | KeyLocker cloud, or shipped eToken, or BYO token | **Does not publish list prices** — configurator only |
| **DigiCert** | EV Code Signing | **$608.00** | Aggregator / reseller | **Same as OV** | Same three options | Premium brand; meaningful if enterprise customers name DigiCert |
| **GlobalSign** | OV / EV | **NOT VERIFIED** | — | Builds over time | USB token "**Included in the price**" | Page renders "From • / year" — number is JS-injected. **Will not sell to individuals** (see below) |
| **Certum** | Code Signing | **NOT VERIFIED** | — | Builds over time | Card or SimplySign cloud | See note below — highest-value gap |
| **Microsoft** | Azure Artifact Signing Basic | **$9.99/month = $119.88** | ✅ **Microsoft retail pricing API** | Builds over time | **None** | ❌ **Turkey not eligible** |

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

## 5. What you'd need to buy (documents)

Based on the CA/B Forum CSBR verification requirements ([§3.2.2.1](https://cabforum.org/working-groups/code-signing/requirements/)) and Certum's own purchase flow ([support.certum.eu/en/how-to-buy-code-signing](https://support.certum.eu/en/how-to-buy-code-signing/)):

**If you buy as an organization (recommended — GlobalSign requires it, and it produces a more credible certificate subject):**
- Turkish company registration evidence — MERSIS record and/or Ticaret Sicil Gazetesi (Trade Registry Gazette) showing the legal entity name and address
- Tax number (VKN) and a current tax certificate (vergi levhası)
- Articles of association, if requested
- A government photo ID for the authorized representative — passport is the safest choice for international CAs
- Proof of business address — utility bill or bank statement, recent (typically within 3 months), name and address on the first page
- A business phone number listed in a third-party directory, or a **D-U-N-S number**
- Domain control evidence for your company domain (e.g. whois or a DNS TXT record)

**If you buy as an individual / sole proprietor:**
- Government photo ID **with your address on it** — Certum/Azure guidance is explicit that an ID bearing the address is the reliable path; a bank statement or utility bill may substitute
- Proof of address (recent utility bill / bank statement)
- Same directory/phone verification step

**Practical warnings:**
- **Validate the exact legal name first.** The certificate subject CN must be your legal entity's validated name — Azure states "CN values must always be the legal entity's validated name" ([FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq)). A mismatch between your registry name, your website, and your invoice is the single most common cause of delay. Make them consistent *before* applying.
- **Documents must be current.** Azure's rule of thumb: "All documents submitted must be issued within the previous 12 months and where the expiration date is a future date that is at least two months away."
- **Pick a signing identity you will keep.** Because publisher reputation is tied to the certificate identity, changing from "Anıl XYZ" to "Singularity AIDR Ltd" later resets your trust signal. If a company formation is plausible within 12 months, consider doing it *before* your first certificate.
- **Payment from Turkey:** expect to pay by international credit card or wire in USD/EUR; some CAs may require a card issued in the country of the legal entity. **NOT VERIFIED** whether any CA in this list has a specific Turkey payment restriction.

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

4. **Open <https://shop.certum.eu/code-signing.html> in a browser** and get the real EUR price for "Code Signing in the cloud" (SimplySign). If it beats SSL.com's ~$129 and Certum will take a Turkish applicant, that is your best combination of price, geography, and cloud signing.
5. **Otherwise contact SSL.com sales** and ask three specific questions: (a) will you issue an **OV** code signing certificate to a Turkish-registered company; (b) can I use **eSigner cloud signing** so I do not need a physical token shipped to Turkey; (c) what is the exact document checklist? Do the same with **Sectigo** in parallel. Applications cost nothing — only issuance does.
6. **Do not buy EV.** Per Microsoft, the premium buys no SmartScreen benefit.

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
| **Certum's prices** | ❌ **NOT VERIFIED.** Storefronts return only nav chrome to a text fetch; support KB is JS-rendered. Verify in a browser. |
| **Certum's / SSL.com's / Sectigo's / DigiCert's eligibility for a Turkish applicant** | ❌ **NOT VERIFIED.** No CA publishes a country blocklist. The constraint is documentary validation, not a list. Confirm with sales before assuming approval *or* rejection. |
| **GlobalSign and SSL.com own-site list prices** | ❌ **NOT VERIFIED** (JS-rendered). Figures in §4 for SSL.com/DigiCert/Sectigo are **reseller/aggregator** prices. |
| **Whether a signed `.vsix` changes install behavior in VS Code/Cursor** | ❌ **NOT VERIFIED.** No Microsoft/VS Code documentation found. Do not make customer claims about it. |
| **Exact document checklist per CA** | ⚠️ **PARTIAL.** §5 is derived from CA/B Forum CSBR §3.2.2.1 plus Certum's purchase-flow description, not from a per-CA published checklist. |
| **Payment restrictions on Turkish cards/entities** | ❌ **NOT VERIFIED.** |
| **Azure Artifact Signing's 3-year-business-history rule** | ⚠️ **Could not find this rule in current sources.** It appears in older secondary write-ups. The *current* documented gates are geography, identity validation, and a paid subscription. Treat the "3 years" claim as superseded — and moot, since geography already excludes you. |
| **DigiCert list pricing** | ❌ **Not published** by DigiCert; configurator only. |
| **`web_search`** | ❌ Unavailable this session (missing API key). All findings come from direct URL fetches, so coverage of secondary commentary is narrower than a full search would give. |

---

## 10. Bottom line

| Decision | Answer |
| --- | --- |
| **Buy** | **OV code signing certificate**, from a CA offering **cloud signing** (no physical token) |
| **Runner-up** | **Azure Artifact Signing** ($9.99/mo) — cheaper and better, but **Turkey is not on the eligible country list** |
| **Don't buy** | **EV.** Microsoft: the SmartScreen bypass was removed; the premium "is no longer justified" |
| **Best candidates to quote** | **Certum** (verify price in browser — likely cheapest, European, individual-friendly), **SSL.com** (~$129 OV, sells internationally, has eSigner cloud signing) |
| **Budget** | **~$130–$320/year**, plus possible token/shipping if cloud signing is unavailable |
| **Time to first signed build** | **~1–3 weeks** (faster if cloud signing; slower if a token must ship to Turkey) |
| **Time to warning-free downloads** | **Weeks to months** of real download volume — signing does not make the warning disappear |
| **What signing actually buys you** | A **named publisher** instead of "Unknown Publisher", a signature that **survives expiry** (with timestamping), **publisher reputation that carries across versions**, and — the real win — **enterprise policy that no longer blocks you outright** |
| **Do this week** | Test Azure eligibility · fix name consistency · start VS Code publisher-verification clock · quote Certum + SSL.com + Sectigo · build the signing path with a self-signed cert · publish checksums · write the warning-expectation page |

**The blunt version:** you cannot get the cheap Microsoft option, and EV is no longer worth paying for. Buy OV from whoever will take a Turkish applicant and give you cloud signing, and start the reputation clock as early as possible — because the certificate is quick, but the reputation that removes the warning takes months, and it only starts accumulating once you are signing.
