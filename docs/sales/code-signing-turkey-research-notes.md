# Raw research evidence: Turkey + code signing 2026

## CABF Code Signing Baseline Requirements v3.11.0 (June 16, 2026)
URL: https://cabforum.org/working-groups/code-signing/requirements/
(Fetched live via PowerShell Invoke-WebRequest — full text, 261,647 chars)

Key definitions:
- "Individual: A natural person."
- "Individual Applicant: An Applicant who is a natural person and requests a Certificate
  that will list the Applicant's legal name as the Certificate's Subject."
- "Qualified Independent Information Source (QIIS): A regularly-updated and current,
  publicly available, database designed for the purpose of accurately providing the
  information for which it is consulted, and which is generally recognized as a
  dependable source of such information."

§3.2.3 Authentication of individual identity — INDIVIDUAL APPLICANTS ARE PERMITTED:
"Prior to issuing a Code Signing Certificate to an Individual Applicant, the CA MUST
verify the Subject's Identity and authenticity of the Identity as follows."
§3.2.3.1: photo ID (passport, driver's license, military ID, national ID) + address via
  "a government-issued photo ID, a QIIS or QGIS, or an access code to activate the
  Certificate where the access code was physically mailed"
§3.2.3.2: photo holding ID / webcam verification / Declaration of Identity w/ biometric.

§3.2.2.2.3.1 Address of Applicant's Place of Business:
"not, for example, a mail drop or P.O. box, or 'care of' (C/O) address"
- If NOT listed in QGIS/QIIS/QTIS => site visit documentation required, OR
  Verified Professional Letter.

§3.2.2.2.4 Verified Method of Communication:
"the CA MUST verify a telephone number, fax number, email address, or postal delivery
address as a Verified Method of Communication with the Applicant."

§3.2.2.2.10.5 QIIS qualification test (CA must determine):
- "Industries other than the certificate industry rely on the database"
- "The database provider updates its data on at least an annual basis"

No country/geographic restriction anywhere in the CABF CSBR. Turkey is not mentioned.

## DigiCert
### Embargoed Countries & Regions (SO101120141837, last modified 04/26/2026)
URL: https://knowledge.digicert.com/solution/embargoed-countries-and-regions
"Due to U.S.-imposed sanctions, DigiCert is legally prohibited or restricted from
offering its products and services to specific countries or regions."
Embargoed: Cuba (CU), Iran (IR), North Korea (KP), Syria (SY)
Embargoed regions: Crimea, Donetsk, Luhansk (RU/UA)
Sectoral sanctions: Russia, Venezuela. High risk: Russia, Belarus, Venezuela.
=> TURKEY IS NOT LISTED.

### Request a code signing certificate (docs.digicert.com, last modified Aug 4, 2026)
URL: https://docs.digicert.com/en/certcentral/manage-certificates/code-signing-certificates/order-a-code-signing-certificate.html
- "The organization must be active and validated for code signing in your account."
- "For Code Signing certificates, the required validation type is CS — Code Signing
  Organization Validation."
- "For EV Code Signing certificates, the required validation type is EV CS — Code
  Signing Organization Extended Validation."
- "A validated verified contact must be available to approve the code signing
  certificate order."
- "DigiCert also contacts a verified phone number for the organization to confirm
  authority to order. This call typically occurs within 24 hours of submission."
- "All code signing private keys must be stored on hardware certified to FIPS 140-2
  Level 2, Common Criteria EAL 4+, or equivalent."
- As of February 24, 2026: max validity for public code signing / EV code signing = 459 days.

### Public code signing certificates (Software Trust Manager)
URL: https://docs.digicert.com/en/software-trust-manager/certificates/certificates-types/public-code-signing-certificates.html
"[They] Are issued by DigiCert ... Contains verified information about your
organization." (last modified September 16, 2025)

### SSL/TLS Order Validation FAQ (INFO1572, last modified 04/26/2026)
URL: https://knowledge.digicert.com/general-information/ssl-tls-order-validation-faq
DigiCert teams verify:
- "The organization and organizational contact are not listed on denied entity lists."
- "The organization is registered or licensed to conduct business."
- "The organizational contact can be verified as a representative of the organization."
- "The organization requesting the certificate is in business and operates in the
  country listed in the enrollment."
- "The organization is not listed..." etc.

### Code Signing Certificate FAQs (INFO1119, last modified 09/14/2024)
URL: https://knowledge.digicert.com/general-information/code-signing-certificate-faqs
"No, a Code Signing certificate is tied to your Organization Name only."
"...provided that the applications are used for and distributed by the organization
that owns the certificate."
=> DigiCert OV code signing = ORGANIZATION, not individual.

### Code signing changes in 2023 (AL310523141628, last modified 04/23/2026)
URL: https://knowledge.digicert.com/alerts/code-signing-changes-in-2023
Private key hardware storage mandate (FIPS 140-2 L2 / CC EAL4+ / 3072-bit+).

## GlobalSign
### Minimum Requirements for Code Signing (support KB, dated Aug 19, 2025)
URL: https://support.globalsign.com/code-signing/general-information/minimum-requirements-code-signing
(Captured via Wayback 20251107035412; live returns 404)
"GlobalSign requires Code Signing Certificates to contain State and/or Locality in
the subjectDN."
- Only EV Code Signing gets USB tokens; standard multi-platform CS may use TPM/HCM/token
- References CASC Minimum Requirements + Microsoft Trusted Root Program

### Code Signing FAQs (support KB, page dated May 25, 2026 — LIVE)
URL: https://support.globalsign.com/code-signing/general-information/code-signing-faq
- "Standard Code Signing Certificates undergo standard organization validation."
- "EV Code Signing Certificates undergo strict Extended Validation vetting
  requirements set by the CA/B Forum."
- "Starting March 1, 2026, the maximum validity period for Code Signing Certificates
  will be reduced from 39 Months to 15 Months (or 460 days)."
- "No, renewing a certificate does not modify the organization information provided in
  the original order."
- NO mention of "individual" or "sole proprietor" anywhere in the FAQ.

### Order Code Signing Certificate (support KB, dated Jun 30, 2025)
URL: https://support.globalsign.com/code-signing/how-order-new-code-signing-certificate
"Standard Code Signing Certificates undergo standard organization validation"
"In the Certificate Identity Details screen, provide your information..."

### CDX evidence of INDIVIDUAL product discontinuation (globalsign.com)
http://web.archive.org/cdx/search/cdx?url=globalsign.com/en/code-signing-certificate*&output=text&fl=original,timestamp,statuscode
- https://www.globalsign.com/en/code-signing-certificate/code-signing-for-individual-developers/  -> 20210420053610, statuscode 301 (redirected)
- https://www.globalsign.com/en/code-signing-certificate/buy-code-signing-for-individual-developers -> 20210420053604, statuscode 404
- Historical: http://www.globalsign.com/code-signing-for-individual-developers.html
- Historical: http://www.globalsign.com/company/press/100301-code-signing-for-indivduals.html
=> The individual-developer product path was retired/redirected around April 2021.

## Sectigo
### What documentation do I need to send to you? (updated January 22, 2021)
URL: https://www.sectigo.com/knowledge-base/detail/What-documentation-do-I-need-to-send-to-you-1527076113420
"We accept many forms of documentation, from many countries.
To find out what documentation we accept for your country of business go to:
http://www.instantssl.com/ssl-certificate-support/validation_guidelines_table.html"

### Extended Validation (EV) Code Signing Certificates: What to Expect During Validation
(updated May 29, 2026)
URL: https://www.sectigo.com/knowledge-base/detail/extended-validation-ev-code-signing-certificates-what-to-expect-during-validation
*** MOST DIRECT QUOTE ***
"EV Code Signing certificates are issued only to verified organizations, such as
registered businesses, private organizations, international organizations, and
government entities. They cannot be issued to individuals."
Verification performed:
- organization legally exists and is active
- "Legal details verified directly through official government registry databases"
- "operates at a real, verified physical address"
- "PO Boxes, virtual offices, mail forwarding addresses, or registered agent
  addresses are not accepted"
- "A verified, working business phone number and/or email address listed in reliable
  third-party public data sources or government sources"
- Subscriber Agreement signed; callback to authorized representative
- "second approver" review
- Certificates shipped on secure hardware token

### Sectigo Code Signing product page (LIVE, 2026)
URL: https://www.sectigo.com/ssl-certificates-tls/code-signing
- OV Code Signing Certificate: "Organization Validation (OV) offers baseline trust and
  fast issuance"
- EV Code Signing Certificate: "Extended validation (EV) offers highest level of security"
- Both: "Meet CA/Browser Forum authentication standards and Microsoft specifications"
- Both ship FIPS-Compliant token
- NO individual / sole-proprietor code signing SKU on the page.

### Sectigo Code Signing KB category (25 articles) — article inventory
URL: https://www.sectigo.com/knowledge-base/product/Code_Signing
Articles are all CSR generation / token usage / VBA signing / DCV. No individual CS SKU.

## Verification status of "Turkey" specifically
- NOT found in DigiCert embargoed list (checked full page).
- GlobalSign: no published country restriction list found to date.
- Sectigo: no published country restriction list found to date.
- Turkish registry evidence (MERSIS, Ticaret Sicil Gazetesi): NOT VERIFIED in any CA page.
