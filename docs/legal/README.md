# Procurement document set / Satın alma belge seti

> **Every legal and commercial document in this set is a DRAFT** that needs
> approval by counsel and the business owner before it is sent to a customer
> or signed. Bu setteki her hukuki ve ticari belge **TASLAKTIR**; müşteriye
> gönderilmeden ya da imzalanmadan önce hukuk ve iş sahibi onayı gerekir.
> None of them claims a certification, an audit or a penetration test that has
> not happened.

| Document | EN | TR | Owner / approver | Status |
|---|---|---|---|---|
| End User License Agreement (also rendered into the MSI licence page) | [eula.en.md](eula.en.md) | [eula.tr.md](eula.tr.md) | Legal | Draft 0.1 |
| Data Processing Agreement with TOMs and subprocessor annexes | [dpa.en.md](dpa.en.md) | [dpa.tr.md](dpa.tr.md) | Legal, DPO | Draft 0.1 |
| Support and service level schedule (SLA) | [sla.en.md](sla.en.md) | [sla.tr.md](sla.tr.md) | Legal, Support | Draft 0.1; not staffed |
| Employee privacy notice template (for the customer, as controller) | — | [kvkk-aydinlatma-metni-calisan.tr.md](kvkk-aydinlatma-metni-calisan.tr.md) | Customer's Legal/DPO | Template |
| Source-code escrow offer | [kaynak-kod-emaneti-teklif.md](kaynak-kod-emaneti-teklif.md) (§2) | [kaynak-kod-emaneti-teklif.md](kaynak-kod-emaneti-teklif.md) | Legal, business | Draft; no escrow agent engaged |
| Security whitepaper with data-flow diagrams | [../security/whitepaper.md](../security/whitepaper.md) | — | Security | Draft 0.1 |
| Security FAQ | [../sales/security-faq.md](../sales/security-faq.md) | [../sales/security-faq.tr.md](../sales/security-faq.tr.md) | Security | Current |
| Privacy and telemetry data flow | [../privacy.md](../privacy.md) | [../privacy.tr.md](../privacy.tr.md) | Engineering | Current |
| Compliance evidence report | [../compliance-report.md](../compliance-report.md) | [../compliance-report.tr.md](../compliance-report.tr.md) | Engineering | Current |
| KVKK guide for operators (inventory, retention presets, VERBİS, DPIA) | — | [../operations/kvkk.md](../operations/kvkk.md) | DPO | Current |
| Data residency positioning | [../deployment/data-residency.md](../deployment/data-residency.md) | (summary inside) | Business, Operations | Current |
| Vulnerability disclosure policy and `security.txt` template | [../security/vulnerability-disclosure-policy.md](../security/vulnerability-disclosure-policy.md), [template](../security/security.txt.template) | (summary inside) | Security, Legal | Draft; not in force |
| Supported versions policy | [../security/supported-versions.md](../security/supported-versions.md) | (summary inside) | Product, Security | Draft |
| Penetration test scope and RFP (for commissioning one) | [../security/pentest-scope-rfp.md](../security/pentest-scope-rfp.md) | — | Security | Draft; **no test performed** |
| On-prem quote template (TRY) and SKU structure | — | [../sales/onprem-teklif-sablonu.tr.md](../sales/onprem-teklif-sablonu.tr.md) | Business, Finance | Draft; internal |
| e-Fatura / e-Arşiv checklist | — | [../sales/e-fatura-kontrol-listesi.tr.md](../sales/e-fatura-kontrol-listesi.tr.md) | Finance, accountant | Draft; internal |
| POC kit and demo VM runbook | — | [../sales/poc-kiti.tr.md](../sales/poc-kiti.tr.md), [../sales/demo-vm-runbook.tr.md](../sales/demo-vm-runbook.tr.md) | Sales, solutions | Draft |

The Markdown EULA is the source of the Windows installer's licence page:
after Legal approves a change, run
`node deploy/installers/windows/ui/render-eula.mjs` and commit the regenerated
`deploy/installers/windows/ui/eula.*.rtf`; the installer build and
`pnpm test:installers` fail while the RTF is stale.
