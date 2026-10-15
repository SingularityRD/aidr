# Singularity AIDR End User License Agreement

> DRAFT - LEGAL REVIEW REQUIRED. This text has not been approved by counsel or by the business owner and is not yet an offer or a binding agreement. It is shown in the installer so that the final, approved text can replace it without changing the installer. Do not rely on it until the approved version is published.

Version: draft 0.1 (14 October 2026). Turkish version: docs/legal/eula.tr.md. If the two versions differ, the version named in the Order Form prevails; if the Order Form names none, the Turkish version prevails for customers established in Turkey.

## 1. Parties and scope

This End User License Agreement ("Agreement") is between SingularityRD [full legal name, trade registry and MERSIS number to be completed by Legal] ("Licensor") and the organisation that obtained the Software under an Order Form, quote acceptance or evaluation confirmation ("Customer"). A person who installs the Software on behalf of Customer confirms that they are authorised to accept this Agreement for Customer.

The Agreement covers the Singularity AIDR software delivered to Customer: the endpoint command-line tool and agent connectors, the desktop installers, the browser extension (Browser Guard), the MCP gateway, the on-premises control plane (dashboard, database schema and server functions) and the threat rules, intel packs, policies and documentation delivered with them or as updates (together, the "Software").

Third-party components included in the Software remain under their own licences, listed in THIRD_PARTY_NOTICES.txt in the docs folder of the installation folder (for example C:\Program Files\Singularity AIDR\docs\THIRD_PARTY_NOTICES.txt). Nothing in this Agreement limits Customer's rights under those licences.

## 2. Licence grant

Subject to this Agreement and to payment of the applicable fees, Licensor grants Customer a non-exclusive, non-transferable, non-sublicensable licence, for the Licence Term, to install and use the Software in object-code form for Customer's internal business purposes, up to the number of Seats and within the edition, modules and deployment type stated in the Order Form and in the signed licence file.

Customer may let its employees and contractors use the Software for Customer's benefit. Customer is responsible for their compliance with this Agreement.

Customer may make a reasonable number of copies for backup, disaster recovery, testing and staging, provided that test and staging installations do not protect production users beyond the licensed Seats.

## 3. Seats and usage reporting

A "Seat" is one person whose AI agent hosts or browser are protected by the Software under Customer's policy. Unless the Order Form says otherwise, one Seat covers that person's browser and one enrolled agent installation.

The control plane counts enrolled installations against the licensed Seats. Customer shall not circumvent this count, for example by altering the database, re-using one enrollment for several people or modifying the licence file.

On Licensor's reasonable written request, and not more than once per year (or at renewal), Customer shall provide the usage report produced by the Software (aidr-usage-report-v1) or an equivalent written statement of Seats in use. The report is prepared and attested by Customer; it is not a tamper-proof measurement. If Customer uses more Seats than licensed, Customer shall order the additional Seats for the remainder of the Licence Term at the prices in the Order Form or, if none are stated, at Licensor's then-current quote.

## 4. Licence Term and evaluation licences

The "Licence Term" is the period stated in the Order Form and in the signed licence file. It ends on the expiry date unless renewed in writing.

An evaluation or proof-of-concept licence is granted free of charge for the period stated in the evaluation confirmation, normally 30 days, for evaluation only and not for production use. It may be limited in Seats and features, is provided "as is" without support commitments, and ends automatically at the end of that period unless converted to a paid licence.

When the Licence Term ends, the managed features of the Software (seat admission, device enrollment, event ingest and other control-plane features) stop after the grace period stated in the licence file. Local detection on endpoints keeps working with the last installed version, rules and policy, because switching protection off on a missed renewal would expose Customer's users. Customer is not licensed to receive Updates after the Licence Term and shall uninstall the Software within a reasonable period after termination unless the Agreement is renewed.

## 5. Updates follow the licence

"Updates" are new versions, fixes, threat rules, intel packs and signed policy content that Licensor makes generally available for Customer's edition. Customer is entitled to Updates only during a paid Licence Term (and, for evaluation licences, during the evaluation period). Updates are licensed under this Agreement unless they come with different terms.

Licensor may deliver Updates through the control plane, through signed offline bundles for disconnected installations, or through browser extension stores. Customer is responsible for deciding when to install an Update in its environment. Licensor's support obligations, if any, apply only to the versions named as supported in Licensor's supported-versions policy.

## 6. Restrictions

Except as expressly permitted by this Agreement or by mandatory law, Customer shall not:

- copy, modify, translate or create derivative works of the Software, except for configuration, policies, allowlists and rules that the Software is designed to let Customer author;
- reverse engineer, decompile or disassemble the Software, or otherwise try to derive its source code, except to the extent that mandatory law (including Article 38 of the Turkish Law on Intellectual and Artistic Works No. 5846 for interoperability) expressly permits it despite this restriction, and then only after first asking Licensor in writing for the interoperability information;
- remove, disable or circumvent licence checks, signature and integrity verification, seat counting or the security controls of the Software;
- rent, lease, lend, sell, sublicense, or provide the Software to third parties as a hosted or managed service, unless the Order Form expressly allows it;
- remove or alter proprietary notices, or publish benchmark or test results of the Software without Licensor's prior written consent, except where mandatory law permits;
- use the Software in breach of applicable law, including export control and sanctions law.

## 7. Customer data and data processing

The Software evaluates commands, files and web requests on Customer's endpoints and, by default, does so locally without sending them to Licensor. Customer controls whether endpoints connect to a control plane, which control plane they use (Customer's own on-premises installation or a service hosted by Licensor), and which optional features (for example reputation lookups, diagnostics or SIEM delivery) are enabled.

To the extent Licensor processes personal data on Customer's behalf (for example when hosting the control plane or handling a support case), the Data Processing Agreement between the parties applies (draft: docs/legal/dpa.en.md and docs/legal/dpa.tr.md). For on-premises installations operated by Customer, Licensor does not receive Customer's telemetry, and Customer is the data controller for the data the Software records. Customer is responsible for informing its employees about the Software as required by law (a template notice is provided in docs/legal/kvkk-aydinlatma-metni-calisan.tr.md).

## 8. Ownership and feedback

The Software is licensed, not sold. Licensor and its licensors retain all rights, title and interest in the Software, including all intellectual property rights. Customer retains all rights in its data, configuration and policies. Licensor may use suggestions and feedback that Customer chooses to give, without obligation, provided that it does not disclose Customer's confidential information or identify Customer.

## 9. Confidentiality

Each party shall keep the other party's non-public information confidential, use it only to perform this Agreement and protect it with at least reasonable care. The Software, its documentation not published by Licensor, the licence file and pricing are Licensor's confidential information.

## 10. Warranty

Licensor warrants for 90 days from first delivery of a paid version that the Software will perform materially as described in its documentation. Customer's sole remedy for breach of this warranty is, at Licensor's option, correction of the non-conformity or termination of the affected licence and refund of the fees paid for the remaining Licence Term.

The Software is a detection and response layer. It reduces risk; it does not guarantee that every malicious or unwanted action is detected or blocked, and it does not replace Customer's other security controls, backups or review processes. Behaviour depends on the AI agent host: when a host disables, does not trust, times out or kills a hook, the host decides what happens to the call. Except as stated in this section and to the extent permitted by law, the Software is provided without other warranties, express or implied, including fitness for a particular purpose. Evaluation licences are provided "as is".

## 11. Limitation of liability

To the extent permitted by law, neither party is liable for indirect or consequential damages, lost profits, lost revenue or loss of data, and each party's total liability under this Agreement is limited to the fees paid or payable by Customer for the Software in the 12 months before the event giving rise to the claim. These limits do not apply to liability that cannot be limited by law, including liability for gross negligence or wilful misconduct (Article 115 of the Turkish Code of Obligations), to breaches of Section 6, or to Customer's payment obligations.

## 12. Term and termination

This Agreement starts when Customer accepts it or first installs the Software and continues for the Licence Term. Either party may terminate it by written notice if the other party materially breaches it and does not cure the breach within 30 days of notice. On termination, the licences end, Customer shall stop using and uninstall the Software, and Sections 6, 8, 9, 11 and 13 survive.

## 13. Governing law and disputes

This Agreement is governed by the laws of the Republic of Turkey. The courts and enforcement offices of [Istanbul (Caglayan) - to be confirmed by Legal] have exclusive jurisdiction. Mandatory consumer or public-procurement rules that apply to Customer prevail where they conflict with this section.

## 14. Miscellaneous

The Order Form, this Agreement, the Data Processing Agreement and any support schedule form the entire agreement for the Software. If they conflict, the Order Form prevails, then the Data Processing Agreement for data protection matters, then this Agreement. Neither party may assign this Agreement without the other's written consent, except to a successor of its entire business. A provision held invalid is replaced by a valid one closest to its intent, and the rest of the Agreement remains in force. Notices must be in writing, including by registered e-mail (KEP) or e-mail to the addresses in the Order Form.

By clicking "I accept" or installing the Software, the person installing confirms the above on behalf of Customer.
