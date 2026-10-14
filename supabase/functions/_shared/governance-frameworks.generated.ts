// Generated from governance/frameworks/*.yaml; do not edit.
// Regenerate: node scripts/sync-governance-frameworks.mjs --write

interface ComplianceMappedControl {
	readonly id: string;
	readonly group: string;
	readonly title: string;
	readonly coverage: "full" | "partial" | "customer-responsibility";
	readonly capabilities: readonly string[];
	readonly evidence: readonly string[];
	readonly note: string;
}

export interface ComplianceMappedFramework {
	readonly id: string;
	readonly name: string;
	readonly version: string;
	readonly scope: string;
	readonly controls: readonly ComplianceMappedControl[];
}

export const COMPLIANCE_CONTROL_MAPPING: {
	readonly source: string;
	readonly source_sha256: string;
	readonly frameworks: readonly ComplianceMappedFramework[];
} = {
	"source": "governance/frameworks",
	"source_sha256": "69f4c146590a5546947732464f5fd7dae8962cee8c8b54d31ea3d479932c6d7f",
	"frameworks": [
		{
			"id": "nist-ai-rmf",
			"name": "NIST AI Risk Management Framework",
			"version": "AI RMF 1.0 (NIST AI 100-1, January 2023)",
			"scope": "Subcategories of the GOVERN, MAP, MEASURE and MANAGE functions where Singularity AIDR provides a technical capability or evidence for the AI coding agents, AI chat sites and MCP servers it guards. The framework is voluntary; this mapping supports your risk management program and is not an attestation.",
			"controls": [
				{
					"id": "GOVERN 1.1",
					"group": "GOVERN",
					"title": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Signed compliance evidence report",
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"compliance-report.data_flows",
						"privacy-data-flow-matrix"
					],
					"note": "Understanding which laws apply is the organisation's task. The compliance evidence report and the data-flow inventory are inputs to that work, not a legal assessment."
				},
				{
					"id": "GOVERN 1.4",
					"group": "GOVERN",
					"title": "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities.",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"Prompt and tool-input data loss prevention for coding agents",
						"Inline allow / ask / deny decisions on AI coding agent tool calls"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions",
						"tenant_dlp_policies",
						"compliance-report.policy_inventory"
					],
					"note": "Runtime and DLP policies are explicit, versioned and enforced on every guarded tool call, with revision history and digests. The risk priorities behind them are set by the organisation."
				},
				{
					"id": "GOVERN 1.5",
					"group": "GOVERN",
					"title": "Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities clearly defined, including determining the frequency of periodic review.",
					"coverage": "partial",
					"capabilities": [
						"Governance scorecard and framework control matrix",
						"Scheduled governance summary and executive report by email (English or Turkish)"
					],
					"evidence": [
						"governance-scorecard",
						"governance-digest",
						"governance_digest_deliveries",
						"tenant_governance_settings"
					],
					"note": "The scorecard and the weekly or monthly summary give reviewers a recurring, data-backed view; who reviews and what they decide stays with the organisation."
				},
				{
					"id": "GOVERN 1.6",
					"group": "GOVERN",
					"title": "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.",
					"coverage": "partial",
					"capabilities": [
						"Inventory of protected AI agents, browser installs and AI sites",
						"MCP server inventory and attestation reporting",
						"Browser Guard masking of personal data and secrets on AI chat sites"
					],
					"evidence": [
						"agents",
						"posture_findings",
						"events.privacy_scan",
						"compliance-report.protection_coverage"
					],
					"note": "Enrolled agents, browser installs, AI sites seen by Browser Guard and reported MCP servers form an inventory of AI tool use. Unmanaged endpoints and AI systems outside these channels are not visible."
				},
				{
					"id": "GOVERN 2.1",
					"group": "GOVERN",
					"title": "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.",
					"coverage": "partial",
					"capabilities": [
						"Role-based access with MFA, SSO and SCIM",
						"Out-of-band human approval for ask decisions"
					],
					"evidence": [
						"compliance-report.access_identity",
						"admin_audit_logs"
					],
					"note": "Workspace roles decide who may change policy and who may approve blocked actions; the role list and administrative actions are recorded. Organisational role definitions outside the product remain the customer's."
				},
				{
					"id": "GOVERN 2.2",
					"group": "GOVERN",
					"title": "The organization's personnel and partners receive AI risk management training to enable them to perform their duties and responsibilities consistent with related policies, procedures, and agreements.",
					"coverage": "partial",
					"capabilities": [
						"AI acceptable-use notice with per-version acknowledgement"
					],
					"evidence": [
						"events.aup_acknowledgement"
					],
					"note": "The acceptable-use notice and its per-version acknowledgement counts show that browser users were shown the policy. It is awareness, not training; training content and records stay with the organisation."
				},
				{
					"id": "GOVERN 4.3",
					"group": "GOVERN",
					"title": "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.",
					"coverage": "partial",
					"capabilities": [
						"Incident correlation and tracking",
						"SIEM export of incidents",
						"Paginated audit export with legal-hold awareness"
					],
					"evidence": [
						"events.incident",
						"compliance-report.incidents",
						"siem-export",
						"audit-export"
					],
					"note": "Blocked and flagged agent actions become incidents that can be exported to a SIEM or as audit records. Testing practices and external information sharing are the organisation's."
				},
				{
					"id": "GOVERN 6.1",
					"group": "GOVERN",
					"title": "Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party's intellectual property or other rights.",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"Loopback MCP gateway with signed manifests",
						"Plugin and skill scanning at session start",
						"Browser Guard masking of personal data and secrets on AI chat sites"
					],
					"evidence": [
						"tenant_runtime_policies",
						"posture_findings"
					],
					"note": "MCP server and tool allow/approval/deny lists, plugin and skill scanning and AI-site blocking address security and data-exposure risk from third-party AI components. Intellectual-property and contractual risk are not assessed by the product."
				},
				{
					"id": "GOVERN 6.2",
					"group": "GOVERN",
					"title": "Contingency processes are in place to handle failures or incidents in third-party data or AI systems deemed to be high-risk.",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Versioned runtime policy with revision history"
					],
					"evidence": [
						"tenant_runtime_policies",
						"events.incident"
					],
					"note": "Connector entry points fail closed on an internal error, and a policy change can deny a misbehaving MCP server or tool across the fleet. Business continuity for the third-party AI service itself is the organisation's."
				},
				{
					"id": "MAP 3.5",
					"group": "MAP",
					"title": "Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function.",
					"coverage": "partial",
					"capabilities": [
						"Out-of-band human approval for ask decisions",
						"Human oversight analytics (decision latency, expiry, rubber-stamp review prompts)"
					],
					"evidence": [
						"approval_requests",
						"governance-scorecard",
						"admin_audit_logs"
					],
					"note": "Ask decisions stop an agent action until a person approves it out of band, and the scorecard measures how those decisions are made. Defining which actions need oversight is done in policy by the organisation."
				},
				{
					"id": "MAP 4.1",
					"group": "MAP",
					"title": "Approaches for mapping AI technology and legal risks of its components, including the use of third-party data or software, are in place, followed, and documented, as are risks of infringement of a third party's intellectual property or other rights.",
					"coverage": "partial",
					"capabilities": [
						"MCP server inventory and attestation reporting",
						"Plugin and skill scanning at session start",
						"AI tool-chain vulnerability and skill posture findings"
					],
					"evidence": [
						"posture_findings",
						"compliance-report.ai_security_posture"
					],
					"note": "Covers the security risk of agent components (MCP servers, plugins, skills and known vulnerabilities). Legal and intellectual-property risk mapping is not performed."
				},
				{
					"id": "MAP 4.2",
					"group": "MAP",
					"title": "Internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented.",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"tenant_runtime_policies",
						"compliance-report.policy_inventory",
						"governance-scorecard"
					],
					"note": "The controls AIDR applies are documented by the policy inventory and by this control matrix. Controls implemented in other tools are outside it."
				},
				{
					"id": "MEASURE 1.1",
					"group": "MEASURE",
					"title": "Approaches and metrics for measurement of AI risks enumerated during the MAP function are selected for implementation starting with the most significant AI risks.",
					"coverage": "partial",
					"capabilities": [
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"governance-scorecard"
					],
					"note": "The scorecard supplies ready metrics (decision volumes, approvals, incidents, masking counts, policy age). Selecting which metrics matter is the organisation's."
				},
				{
					"id": "MEASURE 2.4",
					"group": "MEASURE",
					"title": "The functionality and behavior of the AI system and its components, as identified in the MAP function, are monitored when in production.",
					"coverage": "full",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"events.runtime_verdict",
						"events.privacy_scan",
						"governance-scorecard"
					],
					"note": "Every guarded tool call and every Browser Guard send is evaluated and, on managed installs, reported as a counts-only event. Only enrolled agents and browsers are monitored."
				},
				{
					"id": "MEASURE 2.7",
					"group": "MEASURE",
					"title": "AI system security and resilience, as identified in the MAP function, are evaluated and documented.",
					"coverage": "partial",
					"capabilities": [
						"Versioned threat rule library (data, not code)",
						"Tool output and MCP result inspection",
						"AI tool-chain vulnerability and skill posture findings",
						"Plugin and skill scanning at session start"
					],
					"evidence": [
						"threat-rules",
						"posture_findings",
						"compliance-report.ai_security_posture"
					],
					"note": "Threat rules, prompt-injection signals, output inspection and posture findings document the security of the agent tool chain. Model-level robustness testing is not performed."
				},
				{
					"id": "MEASURE 2.10",
					"group": "MEASURE",
					"title": "Privacy risk of the AI system, as identified in the MAP function, is examined and documented.",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents",
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity",
						"privacy-data-flow-matrix"
					],
					"note": "Counts of personal data and secrets masked, warned about or blocked show where prompts carried personal data. Privacy impact assessments remain the organisation's."
				},
				{
					"id": "MEASURE 3.1",
					"group": "MEASURE",
					"title": "Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual performance in deployed contexts.",
					"coverage": "partial",
					"capabilities": [
						"Incident correlation and tracking",
						"AI tool-chain vulnerability and skill posture findings",
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"events.incident",
						"posture_findings",
						"governance-scorecard"
					],
					"note": "Incidents, posture findings and the scorecard's top-risks list are tracked over time. Personnel and review cadence are the organisation's."
				},
				{
					"id": "MANAGE 1.3",
					"group": "MANAGE",
					"title": "Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Prompt and tool-input data loss prevention for coding agents"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions",
						"tenant_dlp_policies"
					],
					"note": "Deny, ask and masking policies are the documented technical responses for the risks AIDR detects. Transfer and acceptance decisions are made by the organisation."
				},
				{
					"id": "MANAGE 2.4",
					"group": "MANAGE",
					"title": "Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Versioned runtime policy with revision history",
						"Browser Guard masking of personal data and secrets on AI chat sites"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions"
					],
					"note": "A policy change can deny an agent action type, an MCP server or tool, or block an AI site in managed browsers. AIDR stops actions of guarded tools; it does not switch off the vendor's AI service."
				},
				{
					"id": "MANAGE 3.1",
					"group": "MANAGE",
					"title": "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.",
					"coverage": "partial",
					"capabilities": [
						"MCP server inventory and attestation reporting",
						"AI tool-chain vulnerability and skill posture findings",
						"Versioned runtime policy with revision history"
					],
					"evidence": [
						"posture_findings",
						"tenant_runtime_policies"
					],
					"note": "MCP servers, plugins, skills and known vulnerabilities are monitored where scans are uploaded. Benefits are not measured."
				},
				{
					"id": "MANAGE 4.1",
					"group": "MANAGE",
					"title": "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management.",
					"coverage": "partial",
					"capabilities": [
						"Out-of-band human approval for ask decisions",
						"Incident correlation and tracking",
						"Versioned runtime policy with revision history",
						"Scheduled governance summary and executive report by email (English or Turkish)"
					],
					"evidence": [
						"approval_requests",
						"events.incident",
						"runtime_policy_revisions",
						"governance_digest_deliveries"
					],
					"note": "Human approval provides the override path, incidents the response trail and policy revisions the change record. User feedback collection and decommissioning plans are the organisation's."
				},
				{
					"id": "MANAGE 4.3",
					"group": "MANAGE",
					"title": "Incidents and errors are communicated to relevant AI actors, including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.",
					"coverage": "partial",
					"capabilities": [
						"Incident correlation and tracking",
						"SIEM export of incidents",
						"Scheduled governance summary and executive report by email (English or Turkish)"
					],
					"evidence": [
						"events.incident",
						"compliance-report.incidents",
						"siem-export"
					],
					"note": "Incidents are tracked with severity and status, exported to SIEM and summarised to owners. Communication to affected people and regulators is the organisation's."
				}
			]
		},
		{
			"id": "iso-iec-42001",
			"name": "ISO/IEC 42001 AI management system",
			"version": "ISO/IEC 42001:2023, Annex A",
			"scope": "Annex A controls where Singularity AIDR provides a technical capability or evidence for an organisation that uses AI coding agents, AI chat sites and MCP servers. The organisation decides applicability in its Statement of Applicability; this mapping supports that work and is not a certification.",
			"controls": [
				{
					"id": "A.2.2",
					"group": "A.2 Policies related to AI",
					"title": "AI policy",
					"coverage": "partial",
					"capabilities": [
						"AI acceptable-use notice with per-version acknowledgement",
						"Versioned runtime policy with revision history"
					],
					"evidence": [
						"events.aup_acknowledgement",
						"tenant_runtime_policies"
					],
					"note": "The acceptable-use notice distributes the organisation's AI use policy to browser users and runtime policy enforces its technical rules for coding agents. Writing and approving the AI policy is the organisation's."
				},
				{
					"id": "A.2.4",
					"group": "A.2 Policies related to AI",
					"title": "Review of the AI policy",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"runtime_policy_revisions",
						"dlp_policy_revisions",
						"governance-scorecard"
					],
					"note": "Revision history and the scorecard's policy-age figures show when technical policy was last reviewed. Review of the written policy itself is outside the product."
				},
				{
					"id": "A.3.2",
					"group": "A.3 Internal organization",
					"title": "AI roles and responsibilities",
					"coverage": "partial",
					"capabilities": [
						"Role-based access with MFA, SSO and SCIM",
						"Out-of-band human approval for ask decisions"
					],
					"evidence": [
						"compliance-report.access_identity",
						"admin_audit_logs"
					],
					"note": "Workspace roles separate who administers policy, who approves blocked actions and who only reads. Organisation-wide AI roles are defined by the customer."
				},
				{
					"id": "A.3.3",
					"group": "A.3 Internal organization",
					"title": "Reporting of concerns",
					"coverage": "customer-responsibility",
					"capabilities": [],
					"evidence": [],
					"note": "AIDR has no channel for people to report concerns; incidents in the product are raised by connectors, not by staff."
				},
				{
					"id": "A.4.4",
					"group": "A.4 Resources for AI systems",
					"title": "Tooling resources",
					"coverage": "partial",
					"capabilities": [
						"Inventory of protected AI agents, browser installs and AI sites",
						"MCP server inventory and attestation reporting"
					],
					"evidence": [
						"agents",
						"posture_findings",
						"compliance-report.protection_coverage"
					],
					"note": "The inventory lists agent runtimes, browser installs and MCP servers in use on enrolled endpoints. Unmanaged tooling is not visible."
				},
				{
					"id": "A.5.2",
					"group": "A.5 Assessing impacts of AI systems",
					"title": "AI system impact assessment process",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Signed compliance evidence report",
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"compliance-report.data_protection_activity",
						"governance-scorecard"
					],
					"note": "Impact assessments are performed by the organisation; the evidence report and the scorecard provide factual input on how AI tools are used."
				},
				{
					"id": "A.6.2.6",
					"group": "A.6 AI system life cycle",
					"title": "AI system operation and monitoring",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Governance scorecard and framework control matrix",
						"Incident correlation and tracking"
					],
					"evidence": [
						"events.runtime_verdict",
						"events.privacy_scan",
						"events.incident",
						"governance-scorecard"
					],
					"note": "Operation of the AI tools the organisation uses is monitored at the point of use (tool calls and prompts). Monitoring of models the organisation builds itself is out of scope."
				},
				{
					"id": "A.6.2.8",
					"group": "A.6 AI system life cycle",
					"title": "AI system recording of event logs",
					"coverage": "partial",
					"capabilities": [
						"Decision and administrative audit logs",
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Paginated audit export with legal-hold awareness"
					],
					"evidence": [
						"events.runtime_verdict",
						"admin_audit_logs",
						"local-audit-log",
						"audit-export"
					],
					"note": "Decisions are logged on the endpoint and, on managed installs, in the control plane; administrative actions are logged append-only. Logs carry decisions, digests and identifiers rather than prompt text, and are kept according to the workspace retention policy."
				},
				{
					"id": "A.8.2",
					"group": "A.8 Information for interested parties of AI systems",
					"title": "System documentation and information for users",
					"coverage": "partial",
					"capabilities": [
						"AI acceptable-use notice with per-version acknowledgement",
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Browser Guard masking of personal data and secrets on AI chat sites"
					],
					"evidence": [
						"events.aup_acknowledgement"
					],
					"note": "Users see the acceptable-use notice, the reason for each blocked action and in-page coaching when data is masked. Vendor documentation of the AI service is outside the product."
				},
				{
					"id": "A.8.4",
					"group": "A.8 Information for interested parties of AI systems",
					"title": "Communication of incidents",
					"coverage": "partial",
					"capabilities": [
						"Incident correlation and tracking",
						"SIEM export of incidents",
						"Scheduled governance summary and executive report by email (English or Turkish)"
					],
					"evidence": [
						"events.incident",
						"siem-export",
						"governance_digest_deliveries"
					],
					"note": "Incidents reach the SIEM and the owners' summary. Communicating incidents to users, customers or authorities is the organisation's."
				},
				{
					"id": "A.9.2",
					"group": "A.9 Use of AI systems",
					"title": "Processes for responsible use of AI systems",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"AI acceptable-use notice with per-version acknowledgement",
						"Out-of-band human approval for ask decisions"
					],
					"evidence": [
						"tenant_runtime_policies",
						"events.runtime_verdict",
						"events.privacy_scan",
						"approval_requests"
					],
					"note": "Responsible-use rules are enforced at the point of use: risky agent actions are denied or held for human approval and personal data is masked before it reaches AI sites. The organisation defines the process those rules implement."
				},
				{
					"id": "A.9.3",
					"group": "A.9 Use of AI systems",
					"title": "Objectives for responsible use of AI system",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"governance-scorecard"
					],
					"note": "Objectives are set by the organisation; the scorecard can track the ones that map to product metrics."
				},
				{
					"id": "A.9.4",
					"group": "A.9 Use of AI systems",
					"title": "Intended use of the AI system",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Loopback MCP gateway with signed manifests"
					],
					"evidence": [
						"tenant_runtime_policies"
					],
					"note": "Blocked AI sites, MCP allow/deny lists and per-artifact default actions keep agent and browser use within the scope the organisation allows."
				},
				{
					"id": "A.10.2",
					"group": "A.10 Third-party and customer relationships",
					"title": "Allocating responsibilities",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"note": "The data-flow inventory documents what the product processes and which subprocessors are involved; allocating responsibilities between the organisation and its AI suppliers is contractual."
				},
				{
					"id": "A.10.3",
					"group": "A.10 Third-party and customer relationships",
					"title": "Suppliers",
					"coverage": "partial",
					"capabilities": [
						"MCP server inventory and attestation reporting",
						"Plugin and skill scanning at session start",
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Inventory of protected AI agents, browser installs and AI sites"
					],
					"evidence": [
						"posture_findings",
						"events.privacy_scan"
					],
					"note": "Shows which AI sites, MCP servers, plugins and skills are in use and their findings. Supplier due diligence and contracts are the organisation's."
				}
			]
		},
		{
			"id": "eu-ai-act",
			"name": "EU Artificial Intelligence Act",
			"version": "Regulation (EU) 2024/1689",
			"scope": "Obligations of organisations that use (deploy) AI systems, plus the human-oversight article customers use as a reference. The mapping supports your obligations; it is not legal advice and does not determine whether a system is high-risk.",
			"controls": [
				{
					"id": "Art. 4",
					"group": "General provisions",
					"title": "AI literacy",
					"coverage": "partial",
					"capabilities": [
						"AI acceptable-use notice with per-version acknowledgement",
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Inline allow / ask / deny decisions on AI coding agent tool calls"
					],
					"evidence": [
						"events.aup_acknowledgement",
						"events.privacy_scan"
					],
					"note": "Applies to all deployers. The acceptable-use notice is shown once per version on protected AI sites and acknowledgements are counted; in-page coaching and block reasons explain risky use in context. Training measures appropriate to staff roles remain the organisation's."
				},
				{
					"id": "Art. 5",
					"group": "Prohibited AI practices",
					"title": "Prohibited AI practices",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites"
					],
					"evidence": [],
					"note": "Whether an AI use falls under a prohibited practice is a legal assessment. Browser Guard can block an AI site the organisation decides not to allow, but it does not classify practices."
				},
				{
					"id": "Art. 14",
					"group": "High-risk AI systems - requirements",
					"title": "Human oversight (provider design obligation; reference for agent oversight)",
					"coverage": "partial",
					"capabilities": [
						"Out-of-band human approval for ask decisions",
						"Human oversight analytics (decision latency, expiry, rubber-stamp review prompts)",
						"Inline allow / ask / deny decisions on AI coding agent tool calls"
					],
					"evidence": [
						"approval_requests",
						"governance-scorecard",
						"events.runtime_verdict"
					],
					"note": "Article 14 binds providers of high-risk systems. For AI agents, AIDR gives deployers a working oversight layer: actions can be stopped (deny) or held for a person (ask), and the scorecard flags approval patterns that suggest over-reliance (automation bias) as a review prompt. It does not make any AI system conform to Article 14."
				},
				{
					"id": "Art. 26(1)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Use in accordance with the instructions for use",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"Inline allow / ask / deny decisions on AI coding agent tool calls"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions"
					],
					"note": "High-risk systems only. Technical and organisational measures that keep agent use within the instructions can be expressed as runtime policy; reading and following the provider's instructions is the organisation's."
				},
				{
					"id": "Art. 26(2)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Assign human oversight to competent, trained persons with authority and support",
					"coverage": "partial",
					"capabilities": [
						"Out-of-band human approval for ask decisions",
						"Role-based access with MFA, SSO and SCIM",
						"Human oversight analytics (decision latency, expiry, rubber-stamp review prompts)"
					],
					"evidence": [
						"approval_requests",
						"compliance-report.access_identity",
						"governance-scorecard"
					],
					"note": "High-risk systems only. Only owners and admins (with step-up authentication) can approve held actions; the scorecard shows who decides and how. Competence and training of those people are the organisation's."
				},
				{
					"id": "Art. 26(5)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Monitor operation; inform the provider and suspend use when a risk or serious incident arises",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Incident correlation and tracking",
						"Scheduled governance summary and executive report by email (English or Turkish)",
						"Versioned runtime policy with revision history"
					],
					"evidence": [
						"events.runtime_verdict",
						"events.incident",
						"governance_digest_deliveries"
					],
					"note": "High-risk systems only. Decisions and incidents are monitored and summarised, and a policy change can stop agent actions. Informing the provider, distributor or market surveillance authority is the organisation's."
				},
				{
					"id": "Art. 26(6)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Keep automatically generated logs under the deployer's control for at least six months",
					"coverage": "partial",
					"capabilities": [
						"Decision and administrative audit logs",
						"Retention policies, legal holds and verified offboarding",
						"Paginated audit export with legal-hold awareness"
					],
					"evidence": [
						"events.runtime_verdict",
						"tenant_data_retention_policies",
						"tenant_legal_holds",
						"audit-export"
					],
					"note": "High-risk systems only. AIDR's own decision logs can be retained for six months or longer by setting telemetry retention to at least 183 days, and exported. Logs generated by the high-risk AI system itself are outside AIDR."
				},
				{
					"id": "Art. 26(7)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Inform workers' representatives and affected workers before workplace use",
					"coverage": "customer-responsibility",
					"capabilities": [
						"AI acceptable-use notice with per-version acknowledgement"
					],
					"evidence": [
						"events.aup_acknowledgement"
					],
					"note": "High-risk systems only. The acceptable-use notice can carry the information to browser users, but information and consultation duties toward worker representatives are the organisation's."
				},
				{
					"id": "Art. 27",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Fundamental rights impact assessment",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Signed compliance evidence report"
					],
					"evidence": [
						"compliance-report.data_protection_activity"
					],
					"note": "Applies to certain deployers of certain high-risk systems. The assessment is the deployer's; product evidence can be an input."
				}
			]
		},
		{
			"id": "kvkk-gdpr",
			"name": "KVKK and GDPR",
			"version": "KVKK Law No. 6698; GDPR Regulation (EU) 2016/679",
			"scope": "Articles where the compliance evidence report and the product's privacy capabilities provide evidence about AI tool use. This is not a statement that an organisation meets either law.",
			"controls": [
				{
					"id": "GDPR Art. 5(1)(c)",
					"group": "GDPR",
					"title": "Data minimisation",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity"
					],
					"note": "Personal data is masked or blocked before prompts reach AI services, and telemetry is counts only. A masked send still sends the redacted text; monitor-mode and allowed sends go unchanged."
				},
				{
					"id": "GDPR Art. 5(2)",
					"group": "GDPR",
					"title": "Accountability",
					"coverage": "partial",
					"capabilities": [
						"Signed compliance evidence report",
						"Governance scorecard and framework control matrix",
						"Decision and administrative audit logs"
					],
					"evidence": [
						"compliance-report.policy_inventory",
						"admin_audit_logs",
						"governance-scorecard"
					],
					"note": "Signed evidence reports, the audit log and the scorecard help demonstrate the measures in place for AI tool use. Accountability for the processing as a whole remains the controller's."
				},
				{
					"id": "GDPR Art. 25",
					"group": "GDPR",
					"title": "Data protection by design and by default",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents",
						"Versioned runtime policy with revision history"
					],
					"evidence": [
						"compliance-report.data_protection_activity",
						"tenant_dlp_policies"
					],
					"note": "Masking is on by default in Browser Guard and DLP policy applies to agent prompts and tool inputs, so protection does not depend on each user's choice."
				},
				{
					"id": "GDPR Art. 30",
					"group": "GDPR",
					"title": "Records of processing activities",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Product data-flow and subprocessor inventory",
						"Signed compliance evidence report"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"note": "The data-flow inventory is input for the controller's records; values marked unknown must be completed for the deployment."
				},
				{
					"id": "GDPR Art. 32",
					"group": "GDPR",
					"title": "Security of processing",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Role-based access with MFA, SSO and SCIM",
						"Tenant isolation with row-level security",
						"Decision and administrative audit logs",
						"Browser Guard masking of personal data and secrets on AI chat sites"
					],
					"evidence": [
						"compliance-report.access_identity",
						"compliance-report.protection_coverage",
						"events.runtime_verdict",
						"tenant_identity_policies"
					],
					"note": "Technical measures around AI tool use: inline enforcement, masking, MFA/SSO, tenant isolation and logging. Organisational measures and the rest of the estate are outside the product."
				},
				{
					"id": "GDPR Art. 33",
					"group": "GDPR",
					"title": "Notification of a personal data breach to the supervisory authority",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Incident correlation and tracking"
					],
					"evidence": [
						"events.incident",
						"compliance-report.incidents"
					],
					"note": "Incidents give the timeline input; deciding whether an incident is a personal data breach and notifying within 72 hours is the controller's."
				},
				{
					"id": "KVKK Art. 4",
					"group": "KVKK",
					"title": "General principles (processing that is relevant, limited and proportionate)",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity"
					],
					"note": "Masking and DLP limit the personal data sent to AI services to what the prompt needs. Lawfulness of the underlying processing is the controller's assessment."
				},
				{
					"id": "KVKK Art. 7",
					"group": "KVKK",
					"title": "Erasure, destruction or anonymisation of personal data",
					"coverage": "partial",
					"capabilities": [
						"Retention policies, legal holds and verified offboarding"
					],
					"evidence": [
						"tenant_data_retention_policies",
						"tenant_legal_holds",
						"tenant_offboarding_runs",
						"compliance-report.retention_deletion"
					],
					"note": "Product telemetry is deleted according to the workspace retention policy, legal holds pause deletion, and offboarding leaves phase receipts. Backups follow a separate expiry and are outside the live-data receipts."
				},
				{
					"id": "KVKK Art. 9",
					"group": "KVKK",
					"title": "Transfer of personal data abroad",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"note": "The inventory lists destinations, regions and transfer mechanisms for product data flows; the transfer assessment and its legal basis are the controller's."
				},
				{
					"id": "KVKK Art. 12",
					"group": "KVKK",
					"title": "Obligations concerning data security",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Role-based access with MFA, SSO and SCIM",
						"Tenant isolation with row-level security",
						"Decision and administrative audit logs"
					],
					"evidence": [
						"compliance-report.access_identity",
						"compliance-report.data_protection_activity",
						"admin_audit_logs",
						"tenant_identity_policies"
					],
					"note": "Technical measures to prevent unlawful disclosure of personal data through AI tools, with access control and audit evidence. Administrative measures and audits are the controller's."
				}
			]
		},
		{
			"id": "iso-iec-27001",
			"name": "ISO/IEC 27001 Annex A",
			"version": "ISO/IEC 27001:2022, Annex A",
			"scope": "Annex A controls where Singularity AIDR provides a technical measure or evidence for AI tool use (coding agents, AI chat sites, MCP servers). Vendor mapping only: the organisation decides applicability and implementation in its own ISMS, and an accredited certification body, not this mapping, assesses conformity.",
			"controls": [
				{
					"id": "A.5.1",
					"group": "A.5 Organizational controls",
					"title": "Policies for information security",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"AI acceptable-use notice with per-version acknowledgement"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions",
						"events.aup_acknowledgement"
					],
					"note": "Runtime policy enforces the technical part of the AI-use rules for coding agents and the acceptable-use notice distributes the written rule to browser users. Writing, approving and reviewing the policy is the organisation's."
				},
				{
					"id": "A.5.7",
					"group": "A.5 Organizational controls",
					"title": "Threat intelligence",
					"coverage": "partial",
					"capabilities": [
						"Versioned threat rule library (data, not code)",
						"AI tool-chain vulnerability and skill posture findings"
					],
					"evidence": [
						"threat-rules",
						"posture_findings"
					],
					"note": "Versioned threat rules and CVE/MCP/skill findings bring threat information about AI tool chains into enforcement and reporting. Collecting and analysing threat intelligence for the wider estate is outside the product."
				},
				{
					"id": "A.5.9",
					"group": "A.5 Organizational controls",
					"title": "Inventory of information and other associated assets",
					"coverage": "partial",
					"capabilities": [
						"Inventory of protected AI agents, browser installs and AI sites",
						"MCP server inventory and attestation reporting"
					],
					"evidence": [
						"agents",
						"posture_findings",
						"compliance-report.protection_coverage"
					],
					"note": "Enrolled coding agents, browser installs, AI sites in use and reported MCP servers are inventoried. Only endpoints with an AIDR connector or Browser Guard are visible."
				},
				{
					"id": "A.5.10",
					"group": "A.5 Organizational controls",
					"title": "Acceptable use of information and other associated assets",
					"coverage": "partial",
					"capabilities": [
						"AI acceptable-use notice with per-version acknowledgement",
						"Browser Guard masking of personal data and secrets on AI chat sites"
					],
					"evidence": [
						"events.aup_acknowledgement",
						"events.privacy_scan"
					],
					"note": "The acceptable-use notice is shown once per version on protected AI sites and acknowledgements are counted; masking enforces the data rule at the moment of use."
				},
				{
					"id": "A.5.12",
					"group": "A.5 Organizational controls",
					"title": "Classification of information",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Prompt and tool-input data loss prevention for coding agents"
					],
					"evidence": [
						"tenant_dlp_policies",
						"dlp_policy_revisions"
					],
					"note": "DLP policy labels and rules can carry the organisation's classification scheme into AI prompts and tool inputs. The classification scheme itself is the organisation's."
				},
				{
					"id": "A.5.14",
					"group": "A.5 Organizational controls",
					"title": "Information transfer",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents",
						"Tool output and MCP result inspection"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity"
					],
					"note": "Personal data and secrets are masked, warned on or blocked before a prompt, paste or file reaches an AI service. A masked send still transfers the redacted text, and monitor-mode or allowed sends go unchanged."
				},
				{
					"id": "A.5.15",
					"group": "A.5 Organizational controls",
					"title": "Access control",
					"coverage": "partial",
					"capabilities": [
						"Role-based access with MFA, SSO and SCIM",
						"Tenant isolation with row-level security"
					],
					"evidence": [
						"tenant_identity_policies",
						"compliance-report.access_identity"
					],
					"note": "Role-based access to the control plane with owner, admin, member and viewer roles, enforced by row-level security and the tenant identity barrier. Access control for the organisation's other systems is outside the product."
				},
				{
					"id": "A.5.16",
					"group": "A.5 Organizational controls",
					"title": "Identity management",
					"coverage": "partial",
					"capabilities": [
						"Role-based access with MFA, SSO and SCIM"
					],
					"evidence": [
						"tenant_identity_policies",
						"compliance-report.access_identity"
					],
					"note": "SCIM provisioning and SAML/OIDC single sign-on tie control-plane accounts to the organisation's directory. The directory and its joiner-mover-leaver process remain the organisation's."
				},
				{
					"id": "A.5.19",
					"group": "A.5 Organizational controls",
					"title": "Information security in supplier relationships",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"note": "The product's data-flow and subprocessor inventory is input for the supplier assessment of Singularity AIDR itself. Assessing AI service providers is the organisation's."
				},
				{
					"id": "A.5.23",
					"group": "A.5 Organizational controls",
					"title": "Information security for use of cloud services",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Inventory of protected AI agents, browser installs and AI sites"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity"
					],
					"note": "AI chat sites in use are counted and personal data is masked before it reaches them. Contracting, configuring and exiting cloud AI services is the organisation's."
				},
				{
					"id": "A.5.24",
					"group": "A.5 Organizational controls",
					"title": "Information security incident management planning and preparation",
					"coverage": "partial",
					"capabilities": [
						"Incident triage with owner, resolution note, snooze and audit trail",
						"SIEM export of incidents"
					],
					"evidence": [
						"incident_triage",
						"siem-export"
					],
					"note": "Incident triage with owners and SIEM export give the AI tool-use part of the incident process its tooling. The incident management plan and roles are the organisation's."
				},
				{
					"id": "A.5.25",
					"group": "A.5 Organizational controls",
					"title": "Assessment and decision on information security events",
					"coverage": "partial",
					"capabilities": [
						"Incident correlation and tracking",
						"Incident triage with owner, resolution note, snooze and audit trail"
					],
					"evidence": [
						"events.incident",
						"incident_triage",
						"incident_triage_history"
					],
					"note": "Blocked and flagged actions are listed as incidents; analysts acknowledge, resolve or mark each one a false positive with a recorded note. Deciding what is a reportable incident is the organisation's."
				},
				{
					"id": "A.5.26",
					"group": "A.5 Organizational controls",
					"title": "Response to information security incidents",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Incident triage with owner, resolution note, snooze and audit trail",
						"Out-of-band human approval for ask decisions"
					],
					"evidence": [
						"events.runtime_verdict",
						"incident_triage_history",
						"approval_requests"
					],
					"note": "Deny decisions stop the action before it runs and ask decisions hold it for out-of-band human approval. Containment and recovery beyond the blocked action are the organisation's."
				},
				{
					"id": "A.5.27",
					"group": "A.5 Organizational controls",
					"title": "Learning from information security incidents",
					"coverage": "partial",
					"capabilities": [
						"Incident triage with owner, resolution note, snooze and audit trail",
						"Scheduled governance summary and executive report by email (English or Turkish)"
					],
					"evidence": [
						"incident_triage_history",
						"executive-report"
					],
					"note": "Resolution notes, false-positive decisions and the executive report's incident figures feed lessons learned. Running the review is the organisation's."
				},
				{
					"id": "A.5.28",
					"group": "A.5 Organizational controls",
					"title": "Collection of evidence",
					"coverage": "partial",
					"capabilities": [
						"Decision and administrative audit logs",
						"Paginated audit export with legal-hold awareness",
						"Signed compliance evidence report"
					],
					"evidence": [
						"admin_audit_logs",
						"audit-export",
						"compliance-report.incidents"
					],
					"note": "Append-only audit logs, paginated export and the signed evidence report preserve records of decisions. Forensic evidence handling procedures are the organisation's."
				},
				{
					"id": "A.5.33",
					"group": "A.5 Organizational controls",
					"title": "Protection of records",
					"coverage": "partial",
					"capabilities": [
						"Decision and administrative audit logs",
						"Retention policies, legal holds and verified offboarding"
					],
					"evidence": [
						"admin_audit_logs",
						"tenant_legal_holds",
						"tenant_data_retention_policies"
					],
					"note": "Audit records are append-only, retention is configured per data class and legal holds pause deletion. Backup copies need separate expiry evidence."
				},
				{
					"id": "A.5.34",
					"group": "A.5 Organizational controls",
					"title": "Privacy and protection of PII",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents",
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity",
						"compliance-report.data_flows"
					],
					"note": "TR/EN personal data is masked before AI services receive it and telemetry is counts only. Obligations under KVKK or GDPR as a whole remain the controller's."
				},
				{
					"id": "A.5.36",
					"group": "A.5 Organizational controls",
					"title": "Compliance with policies, rules and standards for information security",
					"coverage": "partial",
					"capabilities": [
						"Governance scorecard and framework control matrix",
						"Signed compliance evidence report",
						"Scheduled governance summary and executive report by email (English or Turkish)"
					],
					"evidence": [
						"governance-scorecard",
						"compliance-report.policy_inventory",
						"executive-report"
					],
					"note": "The scorecard, evidence report and scheduled executive report show whether the AI tool-use controls are deployed and used. Reviewing compliance is the organisation's."
				},
				{
					"id": "A.6.3",
					"group": "A.6 People controls",
					"title": "Information security awareness, education and training",
					"coverage": "customer-responsibility",
					"capabilities": [
						"AI acceptable-use notice with per-version acknowledgement"
					],
					"evidence": [
						"events.aup_acknowledgement"
					],
					"note": "The acceptable-use notice reaches browser users at the point of AI use and records acknowledgement. Awareness and training programmes are the organisation's."
				},
				{
					"id": "A.8.2",
					"group": "A.8 Technological controls",
					"title": "Privileged access rights",
					"coverage": "partial",
					"capabilities": [
						"Role-based access with MFA, SSO and SCIM",
						"Decision and administrative audit logs"
					],
					"evidence": [
						"compliance-report.access_identity",
						"admin_audit_logs"
					],
					"note": "Owner and admin roles are listed in the evidence report with MFA status and every administrative change is audited. Privileged access elsewhere is outside the product."
				},
				{
					"id": "A.8.5",
					"group": "A.8 Technological controls",
					"title": "Secure authentication",
					"coverage": "partial",
					"capabilities": [
						"Role-based access with MFA, SSO and SCIM"
					],
					"evidence": [
						"tenant_identity_policies"
					],
					"note": "Workspace MFA and SSO requirements are enforced on every tenant table, and sensitive administrative actions require a second factor. Authentication to other systems is outside the product."
				},
				{
					"id": "A.8.7",
					"group": "A.8 Technological controls",
					"title": "Protection against malware",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Plugin and skill scanning at session start",
						"Loopback MCP gateway with signed manifests"
					],
					"evidence": [
						"events.runtime_verdict",
						"threat-rules"
					],
					"note": "Malicious commands, downloads, plugins, skills and MCP results are detected and blocked on the coding-agent path. The product is not an endpoint anti-malware agent."
				},
				{
					"id": "A.8.8",
					"group": "A.8 Technological controls",
					"title": "Management of technical vulnerabilities",
					"coverage": "partial",
					"capabilities": [
						"AI tool-chain vulnerability and skill posture findings",
						"MCP server inventory and attestation reporting"
					],
					"evidence": [
						"posture_findings",
						"compliance-report.ai_security_posture"
					],
					"note": "CVE and exposed-component findings for the AI tool chain are reported by severity. Patching and vulnerability management for the estate are the organisation's."
				},
				{
					"id": "A.8.11",
					"group": "A.8 Technological controls",
					"title": "Data masking",
					"coverage": "full",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity"
					],
					"note": "Masking of TR/EN personal data and secrets with reversible placeholders on AI chat sites, and DLP handling of agent prompts and tool inputs, is a core product function."
				},
				{
					"id": "A.8.12",
					"group": "A.8 Technological controls",
					"title": "Data leakage prevention",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents",
						"Tool output and MCP result inspection",
						"Inline allow / ask / deny decisions on AI coding agent tool calls"
					],
					"evidence": [
						"events.privacy_scan",
						"events.runtime_verdict",
						"compliance-report.data_protection_activity"
					],
					"note": "Leakage of personal data and secrets through AI prompts, uploads, agent tool calls and MCP results is prevented on protected channels. Other channels (mail, removable media, unprotected sites) are outside the product."
				},
				{
					"id": "A.8.15",
					"group": "A.8 Technological controls",
					"title": "Logging",
					"coverage": "partial",
					"capabilities": [
						"Decision and administrative audit logs",
						"Paginated audit export with legal-hold awareness",
						"SIEM export of incidents"
					],
					"evidence": [
						"local-audit-log",
						"admin_audit_logs",
						"siem-export"
					],
					"note": "Decisions are logged on the endpoint and, in managed mode, in the control plane; logs can be exported to a SIEM. Logs hold decisions and digests, not prompt text."
				},
				{
					"id": "A.8.16",
					"group": "A.8 Technological controls",
					"title": "Monitoring activities",
					"coverage": "partial",
					"capabilities": [
						"Incident correlation and tracking",
						"Governance scorecard and framework control matrix",
						"Human oversight analytics (decision latency, expiry, rubber-stamp review prompts)"
					],
					"evidence": [
						"events.runtime_verdict",
						"governance-scorecard",
						"governance_digest_deliveries"
					],
					"note": "Agent decisions, incidents and approval patterns are monitored in the dashboard and the scheduled summary. Only telemetry that reached the control plane is visible."
				},
				{
					"id": "A.8.19",
					"group": "A.8 Technological controls",
					"title": "Installation of software on operational systems",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Plugin and skill scanning at session start"
					],
					"evidence": [
						"events.runtime_verdict",
						"threat-rules"
					],
					"note": "Package installs and agent plugins are checked before they run on the coding-agent path. Software installed by other means is outside the product."
				},
				{
					"id": "A.8.23",
					"group": "A.8 Technological controls",
					"title": "Web filtering",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Browser Guard masking of personal data and secrets on AI chat sites"
					],
					"evidence": [
						"events.runtime_verdict",
						"events.privacy_scan"
					],
					"note": "Agent web requests are checked against threat rules and reputation, and Browser Guard can block AI sites by policy. It is not a general web proxy."
				},
				{
					"id": "A.8.28",
					"group": "A.8 Technological controls",
					"title": "Secure coding",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Tool output and MCP result inspection"
					],
					"evidence": [
						"events.runtime_verdict"
					],
					"note": "Dangerous commands and secret exposure by AI coding agents are blocked while code is written. Secure coding practice and code review remain the organisation's."
				},
				{
					"id": "A.8.32",
					"group": "A.8 Technological controls",
					"title": "Change management",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history"
					],
					"evidence": [
						"runtime_policy_revisions",
						"dlp_policy_revisions"
					],
					"note": "Policy changes are versioned with digests and can require four-eyes change control. Change management for other systems is outside the product."
				}
			]
		},
		{
			"id": "bddk-bsebh",
			"name": "BDDK Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Yönetmeliği",
			"version": "Resmî Gazete 15.03.2020, No. 31069 (topic-level mapping)",
			"scope": "Requirement topics of the BDDK information systems and electronic banking regulation where Singularity AIDR provides a technical measure or evidence for the bank's use of AI coding agents, AI chat sites and MCP servers. Topic codes are this mapping's own; article references, applicability and the bank's other information systems are the bank's to determine. Vendor mapping only, not a regulatory approval.",
			"controls": [
				{
					"id": "BSEBY-BGYS",
					"group": "Bilgi güvenliği yönetimi",
					"title": "Bilgi güvenliği politikası ve yönetimi (information security policy and management)",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history",
						"AI acceptable-use notice with per-version acknowledgement",
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions",
						"governance-scorecard"
					],
					"note": "Versioned runtime and DLP policy carry the bank's AI-use rules into enforcement and the scorecard shows whether they are deployed. The bank's information security management system, policy approval and committees are outside the product."
				},
				{
					"id": "BSEBY-VARLIK",
					"group": "Bilgi güvenliği yönetimi",
					"title": "Bilgi varlıkları envanteri (information asset inventory)",
					"coverage": "partial",
					"capabilities": [
						"Inventory of protected AI agents, browser installs and AI sites",
						"MCP server inventory and attestation reporting"
					],
					"evidence": [
						"agents",
						"posture_findings",
						"compliance-report.protection_coverage"
					],
					"note": "AI coding agents, browser installs, AI sites in use and MCP servers are inventoried for the endpoints that run an AIDR connector or Browser Guard. The bank's full asset inventory and classification remain the bank's."
				},
				{
					"id": "BSEBY-ERISIM",
					"group": "Bilgi güvenliği yönetimi",
					"title": "Kimlik doğrulama ve erişim yönetimi (authentication and access management)",
					"coverage": "partial",
					"capabilities": [
						"Role-based access with MFA, SSO and SCIM",
						"Tenant isolation with row-level security"
					],
					"evidence": [
						"tenant_identity_policies",
						"compliance-report.access_identity"
					],
					"note": "Control-plane access uses roles, MFA, SAML/OIDC single sign-on and SCIM, enforced on every tenant table; administrators and their MFA status appear in the evidence report. Access to banking systems is outside the product."
				},
				{
					"id": "BSEBY-IZKAYDI",
					"group": "Bilgi güvenliği yönetimi",
					"title": "İz kayıtları (audit trails)",
					"coverage": "partial",
					"capabilities": [
						"Decision and administrative audit logs",
						"Paginated audit export with legal-hold awareness",
						"SIEM export of incidents"
					],
					"evidence": [
						"admin_audit_logs",
						"local-audit-log",
						"audit-export",
						"siem-export"
					],
					"note": "Decisions on agent actions and administrative changes are kept in append-only logs, exportable to the bank's SIEM. Integrity protection and retention periods of the bank's central log store are the bank's."
				},
				{
					"id": "BSEBY-OLAY",
					"group": "Siber olay yönetimi",
					"title": "Siber olay yönetimi ve müdahale (cyber incident management and response)",
					"coverage": "partial",
					"capabilities": [
						"Incident correlation and tracking",
						"Incident triage with owner, resolution note, snooze and audit trail",
						"SIEM export of incidents"
					],
					"evidence": [
						"events.incident",
						"incident_triage",
						"incident_triage_history"
					],
					"note": "Blocked and flagged AI tool actions are listed as incidents with owner, status, resolution note and an append-only history, and can be sent to the SIEM. Notifying the regulator and running the bank's incident response team are the bank's."
				},
				{
					"id": "BSEBY-GIZLILIK",
					"group": "Veri güvenliği",
					"title": "Gizli ve müşteri sırrı niteliğindeki verilerin korunması (protection of confidential and customer-secret data)",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents",
						"Tool output and MCP result inspection"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity",
						"tenant_dlp_policies"
					],
					"note": "TCKN, IBAN, card numbers, other personal data and secrets are masked or blocked before they reach AI services, and DLP rules apply to agent prompts and tool inputs. Other leakage channels and the bank's data classification are outside the product."
				},
				{
					"id": "BSEBY-ZARARLI",
					"group": "Bilgi güvenliği yönetimi",
					"title": "Zararlı yazılımlara karşı koruma (protection against malicious software)",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Plugin and skill scanning at session start",
						"Loopback MCP gateway with signed manifests"
					],
					"evidence": [
						"events.runtime_verdict",
						"threat-rules"
					],
					"note": "Malicious commands, packages, plugins, skills and MCP results are blocked on the coding-agent path before they run. The product does not replace endpoint protection."
				},
				{
					"id": "BSEBY-ZAFIYET",
					"group": "Bilgi güvenliği yönetimi",
					"title": "Güvenlik açığı yönetimi ve sızma testleri (vulnerability management and penetration tests)",
					"coverage": "customer-responsibility",
					"capabilities": [
						"AI tool-chain vulnerability and skill posture findings"
					],
					"evidence": [
						"posture_findings",
						"compliance-report.ai_security_posture"
					],
					"note": "CVE and exposed-component findings of the AI tool chain are reported by severity. Penetration tests, their scope and remediation tracking are the bank's."
				},
				{
					"id": "BSEBY-DEGISIKLIK",
					"group": "Bilgi sistemleri yönetimi",
					"title": "Değişiklik yönetimi (change management)",
					"coverage": "partial",
					"capabilities": [
						"Versioned runtime policy with revision history"
					],
					"evidence": [
						"runtime_policy_revisions",
						"dlp_policy_revisions"
					],
					"note": "Security policy changes are versioned with digests, can be staged in rings and can require four-eyes approval. Change management for banking systems is the bank's."
				},
				{
					"id": "BSEBY-SAKLAMA",
					"group": "Bilgi sistemleri yönetimi",
					"title": "Kayıtların saklanması ve imhası (retention and disposal of records)",
					"coverage": "partial",
					"capabilities": [
						"Retention policies, legal holds and verified offboarding",
						"Decision and administrative audit logs"
					],
					"evidence": [
						"tenant_data_retention_policies",
						"tenant_legal_holds",
						"compliance-report.retention_deletion"
					],
					"note": "Retention days per data class, legal holds and offboarding receipts are recorded. Statutory retention periods are set by the bank; backup copies need separate evidence."
				},
				{
					"id": "BSEBY-YONETIM",
					"group": "Bilgi sistemleri yönetimi",
					"title": "Üst yönetime raporlama ve gözetim (reporting to and oversight by senior management)",
					"coverage": "partial",
					"capabilities": [
						"Scheduled governance summary and executive report by email (English or Turkish)",
						"Governance scorecard and framework control matrix",
						"Out-of-band human approval for ask decisions",
						"Human oversight analytics (decision latency, expiry, rubber-stamp review prompts)"
					],
					"evidence": [
						"executive-report",
						"governance_digest_deliveries",
						"approval_requests"
					],
					"note": "A scheduled executive report in Turkish or English, the scorecard and human-approval analytics give management a counts-only view of AI tool use. Board and committee oversight duties are the bank's."
				},
				{
					"id": "BSEBY-DISHIZMET",
					"group": "Bilgi sistemleri yönetimi",
					"title": "Dış hizmet ve tedarikçi riskleri (outsourcing and supplier risk)",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"note": "The data-flow and subprocessor inventory supports the bank's assessment of Singularity AIDR as a supplier. Assessing AI service providers and any support service obligations are the bank's."
				}
			]
		},
		{
			"id": "cbddo-big",
			"name": "Cumhurbaşkanlığı Bilgi ve İletişim Güvenliği Rehberi",
			"version": "Dijital Dönüşüm Ofisi BİG Rehberi (topic-level mapping)",
			"scope": "Measure topics of the Information and Communication Security Guide where Singularity AIDR provides a technical measure or evidence for an institution's use of AI coding agents, AI chat sites and MCP servers. Topic codes are this mapping's own; measure numbers, the institution's asset criticality level and its other systems are the institution's to determine. Vendor mapping only, not an audit result.",
			"controls": [
				{
					"id": "BIG-VARLIK",
					"group": "Varlık yönetimi",
					"title": "Varlık envanteri ve sınıflandırma (asset inventory and classification)",
					"coverage": "partial",
					"capabilities": [
						"Inventory of protected AI agents, browser installs and AI sites",
						"MCP server inventory and attestation reporting"
					],
					"evidence": [
						"agents",
						"posture_findings",
						"compliance-report.protection_coverage"
					],
					"note": "AI coding agents, browser installs, AI sites in use and MCP servers are inventoried for endpoints that run an AIDR connector or Browser Guard. Criticality grading of assets is the institution's."
				},
				{
					"id": "BIG-ERISIM",
					"group": "Ağ ve sistem güvenliği",
					"title": "Kimlik doğrulama ve erişim yönetimi (authentication and access management)",
					"coverage": "partial",
					"capabilities": [
						"Role-based access with MFA, SSO and SCIM",
						"Tenant isolation with row-level security"
					],
					"evidence": [
						"tenant_identity_policies",
						"compliance-report.access_identity"
					],
					"note": "Control-plane access uses roles, MFA, SSO and SCIM enforced on every tenant table. Access management for the institution's other systems is outside the product."
				},
				{
					"id": "BIG-KAYIT",
					"group": "Ağ ve sistem güvenliği",
					"title": "Kayıt yönetimi ve izleme (log management and monitoring)",
					"coverage": "partial",
					"capabilities": [
						"Decision and administrative audit logs",
						"Paginated audit export with legal-hold awareness",
						"SIEM export of incidents"
					],
					"evidence": [
						"admin_audit_logs",
						"local-audit-log",
						"siem-export"
					],
					"note": "Agent decisions and administrative changes are logged append-only and can be sent to the institution's SIEM. Central log retention and time synchronisation are the institution's."
				},
				{
					"id": "BIG-OLAY",
					"group": "Siber olay yönetimi",
					"title": "Siber olaylara müdahale (cyber incident response)",
					"coverage": "partial",
					"capabilities": [
						"Incident correlation and tracking",
						"Incident triage with owner, resolution note, snooze and audit trail"
					],
					"evidence": [
						"events.incident",
						"incident_triage",
						"incident_triage_history"
					],
					"note": "Incidents from blocked or flagged AI tool actions are triaged with owner, status, resolution note and an append-only history. Reporting to the national CERT (USOM/SOME) and the institution's response team are the institution's."
				},
				{
					"id": "BIG-KISISEL",
					"group": "Uygulama ve veri güvenliği",
					"title": "Kişisel verilerin güvenliği (security of personal data)",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents",
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity",
						"compliance-report.data_flows"
					],
					"note": "TR/EN personal data is masked before AI services receive it, telemetry is counts only and the data-flow inventory documents the product's own processing. KVKK obligations as a whole remain the controller's."
				},
				{
					"id": "BIG-SIZINTI",
					"group": "Uygulama ve veri güvenliği",
					"title": "Veri sızıntısının önlenmesi (data leakage prevention)",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"Prompt and tool-input data loss prevention for coding agents",
						"Tool output and MCP result inspection",
						"Inline allow / ask / deny decisions on AI coding agent tool calls"
					],
					"evidence": [
						"events.privacy_scan",
						"events.runtime_verdict",
						"tenant_dlp_policies"
					],
					"note": "Secrets and personal data are kept out of AI prompts, uploads, agent tool calls and MCP results on protected channels. Mail, removable media and unprotected sites are outside the product."
				},
				{
					"id": "BIG-BULUT",
					"group": "Uygulama ve veri güvenliği",
					"title": "Bulut ve yapay zekâ hizmetlerinin güvenli kullanımı (secure use of cloud and AI services)",
					"coverage": "partial",
					"capabilities": [
						"Browser Guard masking of personal data and secrets on AI chat sites",
						"AI acceptable-use notice with per-version acknowledgement",
						"Inventory of protected AI agents, browser installs and AI sites"
					],
					"evidence": [
						"events.privacy_scan",
						"events.aup_acknowledgement"
					],
					"note": "AI sites in use are counted, can be blocked by policy, show the acceptable-use notice and receive masked prompts. Choosing and contracting cloud services is the institution's."
				},
				{
					"id": "BIG-YERELLESTIRME",
					"group": "Uygulama ve veri güvenliği",
					"title": "Veri yerelleştirme (data localisation)",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Product data-flow and subprocessor inventory"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"note": "The control plane can run on the institution's own premises and the data-flow inventory lists every destination of product data. Deciding where data may be processed is the institution's."
				},
				{
					"id": "BIG-YAZILIM",
					"group": "Uygulama ve veri güvenliği",
					"title": "Güvenli yazılım geliştirme (secure software development)",
					"coverage": "customer-responsibility",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Plugin and skill scanning at session start",
						"Tool output and MCP result inspection"
					],
					"evidence": [
						"events.runtime_verdict",
						"threat-rules"
					],
					"note": "Dangerous commands, packages and secret exposure by AI coding agents are blocked during development. The institution's secure development process stays its own."
				},
				{
					"id": "BIG-ZARARLI",
					"group": "Ağ ve sistem güvenliği",
					"title": "Zararlı yazılımlardan korunma (protection against malware)",
					"coverage": "partial",
					"capabilities": [
						"Inline allow / ask / deny decisions on AI coding agent tool calls",
						"Plugin and skill scanning at session start",
						"Loopback MCP gateway with signed manifests"
					],
					"evidence": [
						"events.runtime_verdict",
						"threat-rules"
					],
					"note": "Malicious commands, downloads, plugins, skills and MCP results are blocked on the coding-agent path. The product does not replace endpoint protection."
				},
				{
					"id": "BIG-ZAFIYET",
					"group": "Ağ ve sistem güvenliği",
					"title": "Zafiyet yönetimi (vulnerability management)",
					"coverage": "customer-responsibility",
					"capabilities": [
						"AI tool-chain vulnerability and skill posture findings"
					],
					"evidence": [
						"posture_findings",
						"compliance-report.ai_security_posture"
					],
					"note": "CVE and exposed-component findings of the AI tool chain are reported by severity. Scanning and patching the institution's systems are the institution's."
				},
				{
					"id": "BIG-FARKINDALIK",
					"group": "Personel güvenliği",
					"title": "Personel farkındalığı (staff awareness)",
					"coverage": "customer-responsibility",
					"capabilities": [
						"AI acceptable-use notice with per-version acknowledgement"
					],
					"evidence": [
						"events.aup_acknowledgement"
					],
					"note": "The acceptable-use notice reaches staff at the moment they use an AI site and records acknowledgement. Awareness training is the institution's."
				},
				{
					"id": "BIG-DENETIM",
					"group": "Uygulama süreci",
					"title": "Uyum denetimi ve yönetime raporlama (compliance audit and reporting to management)",
					"coverage": "partial",
					"capabilities": [
						"Signed compliance evidence report",
						"Scheduled governance summary and executive report by email (English or Turkish)",
						"Governance scorecard and framework control matrix"
					],
					"evidence": [
						"compliance-report.policy_inventory",
						"executive-report",
						"governance-scorecard"
					],
					"note": "A signed evidence report, the scorecard and a scheduled executive report in Turkish or English support the institution's audit. The conformity audit itself is the institution's."
				}
			]
		}
	]
};
