// Generated from governance/frameworks/*.yaml; do not edit.
// Regenerate: node scripts/sync-governance-frameworks.mjs --write

export type GovernanceCoverage = "full" | "partial" | "customer-responsibility";

export interface GovernanceCapability {
	readonly id: string;
	readonly title: string;
	readonly description: string;
	readonly signal: string;
}

export interface GovernanceEvidenceSource {
	readonly id: string;
	readonly kind: string;
	readonly ref: string;
	readonly detail: string;
}

export interface GovernanceControl {
	readonly id: string;
	readonly group: string;
	readonly title: string;
	readonly capabilities: readonly string[];
	readonly evidence: readonly string[];
	readonly coverage: GovernanceCoverage;
	readonly note: string;
}

export interface GovernanceFramework {
	readonly id: string;
	readonly name: string;
	readonly version: string;
	readonly reference: string;
	readonly scope: string;
	readonly controls: readonly GovernanceControl[];
}

export const GOVERNANCE_MAPPING: {
	readonly source: string;
	readonly source_sha256: string;
	readonly capabilities: readonly GovernanceCapability[];
	readonly evidence: readonly GovernanceEvidenceSource[];
	readonly frameworks: readonly GovernanceFramework[];
} = {
	"source": "governance/frameworks",
	"source_sha256": "aea5733d805d194bb65eef2294f2cd7f2b1ad160c8b001b21565b343544ef048",
	"capabilities": [
		{
			"id": "runtime-enforcement",
			"title": "Inline allow / ask / deny decisions on AI coding agent tool calls",
			"description": "Commands, file access, web requests, packages and MCP calls of the supported coding agents are evaluated before they run. Connector entry points fail closed on an internal error.",
			"signal": "agents_reporting"
		},
		{
			"id": "threat-rule-library",
			"title": "Versioned threat rule library (data, not code)",
			"description": "YAML threat definitions evaluated by every connector.",
			"signal": "agents_reporting"
		},
		{
			"id": "prompt-dlp-protection",
			"title": "Prompt and tool-input data loss prevention for coding agents",
			"description": "Personal data and secrets in agent prompts and tool inputs are detected and handled according to the workspace DLP policy.",
			"signal": "dlp_policy_configured"
		},
		{
			"id": "output-inspection",
			"title": "Tool output and MCP result inspection",
			"description": "Sensitive data and injected instructions in tool outputs are detected before they reach the model.",
			"signal": "agents_reporting"
		},
		{
			"id": "browser-guard-masking",
			"title": "Browser Guard masking of personal data and secrets on AI chat sites",
			"description": "The browser extension masks TR/EN personal data and secrets before a prompt, paste or file reaches a protected AI site, and can block sites. Only counts are reported.",
			"signal": "browser_guard_reporting"
		},
		{
			"id": "acceptable-use-notice",
			"title": "AI acceptable-use notice with per-version acknowledgement",
			"description": "Administrators publish an acceptable-use notice in managed browser policy; Browser Guard shows it once per version on a protected AI site and reports acknowledgement counts only.",
			"signal": "acceptable_use_acknowledged"
		},
		{
			"id": "human-approval",
			"title": "Out-of-band human approval for ask decisions",
			"description": "An ask verdict blocks the action until a person approves it outside the agent (dashboard approval by an owner or admin, or the local operator CLI). No approval tool is exposed to the agent.",
			"signal": "human_approval_in_use"
		},
		{
			"id": "oversight-analytics",
			"title": "Human oversight analytics (decision latency, expiry, rubber-stamp review prompts)",
			"description": "The governance scorecard measures how approvals are decided: volume, approve/deny ratio, median decision latency, requests that expired undecided and approvers whose pattern suggests automatic approval.",
			"signal": "human_approval_in_use"
		},
		{
			"id": "runtime-policy-management",
			"title": "Versioned runtime policy with revision history",
			"description": "Default actions per artifact type, MCP server and tool allow/approval/deny lists, staged rollout and a revision history with digests.",
			"signal": "runtime_policy_configured"
		},
		{
			"id": "mcp-gateway",
			"title": "Loopback MCP gateway with signed manifests",
			"description": "Inspects MCP tool results and enforces operator-approved server manifests on the endpoint.",
			"signal": "local_only"
		},
		{
			"id": "mcp-inventory",
			"title": "MCP server inventory and attestation reporting",
			"description": "MCP servers found on endpoints are reported with transport, attestation state and risk categories.",
			"signal": "mcp_inventory_reported"
		},
		{
			"id": "ai-posture-scanning",
			"title": "AI tool-chain vulnerability and skill posture findings",
			"description": "CVE, exposed component and skill findings uploaded from scans, by severity.",
			"signal": "posture_reported"
		},
		{
			"id": "plugin-skill-scanning",
			"title": "Plugin and skill scanning at session start",
			"description": "Installed agent plugins and skills are scanned against the threat rules when a session starts.",
			"signal": "agents_reporting"
		},
		{
			"id": "ai-asset-inventory",
			"title": "Inventory of protected AI agents, browser installs and AI sites",
			"description": "Every enrolled agent and browser install is a registered seat with runtime, first and last seen; AI sites in use are counted from Browser Guard scans.",
			"signal": "agents_reporting"
		},
		{
			"id": "incident-management",
			"title": "Incident correlation and tracking",
			"description": "Blocked and flagged actions are correlated into incidents with severity and status.",
			"signal": "agents_reporting"
		},
		{
			"id": "siem-export",
			"title": "SIEM export of incidents",
			"description": "Incidents are delivered to the organisation's SIEM from a durable local queue.",
			"signal": "local_only"
		},
		{
			"id": "audit-logging",
			"title": "Decision and administrative audit logs",
			"description": "Endpoints keep a local JSONL decision log; the control plane keeps an append-only administrative audit log and the reported decision events. Logs hold decisions, digests and identifiers, not prompt text.",
			"signal": "always"
		},
		{
			"id": "audit-export",
			"title": "Paginated audit export with legal-hold awareness",
			"description": "Owners and admins export audit records as JSON or CSV.",
			"signal": "always"
		},
		{
			"id": "identity-access-control",
			"title": "Role-based access with MFA, SSO and SCIM",
			"description": "Owner, admin, member and viewer roles; workspace MFA and SAML requirements enforced as a tenant identity barrier on every tenant table; SCIM provisioning.",
			"signal": "mfa_required"
		},
		{
			"id": "tenant-isolation",
			"title": "Tenant isolation with row-level security",
			"description": "Every tenant table carries membership policies plus the restrictive tenant identity barrier.",
			"signal": "always"
		},
		{
			"id": "retention-legal-hold",
			"title": "Retention policies, legal holds and verified offboarding",
			"description": "Retention days per data class, legal holds that pause deletion, and offboarding with phase receipts.",
			"signal": "retention_configured"
		},
		{
			"id": "compliance-evidence-report",
			"title": "Signed compliance evidence report",
			"description": "Tenant-scoped, period-bounded evidence bundle designed to support KVKK and GDPR accountability work.",
			"signal": "compliance_report_generated"
		},
		{
			"id": "data-flow-inventory",
			"title": "Product data-flow and subprocessor inventory",
			"description": "Purpose, destination, region, retention and transfer mechanism of each product data flow.",
			"signal": "always"
		},
		{
			"id": "governance-scorecard",
			"title": "Governance scorecard and framework control matrix",
			"description": "Executive view computed from the workspace's own records, with this control mapping.",
			"signal": "always"
		},
		{
			"id": "governance-digest",
			"title": "Scheduled governance summary by email",
			"description": "Weekly or monthly counts-only summary sent to the workspace owners (and admins).",
			"signal": "governance_digest_enabled"
		}
	],
	"evidence": [
		{
			"id": "events.runtime_verdict",
			"kind": "table",
			"ref": "events",
			"detail": "Agent decisions (allow, ask, deny) reported by managed connectors, with source and severity."
		},
		{
			"id": "events.privacy_scan",
			"kind": "table",
			"ref": "events",
			"detail": "Browser Guard scans (masked, warned, blocked, allowed) by site, channel and entity type. Counts only."
		},
		{
			"id": "events.incident",
			"kind": "table",
			"ref": "events",
			"detail": "Incidents reported by connectors, with severity and status."
		},
		{
			"id": "events.aup_acknowledgement",
			"kind": "table",
			"ref": "events",
			"detail": "One acknowledgement per browser install and acceptable-use notice version. Counts only."
		},
		{
			"id": "agents",
			"kind": "table",
			"ref": "agents",
			"detail": "Enrolled agents and browser installs by runtime, first seen and last seen."
		},
		{
			"id": "approval_requests",
			"kind": "table",
			"ref": "approval_requests",
			"detail": "Dashboard approval requests with status, approver and decision time."
		},
		{
			"id": "admin_audit_logs",
			"kind": "table",
			"ref": "admin_audit_logs",
			"detail": "Append-only administrative audit log."
		},
		{
			"id": "posture_findings",
			"kind": "table",
			"ref": "posture_findings",
			"detail": "CVE, MCP server and skill findings by severity, attestation and risk category."
		},
		{
			"id": "tenant_runtime_policies",
			"kind": "table",
			"ref": "tenant_runtime_policies",
			"detail": "Current runtime policy version and update time."
		},
		{
			"id": "runtime_policy_revisions",
			"kind": "table",
			"ref": "runtime_policy_revisions",
			"detail": "Runtime policy revision history."
		},
		{
			"id": "tenant_dlp_policies",
			"kind": "table",
			"ref": "tenant_dlp_policies",
			"detail": "Current DLP policy version and update time."
		},
		{
			"id": "dlp_policy_revisions",
			"kind": "table",
			"ref": "dlp_policy_revisions",
			"detail": "DLP policy revision history."
		},
		{
			"id": "tenant_identity_policies",
			"kind": "table",
			"ref": "tenant_identity_policies",
			"detail": "Workspace MFA, SSO and break-glass settings."
		},
		{
			"id": "tenant_data_retention_policies",
			"kind": "table",
			"ref": "tenant_data_retention_policies",
			"detail": "Retention days per data class."
		},
		{
			"id": "tenant_legal_holds",
			"kind": "table",
			"ref": "tenant_legal_holds",
			"detail": "Legal holds that pause deletion."
		},
		{
			"id": "tenant_offboarding_runs",
			"kind": "table",
			"ref": "tenant_offboarding_runs",
			"detail": "Offboarding runs with phase receipts."
		},
		{
			"id": "tenant_governance_settings",
			"kind": "table",
			"ref": "tenant_governance_settings",
			"detail": "Governance summary schedule and human-oversight review thresholds."
		},
		{
			"id": "governance_digest_deliveries",
			"kind": "table",
			"ref": "governance_digest_deliveries",
			"detail": "Delivery receipts of scheduled and test governance summaries (counts, status)."
		},
		{
			"id": "compliance-report.protection_coverage",
			"kind": "report_section",
			"ref": "protection_coverage",
			"detail": "Compliance report section on agents and browser installs in scope."
		},
		{
			"id": "compliance-report.data_protection_activity",
			"kind": "report_section",
			"ref": "data_protection_activity",
			"detail": "Compliance report section on masking and DLP decisions (counts only)."
		},
		{
			"id": "compliance-report.policy_inventory",
			"kind": "report_section",
			"ref": "policy_inventory",
			"detail": "Compliance report section on policy versions and digests."
		},
		{
			"id": "compliance-report.access_identity",
			"kind": "report_section",
			"ref": "access_identity",
			"detail": "Compliance report section on MFA, SSO, SCIM and the owner/admin list."
		},
		{
			"id": "compliance-report.incidents",
			"kind": "report_section",
			"ref": "incidents",
			"detail": "Compliance report section on incidents by severity and status."
		},
		{
			"id": "compliance-report.ai_security_posture",
			"kind": "report_section",
			"ref": "ai_security_posture",
			"detail": "Compliance report section on CVE, MCP and skill findings."
		},
		{
			"id": "compliance-report.data_flows",
			"kind": "report_section",
			"ref": "data_flows",
			"detail": "Compliance report section with the data-flow and subprocessor inventory."
		},
		{
			"id": "compliance-report.retention_deletion",
			"kind": "report_section",
			"ref": "retention_deletion",
			"detail": "Compliance report section on retention, legal holds and offboarding receipts."
		},
		{
			"id": "audit-export",
			"kind": "function",
			"ref": "audit-export",
			"detail": "JSON or CSV export of audit records."
		},
		{
			"id": "governance-digest",
			"kind": "function",
			"ref": "governance-digest",
			"detail": "Scheduled governance summary dispatch and test sends."
		},
		{
			"id": "governance-scorecard",
			"kind": "rpc",
			"ref": "governance_scorecard",
			"detail": "Counts-only governance scorecard for a 7, 30 or 90 day period."
		},
		{
			"id": "local-audit-log",
			"kind": "file",
			"ref": "packages/core/src/audit-log.ts",
			"detail": "Endpoint JSONL decision log (stays on the endpoint unless exported)."
		},
		{
			"id": "siem-export",
			"kind": "file",
			"ref": "packages/core/src/siem-export.ts",
			"detail": "SIEM export format and delivery queue."
		},
		{
			"id": "privacy-data-flow-matrix",
			"kind": "file",
			"ref": "docs/production-readiness/privacy-data-flow-matrix.json",
			"detail": "Engineering data-flow matrix; unknown values are completed per deployment."
		},
		{
			"id": "threat-rules",
			"kind": "file",
			"ref": "threats",
			"detail": "Threat rule files evaluated by the connectors."
		}
	],
	"frameworks": [
		{
			"id": "nist-ai-rmf",
			"name": "NIST AI Risk Management Framework",
			"version": "AI RMF 1.0 (NIST AI 100-1, January 2023)",
			"reference": "https://www.nist.gov/itl/ai-risk-management-framework",
			"scope": "Subcategories of the GOVERN, MAP, MEASURE and MANAGE functions where Singularity AIDR provides a technical capability or evidence for the AI coding agents, AI chat sites and MCP servers it guards. The framework is voluntary; this mapping supports your risk management program and is not an attestation.",
			"controls": [
				{
					"id": "GOVERN 1.1",
					"group": "GOVERN",
					"title": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
					"capabilities": [
						"compliance-evidence-report",
						"data-flow-inventory"
					],
					"evidence": [
						"compliance-report.data_flows",
						"privacy-data-flow-matrix"
					],
					"coverage": "customer-responsibility",
					"note": "Understanding which laws apply is the organisation's task. The compliance evidence report and the data-flow inventory are inputs to that work, not a legal assessment."
				},
				{
					"id": "GOVERN 1.4",
					"group": "GOVERN",
					"title": "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities.",
					"capabilities": [
						"runtime-policy-management",
						"prompt-dlp-protection",
						"runtime-enforcement"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions",
						"tenant_dlp_policies",
						"compliance-report.policy_inventory"
					],
					"coverage": "partial",
					"note": "Runtime and DLP policies are explicit, versioned and enforced on every guarded tool call, with revision history and digests. The risk priorities behind them are set by the organisation."
				},
				{
					"id": "GOVERN 1.5",
					"group": "GOVERN",
					"title": "Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities clearly defined, including determining the frequency of periodic review.",
					"capabilities": [
						"governance-scorecard",
						"governance-digest"
					],
					"evidence": [
						"governance-scorecard",
						"governance-digest",
						"governance_digest_deliveries",
						"tenant_governance_settings"
					],
					"coverage": "partial",
					"note": "The scorecard and the weekly or monthly summary give reviewers a recurring, data-backed view; who reviews and what they decide stays with the organisation."
				},
				{
					"id": "GOVERN 1.6",
					"group": "GOVERN",
					"title": "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.",
					"capabilities": [
						"ai-asset-inventory",
						"mcp-inventory",
						"browser-guard-masking"
					],
					"evidence": [
						"agents",
						"posture_findings",
						"events.privacy_scan",
						"compliance-report.protection_coverage"
					],
					"coverage": "partial",
					"note": "Enrolled agents, browser installs, AI sites seen by Browser Guard and reported MCP servers form an inventory of AI tool use. Unmanaged endpoints and AI systems outside these channels are not visible."
				},
				{
					"id": "GOVERN 2.1",
					"group": "GOVERN",
					"title": "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.",
					"capabilities": [
						"identity-access-control",
						"human-approval"
					],
					"evidence": [
						"compliance-report.access_identity",
						"admin_audit_logs"
					],
					"coverage": "partial",
					"note": "Workspace roles decide who may change policy and who may approve blocked actions; the role list and administrative actions are recorded. Organisational role definitions outside the product remain the customer's."
				},
				{
					"id": "GOVERN 2.2",
					"group": "GOVERN",
					"title": "The organization's personnel and partners receive AI risk management training to enable them to perform their duties and responsibilities consistent with related policies, procedures, and agreements.",
					"capabilities": [
						"acceptable-use-notice"
					],
					"evidence": [
						"events.aup_acknowledgement"
					],
					"coverage": "partial",
					"note": "The acceptable-use notice and its per-version acknowledgement counts show that browser users were shown the policy. It is awareness, not training; training content and records stay with the organisation."
				},
				{
					"id": "GOVERN 4.3",
					"group": "GOVERN",
					"title": "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.",
					"capabilities": [
						"incident-management",
						"siem-export",
						"audit-export"
					],
					"evidence": [
						"events.incident",
						"compliance-report.incidents",
						"siem-export",
						"audit-export"
					],
					"coverage": "partial",
					"note": "Blocked and flagged agent actions become incidents that can be exported to a SIEM or as audit records. Testing practices and external information sharing are the organisation's."
				},
				{
					"id": "GOVERN 6.1",
					"group": "GOVERN",
					"title": "Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party's intellectual property or other rights.",
					"capabilities": [
						"runtime-policy-management",
						"mcp-gateway",
						"plugin-skill-scanning",
						"browser-guard-masking"
					],
					"evidence": [
						"tenant_runtime_policies",
						"posture_findings"
					],
					"coverage": "partial",
					"note": "MCP server and tool allow/approval/deny lists, plugin and skill scanning and AI-site blocking address security and data-exposure risk from third-party AI components. Intellectual-property and contractual risk are not assessed by the product."
				},
				{
					"id": "GOVERN 6.2",
					"group": "GOVERN",
					"title": "Contingency processes are in place to handle failures or incidents in third-party data or AI systems deemed to be high-risk.",
					"capabilities": [
						"runtime-enforcement",
						"runtime-policy-management"
					],
					"evidence": [
						"tenant_runtime_policies",
						"events.incident"
					],
					"coverage": "partial",
					"note": "Connector entry points fail closed on an internal error, and a policy change can deny a misbehaving MCP server or tool across the fleet. Business continuity for the third-party AI service itself is the organisation's."
				},
				{
					"id": "MAP 3.5",
					"group": "MAP",
					"title": "Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function.",
					"capabilities": [
						"human-approval",
						"oversight-analytics"
					],
					"evidence": [
						"approval_requests",
						"governance-scorecard",
						"admin_audit_logs"
					],
					"coverage": "partial",
					"note": "Ask decisions stop an agent action until a person approves it out of band, and the scorecard measures how those decisions are made. Defining which actions need oversight is done in policy by the organisation."
				},
				{
					"id": "MAP 4.1",
					"group": "MAP",
					"title": "Approaches for mapping AI technology and legal risks of its components, including the use of third-party data or software, are in place, followed, and documented, as are risks of infringement of a third party's intellectual property or other rights.",
					"capabilities": [
						"mcp-inventory",
						"plugin-skill-scanning",
						"ai-posture-scanning"
					],
					"evidence": [
						"posture_findings",
						"compliance-report.ai_security_posture"
					],
					"coverage": "partial",
					"note": "Covers the security risk of agent components (MCP servers, plugins, skills and known vulnerabilities). Legal and intellectual-property risk mapping is not performed."
				},
				{
					"id": "MAP 4.2",
					"group": "MAP",
					"title": "Internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented.",
					"capabilities": [
						"runtime-policy-management",
						"governance-scorecard"
					],
					"evidence": [
						"tenant_runtime_policies",
						"compliance-report.policy_inventory",
						"governance-scorecard"
					],
					"coverage": "partial",
					"note": "The controls AIDR applies are documented by the policy inventory and by this control matrix. Controls implemented in other tools are outside it."
				},
				{
					"id": "MEASURE 1.1",
					"group": "MEASURE",
					"title": "Approaches and metrics for measurement of AI risks enumerated during the MAP function are selected for implementation starting with the most significant AI risks.",
					"capabilities": [
						"governance-scorecard"
					],
					"evidence": [
						"governance-scorecard"
					],
					"coverage": "partial",
					"note": "The scorecard supplies ready metrics (decision volumes, approvals, incidents, masking counts, policy age). Selecting which metrics matter is the organisation's."
				},
				{
					"id": "MEASURE 2.4",
					"group": "MEASURE",
					"title": "The functionality and behavior of the AI system and its components, as identified in the MAP function, are monitored when in production.",
					"capabilities": [
						"runtime-enforcement",
						"browser-guard-masking",
						"governance-scorecard"
					],
					"evidence": [
						"events.runtime_verdict",
						"events.privacy_scan",
						"governance-scorecard"
					],
					"coverage": "full",
					"note": "Every guarded tool call and every Browser Guard send is evaluated and, on managed installs, reported as a counts-only event. Only enrolled agents and browsers are monitored."
				},
				{
					"id": "MEASURE 2.7",
					"group": "MEASURE",
					"title": "AI system security and resilience, as identified in the MAP function, are evaluated and documented.",
					"capabilities": [
						"threat-rule-library",
						"output-inspection",
						"ai-posture-scanning",
						"plugin-skill-scanning"
					],
					"evidence": [
						"threat-rules",
						"posture_findings",
						"compliance-report.ai_security_posture"
					],
					"coverage": "partial",
					"note": "Threat rules, prompt-injection signals, output inspection and posture findings document the security of the agent tool chain. Model-level robustness testing is not performed."
				},
				{
					"id": "MEASURE 2.10",
					"group": "MEASURE",
					"title": "Privacy risk of the AI system, as identified in the MAP function, is examined and documented.",
					"capabilities": [
						"browser-guard-masking",
						"prompt-dlp-protection",
						"data-flow-inventory"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity",
						"privacy-data-flow-matrix"
					],
					"coverage": "partial",
					"note": "Counts of personal data and secrets masked, warned about or blocked show where prompts carried personal data. Privacy impact assessments remain the organisation's."
				},
				{
					"id": "MEASURE 3.1",
					"group": "MEASURE",
					"title": "Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual performance in deployed contexts.",
					"capabilities": [
						"incident-management",
						"ai-posture-scanning",
						"governance-scorecard"
					],
					"evidence": [
						"events.incident",
						"posture_findings",
						"governance-scorecard"
					],
					"coverage": "partial",
					"note": "Incidents, posture findings and the scorecard's top-risks list are tracked over time. Personnel and review cadence are the organisation's."
				},
				{
					"id": "MANAGE 1.3",
					"group": "MANAGE",
					"title": "Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.",
					"capabilities": [
						"runtime-policy-management",
						"runtime-enforcement",
						"prompt-dlp-protection"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions",
						"tenant_dlp_policies"
					],
					"coverage": "partial",
					"note": "Deny, ask and masking policies are the documented technical responses for the risks AIDR detects. Transfer and acceptance decisions are made by the organisation."
				},
				{
					"id": "MANAGE 2.4",
					"group": "MANAGE",
					"title": "Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.",
					"capabilities": [
						"runtime-enforcement",
						"runtime-policy-management",
						"browser-guard-masking"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions"
					],
					"coverage": "partial",
					"note": "A policy change can deny an agent action type, an MCP server or tool, or block an AI site in managed browsers. AIDR stops actions of guarded tools; it does not switch off the vendor's AI service."
				},
				{
					"id": "MANAGE 3.1",
					"group": "MANAGE",
					"title": "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.",
					"capabilities": [
						"mcp-inventory",
						"ai-posture-scanning",
						"runtime-policy-management"
					],
					"evidence": [
						"posture_findings",
						"tenant_runtime_policies"
					],
					"coverage": "partial",
					"note": "MCP servers, plugins, skills and known vulnerabilities are monitored where scans are uploaded. Benefits are not measured."
				},
				{
					"id": "MANAGE 4.1",
					"group": "MANAGE",
					"title": "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management.",
					"capabilities": [
						"human-approval",
						"incident-management",
						"runtime-policy-management",
						"governance-digest"
					],
					"evidence": [
						"approval_requests",
						"events.incident",
						"runtime_policy_revisions",
						"governance_digest_deliveries"
					],
					"coverage": "partial",
					"note": "Human approval provides the override path, incidents the response trail and policy revisions the change record. User feedback collection and decommissioning plans are the organisation's."
				},
				{
					"id": "MANAGE 4.3",
					"group": "MANAGE",
					"title": "Incidents and errors are communicated to relevant AI actors, including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.",
					"capabilities": [
						"incident-management",
						"siem-export",
						"governance-digest"
					],
					"evidence": [
						"events.incident",
						"compliance-report.incidents",
						"siem-export"
					],
					"coverage": "partial",
					"note": "Incidents are tracked with severity and status, exported to SIEM and summarised to owners. Communication to affected people and regulators is the organisation's."
				}
			]
		},
		{
			"id": "iso-iec-42001",
			"name": "ISO/IEC 42001 AI management system",
			"version": "ISO/IEC 42001:2023, Annex A",
			"reference": "https://www.iso.org/standard/81230.html",
			"scope": "Annex A controls where Singularity AIDR provides a technical capability or evidence for an organisation that uses AI coding agents, AI chat sites and MCP servers. The organisation decides applicability in its Statement of Applicability; this mapping supports that work and is not a certification.",
			"controls": [
				{
					"id": "A.2.2",
					"group": "A.2 Policies related to AI",
					"title": "AI policy",
					"capabilities": [
						"acceptable-use-notice",
						"runtime-policy-management"
					],
					"evidence": [
						"events.aup_acknowledgement",
						"tenant_runtime_policies"
					],
					"coverage": "partial",
					"note": "The acceptable-use notice distributes the organisation's AI use policy to browser users and runtime policy enforces its technical rules for coding agents. Writing and approving the AI policy is the organisation's."
				},
				{
					"id": "A.2.4",
					"group": "A.2 Policies related to AI",
					"title": "Review of the AI policy",
					"capabilities": [
						"runtime-policy-management",
						"governance-scorecard"
					],
					"evidence": [
						"runtime_policy_revisions",
						"dlp_policy_revisions",
						"governance-scorecard"
					],
					"coverage": "partial",
					"note": "Revision history and the scorecard's policy-age figures show when technical policy was last reviewed. Review of the written policy itself is outside the product."
				},
				{
					"id": "A.3.2",
					"group": "A.3 Internal organization",
					"title": "AI roles and responsibilities",
					"capabilities": [
						"identity-access-control",
						"human-approval"
					],
					"evidence": [
						"compliance-report.access_identity",
						"admin_audit_logs"
					],
					"coverage": "partial",
					"note": "Workspace roles separate who administers policy, who approves blocked actions and who only reads. Organisation-wide AI roles are defined by the customer."
				},
				{
					"id": "A.3.3",
					"group": "A.3 Internal organization",
					"title": "Reporting of concerns",
					"capabilities": [],
					"evidence": [],
					"coverage": "customer-responsibility",
					"note": "AIDR has no channel for people to report concerns; incidents in the product are raised by connectors, not by staff."
				},
				{
					"id": "A.4.4",
					"group": "A.4 Resources for AI systems",
					"title": "Tooling resources",
					"capabilities": [
						"ai-asset-inventory",
						"mcp-inventory"
					],
					"evidence": [
						"agents",
						"posture_findings",
						"compliance-report.protection_coverage"
					],
					"coverage": "partial",
					"note": "The inventory lists agent runtimes, browser installs and MCP servers in use on enrolled endpoints. Unmanaged tooling is not visible."
				},
				{
					"id": "A.5.2",
					"group": "A.5 Assessing impacts of AI systems",
					"title": "AI system impact assessment process",
					"capabilities": [
						"compliance-evidence-report",
						"governance-scorecard"
					],
					"evidence": [
						"compliance-report.data_protection_activity",
						"governance-scorecard"
					],
					"coverage": "customer-responsibility",
					"note": "Impact assessments are performed by the organisation; the evidence report and the scorecard provide factual input on how AI tools are used."
				},
				{
					"id": "A.6.2.6",
					"group": "A.6 AI system life cycle",
					"title": "AI system operation and monitoring",
					"capabilities": [
						"runtime-enforcement",
						"browser-guard-masking",
						"governance-scorecard",
						"incident-management"
					],
					"evidence": [
						"events.runtime_verdict",
						"events.privacy_scan",
						"events.incident",
						"governance-scorecard"
					],
					"coverage": "partial",
					"note": "Operation of the AI tools the organisation uses is monitored at the point of use (tool calls and prompts). Monitoring of models the organisation builds itself is out of scope."
				},
				{
					"id": "A.6.2.8",
					"group": "A.6 AI system life cycle",
					"title": "AI system recording of event logs",
					"capabilities": [
						"audit-logging",
						"runtime-enforcement",
						"audit-export"
					],
					"evidence": [
						"events.runtime_verdict",
						"admin_audit_logs",
						"local-audit-log",
						"audit-export"
					],
					"coverage": "partial",
					"note": "Decisions are logged on the endpoint and, on managed installs, in the control plane; administrative actions are logged append-only. Logs carry decisions, digests and identifiers rather than prompt text, and are kept according to the workspace retention policy."
				},
				{
					"id": "A.8.2",
					"group": "A.8 Information for interested parties of AI systems",
					"title": "System documentation and information for users",
					"capabilities": [
						"acceptable-use-notice",
						"runtime-enforcement",
						"browser-guard-masking"
					],
					"evidence": [
						"events.aup_acknowledgement"
					],
					"coverage": "partial",
					"note": "Users see the acceptable-use notice, the reason for each blocked action and in-page coaching when data is masked. Vendor documentation of the AI service is outside the product."
				},
				{
					"id": "A.8.4",
					"group": "A.8 Information for interested parties of AI systems",
					"title": "Communication of incidents",
					"capabilities": [
						"incident-management",
						"siem-export",
						"governance-digest"
					],
					"evidence": [
						"events.incident",
						"siem-export",
						"governance_digest_deliveries"
					],
					"coverage": "partial",
					"note": "Incidents reach the SIEM and the owners' summary. Communicating incidents to users, customers or authorities is the organisation's."
				},
				{
					"id": "A.9.2",
					"group": "A.9 Use of AI systems",
					"title": "Processes for responsible use of AI systems",
					"capabilities": [
						"runtime-policy-management",
						"runtime-enforcement",
						"browser-guard-masking",
						"acceptable-use-notice",
						"human-approval"
					],
					"evidence": [
						"tenant_runtime_policies",
						"events.runtime_verdict",
						"events.privacy_scan",
						"approval_requests"
					],
					"coverage": "partial",
					"note": "Responsible-use rules are enforced at the point of use: risky agent actions are denied or held for human approval and personal data is masked before it reaches AI sites. The organisation defines the process those rules implement."
				},
				{
					"id": "A.9.3",
					"group": "A.9 Use of AI systems",
					"title": "Objectives for responsible use of AI system",
					"capabilities": [
						"governance-scorecard"
					],
					"evidence": [
						"governance-scorecard"
					],
					"coverage": "customer-responsibility",
					"note": "Objectives are set by the organisation; the scorecard can track the ones that map to product metrics."
				},
				{
					"id": "A.9.4",
					"group": "A.9 Use of AI systems",
					"title": "Intended use of the AI system",
					"capabilities": [
						"runtime-policy-management",
						"browser-guard-masking",
						"mcp-gateway"
					],
					"evidence": [
						"tenant_runtime_policies"
					],
					"coverage": "partial",
					"note": "Blocked AI sites, MCP allow/deny lists and per-artifact default actions keep agent and browser use within the scope the organisation allows."
				},
				{
					"id": "A.10.2",
					"group": "A.10 Third-party and customer relationships",
					"title": "Allocating responsibilities",
					"capabilities": [
						"data-flow-inventory"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"coverage": "customer-responsibility",
					"note": "The data-flow inventory documents what the product processes and which subprocessors are involved; allocating responsibilities between the organisation and its AI suppliers is contractual."
				},
				{
					"id": "A.10.3",
					"group": "A.10 Third-party and customer relationships",
					"title": "Suppliers",
					"capabilities": [
						"mcp-inventory",
						"plugin-skill-scanning",
						"browser-guard-masking",
						"ai-asset-inventory"
					],
					"evidence": [
						"posture_findings",
						"events.privacy_scan"
					],
					"coverage": "partial",
					"note": "Shows which AI sites, MCP servers, plugins and skills are in use and their findings. Supplier due diligence and contracts are the organisation's."
				}
			]
		},
		{
			"id": "eu-ai-act",
			"name": "EU Artificial Intelligence Act",
			"version": "Regulation (EU) 2024/1689",
			"reference": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
			"scope": "Obligations of organisations that use (deploy) AI systems, plus the human-oversight article customers use as a reference. The mapping supports your obligations; it is not legal advice and does not determine whether a system is high-risk.",
			"controls": [
				{
					"id": "Art. 4",
					"group": "General provisions",
					"title": "AI literacy",
					"capabilities": [
						"acceptable-use-notice",
						"browser-guard-masking",
						"runtime-enforcement"
					],
					"evidence": [
						"events.aup_acknowledgement",
						"events.privacy_scan"
					],
					"coverage": "partial",
					"note": "Applies to all deployers. The acceptable-use notice is shown once per version on protected AI sites and acknowledgements are counted; in-page coaching and block reasons explain risky use in context. Training measures appropriate to staff roles remain the organisation's."
				},
				{
					"id": "Art. 5",
					"group": "Prohibited AI practices",
					"title": "Prohibited AI practices",
					"capabilities": [
						"browser-guard-masking"
					],
					"evidence": [],
					"coverage": "customer-responsibility",
					"note": "Whether an AI use falls under a prohibited practice is a legal assessment. Browser Guard can block an AI site the organisation decides not to allow, but it does not classify practices."
				},
				{
					"id": "Art. 14",
					"group": "High-risk AI systems - requirements",
					"title": "Human oversight (provider design obligation; reference for agent oversight)",
					"capabilities": [
						"human-approval",
						"oversight-analytics",
						"runtime-enforcement"
					],
					"evidence": [
						"approval_requests",
						"governance-scorecard",
						"events.runtime_verdict"
					],
					"coverage": "partial",
					"note": "Article 14 binds providers of high-risk systems. For AI agents, AIDR gives deployers a working oversight layer: actions can be stopped (deny) or held for a person (ask), and the scorecard flags approval patterns that suggest over-reliance (automation bias) as a review prompt. It does not make any AI system conform to Article 14."
				},
				{
					"id": "Art. 26(1)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Use in accordance with the instructions for use",
					"capabilities": [
						"runtime-policy-management",
						"runtime-enforcement"
					],
					"evidence": [
						"tenant_runtime_policies",
						"runtime_policy_revisions"
					],
					"coverage": "partial",
					"note": "High-risk systems only. Technical and organisational measures that keep agent use within the instructions can be expressed as runtime policy; reading and following the provider's instructions is the organisation's."
				},
				{
					"id": "Art. 26(2)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Assign human oversight to competent, trained persons with authority and support",
					"capabilities": [
						"human-approval",
						"identity-access-control",
						"oversight-analytics"
					],
					"evidence": [
						"approval_requests",
						"compliance-report.access_identity",
						"governance-scorecard"
					],
					"coverage": "partial",
					"note": "High-risk systems only. Only owners and admins (with step-up authentication) can approve held actions; the scorecard shows who decides and how. Competence and training of those people are the organisation's."
				},
				{
					"id": "Art. 26(5)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Monitor operation; inform the provider and suspend use when a risk or serious incident arises",
					"capabilities": [
						"runtime-enforcement",
						"incident-management",
						"governance-digest",
						"runtime-policy-management"
					],
					"evidence": [
						"events.runtime_verdict",
						"events.incident",
						"governance_digest_deliveries"
					],
					"coverage": "partial",
					"note": "High-risk systems only. Decisions and incidents are monitored and summarised, and a policy change can stop agent actions. Informing the provider, distributor or market surveillance authority is the organisation's."
				},
				{
					"id": "Art. 26(6)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Keep automatically generated logs under the deployer's control for at least six months",
					"capabilities": [
						"audit-logging",
						"retention-legal-hold",
						"audit-export"
					],
					"evidence": [
						"events.runtime_verdict",
						"tenant_data_retention_policies",
						"tenant_legal_holds",
						"audit-export"
					],
					"coverage": "partial",
					"note": "High-risk systems only. AIDR's own decision logs can be retained for six months or longer by setting telemetry retention to at least 183 days, and exported. Logs generated by the high-risk AI system itself are outside AIDR."
				},
				{
					"id": "Art. 26(7)",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Inform workers' representatives and affected workers before workplace use",
					"capabilities": [
						"acceptable-use-notice"
					],
					"evidence": [
						"events.aup_acknowledgement"
					],
					"coverage": "customer-responsibility",
					"note": "High-risk systems only. The acceptable-use notice can carry the information to browser users, but information and consultation duties toward worker representatives are the organisation's."
				},
				{
					"id": "Art. 27",
					"group": "Obligations of deployers of high-risk AI systems",
					"title": "Fundamental rights impact assessment",
					"capabilities": [
						"compliance-evidence-report"
					],
					"evidence": [
						"compliance-report.data_protection_activity"
					],
					"coverage": "customer-responsibility",
					"note": "Applies to certain deployers of certain high-risk systems. The assessment is the deployer's; product evidence can be an input."
				}
			]
		},
		{
			"id": "kvkk-gdpr",
			"name": "KVKK and GDPR",
			"version": "KVKK Law No. 6698; GDPR Regulation (EU) 2016/679",
			"reference": "docs/compliance-report.md",
			"scope": "Articles where the compliance evidence report and the product's privacy capabilities provide evidence about AI tool use. This is not a statement that an organisation meets either law.",
			"controls": [
				{
					"id": "GDPR Art. 5(1)(c)",
					"group": "GDPR",
					"title": "Data minimisation",
					"capabilities": [
						"browser-guard-masking",
						"prompt-dlp-protection"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity"
					],
					"coverage": "partial",
					"note": "Personal data is masked or blocked before prompts reach AI services, and telemetry is counts only. A masked send still sends the redacted text; monitor-mode and allowed sends go unchanged."
				},
				{
					"id": "GDPR Art. 5(2)",
					"group": "GDPR",
					"title": "Accountability",
					"capabilities": [
						"compliance-evidence-report",
						"governance-scorecard",
						"audit-logging"
					],
					"evidence": [
						"compliance-report.policy_inventory",
						"admin_audit_logs",
						"governance-scorecard"
					],
					"coverage": "partial",
					"note": "Signed evidence reports, the audit log and the scorecard help demonstrate the measures in place for AI tool use. Accountability for the processing as a whole remains the controller's."
				},
				{
					"id": "GDPR Art. 25",
					"group": "GDPR",
					"title": "Data protection by design and by default",
					"capabilities": [
						"browser-guard-masking",
						"prompt-dlp-protection",
						"runtime-policy-management"
					],
					"evidence": [
						"compliance-report.data_protection_activity",
						"tenant_dlp_policies"
					],
					"coverage": "partial",
					"note": "Masking is on by default in Browser Guard and DLP policy applies to agent prompts and tool inputs, so protection does not depend on each user's choice."
				},
				{
					"id": "GDPR Art. 30",
					"group": "GDPR",
					"title": "Records of processing activities",
					"capabilities": [
						"data-flow-inventory",
						"compliance-evidence-report"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"coverage": "customer-responsibility",
					"note": "The data-flow inventory is input for the controller's records; values marked unknown must be completed for the deployment."
				},
				{
					"id": "GDPR Art. 32",
					"group": "GDPR",
					"title": "Security of processing",
					"capabilities": [
						"runtime-enforcement",
						"identity-access-control",
						"tenant-isolation",
						"audit-logging",
						"browser-guard-masking"
					],
					"evidence": [
						"compliance-report.access_identity",
						"compliance-report.protection_coverage",
						"events.runtime_verdict",
						"tenant_identity_policies"
					],
					"coverage": "partial",
					"note": "Technical measures around AI tool use: inline enforcement, masking, MFA/SSO, tenant isolation and logging. Organisational measures and the rest of the estate are outside the product."
				},
				{
					"id": "GDPR Art. 33",
					"group": "GDPR",
					"title": "Notification of a personal data breach to the supervisory authority",
					"capabilities": [
						"incident-management"
					],
					"evidence": [
						"events.incident",
						"compliance-report.incidents"
					],
					"coverage": "customer-responsibility",
					"note": "Incidents give the timeline input; deciding whether an incident is a personal data breach and notifying within 72 hours is the controller's."
				},
				{
					"id": "KVKK Art. 4",
					"group": "KVKK",
					"title": "General principles (processing that is relevant, limited and proportionate)",
					"capabilities": [
						"browser-guard-masking",
						"prompt-dlp-protection"
					],
					"evidence": [
						"events.privacy_scan",
						"compliance-report.data_protection_activity"
					],
					"coverage": "partial",
					"note": "Masking and DLP limit the personal data sent to AI services to what the prompt needs. Lawfulness of the underlying processing is the controller's assessment."
				},
				{
					"id": "KVKK Art. 7",
					"group": "KVKK",
					"title": "Erasure, destruction or anonymisation of personal data",
					"capabilities": [
						"retention-legal-hold"
					],
					"evidence": [
						"tenant_data_retention_policies",
						"tenant_legal_holds",
						"tenant_offboarding_runs",
						"compliance-report.retention_deletion"
					],
					"coverage": "partial",
					"note": "Product telemetry is deleted according to the workspace retention policy, legal holds pause deletion, and offboarding leaves phase receipts. Backups follow a separate expiry and are outside the live-data receipts."
				},
				{
					"id": "KVKK Art. 9",
					"group": "KVKK",
					"title": "Transfer of personal data abroad",
					"capabilities": [
						"data-flow-inventory"
					],
					"evidence": [
						"privacy-data-flow-matrix",
						"compliance-report.data_flows"
					],
					"coverage": "customer-responsibility",
					"note": "The inventory lists destinations, regions and transfer mechanisms for product data flows; the transfer assessment and its legal basis are the controller's."
				},
				{
					"id": "KVKK Art. 12",
					"group": "KVKK",
					"title": "Obligations concerning data security",
					"capabilities": [
						"runtime-enforcement",
						"browser-guard-masking",
						"identity-access-control",
						"tenant-isolation",
						"audit-logging"
					],
					"evidence": [
						"compliance-report.access_identity",
						"compliance-report.data_protection_activity",
						"admin_audit_logs",
						"tenant_identity_policies"
					],
					"coverage": "partial",
					"note": "Technical measures to prevent unlawful disclosure of personal data through AI tools, with access control and audit evidence. Administrative measures and audits are the controller's."
				}
			]
		}
	]
};
