/**
 * SkillTrustBench T01–T09 taxonomy used by AI-Infra-Guard Skill-Scan
 * (vendor/ai-infra-guard/skill-scan/skill_scan/utils/sarif_formatter.py).
 * The deterministic rules are data in `threats/skill-scan.yaml`; the code
 * carried in each rule id (`SKILL-T04-002`) selects the entry here.
 */
export const SKILL_RISK_TYPES: Readonly<Record<string, string>> = Object.freeze({
	T01: "Skill Instruction Hijacking",
	T02: "Agent Memory Poisoning",
	T03: "Remote Payload Retrieval and Execution",
	T04: "Embedded Malicious Code",
	T05: "Unauthorized Access and Privilege Escalation",
	T06: "System Persistence",
	T07: "Tool Hijacking and Spoofing",
	T08: "Insecure Dependencies",
	T09: "Insecure Skill Coding Practices",
});

const SKILL_RULE_ID_PATTERN = /^SKILL-(T0[1-9])-\d{3}$/;

/** The T01–T09 code of a skill-scan rule id, or undefined for any other rule. */
export function skillRiskTypeForThreatId(threatId: string): string | undefined {
	return SKILL_RULE_ID_PATTERN.exec(threatId)?.[1];
}
