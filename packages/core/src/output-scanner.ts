import { detectPII } from "./pii-detector.js";

export type OutputFindingType =
	| "secret_leak"
	| "prompt_injection_payload"
	| "system_prompt_leakage"
	| "unsafe_tool_instruction";

export interface OutputFinding {
	type: OutputFindingType;
	severity: "high" | "critical";
	reason: string;
	redactedExcerpt: string;
	ruleId: string;
}

const OUTPUT_RULES: Array<{
	id: string;
	type: OutputFindingType;
	severity: "high" | "critical";
	reason: string;
	pattern: RegExp;
}> = [
	{
		id: "OUT-INJ-001",
		type: "prompt_injection_payload",
		severity: "high",
		reason: "Output appears to contain prompt override payload",
		pattern:
			/\b(ignore\s+(?:all\s+)?(?:previous\s+|above\s+|system\s+)?(?:instructions?|guidelines?|rules?|constraints?|prompts?|messages?)|you are now|act as|developer mode|jailbreak)\b/i,
	},
	{
		id: "OUT-SYS-001",
		type: "system_prompt_leakage",
		severity: "critical",
		reason: "Output appears to disclose system prompt content",
		pattern:
			/\b(system prompt|system message|initial instructions?|hidden instructions?)\b[\s\S]{0,80}\b(is|are|:|=|contains)\b/i,
	},
	{
		id: "OUT-TOOL-001",
		type: "unsafe_tool_instruction",
		severity: "high",
		reason: "Output appears to instruct unsafe shell/tool execution",
		pattern:
			/\b(use the (bash|shell|terminal) tool|run (this|the following) command|curl\s+[^|]+\|\s*(sh|bash)|wget\s+[^|]+\|\s*(sh|bash))\b/i,
	},
];

function excerptRedacted(input: string, index: number, length: number): string {
	const start = Math.max(0, index - 40);
	const end = Math.min(input.length, index + length + 40);
	return detectPII(input.slice(start, end)).redacted;
}

export function scanModelOutput(output: string): OutputFinding[] {
	if (!output) return [];

	const findings: OutputFinding[] = [];
	const pii = detectPII(output);
	for (const finding of pii.findings) {
		if (finding.severity !== "critical" && finding.severity !== "high") continue;
		findings.push({
			type: "secret_leak",
			severity: finding.severity,
			reason: `Output contains ${finding.type}`,
			redactedExcerpt: excerptRedacted(output, finding.index, finding.value.length),
			ruleId: `OUT-PII-${finding.type.toUpperCase()}`,
		});
	}

	for (const rule of OUTPUT_RULES) {
		const match = rule.pattern.exec(output);
		if (!match || match.index == null) continue;
		findings.push({
			type: rule.type,
			severity: rule.severity,
			reason: rule.reason,
			redactedExcerpt: excerptRedacted(output, match.index, match[0].length),
			ruleId: rule.id,
		});
	}

	return findings;
}
