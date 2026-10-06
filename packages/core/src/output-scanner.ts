import { detectPII } from "./pii-detector.js";

type OutputFindingType =
	| "secret_leak"
	| "prompt_injection_payload"
	| "system_prompt_leakage"
	| "unsafe_tool_instruction"
	| "inspection_incomplete";

export interface OutputFinding {
	type: OutputFindingType;
	severity: "high" | "critical";
	reason: string;
	redactedExcerpt: string;
	ruleId: string;
}

/** Scanner safety ceiling; larger input is never classified clean. */
export const MAX_OUTPUT_SCAN_BYTES = 2 * 1024 * 1024;
export const OUTPUT_SCAN_TIME_BUDGET_MS = 3_000;
const SCAN_STEP_CHARS = 4_096;
const SCAN_OVERLAP_CHARS = 2_048;
const MAX_OUTPUT_FINDINGS = 128;

type CoverageFailure = "oversize" | "timeout" | "finding_limit";

function coverageFinding(failure: CoverageFailure): OutputFinding[] {
	const details = {
		oversize: ["OUT-COVERAGE-SIZE", "Output exceeds the inspection byte limit"],
		timeout: ["OUT-COVERAGE-TIME", "Output inspection exceeded the time budget"],
		finding_limit: ["OUT-COVERAGE-DENSITY", "Output contains too many findings to report safely"],
	} as const;
	const [ruleId, reason] = details[failure];
	return [
		{
			type: "inspection_incomplete",
			severity: "critical",
			reason,
			redactedExcerpt: "[REDACTED_UNINSPECTED_OUTPUT]",
			ruleId,
		},
	];
}

/** Count only up to the cap, without allocating a full UTF-8 copy of output. */
function exceedsByteLimit(output: string): boolean {
	let bytes = 0;
	for (let index = 0; index < output.length; index += 1) {
		const code = output.charCodeAt(index);
		if (code <= 0x7f) bytes += 1;
		else if (code <= 0x7ff) bytes += 2;
		else if (code >= 0xd800 && code <= 0xdbff && index + 1 < output.length) {
			const next = output.charCodeAt(index + 1);
			if (next >= 0xdc00 && next <= 0xdfff) {
				bytes += 4;
				index += 1;
			} else bytes += 3;
		} else bytes += 3;
		if (bytes > MAX_OUTPUT_SCAN_BYTES) return true;
	}
	return false;
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
			/\b(system prompt|system message|initial instructions?|hidden instructions?)\b[\s\S]{0,80}\b(is|are|:|=|contains)\b(?!\s*(?:not|never)\b)/i,
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

/** Decode common JSON escapes before checking model-visible text. */
export function canonicalOutput(output: string): string {
	return output
		.replace(
			/\\u([0-9a-fA-F]{4})|\\([nrt])/g,
			(_match, hex: string | undefined, control: string | undefined) =>
				hex
					? String.fromCharCode(Number.parseInt(hex, 16))
					: control === "n"
						? "\n"
						: control === "r"
							? "\r"
							: "\t",
		)
		.normalize("NFKC")
		.replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
		.replace(/\s+/g, " ");
}

function inspectionViews(output: string): string[] {
	const canonical = canonicalOutput(output);
	// JSON string fragments can split a single instruction or credential.
	const joined = canonical
		.replace(/["']\s*,\s*["']/g, "")
		.replace(/["'`{}\[\]\\,]/g, "")
		.replace(/:/g, " ");
	const views = [output];
	if (canonical !== output) views.push(canonical);
	if (joined !== canonical && joined !== output) views.push(joined);
	return views;
}

function appendSensitiveChunk(
	chunk: string,
	viewIndex: number,
	findings: OutputFinding[],
	seenSensitiveValues: Set<string>,
): boolean {
	const pii = detectPII(chunk);
	for (const finding of pii.findings) {
		if (finding.index >= SCAN_STEP_CHARS) continue;
		if (finding.severity !== "critical" && finding.severity !== "high") continue;
		const key = `${finding.type}:${finding.value}`;
		if (viewIndex > 0 && seenSensitiveValues.has(key)) continue;
		seenSensitiveValues.add(key);
		findings.push({
			type: "secret_leak",
			severity: finding.severity,
			reason: `Output contains ${finding.type}`,
			redactedExcerpt: `[REDACTED_${finding.type.toUpperCase()}]`,
			ruleId: `OUT-PII-${finding.type.toUpperCase()}`,
		});
		if (findings.length >= MAX_OUTPUT_FINDINGS) return false;
	}
	return true;
}

function collectSensitiveFindings(
	views: string[],
	expired: () => boolean,
): OutputFinding[] | CoverageFailure {
	const findings: OutputFinding[] = [];
	const seenSensitiveValues = new Set<string>();
	for (const [viewIndex, view] of views.entries()) {
		for (let start = 0; start < view.length; start += SCAN_STEP_CHARS) {
			if (expired()) return "timeout";
			const chunk = view.slice(start, start + SCAN_STEP_CHARS + SCAN_OVERLAP_CHARS);
			// Every PII pattern requires one of these characters or the bearer prefix.
			if (!/[@0-9A-Z:_=-]|bearer/.test(chunk)) continue;
			const withinLimit = appendSensitiveChunk(chunk, viewIndex, findings, seenSensitiveValues);
			if (expired()) return "timeout";
			if (!withinLimit) return "finding_limit";
		}
	}
	return findings;
}

function isEducationalInjectionMention(view: string, start: number, end: number): boolean {
	const prefix = view.slice(Math.max(0, start - 120), start);
	const suffix = view.slice(end, end + 64);
	// Exempt only a short, explicitly attributed definition of the phrase.
	return (
		/\b(?:security\s+)?(?:guide|documentation|article|report|training\s+material)\s+(?:explains?|describes?|says?)\s+that\s*$/i.test(
			prefix,
		) && /^\s+is\s+(?:a|an)\s+prompt\s+injection\s+(?:example|pattern)\b/i.test(suffix)
	);
}

function findRuleInView(
	rule: (typeof OUTPUT_RULES)[number],
	view: string,
	expired: () => boolean,
): OutputFinding | "timeout" | null {
	for (let start = 0; start < view.length; start += SCAN_STEP_CHARS) {
		if (expired()) return "timeout";
		const chunk = view.slice(start, start + SCAN_STEP_CHARS + SCAN_OVERLAP_CHARS);
		const pattern = new RegExp(rule.pattern.source, `${rule.pattern.flags}g`);
		while (true) {
			const match = pattern.exec(chunk);
			if (expired()) return "timeout";
			if (!match) break;
			if (match.index >= SCAN_STEP_CHARS) break;
			const absoluteStart = start + match.index;
			const absoluteEnd = absoluteStart + match[0].length;
			if (
				rule.id === "OUT-INJ-001" &&
				isEducationalInjectionMention(view, absoluteStart, absoluteEnd)
			) {
				continue;
			}
			return {
				type: rule.type,
				severity: rule.severity,
				reason: rule.reason,
				redactedExcerpt: "[REDACTED_UNTRUSTED_OUTPUT]",
				ruleId: rule.id,
			};
		}
	}
	return null;
}

function collectRuleFindings(views: string[], expired: () => boolean): OutputFinding[] | "timeout" {
	const findings: OutputFinding[] = [];
	for (const rule of OUTPUT_RULES) {
		for (const view of views) {
			const found = findRuleInView(rule, view, expired);
			if (found === "timeout") return "timeout";
			if (!found) continue;
			findings.push(found);
			break;
		}
	}
	return findings;
}

export function scanModelOutput(output: string): OutputFinding[] {
	if (!output) return [];
	const deadline = performance.now() + OUTPUT_SCAN_TIME_BUDGET_MS;
	const expired = () => performance.now() >= deadline;
	if (exceedsByteLimit(output)) return coverageFinding("oversize");
	if (expired()) return coverageFinding("timeout");
	const views = inspectionViews(output);
	if (expired()) return coverageFinding("timeout");
	const sensitive = collectSensitiveFindings(views, expired);
	if (typeof sensitive === "string") return coverageFinding(sensitive);
	const rules = collectRuleFindings(views, expired);
	if (typeof rules === "string") return coverageFinding(rules);
	return [...sensitive, ...rules];
}
