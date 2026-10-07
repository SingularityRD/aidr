import { CANARY_OUTPUT_RULE_ID, findCanaryTokens } from "./canary/detect.js";
import { inspectHiddenUnicode, ZERO_WIDTH_PAYLOAD_RUN } from "./hidden-unicode.js";
import { detectOutputSensitiveData } from "./output-sensitive-data.js";

type OutputFindingType =
	| "canary_triggered"
	| "secret_leak"
	| "prompt_injection_payload"
	| "system_prompt_leakage"
	| "unsafe_tool_instruction"
	| "hidden_instruction"
	| "context_poisoning"
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
	// Poisoned context: instructions planted in files, documents and tool
	// metadata the agent reads. The write-time counterparts are the rules in
	// threats/context-poisoning.yaml.
	{
		id: "OUT-POISON-001",
		type: "context_poisoning",
		severity: "critical",
		reason: "Output instructs the agent to send secrets or credentials to an external destination",
		pattern:
			/(?<!(?:\bnot|\bnever|n't|\bno)\s{1,4})\b(?:send|upload|post|transmit|exfiltrate|forward|leak)\b[^\n]{0,120}?\b(?:\.env\b|\.ssh\b|id_rsa|id_ed25519|credentials?|secrets?|api[ _-]?keys?|access[ _-]?tokens?|passwords?|private[ _-]?keys?|\.aws\b|\.npmrc|\.netrc|session[ _-]?tokens?)\b[^\n]{0,160}?(?:https?:\/\/|\bwebhooks?\b|\bcurl\b|pastebin|ngrok|requestbin|discord(?:app)?\.com|\b[\w.+-]{1,64}@[\w-]{1,63}\.[a-z]{2,})/i,
	},
	{
		id: "OUT-POISON-002",
		type: "context_poisoning",
		severity: "high",
		reason: "Output directs the agent to read private keys or credential files first",
		pattern:
			/\b(?:before|first|prior to)\b[^\n]{0,80}?\b(?:read|cat|open|load|include|attach|send|upload)\b[^\n]{0,80}?(?:~|\$HOME|%USERPROFILE%|\/home\/[^/\s]{1,64}|\/Users\/[^/\s]{1,64}|\/root)[/\\]\.(?:ssh|aws|gnupg|netrc|npmrc|pypirc|git-credentials|env\b)/i,
	},
	{
		id: "OUT-POISON-003",
		type: "context_poisoning",
		severity: "high",
		reason: "Output asks the agent to persist instructions into its instruction or memory files",
		pattern:
			/\b(?:add|append|write|save|insert|put|store|copy)\s{1,4}(?:this|these|the\s{1,4}following|it|them)\b[^\n]{0,60}?\b(?:to|into|in)\s{1,4}(?:your\s{1,4}|the\s{1,4})?(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|MEMORY\.md|copilot-instructions\.md|(?:long[- ]term\s{1,4})?memory|memories|system\s{1,4}prompt)(?![\w.])/i,
	},
	{
		id: "OUT-POISON-004",
		type: "context_poisoning",
		severity: "high",
		reason:
			"Output carries model-directed pseudo-markup, tool shadowing or a concealment directive",
		pattern:
			/<\s{0,4}(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|HIDDEN)\s{0,4}>|\b(?:when|whenever|every\s{1,4}time|if)\s{1,4}(?:you\s{1,4})?(?:use|call|invoke)s?\s{1,4}(?:any\s{1,4}other|another|other|all\s{1,4}other)\s{1,4}tools?\b[^\n]{0,160}?\b(?:also|must|always|first|instead)\b|(?:do\s{1,4}not|don'?t|never)\s{1,4}(?:tell|inform|notify|mention\s{1,4}(?:this|it)\s{1,4}to)\s{1,4}the\s{1,4}user/i,
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
	for (const finding of detectOutputSensitiveData(chunk)) {
		if (finding.index >= SCAN_STEP_CHARS) continue;
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
			// Every sensitive-data pattern requires a digit, an uppercase letter, `_`, `=` or `-`.
			if (!/[0-9A-Z_=-]/.test(chunk)) continue;
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

/**
 * Invisible-Unicode smuggling. It is checked on the raw output because the
 * canonical view deliberately strips zero-width characters. Text hidden in tag
 * characters is decoded and returned as an extra view, so the other rules also
 * see the instruction it carries.
 */
function hiddenUnicodeFindings(output: string): { findings: OutputFinding[]; decoded: string } {
	const report = inspectHiddenUnicode(output);
	const findings: OutputFinding[] = [];
	const hidden = (ruleId: string, severity: OutputFinding["severity"], reason: string) =>
		findings.push({
			type: "hidden_instruction",
			severity,
			reason,
			redactedExcerpt: "[REDACTED_HIDDEN_TEXT]",
			ruleId,
		});
	if (report.tagCount > 0) {
		hidden(
			"OUT-HIDE-001",
			"critical",
			"Output hides text in invisible Unicode tag characters (smuggled instructions)",
		);
	}
	if (report.longestZeroWidthRun >= ZERO_WIDTH_PAYLOAD_RUN) {
		hidden(
			"OUT-HIDE-002",
			"critical",
			"Output contains a long run of zero-width characters that can encode a hidden payload",
		);
	}
	if (report.bidiCount > 0) {
		hidden(
			"OUT-HIDE-003",
			"high",
			"Output contains bidirectional control characters that make text read differently from how it displays",
		);
	}
	return { findings, decoded: report.tagText };
}

/**
 * A registered canary token in tool output means the agent obtained decoy
 * credential content (a recursive grep, a copied file). Detection-internal
 * failures skip this signal; the pre-execution check logs registry problems.
 */
function canaryFindings(views: string[]): OutputFinding[] {
	try {
		const hits = views.flatMap((view) => findCanaryTokens(view));
		if (hits.length === 0) return [];
		const kinds = [...new Set(hits.map((hit) => hit.kind))].join(", ");
		return [
			{
				type: "canary_triggered",
				severity: "critical",
				reason: `Output contains a canary credential planted by Singularity AIDR (${kinds}); the agent may be following injected instructions`,
				redactedExcerpt: "[REDACTED_CANARY]",
				ruleId: CANARY_OUTPUT_RULE_ID,
			},
		];
	} catch {
		return [];
	}
}

export function scanModelOutput(output: string): OutputFinding[] {
	if (!output) return [];
	const deadline = performance.now() + OUTPUT_SCAN_TIME_BUDGET_MS;
	const expired = () => performance.now() >= deadline;
	if (exceedsByteLimit(output)) return coverageFinding("oversize");
	if (expired()) return coverageFinding("timeout");
	const hidden = hiddenUnicodeFindings(output);
	const views = inspectionViews(output);
	if (hidden.decoded) views.push(hidden.decoded);
	if (expired()) return coverageFinding("timeout");
	const sensitive = collectSensitiveFindings(views, expired);
	if (typeof sensitive === "string") return coverageFinding(sensitive);
	const rules = collectRuleFindings(views, expired);
	if (typeof rules === "string") return coverageFinding(rules);
	return [...canaryFindings(views), ...sensitive, ...rules, ...hidden.findings];
}
