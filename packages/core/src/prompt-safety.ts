/**
 * Jailbreak and content-safety inspection for user prompts.
 *
 * This is a conservative, high-precision PATTERN matcher, not a model-grade
 * classifier. It is an oversight and policy aid: it catches well-known jailbreak
 * phrasings (instruction overrides, persona/role-play overrides, encoded-payload
 * requests, many-shot framing) and explicit requests in a configurable set of
 * content-safety categories. It will miss paraphrased or novel attempts, and it
 * is tuned to avoid firing on ordinary security, research or defensive work, so
 * it must never be presented as a guarantee. See `prompt_protection` in
 * docs/configuration.md.
 *
 * Results carry category names and match counts only, never the prompt text, so
 * the outcome can be shown, logged and audited without repeating the content.
 */

import type {
	PromptContentSafetyCategory,
	PromptProtectionConfig,
	PromptProtectionMode,
} from "./types.js";

export type PromptSafetyCategory = "jailbreak" | PromptContentSafetyCategory;

export interface PromptSafetyFinding {
	category: PromptSafetyCategory;
	/** Stable rule id, e.g. `jailbreak.instruction_override`. Never the matched text. */
	rule: string;
	count: number;
	/** The configured action for this finding's category (`warn` or `block`). */
	action: Exclude<PromptProtectionMode, "off">;
}

export interface PromptSafetyResult {
	/** The strongest action any category requires. */
	decision: PromptProtectionMode;
	findings: PromptSafetyFinding[];
}

/** Defaults applied when a caller's config predates these categories. */
export const DEFAULT_PROMPT_SAFETY = Object.freeze({
	jailbreak: "warn" as PromptProtectionMode,
	content_safety: Object.freeze({
		malware: "warn",
		phishing_kit: "warn",
		weapons_cbrn: "block",
		self_harm: "warn",
		hate_harassment: "warn",
		sexual_minors: "block",
	}) as Readonly<Record<PromptContentSafetyCategory, PromptProtectionMode>>,
});

const CONTENT_SAFETY_CATEGORIES: readonly PromptContentSafetyCategory[] = [
	"malware",
	"phishing_kit",
	"weapons_cbrn",
	"self_harm",
	"hate_harassment",
	"sexual_minors",
];

/** Human-readable category labels for user and model notices. */
export const PROMPT_SAFETY_LABELS: Readonly<Record<PromptSafetyCategory, string>> = {
	jailbreak: "jailbreak / instruction-override attempt",
	malware: "malware authoring request",
	phishing_kit: "credential-phishing kit request",
	weapons_cbrn: "weapons or CBRN request",
	self_harm: "self-harm content",
	hate_harassment: "hateful or harassing content",
	sexual_minors: "sexual content involving a minor",
};

interface Rule {
	rule: string;
	pattern: RegExp;
}

/**
 * Jailbreak phrasings beyond the two existing YAML rules (LLM-INJ-002/003).
 * Every pattern is anchored to an imperative aimed at the assistant's own rules
 * or persona, so it does not fire on a user merely discussing guidelines. TR
 * variants are included because AIDR ships Turkish-language support.
 */
const JAILBREAK_RULES: readonly Rule[] = [
	{
		// "ignore/disregard/forget your (previous) instructions/rules/guidelines/guardrails"
		rule: "jailbreak.instruction_override",
		pattern:
			/\b(?:ignore|disregard|forget|override|bypass|discard)\b[^.!?\n]{0,40}\b(?:your|the|all|previous|prior|above|earlier|any)\b[^.!?\n]{0,40}\b(?:instructions?|guidelines?|guardrails?|rules?|policies|policy|restrictions?|constraints?|safety|system prompt)\b/i,
	},
	{
		// Turkish: "önceki talimatları/kuralları yok say / görmezden gel / unut"
		rule: "jailbreak.instruction_override_tr",
		pattern:
			/\b(?:önceki|tüm|bütün|yukarıdaki|bütün)\b[^.!?\n]{0,40}\b(?:talimatlar[ıi]?|kurallar[ıi]?|y[öo]nergeler[ıi]?|k[ıi]s[ıi]tlamalar[ıi]?)\b[^.!?\n]{0,40}\b(?:yok say|g[öo]rmezden gel|unut|dikkate alma|geç)/i,
	},
	{
		// role-play / persona override that lifts the assistant's restrictions
		rule: "jailbreak.persona_override",
		pattern:
			/\b(?:pretend|act|behave|roleplay|role-play|imagine)\b[^.!?\n]{0,40}\b(?:you(?:'re| are)?|to be|as)\b[^.!?\n]{0,60}\b(?:no (?:rules|restrictions|limits|filters|guidelines)|without (?:any )?(?:rules|restrictions|limits|filters|guidelines|censorship)|unrestricted|unfiltered|uncensored|jailbroken|no longer bound)\b/i,
	},
	{
		// "you have no restrictions / you are not bound by ... / enter <name> mode"
		rule: "jailbreak.constraint_release",
		pattern:
			/\b(?:you (?:have|are) (?:now )?(?:no|free of|without)\b[^.!?\n]{0,40}(?:restrictions|rules|filters|guidelines|limits)|you are (?:not|no longer) (?:bound|restricted|limited|constrained)\b|enter(?:ing)? (?:dan|developer|god|jailbreak|do anything now) mode)\b/i,
	},
	{
		// many-shot framing: repeated "sure, here" jailbreak priming or long fake dialogue turns.
		// Indentation is `[ \t]*`, never `\s*`: a `\s*` after `\n` spans every following
		// blank line, which made a prompt of blank lines cost O(n²) (150k newlines ≈ 10 s,
		// past the host's hook timeout, which sends the prompt uninspected).
		rule: "jailbreak.many_shot",
		pattern:
			/(?:^|\n)[ \t]*(?:user|human|assistant|ai)[ \t]*:[^\n]*(?:\n[^\n]*){0,4}?\n[ \t]*(?:user|human|assistant|ai)[ \t]*:[^\n]*(?:\n[^\n]*){0,4}?\n[ \t]*(?:user|human|assistant|ai)[ \t]*:/i,
	},
	{
		// request to run / execute a decoded (base64/hex/rot13) payload
		rule: "jailbreak.encoded_payload",
		pattern:
			/\b(?:decode|base64[- ]?decode|from ?base64|rot13|hex[- ]?decode|unescape|atob)\b[^.!?\n]{0,60}\b(?:then|and)\b[^.!?\n]{0,40}\b(?:run|execute|eval|exec|follow|obey|do)\b/i,
	},
];

/**
 * Content-safety rules. Each requires an action verb AND a harmful object, so
 * ordinary defensive, analytical or fictional discussion does not match. These
 * are deliberately narrow; missing a real request is expected and acceptable for
 * a policy aid, whereas a false block is not.
 */
const AUTHOR = "(?:write|create|generate|build|develop|code|make|produce|design|craft)";

const CONTENT_SAFETY_RULES: Readonly<Record<PromptContentSafetyCategory, readonly Rule[]>> = {
	malware: [
		{
			rule: "malware.authoring",
			pattern: new RegExp(
				`\\b${AUTHOR}\\b[^.!?\\n]{0,60}\\b(?:ransomware|keylogger|rootkit|(?:remote access |r)?trojan|infostealer|info[- ]?stealer|spyware|computer (?:virus|worm)|botnet|cryptor|malware payload)\\b`,
				"i",
			),
		},
		{
			rule: "malware.evasion",
			pattern:
				/\b(?:write|create|generate|build|develop|code|make)\b[^.!?\n]{0,60}\b(?:code|script|payload|program)\b[^.!?\n]{0,60}\b(?:evade|bypass|disable|defeat)\b[^.!?\n]{0,30}\b(?:antivirus|anti-virus|\bav\b|edr|defender|sandbox|detection)\b/i,
		},
	],
	phishing_kit: [
		{
			rule: "phishing_kit.authoring",
			pattern: new RegExp(
				`\\b${AUTHOR}\\b[^.!?\\n]{0,60}\\b(?:phishing (?:kit|page|site|email|template)|fake login (?:page|form|portal)|credential[- ]?harvest(?:er|ing)? (?:page|kit))\\b`,
				"i",
			),
		},
		{
			rule: "phishing_kit.clone_login",
			pattern:
				/\b(?:clone|copy|replicate|spoof)\b[^.!?\n]{0,40}\b(?:login|sign[- ]?in)\b[^.!?\n]{0,40}\b(?:steal|capture|harvest|collect)\b[^.!?\n]{0,30}\b(?:credentials?|passwords?|logins?)\b/i,
		},
	],
	weapons_cbrn: [
		{
			rule: "weapons_cbrn.synthesis",
			pattern:
				/\b(?:synthesi[sz]e|manufacture|produce|make|build|create)\b[^.!?\n]{0,60}\b(?:nerve agent|sarin|vx gas|mustard gas|chemical weapon|biological weapon|bioweapon|nuclear (?:weapon|bomb|device)|dirty bomb|weaponi[sz]ed (?:anthrax|pathogen|virus))\b/i,
		},
		{
			rule: "weapons_cbrn.explosive",
			pattern:
				/\b(?:build|make|construct|assemble|create)\b[^.!?\n]{0,40}\b(?:pipe bomb|ied|improvised explosive|explosive device|detonator)\b/i,
		},
	],
	self_harm: [
		{
			rule: "self_harm.method",
			pattern:
				/\b(?:how (?:can|do) i|best way to|methods? (?:to|for)|help me)\b[^.!?\n]{0,40}\b(?:kill myself|end my life|commit suicide|take my (?:own )?life|hurt myself|harm myself)\b/i,
		},
	],
	hate_harassment: [
		{
			rule: "hate_harassment.generate",
			pattern: new RegExp(
				`\\b${AUTHOR}\\b[^.!?\\n]{0,50}\\b(?:hate speech|racist (?:rant|slurs?|screed)|slurs?)\\b[^.!?\\n]{0,40}\\b(?:against|targeting|about)\\b`,
				"i",
			),
		},
		{
			rule: "hate_harassment.threats",
			pattern:
				/\b(?:write|generate|compose)\b[^.!?\n]{0,40}\b(?:threatening|harassing|intimidating)\b[^.!?\n]{0,30}\b(?:message|letter|email|post)\b[^.!?\n]{0,30}\b(?:to|against|targeting)\b/i,
		},
	],
	sexual_minors: [
		{
			rule: "sexual_minors.explicit",
			pattern:
				/\b(?:sexual|explicit|erotic|pornographic|nude|naked)\b[^.!?\n]{0,60}\b(?:child|children|minor|minors|underage|pre[- ]?teen|preteen|toddler|infant|(?:\d|1[0-7])[- ]?year[- ]?old)\b|\b(?:child|minor|underage|pre[- ]?teen)\b[^.!?\n]{0,40}\b(?:sexual|explicit|erotic|pornograph|nude|naked)/i,
		},
	],
};

const ACTION_RANK: Record<PromptProtectionMode, number> = { off: 0, warn: 1, block: 2 };

function stronger(a: PromptProtectionMode, b: PromptProtectionMode): PromptProtectionMode {
	return ACTION_RANK[b] > ACTION_RANK[a] ? b : a;
}

/** Count non-overlapping matches of one rule. */
function countMatches(prompt: string, pattern: RegExp): number {
	const global = new RegExp(
		pattern.source,
		pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`,
	);
	let count = 0;
	while (global.exec(prompt) !== null) {
		count++;
		if (count >= 1000) break;
		if (global.lastIndex === 0) global.lastIndex = 1;
	}
	return count;
}

function jailbreakMode(config: PromptProtectionConfig): PromptProtectionMode {
	return config.jailbreak ?? DEFAULT_PROMPT_SAFETY.jailbreak;
}

function contentSafetyMode(
	config: PromptProtectionConfig,
	category: PromptContentSafetyCategory,
): PromptProtectionMode {
	if (category === "sexual_minors") return "block"; // always block, non-configurable
	return config.content_safety?.[category] ?? DEFAULT_PROMPT_SAFETY.content_safety[category];
}

/**
 * Scan one prompt for jailbreak and content-safety patterns. `deadlineCheck`, if
 * supplied, is called before every rule so a caller's scan deadline is honored:
 * the scan is synchronous, so a timer cannot interrupt it between checks.
 */
export function scanPromptSafety(
	prompt: string,
	config: PromptProtectionConfig,
	deadlineCheck?: () => void,
): PromptSafetyResult {
	const findings: PromptSafetyFinding[] = [];
	let decision: PromptProtectionMode = "off";

	const jailbreak = jailbreakMode(config);
	if (jailbreak !== "off") {
		for (const { rule, pattern } of JAILBREAK_RULES) {
			deadlineCheck?.();
			const count = countMatches(prompt, pattern);
			if (count > 0) {
				findings.push({ category: "jailbreak", rule, count, action: jailbreak });
				decision = stronger(decision, jailbreak);
			}
		}
	}

	for (const category of CONTENT_SAFETY_CATEGORIES) {
		const mode = contentSafetyMode(config, category);
		if (mode === "off") continue;
		for (const { rule, pattern } of CONTENT_SAFETY_RULES[category]) {
			deadlineCheck?.();
			const count = countMatches(prompt, pattern);
			if (count > 0) {
				findings.push({ category, rule, count, action: mode });
				decision = stronger(decision, mode);
			}
		}
	}

	return { decision, findings };
}

/** Tenant-provisioned prompt-safety floor (signed detector policy `prompt_safety`). */
export interface TenantPromptSafetyPolicy {
	jailbreak?: PromptProtectionMode;
	content_safety?: Partial<Record<PromptContentSafetyCategory, PromptProtectionMode>>;
}

/**
 * Apply a tenant floor to the local config: each category takes the STRONGER of
 * the local and tenant action, so a tenant policy can tighten but never relax
 * what the user configured (and nothing relaxes `sexual_minors`).
 */
export function applyTenantPromptSafety(
	config: PromptProtectionConfig,
	tenant: TenantPromptSafetyPolicy | undefined,
): PromptProtectionConfig {
	if (!tenant) return config;
	const contentSafety: Partial<Record<PromptContentSafetyCategory, PromptProtectionMode>> = {};
	for (const category of CONTENT_SAFETY_CATEGORIES) {
		contentSafety[category] = stronger(
			contentSafetyMode(config, category),
			tenant.content_safety?.[category] ?? "off",
		);
	}
	return {
		...config,
		jailbreak: stronger(jailbreakMode(config), tenant.jailbreak ?? "off"),
		content_safety: contentSafety,
	};
}
