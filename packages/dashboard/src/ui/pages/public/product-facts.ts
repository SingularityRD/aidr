/**
 * Countable product facts shown on the public pages. Each value is checked
 * against the repository by `src/__tests__/public-product-facts.test.ts`, so a
 * rule or catalog change that is not reflected here fails the build instead of
 * leaving stale marketing copy.
 */

/** `- id:` entries across `threats/*.yaml`. */
export const SHIPPED_THREAT_RULES = 358;
/** YAML files under `threats/`. */
export const THREAT_RULE_FILES = 23;
/** AIG CVE rule files (`vendor/ai-infra-guard/data/vuln`, recursive), shown as a lower bound. */
export const AIG_CVE_RULES_FLOOR = 2000;
/** AIG AI component fingerprint files (`vendor/ai-infra-guard/data/fingerprints`, recursive). */
export const AIG_AI_COMPONENTS = 146;

export const AGENT_CONNECTORS = [
	"Claude Code",
	"Cursor",
	"VS Code",
	"OpenClaw",
	"OpenCode",
	"Codex CLI",
] as const;

/** Sites with a dedicated Browser Guard adapter (`packages/browser-guard/src/sites`). */
export const BROWSER_GUARD_SITES = [
	"ChatGPT",
	"Gemini",
	"Claude",
	"Copilot",
	"Perplexity",
	"DeepSeek",
	"Mistral",
	"Grok",
] as const;

export const BROWSER_GUARD_BROWSERS = ["Chrome", "Edge", "Firefox"] as const;

export const LIST_PRICE_NOTE = "List prices, subject to COM-001 approval.";

export interface PublicPlan {
	readonly name: "Free" | "Team" | "Business" | "Enterprise";
	readonly price: string;
	readonly terms: string;
	readonly features: readonly string[];
}

export const PUBLIC_PLANS: readonly PublicPlan[] = [
	{
		name: "Free",
		price: "$0",
		terms: "Local mode, no account",
		features: [
			`Agent connectors with ${SHIPPED_THREAT_RULES} local threat rules`,
			"Browser Guard masking with local settings",
			"Local allowlist and audit log",
		],
	},
	{
		name: "Team",
		price: "$20 / developer / month",
		terms: "Billed annually, or $24 monthly. Minimum 3 developers.",
		features: [
			"Cloud control plane and dashboard",
			"Central policy for agents and Browser Guard",
			"Audit export, SSO and MFA",
		],
	},
	{
		name: "Business",
		price: "$45 / developer / month",
		terms: "Billed annually. Minimum 25 developers.",
		features: [
			"Cloud or on-prem (Docker Compose)",
			"Exact-data match, SIEM delivery, signed packs",
			"AI Security Posture scans and named support",
		],
	},
	{
		name: "Enterprise",
		price: "Custom",
		terms: "Scoped by agreement",
		features: [
			"Kubernetes (Helm) and air-gapped installation",
			"Signed offline license and packs, SCIM",
			"Custom terms and support schedule",
		],
	},
];
