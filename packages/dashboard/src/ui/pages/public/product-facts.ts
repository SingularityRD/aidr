/**
 * Countable product facts shown on the public pages. Each value is checked
 * against the repository by `src/__tests__/public-product-facts.test.ts`, so a
 * rule or catalog change that is not reflected here fails the build instead of
 * leaving stale marketing copy.
 */

import { LIST_PRICE_NOTICE, PLAN_CATALOG, type PlanDefinition } from "../../../billing/plans";

/** `- id:` entries across `threats/*.yaml`. */
export const SHIPPED_THREAT_RULES = 451;
/** YAML files under `threats/`. */
export const THREAT_RULE_FILES = 28;
/** AI Security Posture CVE rule files in the bundled vulnerability dataset, shown as a lower bound. */
export const AIG_CVE_RULES_FLOOR = 2000;
/** AI Security Posture AI component fingerprint files in the bundled dataset. */
export const AIG_AI_COMPONENTS = 146;
/** MCP risk categories (`mcp-01`..`mcp-14`) that `aidr discover` maps servers onto. */
export const POSTURE_MCP_RISK_CATEGORIES = 14;
/** Skill and plugin scan taxonomy codes (`threats/skill-scan.yaml`, `SKILL-Txx-nnn`). */
export const POSTURE_SKILL_RISK_CODES = [
	"T01",
	"T02",
	"T03",
	"T04",
	"T05",
	"T06",
	"T07",
	"T08",
	"T09",
] as const;

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

/**
 * Plans and list prices are not restated here: the single source is the
 * `public.plans` mirror in `src/billing/plans.ts`, which
 * `plan-catalog-drift.test.ts` binds to the migration seed.
 */
export const LIST_PRICE_NOTE = LIST_PRICE_NOTICE;

/** Active catalog plans in display order. */
export const PUBLIC_PLANS: readonly PlanDefinition[] = PLAN_CATALOG.filter(
	(plan) => plan.active,
).sort((a, b) => a.sortOrder - b.sortOrder);
