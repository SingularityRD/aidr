/**
 * Countable product facts shown on the public pages. Each value is checked
 * against the repository by `src/__tests__/public-product-facts.test.ts`, so a
 * rule or catalog change that is not reflected here fails the build instead of
 * leaving stale marketing copy.
 */

import { LIST_PRICE_NOTICE, PLAN_CATALOG, type PlanDefinition } from "../../../billing/plans";

/** `- id:` entries across `threats/*.yaml`. */
export const SHIPPED_THREAT_RULES = 386;
/** YAML files under `threats/`. */
export const THREAT_RULE_FILES = 24;
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
