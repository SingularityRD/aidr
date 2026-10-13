import ruleTitles from "../generated/rule-titles.json";
import type { DashboardMessageKey } from "../i18n/en";
import type { DashboardLocale, Translate } from "../i18n/I18nProvider";

/**
 * Human-readable names for detection rules, generated from threats/*.yaml by
 * packages/dashboard/scripts/rule-titles.mjs. Only titles, categories and
 * severities are bundled; patterns never are.
 */
interface RuleTitleEntry {
	title: string;
	title_tr?: string;
	category?: string;
	severity?: string;
}

const RULES: Readonly<Record<string, RuleTitleEntry>> = ruleTitles.rules;

/**
 * Category → plain-language label. Families of categories share one label
 * (every `secure_code_*` category is "Insecure code").
 */
const CATEGORY_LABELS: ReadonlyArray<readonly [RegExp, DashboardMessageKey]> = [
	[/^tool$|^execution$|^tool_misuse$/, "rules.category.command"],
	[/^secrets$|^credential_access$|^skill_credential/, "rules.category.secrets"],
	[/^irreversible_action$/, "rules.category.irreversible"],
	[/^exfiltration$|^network_egress$|^command_and_control$/, "rules.category.exfiltration"],
	[/^persistence$|^skill_persistence$/, "rules.category.persistence"],
	[/^defense_evasion$|^self_defense$|^agent_sabotage$/, "rules.category.evasion"],
	[/^supply_chain$|^ai_supply_chain$|^skill_insecure_dependency$/, "rules.category.supplyChain"],
	[
		/^context_poisoning|^prompt_injection$|^indirect_prompt_injection$|^memory_poisoning$|^mcp_tool_poisoning$|^skill_instruction_hijack$|^skill_tool_hijack$|^skill_memory_poisoning$|^skill_unicode_smuggling$/,
		"rules.category.injection",
	],
	[/^secure_code_|^skill_insecure_coding$|^script_content$/, "rules.category.insecureCode"],
	[/^resource_hijacking$/, "rules.category.resourceHijacking"],
	[
		/^privilege_escalation$|^autonomy_escalation$|^skill_privilege_escalation$|^skill_excessive_permissions$/,
		"rules.category.privilege",
	],
	[/^discovery$|^reconnaissance$|^collection$|^lateral_movement$/, "rules.category.discovery"],
	[/^prompt_extraction$|^information_disclosure$/, "rules.category.disclosure"],
	[/^reward_hacking$/, "rules.category.rewardHacking"],
	[/^skill_/, "rules.category.skill"],
	[/^content_safety$/, "rules.category.contentSafety"],
];

export interface RuleDescription {
	id: string;
	/** Localized rule title, or null when the rule is not in the bundled catalog. */
	title: string | null;
	/** Localized category label, or null when unknown. */
	category: string | null;
	severity: string | null;
}

function categoryLabel(category: string | undefined, t: Translate): string | null {
	if (!category) return null;
	const match = CATEGORY_LABELS.find(([pattern]) => pattern.test(category));
	return match ? t(match[1]) : null;
}

/** Title (Turkish when the rule has one and the locale is Turkish), category and severity. */
export function describeRule(id: string, locale: DashboardLocale, t: Translate): RuleDescription {
	const entry = Object.hasOwn(RULES, id) ? RULES[id] : undefined;
	if (!entry) return { id, title: null, category: null, severity: null };
	const title = locale === "tr" && entry.title_tr ? entry.title_tr : entry.title;
	return {
		id,
		title,
		category: categoryLabel(entry.category, t),
		severity: entry.severity ?? null,
	};
}
