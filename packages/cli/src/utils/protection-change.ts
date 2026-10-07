import { isDeepStrictEqual } from "node:util";
import { configPathParts } from "./config-values.js";

/**
 * Classify an `aidr config -s` change as tightening (or no change) versus
 * anything that could weaken protection.
 *
 * This is deliberately an ALLOWLIST of changes known to only make detection
 * stricter. Every other change — heuristics off, a rule added to
 * `disabled_threats`, a lower sensitivity, a check or policy disabled, an
 * endpoint, path or credential replaced, a whole object overwritten — needs the
 * operator confirmation that `aidr allowlist add` uses, because a prompt-injected
 * agent could otherwise switch AIDR off with one CLI call.
 */

const SENSITIVITY_RANK: Record<string, number> = { paranoid: 0, balanced: 1, relaxed: 2 };
const PROMPT_MODE_RANK: Record<string, number> = { block: 0, warn: 1, off: 2 };

/** Boolean switches for which `true` can only add inspection. */
const ENABLE_TIGHTENS = new Set([
	"heuristics_enabled",
	"policy.enabled",
	"policy.filesystem.enabled",
	"policy.network.enabled",
	"policy.shell.enabled",
	"policy.mcp.enabled",
	"url_check.enabled",
	"file_check.enabled",
	"package_check.enabled",
	"poisoning_protection.enabled",
	"amsi_check.enabled",
	"secure_code.enabled",
	"toxic_flow.enabled",
	"integrity.enabled",
	"intel.enabled",
	"logging.enabled",
	"incident.enabled",
	"agent_safety.runaway.enabled",
]);

function rankDoesNotLoosen(
	ranks: Record<string, number>,
	before: unknown,
	after: unknown,
): boolean {
	if (typeof before !== "string" || typeof after !== "string") return false;
	const from = ranks[before];
	const to = ranks[after];
	return from !== undefined && to !== undefined && to <= from;
}

/**
 * True when setting `key` from `before` (the effective current value) to
 * `after` cannot weaken protection. Unknown keys and shapes are treated as
 * weakening, so a new configuration field fails closed into a confirmation.
 */
export function isProtectionTightening(key: string, before: unknown, after: unknown): boolean {
	if (isDeepStrictEqual(before, after)) return true;
	const path = configPathParts(key).join(".");
	if (path === "sensitivity") return rankDoesNotLoosen(SENSITIVITY_RANK, before, after);
	// Per-category prompt protection modes (`secrets`, `pii`, `content_safety.*`):
	// off < warn < block. A non-mode value fails the rank check.
	if (path.startsWith("prompt_protection."))
		return rankDoesNotLoosen(PROMPT_MODE_RANK, before, after);
	if (path === "disabled_threats") {
		if (!Array.isArray(after) || !after.every((id) => typeof id === "string")) return false;
		const current = new Set(Array.isArray(before) ? before : []);
		return after.every((id) => current.has(id));
	}
	if (ENABLE_TIGHTENS.has(path)) return after === true;
	return false;
}
