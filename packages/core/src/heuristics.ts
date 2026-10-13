/**
 * Heuristics engine — matches artifacts against loaded threat definitions.
 *
 * ── Bounded-work contract (read before changing this file) ──────────────────
 * Matching runs synchronously in the hook process, and `hooks/hooks.json` gives
 * the PreToolUse hook a 15s timeout. A hook that is killed before it writes its
 * verdict leaves the tool call uninspected — so unbounded matching time is a
 * detection-evasion primitive, not just a slowdown.
 *
 * A previous implementation tried to defend against that with a wall-clock
 * check *after* `RegExp.exec()` returned. That only measured elapsed time; it
 * could not interrupt anything, so it never prevented the blow-up (a 20KB
 * command already cost ~0.9s, 100KB ~27s), and when it did fire it dropped the
 * threat — losing the detection it was meant to protect.
 *
 * GUARANTEED:
 *  - Every artifact is matched against at most MAX_MATCH_INPUT characters (its
 *    retained prefix), so matching work is bounded by
 *    O(patterns × MAX_MATCH_INPUT) and does not grow with the tool call size.
 *  - Truncation is never silent: it is reported on stderr, stating that the
 *    result covers the retained prefix only.
 *  - The patterns shipped in `threats/*.yaml` are linear-time in the input
 *    length (no ambiguous/nested quantifiers over unbounded spans). That is a
 *    data invariant guarded by `__tests__/regex-performance.test.ts`.
 *
 * NOT GUARANTEED:
 *  - There is NO wall-clock timeout. JavaScript cannot pre-empt a running
 *    `RegExp.exec()` on the same thread; only a Worker could, at the cost of
 *    copying and serialising every artifact. Bounded input + linear patterns
 *    are the actual bound: a newly introduced pathological pattern would still
 *    block the thread, but only for the bounded input size.
 *  - Content that appears exclusively after MAX_MATCH_INPUT characters is not
 *    inspected by heuristics. The truncation warning is the signal that this
 *    happened; a truncated evaluation must never be read as a full clean one.
 */

import {
	DELETED_TEST_FILE_VIEW,
	EDIT_VIEW_TYPES,
	type EditLineViewEntry,
	type EditViews,
} from "./agent-safety/edit-views.js";
import {
	isTrustedModelSourceMatch,
	NO_TRUSTED_MODEL_SOURCES,
	type TrustedModelSources,
} from "./ai-supply-chain.js";
import { boundArtifact, extractUrls, MAX_ARTIFACT_SIZE } from "./extractors.js";
import { normalizeShellText } from "./shell-normalize.js";
import { extractDomain, isTrustedDomain } from "./trusted-domains.js";
import type { Artifact, HeuristicMatch, Threat, TrustedDomain } from "./types.js";

/**
 * Maximum number of characters of an artifact that any pattern is run against.
 * Kept equal to the extraction cap so the engine and the extractors agree on
 * what "inspected" means; this is a backstop for artifacts that reach the
 * engine without passing through the extractors.
 */
const MAX_MATCH_INPUT = MAX_ARTIFACT_SIZE;

/**
 * `match_on` suffix for rules evaluated against the shell-normalized view of an
 * artifact (`command_normalized`, `file_path_normalized`, `content_normalized`).
 */
const NORMALIZED_SUFFIX = "_normalized";

/**
 * `match_on` value of the rules run against the canonical paths a call
 * removes, moves, overwrites or re-permissions (`self-defense-paths.ts`).
 */
export const MODIFIED_PATH_VIEW = "modified_path";

function countMatchingLines(
	pattern: RegExp,
	lines: readonly string[],
): { count: number; first: string | undefined } {
	let count = 0;
	let first: string | undefined;
	for (const line of lines) {
		if (!pattern.test(line)) continue;
		count++;
		first ??= line;
	}
	return { count, first };
}

/**
 * `setting -> number` for every line where the pattern's first capture group is
 * a number. The key is the matched text with that number blanked, so
 * `lines: 80` and `lines: 60` compare as the same setting.
 */
function numericSettings(pattern: RegExp, lines: readonly string[]): Map<string, number> {
	const settings = new Map<string, number>();
	for (const line of lines) {
		const match = pattern.exec(line);
		const raw = match?.[1];
		if (!match || raw === undefined) continue;
		const value = Number.parseFloat(raw);
		if (!Number.isFinite(value)) continue;
		const key = match[0].replace(raw, "#").toLowerCase().replace(/\s+/g, "");
		settings.set(key, value);
	}
	return settings;
}
/**
 * Occurrences of one model-source rule examined per artifact before the match
 * is kept as-is (fail towards reporting, never towards suppression).
 */
const MAX_SOURCE_OCCURRENCES = 50;

/** Threat IDs where trusted installer domains suppress matches. */
const TRUSTED_DOMAIN_SUPPRESSIBLE = new Set(["CLT-CMD-001", "CLT-CMD-002", "CLT-SUPPLY-001"]);

export class HeuristicsEngine {
	private readonly threatMap: Map<string, Threat[]> = new Map();
	private readonly trustedDomains: TrustedDomain[];
	private readonly trustedModelSources: TrustedModelSources;
	/** Regex failures are deliberate signal skips, never a clean evaluation. */
	private _unavailableThreats: Array<{ threatId: string; reason: string }> = [];

	get unavailableThreats(): ReadonlyArray<{ threatId: string; reason: string }> {
		return this._unavailableThreats;
	}

	constructor(
		threats: Threat[],
		trustedDomains?: TrustedDomain[],
		trustedModelSources: TrustedModelSources = NO_TRUSTED_MODEL_SOURCES,
	) {
		this.trustedDomains = trustedDomains ?? [];
		this.trustedModelSources = trustedModelSources;

		for (const threat of threats) {
			for (const matchType of threat.matchOn) {
				// Route domain threats to url artifact type
				const artifactType = matchType === "domain" ? "url" : matchType;
				const existing = this.threatMap.get(artifactType);
				if (existing) {
					existing.push(threat);
				} else {
					this.threatMap.set(artifactType, [threat]);
				}
			}
		}
	}

	private isSuppressedByTrustedDomain(match: HeuristicMatch): boolean {
		if (this.trustedDomains.length === 0) return false;
		if (!TRUSTED_DOMAIN_SUPPRESSIBLE.has(match.threat.id)) return false;

		// Suppress only when the *matched* substring exclusively references trusted domains.
		// This prevents a trusted-domain "decoy" from suppressing a match that also contains
		// untrusted URLs elsewhere in the same command artifact.
		const urls = extractUrls(match.matchValue);
		if (urls.length === 0) return false;

		for (const url of urls) {
			const domain = extractDomain(url);
			if (!domain) return false;
			if (!isTrustedDomain(domain, this.trustedDomains)) return false;
		}
		return true;
	}

	/**
	 * A model-source match (AISC rules) is dropped only when EVERY occurrence of
	 * the rule in the artifact names trusted sources. `exec` reports the first
	 * occurrence only, so a trusted download listed first would otherwise hide
	 * an untrusted one after it. Returns the first untrusted occurrence, the
	 * match itself for non-source rules, or null when all occurrences are trusted.
	 */
	private untrustedModelSourceMatch(match: HeuristicMatch): HeuristicMatch | null {
		const trusted = (matchValue: string) =>
			isTrustedModelSourceMatch(
				match.threat.id,
				matchValue,
				this.trustedModelSources,
				match.artifact,
			);
		if (!trusted(match.matchValue)) return match;
		const { source, flags } = match.threat.compiledPattern;
		const pattern = new RegExp(source, `${flags.replace(/[gy]/g, "")}g`);
		let occurrences = 0;
		for (let m = pattern.exec(match.artifact); m !== null; m = pattern.exec(match.artifact)) {
			if (m[0] === "") pattern.lastIndex++;
			if (!trusted(m[0])) {
				return { ...match, matchValue: m[0] };
			}
			if (++occurrences >= MAX_SOURCE_OCCURRENCES) return match;
		}
		return null;
	}

	/** Run one threat against one value; a regex failure is a recorded skip. */
	private runThreat(threat: Threat, value: string, matches: HeuristicMatch[]): boolean {
		try {
			// YAML patterns are compiled without `g`/`y`, so `exec` is stateless and
			// the compiled instance can be reused. Only a caller-supplied stateful
			// pattern needs a fresh clone.
			const pattern =
				threat.compiledPattern.global || threat.compiledPattern.sticky
					? new RegExp(threat.compiledPattern.source, threat.compiledPattern.flags)
					: threat.compiledPattern;
			const m = pattern.exec(value);
			if (!m) return false;
			matches.push({ threat, artifact: value, matchValue: m[0] });
			return true;
		} catch (error) {
			// Preserve the deliberate per-rule skip, but expose it to callers so
			// verdict/audit layers cannot mistake this for a clean scan.
			const reason = error instanceof Error ? error.message : String(error);
			this._unavailableThreats.push({ threatId: threat.id, reason });
			console.warn(`Regex execution failed for threat ${threat.id}: ${reason}`);
			return false;
		}
	}

	/**
	 * Rules that declare `match_on: <type>_normalized` see what the shell would
	 * see: quotes, escapes, variables and state-directory globs peeled off (see
	 * `shell-normalize.ts`). A rule already matched on the literal value is not
	 * reported twice.
	 */
	private matchNormalized(
		type: string,
		value: string,
		alreadyMatched: ReadonlySet<string>,
		matches: HeuristicMatch[],
	): void {
		const threats = this.threatMap.get(`${type}${NORMALIZED_SUFFIX}`);
		if (!threats || threats.length === 0) return;
		const normalized = normalizeShellText(value);
		for (const threat of threats) {
			if (!alreadyMatched.has(threat.id)) this.runThreat(threat, normalized, matches);
		}
	}

	/** True when any loaded rule inspects the diff-aware file-edit views. */
	get hasEditViewRules(): boolean {
		for (const type of EDIT_VIEW_TYPES) {
			if ((this.threatMap.get(type)?.length ?? 0) > 0) return true;
		}
		return false;
	}

	/**
	 * Match the diff-aware file-edit views (see `agent-safety/edit-views.ts`).
	 * Line rules compare how many added and removed lines match (`Threat.diff`);
	 * the reported artifact is the file path, never the edited content. Call
	 * after {@link match}: regex failures are appended to the same skip list.
	 */
	matchEditViews(views: EditViews): HeuristicMatch[] {
		const matches: HeuristicMatch[] = [];
		for (const entry of views.lines) {
			for (const threat of this.threatMap.get(entry.view) ?? []) {
				const match = this.runLineRule(threat, entry);
				if (match) matches.push(match);
			}
		}
		for (const filePath of views.deletedTestFiles) {
			for (const threat of this.threatMap.get(DELETED_TEST_FILE_VIEW) ?? []) {
				this.runThreat(threat, filePath, matches);
			}
		}
		return matches;
	}

	/** True when any loaded rule inspects the paths a call changes (`self-defense-paths.ts`). */
	get hasModifiedPathRules(): boolean {
		return (this.threatMap.get(MODIFIED_PATH_VIEW)?.length ?? 0) > 0;
	}

	/**
	 * Match the canonical paths a call removes, moves, overwrites or
	 * re-permissions (see `self-defense-paths.ts`) against the rules that declare
	 * `match_on: modified_path`. Call after {@link match}: regex failures are
	 * appended to the same skip list.
	 */
	matchModifiedPaths(paths: readonly string[]): HeuristicMatch[] {
		const matches: HeuristicMatch[] = [];
		const threats = this.threatMap.get(MODIFIED_PATH_VIEW) ?? [];
		const matched = new Set<string>();
		for (const path of paths) {
			for (const threat of threats) {
				if (!matched.has(threat.id) && this.runThreat(threat, path, matches)) {
					matched.add(threat.id);
				}
			}
		}
		return matches;
	}

	private runLineRule(threat: Threat, entry: EditLineViewEntry): HeuristicMatch | null {
		try {
			const pattern =
				threat.compiledPattern.global || threat.compiledPattern.sticky
					? new RegExp(threat.compiledPattern.source, threat.compiledPattern.flags)
					: threat.compiledPattern;
			if (threat.diff === "value_decreased") {
				const before = numericSettings(pattern, entry.removed);
				for (const [key, value] of numericSettings(pattern, entry.added)) {
					const previous = before.get(key);
					if (previous !== undefined && value < previous) {
						return { threat, artifact: entry.filePath, matchValue: key };
					}
				}
				return null;
			}
			const added = countMatchingLines(pattern, entry.added);
			const removed = countMatchingLines(pattern, entry.removed);
			const wantsRemoval = threat.diff === "removed";
			const net = wantsRemoval ? removed.count - added.count : added.count - removed.count;
			if (net < (threat.minMatches ?? 1)) return null;
			const sample = (wantsRemoval ? removed.first : added.first) ?? "";
			return { threat, artifact: entry.filePath, matchValue: sample.slice(0, 200) };
		} catch (error) {
			const reason = error instanceof Error ? error.message : String(error);
			this._unavailableThreats.push({ threatId: threat.id, reason });
			console.warn(`Regex execution failed for threat ${threat.id}: ${reason}`);
			return null;
		}
	}

	match(artifacts: Artifact[]): HeuristicMatch[] {
		const matches: HeuristicMatch[] = [];
		this._unavailableThreats = [];

		for (const artifact of artifacts) {
			// Match the retained prefix only. `boundArtifact` reports on stderr
			// when it truncates, so a partial evaluation is never reported as a
			// full clean result.
			const value = boundArtifact(`${artifact.type} artifact`, artifact.value, MAX_MATCH_INPUT);
			const matched = new Set<string>();
			for (const threat of this.threatMap.get(artifact.type) ?? []) {
				if (this.runThreat(threat, value, matches)) matched.add(threat.id);
			}
			this.matchNormalized(artifact.type, value, matched, matches);
		}

		// Post-filter: suppress matches for trusted installer domains, and
		// model-source rules whose publisher or host is on the trusted list.
		return matches.flatMap((m) => {
			if (this.isSuppressedByTrustedDomain(m)) return [];
			const kept = this.untrustedModelSourceMatch(m);
			return kept ? [kept] : [];
		});
	}
}
