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

/** Threat IDs where trusted installer domains suppress matches. */
const TRUSTED_DOMAIN_SUPPRESSIBLE = new Set(["CLT-CMD-001", "CLT-CMD-002", "CLT-SUPPLY-001"]);

export class HeuristicsEngine {
	private readonly threatMap: Map<string, Threat[]> = new Map();
	private readonly trustedDomains: TrustedDomain[];
	/** Regex failures are deliberate signal skips, never a clean evaluation. */
	private _unavailableThreats: Array<{ threatId: string; reason: string }> = [];

	get unavailableThreats(): ReadonlyArray<{ threatId: string; reason: string }> {
		return this._unavailableThreats;
	}

	constructor(threats: Threat[], trustedDomains?: TrustedDomain[]) {
		this.trustedDomains = trustedDomains ?? [];

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

		// Post-filter: suppress matches for trusted installer domains
		if (this.trustedDomains.length > 0) {
			return matches.filter((m) => !this.isSuppressedByTrustedDomain(m));
		}

		return matches;
	}
}
