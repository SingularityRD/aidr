/**
 * Release tag grammar.
 *
 * Release candidates: vMAJOR.MINOR.PATCH-rc.N. RC artifacts carry the stable
 * package version, so any number of RCs of one version may be built and
 * accepted (a failed acceptance no longer burns the version), but only one of
 * them can ever be promoted: npm cannot republish a version, and
 * scripts/restore-promotion-state.mjs refuses a second promotion of a version
 * from a different RC tag. N has no leading zeros so each RC has exactly one
 * spelling. Keep the workflow regexes in release-rc.yml and release-promote.yml
 * equal to RC_TAG_SHELL_PATTERN (scripts/ci-workflows.test.mjs).
 *
 * Final releases: vMAJOR.MINOR.PATCH. Promotion (release-promote.yml) publishes
 * the promoted RC's signed files a second time under the final tag, at the same
 * commit, so customers and per-customer installers (customer-installer.yml)
 * name the version without "-rc.N". A final tag is never built: its bytes are
 * the promoted RC's, attested under that RC tag.
 */

export const RC_TAG_PATTERN = /^v(\d+\.\d+\.\d+)-rc\.(0|[1-9]\d{0,3})$/u;

/** The same grammar as a bash `[[ =~ ]]` (POSIX ERE) pattern. */
export const RC_TAG_SHELL_PATTERN = "^v[0-9]+\\.[0-9]+\\.[0-9]+-rc\\.(0|[1-9][0-9]{0,3})$";

export const FINAL_TAG_PATTERN = /^v(\d+\.\d+\.\d+)$/u;

/** The final-tag grammar as a bash `[[ =~ ]]` (POSIX ERE) pattern. */
export const FINAL_TAG_SHELL_PATTERN = "^v[0-9]+\\.[0-9]+\\.[0-9]+$";

/** @returns {{version: string, rc: number}} */
export function parseRcTag(tag) {
	const match = RC_TAG_PATTERN.exec(String(tag));
	if (!match) throw new Error(`release tag ${JSON.stringify(tag)} is not vX.Y.Z-rc.N`);
	return { version: match[1], rc: Number(match[2]) };
}

/**
 * Either spelling of a release tag.
 * @returns {{version: string, rc: number | null, final: boolean}}
 */
export function parseReleaseTag(tag) {
	const final = FINAL_TAG_PATTERN.exec(String(tag));
	if (final) return { version: final[1], rc: null, final: true };
	if (RC_TAG_PATTERN.test(String(tag))) return { ...parseRcTag(tag), final: false };
	throw new Error(`release tag ${JSON.stringify(tag)} is neither vX.Y.Z-rc.N nor vX.Y.Z`);
}

/** The final tag a promoted RC is republished under: v1.2.3-rc.4 -> v1.2.3. */
export function finalTagFor(rcTag) {
	return `v${parseRcTag(rcTag).version}`;
}
