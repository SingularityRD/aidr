/**
 * Release-candidate tag grammar: vMAJOR.MINOR.PATCH-rc.N.
 *
 * RC artifacts carry the stable package version, so any number of RCs of one
 * version may be built and accepted (a failed acceptance no longer burns the
 * version), but only one of them can ever be promoted: npm cannot republish a
 * version, and scripts/restore-promotion-state.mjs refuses a second promotion
 * of a version from a different RC tag. N has no leading zeros so each RC has
 * exactly one spelling. Keep the workflow regexes in release-rc.yml and
 * release-promote.yml equal to RC_TAG_SHELL_PATTERN (scripts/ci-workflows.test.mjs).
 */

export const RC_TAG_PATTERN = /^v(\d+\.\d+\.\d+)-rc\.(0|[1-9]\d{0,3})$/u;

/** The same grammar as a bash `[[ =~ ]]` (POSIX ERE) pattern. */
export const RC_TAG_SHELL_PATTERN = "^v[0-9]+\\.[0-9]+\\.[0-9]+-rc\\.(0|[1-9][0-9]{0,3})$";

/** @returns {{version: string, rc: number}} */
export function parseRcTag(tag) {
	const match = RC_TAG_PATTERN.exec(String(tag));
	if (!match) throw new Error(`release tag ${JSON.stringify(tag)} is not vX.Y.Z-rc.N`);
	return { version: match[1], rc: Number(match[2]) };
}
