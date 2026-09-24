/** Per-entity-type finding counts, shared by the file sanitiser and the content guard. */
import type { EntityType, Finding } from "../types.js";

export type Counts = Partial<Record<EntityType, number>>;

export function countFindings(findings: readonly Finding[]): Counts {
	const counts: Counts = {};
	for (const f of findings) counts[f.type] = (counts[f.type] ?? 0) + 1;
	return counts;
}

/** Adds `add` into `into` (mutating it) and returns `into`. Zero entries are skipped. */
export function mergeCounts(into: Counts, add: Readonly<Counts>): Counts {
	for (const [type, n] of Object.entries(add) as [EntityType, number | undefined][]) {
		if (n) into[type] = (into[type] ?? 0) + n;
	}
	return into;
}
