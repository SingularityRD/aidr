export function compareSemver(a: string, b: string): number {
	const pa = a.split(".").map((x) => Number.parseInt(x, 10));
	const pb = b.split(".").map((x) => Number.parseInt(x, 10));
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
		const da = Number.isFinite(pa[i]) ? (pa[i] as number) : 0;
		const db = Number.isFinite(pb[i]) ? (pb[i] as number) : 0;
		if (da !== db) return da - db;
	}
	// Fallback to lexical for non-numeric tags.
	if (a === b) return 0;
	return a < b ? -1 : 1;
}
