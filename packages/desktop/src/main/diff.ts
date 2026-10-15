import type { DiffLine } from "../shared/contract.js";

const MAX_CELLS = 4_000_000;

/**
 * Line diff (longest common subsequence) of two texts. Settings files are
 * small; for an implausibly large pair the result degrades to "remove all,
 * add all" rather than spending unbounded time.
 */
export function lineDiff(before: string, after: string): DiffLine[] {
	const a = before === "" ? [] : before.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
	const b = after === "" ? [] : after.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
	if ((a.length + 1) * (b.length + 1) > MAX_CELLS) {
		return [
			...a.map((text): DiffLine => ({ kind: "remove", text })),
			...b.map((text): DiffLine => ({ kind: "add", text })),
		];
	}
	const width = b.length + 1;
	const table = new Uint32Array((a.length + 1) * width);
	for (let i = a.length - 1; i >= 0; i--) {
		for (let j = b.length - 1; j >= 0; j--) {
			table[i * width + j] =
				a[i] === b[j]
					? (table[(i + 1) * width + j + 1] ?? 0) + 1
					: Math.max(table[(i + 1) * width + j] ?? 0, table[i * width + j + 1] ?? 0);
		}
	}
	const out: DiffLine[] = [];
	let i = 0;
	let j = 0;
	while (i < a.length && j < b.length) {
		if (a[i] === b[j]) {
			out.push({ kind: "same", text: a[i] as string });
			i++;
			j++;
		} else if ((table[(i + 1) * width + j] ?? 0) >= (table[i * width + j + 1] ?? 0)) {
			out.push({ kind: "remove", text: a[i] as string });
			i++;
		} else {
			out.push({ kind: "add", text: b[j] as string });
			j++;
		}
	}
	for (; i < a.length; i++) out.push({ kind: "remove", text: a[i] as string });
	for (; j < b.length; j++) out.push({ kind: "add", text: b[j] as string });
	return out;
}
