/**
 * Line diff of two policy documents, for four-eyes review and revision history.
 *
 * Both sides are rendered as key-sorted, two-space indented JSON so that a
 * reordered object is not reported as a change, then compared line by line
 * with a longest-common-subsequence table. Inputs larger than the bound are
 * reported as a whole-document replacement rather than silently truncated.
 */

export type DiffLine = { kind: "same" | "add" | "del"; text: string };

const MAX_LINES = 1500;

function sortKeys(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(sortKeys);
	if (value && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value as Record<string, unknown>)
				.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
				.map(([key, item]) => [key, sortKeys(item)]),
		);
	}
	return value;
}

/** Key-sorted, indented JSON; `null` for an absent document. */
function stableJson(value: unknown): string {
	return value === undefined ? "null" : JSON.stringify(sortKeys(value), null, 2);
}

function diffLines(before: string, after: string): DiffLine[] {
	const a = before.split("\n");
	const b = after.split("\n");
	if (a.length > MAX_LINES || b.length > MAX_LINES) {
		return [
			...a.map((text) => ({ kind: "del" as const, text })),
			...b.map((text) => ({ kind: "add" as const, text })),
		];
	}
	// lcs[i * width + j] = length of the LCS of a[i..] and b[j..].
	const width = b.length + 1;
	const lcs = new Int32Array((a.length + 1) * width);
	const at = (i: number, j: number) => lcs[i * width + j] ?? 0;
	for (let i = a.length - 1; i >= 0; i--) {
		for (let j = b.length - 1; j >= 0; j--) {
			lcs[i * width + j] =
				a[i] === b[j] ? at(i + 1, j + 1) + 1 : Math.max(at(i + 1, j), at(i, j + 1));
		}
	}
	const out: DiffLine[] = [];
	let i = 0;
	let j = 0;
	while (i < a.length && j < b.length) {
		const left = a[i] ?? "";
		const right = b[j] ?? "";
		if (left === right) {
			out.push({ kind: "same", text: left });
			i++;
			j++;
		} else if (at(i + 1, j) >= at(i, j + 1)) {
			out.push({ kind: "del", text: left });
			i++;
		} else {
			out.push({ kind: "add", text: right });
			j++;
		}
	}
	for (; i < a.length; i++) out.push({ kind: "del", text: a[i] ?? "" });
	for (; j < b.length; j++) out.push({ kind: "add", text: b[j] ?? "" });
	return out;
}

export function diffDocuments(before: unknown, after: unknown): DiffLine[] {
	return diffLines(stableJson(before), stableJson(after));
}

export function diffStats(lines: DiffLine[]): { added: number; removed: number } {
	return {
		added: lines.filter((line) => line.kind === "add").length,
		removed: lines.filter((line) => line.kind === "del").length,
	};
}
