/**
 * Page message modules keep each English string next to its Turkish
 * translation (`[english, turkish]`), so a reviewer reads both together; the
 * catalogs in en.ts / tr.ts are assembled from them.
 */
export type MessagePairs<K extends string> = Record<K, readonly [english: string, turkish: string]>;

function pick<K extends string>(pairs: MessagePairs<K>, index: 0 | 1): Record<K, string> {
	const out = {} as Record<K, string>;
	for (const key of Object.keys(pairs) as K[]) out[key] = pairs[key][index];
	return out;
}

export function english<K extends string>(pairs: MessagePairs<K>): Record<K, string> {
	return pick(pairs, 0);
}

export function turkish<K extends string>(pairs: MessagePairs<K>): Record<K, string> {
	return pick(pairs, 1);
}
