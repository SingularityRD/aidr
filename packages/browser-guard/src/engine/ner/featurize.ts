/**
 * Input features of the small local PII tagger (ml/pii-tiny, model B), byte-for-byte the same
 * as `featurize`/`encode` in ml/pii-tiny/train_b.py. The parity test
 * (src/__tests__/ner-featurize.test.ts) checks this file against features the Python code
 * wrote for real prompts; change both together.
 *
 * Offsets are UTF-16 code units into the original text (what the guard masks with). Character
 * features count code points, as Python does.
 */

/** Letters (incl. letter-like numerics), decimal-digit runs, or any other single non-space. */
const TOKEN = /[\p{L}\p{Nl}\p{No}]+|\p{Nd}+|\S/gu;

const GAZ_KEYS = ["tr_first", "tr_last", "en_first", "en_last"] as const;
const N_BASE = 8;

export interface ModelVocab {
	readonly words: readonly string[];
	readonly chars: readonly string[];
	readonly tags: readonly string[];
	readonly maxChars: number;
	/** Name lists for the gazetteer features; null for a model trained without them. */
	readonly gazetteer: Readonly<Record<(typeof GAZ_KEYS)[number], readonly string[]>> | null;
}

export interface Features {
	readonly tokens: ReadonlyArray<readonly [number, number]>;
	/** Word ids, length T. */
	readonly words: Int32Array;
	/** Char ids, T x maxChars. */
	readonly chars: Int32Array;
	/** Shape (+ gazetteer) features, T x width. */
	readonly shape: Float32Array;
	readonly width: number;
}

/** Python `str.translate({I: ı, İ: i}).lower()`. */
export function norm(word: string): string {
	return word.replace(/I/g, "ı").replace(/İ/g, "i").toLowerCase();
}

const isAlpha = (ch: string): boolean => /^\p{L}$/u.test(ch);
const isDigits = (w: string): boolean => /^\p{Nd}+$/u.test(w);
/** Python `str.isupper()`: at least one cased character and no lower-case one. */
const isUpper = (w: string): boolean => w !== w.toLowerCase() && w === w.toUpperCase();

export function shapeOf(word: string, prev: string, next: string): number[] {
	const first = [...word][0] ?? "";
	const alpha = isAlpha(first);
	const length = [...word].length;
	return [
		alpha && isUpper(first) ? 1 : 0,
		alpha && isUpper(word) && length > 1 ? 1 : 0,
		isDigits(word) ? 1 : 0,
		!alpha && !isDigits(word) ? 1 : 0,
		next === "'" || next === "’" ? 1 : 0,
		prev === "." || prev === "!" || prev === "?" || prev === "\n" || prev === "" ? 1 : 0,
		prev === ":" || prev === "=" ? 1 : 0,
		length === 1 ? 1 : 0,
	];
}

/** Compiled vocabulary lookups, built once per loaded model. */
export class Featurizer {
	readonly #words: Map<string, number>;
	readonly #chars: Map<string, number>;
	readonly #gaz: ReadonlyArray<ReadonlySet<string>> | null;
	readonly #maxChars: number;

	constructor(vocab: ModelVocab) {
		this.#words = new Map(vocab.words.map((w, i) => [w, i]));
		this.#chars = new Map(vocab.chars.map((c, i) => [c, i]));
		this.#gaz = vocab.gazetteer ? GAZ_KEYS.map((k) => new Set(vocab.gazetteer?.[k] ?? [])) : null;
		this.#maxChars = vocab.maxChars;
	}

	get width(): number {
		return N_BASE + (this.#gaz ? GAZ_KEYS.length : 0);
	}

	encode(text: string): Features {
		const tokens: Array<readonly [number, number]> = [];
		for (const m of text.matchAll(TOKEN)) tokens.push([m.index, m.index + m[0].length]);
		const t = tokens.length;
		const width = this.width;
		const words = new Int32Array(t);
		const chars = new Int32Array(t * this.#maxChars);
		const shape = new Float32Array(t * width);
		const surface = tokens.map(([a, b]) => text.slice(a, b));
		for (let i = 0; i < t; i++) {
			const w = surface[i] as string;
			const n = norm(w);
			words[i] = this.#words.get(n) ?? 1;
			let j = 0;
			for (const ch of w) {
				if (j >= this.#maxChars) break;
				chars[i * this.#maxChars + j++] = this.#chars.get(ch) ?? 1;
			}
			let prev = i ? (surface[i - 1] as string) : "";
			if (
				i &&
				text
					.slice(
						(tokens[i - 1] as readonly [number, number])[1],
						(tokens[i] as readonly [number, number])[0],
					)
					.includes("\n")
			)
				prev = "\n";
			const next = i + 1 < t ? (surface[i + 1] as string) : "";
			const f = shapeOf(w, prev, next);
			if (this.#gaz) for (const set of this.#gaz) f.push(set.has(n) ? 1 : 0);
			shape.set(f, i * width);
		}
		return { tokens, words, chars, shape, width };
	}
}
