/**
 * Exact-data-match (EDM) for Browser Guard.
 *
 * WebCrypto port of the scanning half of AIDR Privacy's `SensitiveDataIndex`
 * (packages/privacy/src/enterprise/data-index.ts). An administrator ships only keyed
 * fingerprints of sensitive values; the extension never sees the values themselves.
 *
 * Fingerprint scheme (the admin tooling and this scanner MUST agree on it):
 *   tokens      = the value normalised with NFKC, lower-cased, zero-width characters removed,
 *                 Turkish dotless "ı" and "i̇" folded to "i", then split into runs of
 *                 letters/digits ([\p{L}\p{N}]+)
 *   fingerprint = lowercase hex HMAC-SHA256(key, UTF-8(JSON.stringify(tokens)))
 * A value must normalise to 1..16 tokens whose concatenation is at least 3 characters.
 * `fingerprintValue` implements exactly this so that tooling and tests use the same code.
 *
 * Fingerprints are keyed hashes, not encryption: a holder of the key can confirm guesses, and
 * enumerate a value space that is small enough. So the key never travels in browser policy
 * (chrome://policy, the policy registry keys and policies.json are readable by every user).
 * Each dataset has its own key, derived by the AIDR Privacy native host from a secret kept in
 * the host's configuration (packages/privacy/src/native/edm.ts); the background worker asks
 * the host for it and hands it to this matcher as `keyB64`. A dataset whose key has not
 * arrived cannot be checked: every scan with it is reported incomplete (fail closed).
 * Datasets of low-entropy values are refused when they are built and by the policy
 * (`minEntropyBits`, background/policy.ts).
 */
import { sourceSpan, type TextView } from "../../../privacy/src/normalize.js";
import { ENTITY_TYPES, type EntityType, type ExactDataSet } from "../types.js";

/** Longest token sequence that can be fingerprinted and matched. */
export const EXACT_DATA_MAX_TOKENS = 16;
/** Upper bound on HMAC computations per scan; more work marks the scan incomplete. */
export const EXACT_DATA_MAX_HMACS = 65_536;
const MIN_VALUE_CHARS = 3;
const MIN_KEY_BYTES = 16;
const MAX_KEY_BYTES = 1024;
const MAX_FINGERPRINTS = 250_000;
const SIGN_BATCH = 256;

export interface ExactDataToken {
	/** Normalised token text. */
	readonly value: string;
	/** Half-open UTF-16 offsets of the token in the tokenised text. */
	readonly start: number;
	readonly end: number;
}

interface ExactDataHit {
	readonly type: EntityType;
	/** Half-open UTF-16 offsets in the ORIGINAL scanned text. */
	readonly start: number;
	readonly end: number;
}

interface ExactDataScan {
	readonly hits: readonly ExactDataHit[];
	/** True when the HMAC budget, the deadline or key import prevented a full scan. */
	readonly incomplete: boolean;
}

export interface ExactDataMatcher {
	/** Scans every detection view; `deadline` is a `performance.now()` timestamp. */
	scan(views: readonly TextView[], deadline: number): Promise<ExactDataScan>;
}

export class ExactDataConfigError extends TypeError {
	readonly code: string;
	constructor(code: string) {
		super(code);
		this.name = "ExactDataConfigError";
		this.code = code;
	}
}

const ASCII_ONLY = /^[\x00-\x7f]*$/;
const ASCII_TOKEN = /[A-Za-z0-9]+/g;
const WORD_CHAR = /^[\p{L}\p{N}]$/u;
const ZERO_WIDTH = /[​-‏⁠﻿]/gu;
const HEX64 = /^[0-9a-f]{64}$/;
const segmenter = new Intl.Segmenter("und", { granularity: "grapheme" });
const encoder = new TextEncoder();
const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

function normalizeSegment(segment: string): string {
	return segment
		.normalize("NFKC")
		.toLowerCase()
		.replace(ZERO_WIDTH, "")
		.replace(/ı/gu, "i")
		.replace(/i̇/gu, "i");
}

/**
 * Tokenises `text` with the fingerprint normalisation, keeping offsets into `text`.
 * Normalisation is applied per grapheme cluster so each token maps back to a source span.
 */
export function exactDataTokens(text: string): ExactDataToken[] {
	if (!ASCII_ONLY.test(text)) return unicodeTokens(text);
	return Array.from(text.matchAll(ASCII_TOKEN), (m) => ({
		value: m[0].toLowerCase(),
		start: m.index,
		end: m.index + m[0].length,
	}));
}

function unicodeTokens(text: string): ExactDataToken[] {
	const tokens: ExactDataToken[] = [];
	let value = "";
	let start = 0;
	let end = 0;
	for (const { segment, index } of segmenter.segment(text)) {
		for (const ch of normalizeSegment(segment)) {
			if (WORD_CHAR.test(ch)) {
				if (!value) start = index;
				value += ch;
				end = index + segment.length;
			} else if (value) {
				tokens.push({ value, start, end });
				value = "";
			}
		}
	}
	if (value) tokens.push({ value, start, end });
	return tokens;
}

function decodeKey(keyB64: unknown): Uint8Array<ArrayBuffer> {
	if (typeof keyB64 !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(keyB64.trim())) {
		throw new ExactDataConfigError("EXACT_DATA_KEY_INVALID");
	}
	let binary: string;
	try {
		binary = atob(keyB64.trim());
	} catch {
		throw new ExactDataConfigError("EXACT_DATA_KEY_INVALID");
	}
	if (binary.length < MIN_KEY_BYTES || binary.length > MAX_KEY_BYTES) {
		throw new ExactDataConfigError("EXACT_DATA_KEY_INVALID");
	}
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

function importKey(bytes: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
	return globalThis.crypto.subtle.importKey(
		"raw",
		bytes,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
}

async function hmacHex(key: CryptoKey, message: string): Promise<string> {
	const signature = new Uint8Array(
		await globalThis.crypto.subtle.sign("HMAC", key, encoder.encode(message)),
	);
	let hex = "";
	for (const byte of signature) hex += HEX[byte];
	return hex;
}

/** Produces the fingerprint of one sensitive value (for admin tooling and tests). */
export async function fingerprintValue(keyB64: string, value: string): Promise<string> {
	const key = await importKey(decodeKey(keyB64));
	const values = exactDataTokens(String(value)).map((t) => t.value);
	if (
		values.length < 1 ||
		values.length > EXACT_DATA_MAX_TOKENS ||
		values.join("").length < MIN_VALUE_CHARS
	) {
		throw new RangeError("EXACT_DATA_VALUE_INVALID");
	}
	return hmacHex(key, JSON.stringify(values));
}

interface KeyGroup {
	/** null: the dataset key has not been delivered (yet); the group cannot be scanned. */
	readonly bytes: Uint8Array<ArrayBuffer> | null;
	readonly datasets: ReadonlyArray<{
		readonly type: EntityType;
		readonly fingerprints: ReadonlySet<string>;
	}>;
	key: Promise<CryptoKey> | null;
}

interface Occurrence {
	readonly view: TextView;
	readonly start: number;
	readonly end: number;
}

type Dataset = KeyGroup["datasets"][number];

function parseDataset(set: ExactDataSet): Dataset {
	if (!set || typeof set.datasetId !== "string" || !set.datasetId.trim()) {
		throw new ExactDataConfigError("EXACT_DATA_INVALID");
	}
	if (!ENTITY_TYPES.includes(set.type)) throw new ExactDataConfigError("EXACT_DATA_TYPE_INVALID");
	if (!Array.isArray(set.fingerprints)) throw new ExactDataConfigError("EXACT_DATA_INVALID");
	const fingerprints = new Set<string>();
	for (const raw of set.fingerprints) {
		const fp = typeof raw === "string" ? raw.trim().toLowerCase() : "";
		if (!HEX64.test(fp)) throw new ExactDataConfigError("EXACT_DATA_FINGERPRINT_INVALID");
		fingerprints.add(fp);
	}
	return { type: set.type, fingerprints };
}

function groupDatasets(sets: readonly ExactDataSet[]): KeyGroup[] {
	if (!Array.isArray(sets)) throw new ExactDataConfigError("EXACT_DATA_INVALID");
	const groups = new Map<string, KeyGroup & { datasets: Dataset[] }>();
	let total = 0;
	for (const set of sets) {
		const dataset = parseDataset(set);
		total += dataset.fingerprints.size;
		if (total > MAX_FINGERPRINTS) throw new ExactDataConfigError("EXACT_DATA_CAPACITY");
		const keyed = set.keyB64 !== undefined;
		const bytes = keyed ? decodeKey(set.keyB64) : null;
		// Unkeyed datasets share one group that every scan reports as incomplete.
		const id = keyed ? `k:${String(set.keyB64).trim()}` : "unkeyed";
		const group = groups.get(id) ?? { bytes, datasets: [], key: null };
		group.datasets.push(dataset);
		groups.set(id, group);
	}
	return [...groups.values()];
}

/** Adds every `len`-token window of one view; false once the HMAC budget is exhausted. */
function addWindows(
	windows: Map<string, Occurrence[]>,
	view: TextView,
	tokens: readonly ExactDataToken[],
	len: number,
	budget: number,
): boolean {
	for (let i = 0; i + len <= tokens.length; i++) {
		const window = tokens.slice(i, i + len);
		const values = window.map((t) => t.value);
		if (values.join("").length < MIN_VALUE_CHARS) continue;
		const message = JSON.stringify(values);
		const occurrence = {
			view,
			start: (window[0] as ExactDataToken).start,
			end: (window[len - 1] as ExactDataToken).end,
		};
		const known = windows.get(message);
		if (known) known.push(occurrence);
		else if (windows.size >= budget) return false;
		else windows.set(message, [occurrence]);
	}
	return true;
}

/**
 * Unique token-sequence messages -> where they occur, so identical windows are hashed once.
 * Shorter windows come first so a budget cut loses only the longest ones.
 */
function collectWindows(
	views: readonly TextView[],
	budget: number,
): { windows: Map<string, Occurrence[]>; complete: boolean } {
	const windows = new Map<string, Occurrence[]>();
	const tokenized = views.map((view) => ({ view, tokens: exactDataTokens(view.text) }));
	for (let len = 1; len <= EXACT_DATA_MAX_TOKENS; len++) {
		for (const { view, tokens } of tokenized) {
			if (!addWindows(windows, view, tokens, len, budget)) return { windows, complete: false };
		}
	}
	return { windows, complete: true };
}

async function groupKey(group: KeyGroup): Promise<CryptoKey | null> {
	if (!group.bytes) return null;
	try {
		group.key ??= importKey(group.bytes);
		return await group.key;
	} catch {
		group.key = null;
		return null;
	}
}

/** Signs every window with one key group; returns false when the key or deadline stopped it. */
async function matchGroup(
	group: KeyGroup,
	windows: ReadonlyMap<string, readonly Occurrence[]>,
	deadline: number,
	hits: ExactDataHit[],
): Promise<boolean> {
	const key = await groupKey(group);
	if (!key) return false;
	const messages = [...windows.keys()];
	for (let offset = 0; offset < messages.length; offset += SIGN_BATCH) {
		if (performance.now() > deadline) return false;
		const batch = messages.slice(offset, offset + SIGN_BATCH);
		const digests = await Promise.all(batch.map((m) => hmacHex(key, m)));
		digests.forEach((digest, j) => {
			for (const dataset of group.datasets) {
				if (!dataset.fingerprints.has(digest)) continue;
				for (const at of windows.get(batch[j] as string) ?? []) {
					const [start, end] = sourceSpan(at.view, at.start, at.end);
					hits.push({ type: dataset.type, start, end });
				}
			}
		});
	}
	return true;
}

/**
 * Builds a matcher for the configured datasets. Throws `ExactDataConfigError` on malformed
 * configuration (bad key, fingerprint or entity type) so a broken policy is never silently
 * ignored. Datasets sharing a key share their HMAC work; a dataset without its key makes
 * every scan incomplete.
 */
export function createExactDataMatcher(sets: readonly ExactDataSet[]): ExactDataMatcher {
	const groups = groupDatasets(sets);
	return {
		async scan(views, deadline) {
			const hits: ExactDataHit[] = [];
			if (groups.length === 0) return { hits, incomplete: false };
			const budget = Math.floor(EXACT_DATA_MAX_HMACS / groups.length);
			const { windows, complete } = collectWindows(views, budget);
			let incomplete = !complete;
			for (const group of groups) {
				if (!(await matchGroup(group, windows, deadline, hits))) incomplete = true;
			}
			return { hits, incomplete };
		},
	};
}
