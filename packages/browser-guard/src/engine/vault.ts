/**
 * Reversible pseudonymisation vault (one per tab/conversation).
 *
 * `mask` replaces detected sensitive spans with stable placeholders such as
 * `[EMAIL_1]`; `unmask` restores them locally in the page, tolerating the ways LLMs
 * echo placeholders back (markdown escapes, emphasis, code spans, dropped brackets).
 *
 * Security properties:
 *   - Original values live only in this closure's memory. Nothing here logs, and no
 *     error message ever contains a value.
 *   - Memory is bounded: at most MAX_VAULT_ENTRIES live entries (least recently used
 *     evicted first) and entries unused for longer than the TTL are forgotten.
 *   - Placeholder numbers are never reused within a vault's lifetime (until `clear()`),
 *     so an old response that echoes an expired `[EMAIL_1]` can never be "restored"
 *     to a different person's value.
 *   - A vault created with a `tag` (the content script uses a random one per page
 *     life, see ../content/boot.ts) mints tagged placeholders such as `[EMAIL_1_k3f9]`.
 *     Numbering restarts with every vault, so without the tag another conversation's
 *     (or another tab's) `[EMAIL_1]` would be restored with this vault's value; with it
 *     a foreign placeholder matches only by chance (one in 36^4). Untagged entries from
 *     older snapshots stay valid and restorable.
 *   - Entity types in `neverRestore` are masked but never restored nor revealed by
 *     `lookup`.
 *   - Snapshots are validated strictly; a malformed snapshot makes `createVault`
 *     throw instead of importing partial state.
 */
import type { EntityType, Finding, MaskResult, PlaceholderVault, VaultSnapshot } from "../types";
import { ENTITY_TYPES, PLACEHOLDER_PREFIX } from "../types";

export const DEFAULT_VAULT_TTL_MS = 4 * 60 * 60 * 1000;
export const MAX_VAULT_ENTRIES = 10_000;
/** Longest single value accepted from a snapshot (a PEM private key is ~3 KiB). */
const MAX_SNAPSHOT_VALUE_CHARS = 65_536;
/** Snapshots stamped further in the future than this are rejected. */
const MAX_CLOCK_SKEW_MS = 60_000;
/** Bound on remembered foreign placeholder-like tokens (collision avoidance). */
const MAX_RESERVED_NAMES = 10_000;

export interface VaultOptions {
	readonly neverRestore: readonly EntityType[];
	/** Entries unused for longer than this are forgotten. Default 4 hours. */
	readonly ttlMs?: number;
	/** Session snapshot to resume from; validated strictly (throws on malformed input). */
	readonly snapshot?: VaultSnapshot;
	/** Injectable clock in epoch milliseconds (tests). Defaults to `Date.now`. */
	readonly now?: () => number;
	/**
	 * Per-vault tag appended to new placeholders (`[EMAIL_1_k3f9]`), see VAULT_TAG_RE and
	 * newVaultTag. Omitted: untagged placeholders (`[EMAIL_1]`).
	 */
	readonly tag?: string;
}

/** A valid vault tag: lower-case letters and digits only, so it never reads as a prefix. */
export const VAULT_TAG_RE = /^[a-z0-9]{4,8}$/;
const TAG_LENGTH = 4;
const TAG_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

/** A fresh random vault tag (crypto.getRandomValues, uniform over 36^4 values). */
export function newVaultTag(): string {
	let tag = "";
	while (tag.length < TAG_LENGTH) {
		const bytes = new Uint8Array(TAG_LENGTH * 2);
		globalThis.crypto.getRandomValues(bytes);
		for (const byte of bytes) {
			// Rejection sampling keeps the alphabet uniform (252 = 7 * 36).
			if (byte < 252 && tag.length < TAG_LENGTH) tag += TAG_ALPHABET[byte % 36];
		}
	}
	return tag;
}

/** Thrown for malformed snapshots. The message never contains snapshot values. */
export class VaultSnapshotError extends Error {
	constructor(reason: string) {
		super(`invalid vault snapshot: ${reason}`);
		this.name = "VaultSnapshotError";
	}
}

interface Entry {
	readonly placeholder: string;
	readonly value: string;
	readonly type: EntityType;
	readonly key: string;
	lastUsed: number;
}

interface Span {
	readonly start: number;
	readonly end: number;
	readonly type: EntityType;
	readonly score: number;
}

type SnapshotEntry = VaultSnapshot["entries"][number];

const ENTITY_TYPE_SET: ReadonlySet<string> = new Set(ENTITY_TYPES);
const TYPE_ORDER: ReadonlyMap<EntityType, number> = new Map(ENTITY_TYPES.map((t, i) => [t, i]));
const PREFIX_SET: ReadonlySet<string> = new Set(Object.values(PLACEHOLDER_PREFIX));

/**
 * Placeholder name core, tolerating markdown-escaped underscores (`EMAIL\_1`), with the
 * optional vault tag (`EMAIL_1_k3f9`).
 */
const NAME_SRC = String.raw`[A-Z]+(?:\\?_[A-Z]+)*\\?_[1-9][0-9]{0,8}(?:\\?_[a-z0-9]{4,8})?`;
const NOT_WORD_BEFORE = String.raw`(?<![\p{L}\p{N}_\\])`;
const NOT_WORD_AFTER = String.raw`(?![\p{L}\p{N}_])`;

/**
 * Placeholder occurrences as LLMs echo them. Capture groups:
 *   1: bracketed name (`[X_1]`, `\[X_1\]`, `[X\_1]`; emphasis/backticks around it are kept)
 *   2+3: underscore emphasis delimiters + bracket-less name (`_X_1_`, `__X_1__`)
 *   4: bracket-less whole-token name (`X_1`, `**X_1**`, `` `X_1` ``)
 */
const OCCURRENCE_RE = new RegExp(
	[
		String.raw`\\?\[(${NAME_SRC})\\?\]`,
		String.raw`${NOT_WORD_BEFORE}(_{1,2})(${NAME_SRC})\2${NOT_WORD_AFTER}`,
		String.raw`${NOT_WORD_BEFORE}(${NAME_SRC})${NOT_WORD_AFTER}`,
	].join("|"),
	"gu",
);

/** Canonical stored placeholder format. Group 1: prefix, group 2: number, group 3: tag. */
const PLACEHOLDER_RE = /^\[([A-Z]+(?:_[A-Z]+)*)_([1-9][0-9]{0,8})(?:_([a-z0-9]{4,8}))?\]$/;
/** A placeholder name without brackets. Group 1: prefix. */
const NAME_RE = /^([A-Z]+(?:_[A-Z]+)*)_[1-9][0-9]{0,8}(?:_[a-z0-9]{4,8})?$/;

const DIGITS_ONLY_TYPES: ReadonlySet<EntityType> = new Set<EntityType>([
	"PHONE",
	"TC_KIMLIK",
	"CREDIT_CARD",
	"US_SSN",
]);

/**
 * Canonical form used to decide "same value -> same placeholder": NFKC, trimmed,
 * whitespace runs collapsed; EMAIL lowercased; PHONE/TCKN/CARD/SSN digits only;
 * IBAN upper-case alphanumerics only (an IBAN's country code is part of its identity).
 */
export function canonicalValue(type: EntityType, value: string): string {
	const base = value.normalize("NFKC").trim().replace(/\s+/g, " ");
	let canonical = base;
	if (type === "EMAIL") canonical = base.toLowerCase();
	else if (DIGITS_ONLY_TYPES.has(type)) canonical = base.replace(/\D/g, "");
	else if (type === "IBAN") canonical = base.toUpperCase().replace(/[^0-9A-Z]/g, "");
	return canonical === "" ? base : canonical;
}

function placeholderName(match: string): string {
	return match.replaceAll("\\", "");
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
	const own = Object.keys(record);
	return own.length === keys.length && keys.every((k) => Object.hasOwn(record, k));
}

interface ParsedSnapshot {
	readonly createdAt: number;
	readonly entries: readonly SnapshotEntry[];
}

function parseSnapshot(raw: unknown, nowMs: number): ParsedSnapshot {
	if (!isPlainRecord(raw)) throw new VaultSnapshotError("not an object");
	if (!hasExactKeys(raw, ["version", "createdAt", "entries"])) {
		throw new VaultSnapshotError("unexpected or missing fields");
	}
	if (raw.version !== 1) throw new VaultSnapshotError("unsupported version");
	const createdAt = raw.createdAt;
	if (typeof createdAt !== "number" || !Number.isFinite(createdAt) || createdAt < 0) {
		throw new VaultSnapshotError("createdAt must be a non-negative finite number");
	}
	if (createdAt > nowMs + MAX_CLOCK_SKEW_MS)
		throw new VaultSnapshotError("createdAt is in the future");
	const rawEntries = raw.entries;
	if (!Array.isArray(rawEntries)) throw new VaultSnapshotError("entries must be an array");
	if (rawEntries.length > MAX_VAULT_ENTRIES) throw new VaultSnapshotError("too many entries");

	const placeholders = new Set<string>();
	const keys = new Set<string>();
	const entries = rawEntries.map((item: unknown, index) => {
		const where = `entry ${index}`;
		const entry = parseSnapshotEntry(item, where);
		if (placeholders.has(entry.placeholder)) {
			throw new VaultSnapshotError(`${where} duplicates a placeholder`);
		}
		const key = vaultKey(entry.type, entry.value);
		if (keys.has(key)) throw new VaultSnapshotError(`${where} duplicates another entry's value`);
		placeholders.add(entry.placeholder);
		keys.add(key);
		return entry;
	});
	return { createdAt, entries };
}

function parseSnapshotEntry(item: unknown, where: string): SnapshotEntry {
	if (!isPlainRecord(item) || !hasExactKeys(item, ["placeholder", "value", "type"])) {
		throw new VaultSnapshotError(`${where} has an invalid shape`);
	}
	const { placeholder, value, type } = item;
	if (typeof type !== "string" || !ENTITY_TYPE_SET.has(type)) {
		throw new VaultSnapshotError(`${where} has an unknown type`);
	}
	const entityType = type as EntityType;
	const match = typeof placeholder === "string" ? PLACEHOLDER_RE.exec(placeholder) : null;
	if (typeof placeholder !== "string" || match?.[1] !== PLACEHOLDER_PREFIX[entityType]) {
		throw new VaultSnapshotError(`${where} placeholder does not match its type`);
	}
	if (typeof value !== "string" || value.trim() === "" || value.length > MAX_SNAPSHOT_VALUE_CHARS) {
		throw new VaultSnapshotError(`${where} value is empty, too long or not a string`);
	}
	return { placeholder, value, type: entityType };
}

function vaultKey(type: EntityType, value: string): string {
	return `${type}\u0000${canonicalValue(type, value)}`;
}

function placeholderNumber(placeholder: string): number {
	return Number(PLACEHOLDER_RE.exec(placeholder)?.[2] ?? 0);
}

export function createVault(options: VaultOptions): PlaceholderVault {
	const ttlMs = options.ttlMs ?? DEFAULT_VAULT_TTL_MS;
	if (typeof ttlMs !== "number" || Number.isNaN(ttlMs) || ttlMs <= 0) {
		throw new RangeError("ttlMs must be a positive number");
	}
	const now = options.now ?? Date.now;
	if (options.tag !== undefined && !VAULT_TAG_RE.test(options.tag)) {
		throw new RangeError("tag must be 4-8 lower-case letters or digits");
	}
	const suffix = options.tag === undefined ? "" : `_${options.tag}`;
	const neverRestore: ReadonlySet<EntityType> = new Set(options.neverRestore ?? []);

	/** Placeholder -> entry, in least-recently-used-first order. */
	const entries = new Map<string, Entry>();
	/** `${type}\0${canonical}` -> placeholder. */
	const byKey = new Map<string, string>();
	/** Highest number ever handed out (or imported) per type; never decreases until clear(). */
	const counters = new Map<EntityType, number>();
	/** Placeholder-like names seen in user input that are not ours, e.g. "EMAIL_1". */
	const reserved = new Set<string>();

	function remove(entry: Entry): void {
		entries.delete(entry.placeholder);
		byKey.delete(entry.key);
	}

	function touch(entry: Entry, at: number): void {
		entry.lastUsed = at;
		entries.delete(entry.placeholder);
		entries.set(entry.placeholder, entry);
	}

	/** Forgets expired entries. The map is kept in lastUsed order, so stop at the first live one. */
	function sweep(at: number): void {
		for (const entry of entries.values()) {
			if (at - entry.lastUsed <= ttlMs) break;
			remove(entry);
		}
	}

	function evictOverflow(): void {
		for (const entry of entries.values()) {
			if (entries.size <= MAX_VAULT_ENTRIES) break;
			remove(entry);
		}
	}

	function advanceCounter(type: EntityType, placeholder: string): void {
		const n = placeholderNumber(placeholder);
		if (n > (counters.get(type) ?? 0)) counters.set(type, n);
	}

	function insert(entry: Entry): void {
		entries.set(entry.placeholder, entry);
		byKey.set(entry.key, entry.placeholder);
		advanceCounter(entry.type, entry.placeholder);
		evictOverflow();
	}

	function reserve(name: string): void {
		if (reserved.has(name)) return;
		reserved.add(name);
		if (reserved.size > MAX_RESERVED_NAMES) {
			const oldest = reserved.values().next();
			if (!oldest.done) reserved.delete(oldest.value);
		}
	}

	/** Records placeholder-like tokens in the input that the vault does not own. */
	function reserveForeign(text: string): void {
		for (const m of text.matchAll(OCCURRENCE_RE)) {
			const raw = m[1] ?? m[3] ?? m[4];
			if (raw === undefined) continue;
			const name = placeholderName(raw);
			const prefix = NAME_RE.exec(name)?.[1];
			if (prefix !== undefined && PREFIX_SET.has(prefix) && !entries.has(`[${name}]`)) {
				reserve(name);
			}
		}
	}

	function placeholderFor(type: EntityType, value: string, at: number): string {
		const key = vaultKey(type, value);
		const existing = byKey.get(key);
		const existingEntry = existing === undefined ? undefined : entries.get(existing);
		if (existingEntry) {
			touch(existingEntry, at);
			return existingEntry.placeholder;
		}
		const prefix = PLACEHOLDER_PREFIX[type];
		let n = (counters.get(type) ?? 0) + 1;
		const nameFor = (k: number): string => `${prefix}_${k}${suffix}`;
		while (reserved.has(nameFor(n)) || entries.has(`[${nameFor(n)}]`)) n++;
		const placeholder = `[${nameFor(n)}]`;
		insert({ placeholder, value, type, key, lastUsed: at });
		return placeholder;
	}

	function restorable(name: string): Entry | undefined {
		const entry = entries.get(`[${name}]`);
		return entry && !neverRestore.has(entry.type) ? entry : undefined;
	}

	/**
	 * Imports a validated snapshot. Imported entries count as last used at the
	 * snapshot's createdAt; an expired snapshot imports no values but still advances
	 * the counters so its placeholder numbers are never handed to a different value.
	 */
	function importSnapshot(snapshot: VaultSnapshot): void {
		const at = now();
		const parsed = parseSnapshot(snapshot, at);
		const expired = at - parsed.createdAt > ttlMs;
		for (const item of parsed.entries) {
			advanceCounter(item.type, item.placeholder);
			if (!expired) {
				insert({ ...item, key: vaultKey(item.type, item.value), lastUsed: parsed.createdAt });
			}
		}
	}

	if (options.snapshot !== undefined) importSnapshot(options.snapshot);

	return {
		mask(text: string, findings: readonly Finding[]): MaskResult {
			if (typeof text !== "string") throw new TypeError("mask: text must be a string");
			if (!Array.isArray(findings)) throw new TypeError("mask: findings must be an array");
			const at = now();
			sweep(at);
			reserveForeign(text);

			const parts: string[] = [];
			const introduced: string[] = [];
			const seen = new Set<string>();
			const counts: Partial<Record<EntityType, number>> = {};
			let cursor = 0;
			for (const span of mergeSpans(normaliseSpans(text, findings), neverRestore)) {
				const placeholder = placeholderFor(span.type, text.slice(span.start, span.end), at);
				parts.push(text.slice(cursor, span.start), placeholder);
				cursor = span.end;
				if (!seen.has(placeholder)) {
					seen.add(placeholder);
					introduced.push(placeholder);
				}
				counts[span.type] = (counts[span.type] ?? 0) + 1;
			}
			parts.push(text.slice(cursor));
			return Object.freeze({
				masked: parts.join(""),
				placeholders: Object.freeze(introduced),
				counts: Object.freeze(counts),
			});
		},

		unmask(text: string): string {
			if (typeof text !== "string") throw new TypeError("unmask: text must be a string");
			const at = now();
			sweep(at);
			if (entries.size === 0) return text;
			return text.replace(
				OCCURRENCE_RE,
				(
					match: string,
					bracketed?: string,
					emphasis?: string,
					emphasised?: string,
					bare?: string,
				) => {
					const raw = bracketed ?? emphasised ?? bare;
					if (raw === undefined) return match;
					const entry = restorable(placeholderName(raw));
					if (!entry) return match;
					touch(entry, at);
					return emphasised !== undefined && emphasis !== undefined
						? `${emphasis}${entry.value}${emphasis}`
						: entry.value;
				},
			);
		},

		lookup(placeholder: string): string | undefined {
			if (typeof placeholder !== "string") return undefined;
			sweep(now());
			let name = placeholderName(placeholder.trim());
			if (name.startsWith("[") && name.endsWith("]")) name = name.slice(1, -1);
			return restorable(name)?.value;
		},

		size(): number {
			sweep(now());
			return entries.size;
		},

		clear(): void {
			entries.clear();
			byKey.clear();
			counters.clear();
			reserved.clear();
		},

		exportSession(): VaultSnapshot {
			const at = now();
			sweep(at);
			const exported = [...entries.values()].map((e) =>
				Object.freeze({ placeholder: e.placeholder, value: e.value, type: e.type }),
			);
			return Object.freeze({ version: 1, createdAt: at, entries: Object.freeze(exported) });
		},
	};
}

/**
 * Validates findings against the text: clamps offsets to the text, widens spans that
 * would split a surrogate pair, trims surrounding whitespace and drops empty spans.
 * An unknown entity type or a non-numeric offset throws (callers fail closed).
 */
function normaliseSpans(text: string, findings: readonly Finding[]): Span[] {
	const spans: Span[] = [];
	for (const finding of findings) {
		const span = normaliseSpan(text, finding);
		if (span) spans.push(span);
	}
	return spans;
}

function assertFinding(finding: Finding): void {
	if (typeof finding !== "object" || finding === null) {
		throw new TypeError("mask: finding must be an object");
	}
	if (!ENTITY_TYPE_SET.has(finding.type)) throw new TypeError("mask: unknown entity type");
	const { start, end } = finding;
	if (typeof start !== "number" || typeof end !== "number" || Number.isNaN(start + end)) {
		throw new TypeError("mask: finding offsets must be numbers");
	}
}

function normaliseSpan(text: string, finding: Finding): Span | null {
	assertFinding(finding);
	const length = text.length;
	let start = Math.max(0, Math.floor(finding.start));
	let end = Math.min(length, Math.ceil(finding.end));
	if (start >= end) return null;
	if (
		start > 0 &&
		isLowSurrogate(text.charCodeAt(start)) &&
		isHighSurrogate(text.charCodeAt(start - 1))
	) {
		start--;
	}
	if (
		end < length &&
		isHighSurrogate(text.charCodeAt(end - 1)) &&
		isLowSurrogate(text.charCodeAt(end))
	) {
		end++;
	}
	const slice = text.slice(start, end);
	const leading = slice.length - slice.trimStart().length;
	if (leading === slice.length) return null;
	const trailing = slice.length - slice.trimEnd().length;
	const score = Number.isFinite(finding.score) ? finding.score : 0;
	return { start: start + leading, end: end - trailing, type: finding.type, score };
}

function isHighSurrogate(code: number): boolean {
	return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code: number): boolean {
	return code >= 0xdc00 && code <= 0xdfff;
}

/**
 * Merges overlapping spans into one span covering their union, so no detected
 * character is left in clear text. The union takes the winner's type: a
 * never-restore type first (a secret must not become restorable by overlapping a
 * restorable span), then the longest span, then the highest score. Touching spans
 * (one ends where the next starts) stay separate.
 */
function mergeSpans(spans: Span[], neverRestore: ReadonlySet<EntityType>): Span[] {
	if (spans.length === 0) return spans;
	spans.sort((a, b) => a.start - b.start || b.end - a.end);
	const beats = (a: Span, b: Span): boolean => {
		const lockA = neverRestore.has(a.type);
		if (lockA !== neverRestore.has(b.type)) return lockA;
		const lengthDiff = a.end - a.start - (b.end - b.start);
		if (lengthDiff !== 0) return lengthDiff > 0;
		if (a.score !== b.score) return a.score > b.score;
		if (a.start !== b.start) return a.start < b.start;
		return (TYPE_ORDER.get(a.type) ?? 0) < (TYPE_ORDER.get(b.type) ?? 0);
	};

	const merged: Span[] = [];
	let winner = spans[0] as Span;
	let start = winner.start;
	let end = winner.end;
	for (let i = 1; i < spans.length; i++) {
		const span = spans[i] as Span;
		if (span.start < end) {
			if (span.end > end) end = span.end;
			if (beats(span, winner)) winner = span;
			continue;
		}
		merged.push({ start, end, type: winner.type, score: winner.score });
		start = span.start;
		end = span.end;
		winner = span;
	}
	merged.push({ start, end, type: winner.type, score: winner.score });
	return merged;
}
