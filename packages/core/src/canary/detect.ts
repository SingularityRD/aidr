/**
 * Canary credential detection, shared by every connector.
 *
 * A tool call triggers a canary when it
 *   - carries a registered token value anywhere in its input (command, URL,
 *     file content, MCP arguments ...), compared by SHA-256 digest of every
 *     alphanumeric run whose length matches a registered token, including
 *     percent-, `\u`- and base64-encoded forms; or
 *   - names a registered decoy path (absolute, `~`/`$HOME`-relative, or a
 *     relative path whose segments are a suffix of the decoy's path).
 * Tool output and prompts are checked for token values only.
 *
 * Failure policy (detection internal): an unreadable registry or an input too
 * large to walk makes the canary signal `unavailable`. Callers skip the signal,
 * log it, and must not report the call as clean; nothing here throws.
 */

import { statSync } from "node:fs";
import { homedir } from "node:os";
import { posix } from "node:path";
import type { Verdict } from "../types.js";
import {
	type CanaryKind,
	defaultCanaryRegistryPath,
	MIN_CANARY_TOKEN_LENGTH,
	readCanaryRegistry,
	sha256Hex,
} from "./registry.js";

export const CANARY_TRIGGERED_CATEGORY = "canary_triggered";
export const CANARY_UNAVAILABLE_CATEGORY = "canary_unavailable";
/** A registered canary token value appeared in the inspected content. */
export const CANARY_TOKEN_RULE_ID = "AIDR-CANARY-001";
/** A registered canary file path was referenced by the tool call. */
export const CANARY_PATH_RULE_ID = "AIDR-CANARY-002";
/** Tool output finding id used by the shared output scanner. */
export const CANARY_OUTPUT_RULE_ID = "OUT-CANARY-001";

export interface CanaryHit {
	id: string;
	kind: CanaryKind;
	via: "token" | "path";
}

interface IndexedPath {
	id: string;
	kind: CanaryKind;
	/** Comparison key: posix-style absolute path, case-folded where the file system is. */
	key: string;
}

export type CanaryIndex =
	| { status: "absent" }
	| { status: "unavailable"; reason: string }
	| {
			status: "ok";
			tokens: ReadonlyMap<string, { id: string; kind: CanaryKind }>;
			lengths: ReadonlySet<number>;
			paths: ReadonlyMap<string, IndexedPath>;
			/** Basename -> decoys, for relative-path suffix matching. */
			basenames: ReadonlyMap<string, readonly IndexedPath[]>;
	  };

export type CanaryInspection =
	| { status: "absent" }
	| { status: "clear" }
	| { status: "triggered"; hits: CanaryHit[] }
	| { status: "unavailable"; reason: string };

const CASE_INSENSITIVE_FS = process.platform === "win32" || process.platform === "darwin";
const MAX_WALK_NODES = 50_000;
const MAX_WALK_DEPTH = 64;
const MAX_WALK_CHARS = 32 * 1024 * 1024;
const MAX_BASE64_DECODE_CHARS = 1024 * 1024;
/**
 * Keys whose values are file bodies or free text. A relative decoy name inside
 * them (a README mentioning `.env.backup`) is not an access, so only absolute
 * and home-relative decoy paths count there. Token values count everywhere.
 */
const CONTENT_KEYS = new Set([
	"content",
	"contents",
	"new_string",
	"old_string",
	"new_source",
	"text",
	"body",
	"message",
	"description",
]);

let cached: { path: string; stamp: string; index: CanaryIndex } | null = null;

/** Drop the cached index (deploy/remove call this after changing the registry). */
export function invalidateCanaryIndex(): void {
	cached = null;
}

function comparisonKey(path: string): string {
	const slashed = process.platform === "win32" ? path.replace(/\\/g, "/") : path;
	const normalized = posix.normalize(slashed);
	return CASE_INSENSITIVE_FS ? normalized.toLowerCase() : normalized;
}

function buildIndex(registryPath: string): CanaryIndex {
	const read = readCanaryRegistry(registryPath);
	if (read.status === "absent") return { status: "absent" };
	if (read.status === "invalid") return { status: "unavailable", reason: read.reason };
	const tokens = new Map<string, { id: string; kind: CanaryKind }>();
	const lengths = new Set<number>();
	const paths = new Map<string, IndexedPath>();
	const basenames = new Map<string, IndexedPath[]>();
	for (const record of read.registry.canaries) {
		for (const token of record.tokens) {
			tokens.set(token.sha256, { id: record.id, kind: record.kind });
			lengths.add(token.length);
		}
		const entry: IndexedPath = {
			id: record.id,
			kind: record.kind,
			key: comparisonKey(record.path),
		};
		paths.set(entry.key, entry);
		const base = posix.basename(entry.key);
		basenames.set(base, [...(basenames.get(base) ?? []), entry]);
	}
	if (tokens.size === 0 && paths.size === 0) return { status: "absent" };
	return { status: "ok", tokens, lengths, paths, basenames };
}

/**
 * The canary index for the registry, cached until the registry file changes.
 * Never throws: a registry that cannot be read is `unavailable`.
 */
export function loadCanaryIndex(registryPath = defaultCanaryRegistryPath()): CanaryIndex {
	let stamp: string;
	try {
		const info = statSync(registryPath, { bigint: true });
		stamp = `${info.ino}:${info.size}:${info.mtimeNs}:${info.ctimeNs}`;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") {
			cached = null;
			return { status: "absent" };
		}
		return { status: "unavailable", reason: "registry could not be inspected" };
	}
	if (cached && cached.path === registryPath && cached.stamp === stamp) return cached.index;
	let index: CanaryIndex;
	try {
		index = buildIndex(registryPath);
	} catch {
		index = { status: "unavailable", reason: "registry could not be indexed" };
	}
	cached = { path: registryPath, stamp, index };
	return index;
}

type ReadyIndex = Extract<CanaryIndex, { status: "ok" }>;

class HitCollector {
	private readonly seen = new Set<string>();
	readonly hits: CanaryHit[] = [];

	add(hit: CanaryHit): void {
		const key = `${hit.id}:${hit.via}`;
		if (this.seen.has(key)) return;
		this.seen.add(key);
		this.hits.push(hit);
	}
}

function scanAlnumRuns(text: string, index: ReadyIndex, collector: HitCollector): void {
	for (const match of text.matchAll(/[A-Za-z0-9]{20,}/g)) {
		const run = match[0];
		if (!index.lengths.has(run.length)) continue;
		const found = index.tokens.get(sha256Hex(run));
		if (found) collector.add({ ...found, via: "token" });
	}
}

function decodePercent(text: string): string {
	return text.replace(/%([0-9A-Fa-f]{2})/g, (_match, hex: string) =>
		String.fromCharCode(Number.parseInt(hex, 16)),
	);
}

function decodeUnicodeEscapes(text: string): string {
	return text.replace(/\\u([0-9A-Fa-f]{4})/g, (_match, hex: string) =>
		String.fromCharCode(Number.parseInt(hex, 16)),
	);
}

/** Views of `text` a token can hide in: raw, percent-, `\u`- and base64-encoded. */
function scanTokenViews(text: string, index: ReadyIndex, collector: HitCollector): void {
	if (text.length < MIN_CANARY_TOKEN_LENGTH) return;
	scanAlnumRuns(text, index, collector);
	if (text.includes("%")) scanAlnumRuns(decodePercent(text), index, collector);
	if (text.includes("\\u")) scanAlnumRuns(decodeUnicodeEscapes(text), index, collector);
	let decodedBudget = MAX_BASE64_DECODE_CHARS;
	for (const match of text.matchAll(/[A-Za-z0-9+/_-]{28,}={0,2}/g)) {
		if (decodedBudget <= 0) break;
		const encoded = match[0].slice(0, decodedBudget);
		decodedBudget -= encoded.length;
		const decoded = Buffer.from(encoded, "base64").toString("latin1");
		if (decoded.length >= MIN_CANARY_TOKEN_LENGTH) scanAlnumRuns(decoded, index, collector);
	}
}

function currentHome(): string {
	const envHome = process.env.HOME?.trim();
	return envHome && envHome.length > 0 ? envHome : homedir();
}

function expandHome(token: string): string | null {
	const match = /^(?:~|\$HOME|\$\{HOME\})(?=\/|\\|$)/.exec(token);
	return match ? `${currentHome()}${token.slice(match[0].length)}` : null;
}

function isAbsolutePathToken(token: string): boolean {
	return token.startsWith("/") || /^[A-Za-z]:[\\/]/.test(token);
}

function matchPathToken(
	raw: string,
	index: ReadyIndex,
	allowRelative: boolean,
	collector: HitCollector,
): void {
	let token = raw.replace(/^@/, "").replace(/^file:\/\//i, "");
	const expanded = expandHome(token);
	if (expanded) token = expanded;
	if (isAbsolutePathToken(token)) {
		const hit = index.paths.get(comparisonKey(token));
		if (hit) collector.add({ id: hit.id, kind: hit.kind, via: "path" });
		return;
	}
	if (!allowRelative) return;
	const relative = comparisonKey(token).replace(/^(?:\.{1,2}\/)+/, "");
	if (!relative || relative === "." || relative === "..") return;
	const candidates = index.basenames.get(posix.basename(relative));
	if (!candidates) return;
	for (const candidate of candidates) {
		if (candidate.key === relative || candidate.key.endsWith(`/${relative}`)) {
			collector.add({ id: candidate.id, kind: candidate.kind, via: "path" });
		}
	}
}

const PATH_TOKEN_SEPARATORS = /[\s"'`;|&<>(){}[\],=]+/;

function scanPathTokens(
	text: string,
	index: ReadyIndex,
	allowRelative: boolean,
	collector: HitCollector,
): void {
	for (const token of text.split(PATH_TOKEN_SEPARATORS)) {
		if (token.length > 0 && token.length <= 4096) {
			matchPathToken(token, index, allowRelative, collector);
		}
	}
}

/** Token-value hits in free text (tool output, prompts). */
export function findCanaryTokens(
	text: string,
	index: CanaryIndex = loadCanaryIndex(),
): CanaryHit[] {
	if (index.status !== "ok" || !text) return [];
	const collector = new HitCollector();
	scanTokenViews(text, index, collector);
	return collector.hits;
}

class WalkLimitError extends Error {}

/**
 * Walk every string (and object key) of a value. Returns false when the walk
 * exceeded its node, depth or size bounds and the value was not fully covered.
 */
function walkStrings(value: unknown, visit: (text: string, key: string | null) => void): boolean {
	let nodes = 0;
	let chars = 0;
	const ancestors = new Set<object>();
	const step = (current: unknown, key: string | null, depth: number): void => {
		nodes += 1;
		if (nodes > MAX_WALK_NODES || depth > MAX_WALK_DEPTH) throw new WalkLimitError();
		if (typeof current === "string") {
			chars += current.length;
			if (chars > MAX_WALK_CHARS) throw new WalkLimitError();
			visit(current, key);
			return;
		}
		if (current === null || typeof current !== "object") return;
		if (ancestors.has(current)) return;
		ancestors.add(current);
		if (Array.isArray(current)) {
			for (const item of current) step(item, key, depth + 1);
		} else {
			for (const [childKey, child] of Object.entries(current as Record<string, unknown>)) {
				visit(childKey, null);
				step(child, childKey, depth + 1);
			}
		}
		ancestors.delete(current);
	};
	try {
		step(value, null, 0);
		return true;
	} catch (error) {
		if (error instanceof WalkLimitError) return false;
		throw error;
	}
}

/** Canary hits (token values and decoy paths) anywhere in a tool call's input. */
export function inspectToolInputForCanaries(
	toolInput: unknown,
	index: CanaryIndex = loadCanaryIndex(),
): CanaryInspection {
	if (index.status === "absent") return { status: "absent" };
	if (index.status === "unavailable") return index;
	try {
		const collector = new HitCollector();
		const complete = walkStrings(toolInput, (text, key) => {
			scanTokenViews(text, index, collector);
			const allowRelative = key === null || !CONTENT_KEYS.has(key.toLowerCase());
			scanPathTokens(text, index, allowRelative, collector);
		});
		if (collector.hits.length > 0) return { status: "triggered", hits: collector.hits };
		if (!complete) {
			return { status: "unavailable", reason: "tool input exceeds the canary inspection bounds" };
		}
		return { status: "clear" };
	} catch {
		return { status: "unavailable", reason: "canary inspection failed" };
	}
}

/** Canary token values anywhere in a structured value (a tool response). */
export function inspectValueForCanaryTokens(
	value: unknown,
	index: CanaryIndex = loadCanaryIndex(),
): CanaryInspection {
	if (index.status === "absent") return { status: "absent" };
	if (index.status === "unavailable") return index;
	try {
		const collector = new HitCollector();
		const complete = walkStrings(value, (text) => scanTokenViews(text, index, collector));
		if (collector.hits.length > 0) return { status: "triggered", hits: collector.hits };
		if (!complete) {
			return { status: "unavailable", reason: "value exceeds the canary inspection bounds" };
		}
		return { status: "clear" };
	} catch {
		return { status: "unavailable", reason: "canary inspection failed" };
	}
}

export type CanaryStage = "tool_input" | "tool_output" | "user_prompt";

const STAGE_TEXT: Record<CanaryStage, string> = {
	tool_input: "This tool call",
	tool_output: "The tool output",
	user_prompt: "The prompt",
};

/**
 * The deny verdict for a canary trigger. Artifacts carry only canary ids; the
 * token value and the decoy path never enter the verdict.
 */
export function canaryTriggeredVerdict(
	hits: readonly CanaryHit[],
	stage: CanaryStage = "tool_input",
): Verdict {
	const kinds = [...new Set(hits.map((hit) => hit.kind))].join(", ");
	const byToken = hits.some((hit) => hit.via === "token");
	const what = byToken
		? `contains the value of a canary credential (${kinds})`
		: `accesses a canary credential file (${kinds})`;
	return {
		decision: "deny",
		category: CANARY_TRIGGERED_CATEGORY,
		confidence: 1,
		severity: "critical",
		source: "canary",
		artifacts: [...new Set(hits.map((hit) => `canary:${hit.id}`))],
		matchedThreatId: byToken ? CANARY_TOKEN_RULE_ID : CANARY_PATH_RULE_ID,
		reasons: [
			`${CANARY_TRIGGERED_CATEGORY}: ${STAGE_TEXT[stage]} ${what} planted by Singularity AIDR. No legitimate task uses these decoys, so the agent may be following injected instructions; the action was blocked and recorded as a high-severity incident.`,
		],
	};
}

/** Annotate a clean allow when the canary signal could not run (never a clean result). */
export function canaryUnavailableVerdict(verdict: Verdict, reason: string): Verdict {
	if (verdict.decision !== "allow") return verdict;
	const note = `Canary credential check did not run (${reason}); this call was NOT checked for canary credentials.`;
	// Another audited allow (a redaction, an allowlist hit) keeps its category.
	if (verdict.category !== "none" || verdict.transformedInput) {
		return { ...verdict, reasons: [...verdict.reasons, note] };
	}
	return {
		...verdict,
		category: CANARY_UNAVAILABLE_CATEGORY,
		severity: "warning",
		reasons: [...verdict.reasons, note],
	};
}
