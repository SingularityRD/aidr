/**
 * Browser Guard detection engine.
 *
 * Reuses AIDR Privacy's browser-safe rule layer (detectors, normalisation views, validators,
 * literal dictionary, span merging and heuristic signals) and adds exact-data-match. The
 * pipeline mirrors `BrowserPrivacyEngine.protect` (packages/privacy/src/browser/engine.ts):
 * every detection view is scanned, view spans are mapped back to the original text with
 * `sourceSpan`, and overlapping spans are unioned with `mergeFindings`.
 *
 * Differences from the privacy engine, deliberate for an in-page guard:
 * - Opaque encodings (long base64, 64-hex hashes, `data:` URIs) are NOT blocking by themselves.
 * - Bidi/zero-width controls are stripped for detection only (the normalised views drop \p{Cf});
 *   they never make the scan fail.
 * - Unterminated quoted values and unterminated PEM keys are protected to the end of the line /
 *   text instead of aborting the whole scan; control characters and lone surrogates are replaced
 *   (length-preserving) for detection.
 * - Oversize input, the time budget and undecodable nesting return `incomplete: true` with the
 *   findings gathered so far; `scan` never throws for untrusted input.
 * - Luhn-valid digit runs without a card label must start with a card-network digit (2-6), which
 *   removes epoch-millisecond and order-number false positives.
 *
 * `enabledEntities` gates the built-in rules. Administrator literals and exact-data datasets
 * are explicit configuration and always report their configured type.
 */
import { detectRules, keyType } from "../../../privacy/src/detectors.js";
import { LiteralMatcher } from "../../../privacy/src/dictionary.js";
import { inspectSignals } from "../../../privacy/src/enterprise/signals.js";
import { PrivacyError } from "../../../privacy/src/errors.js";
import {
	assertWellFormed,
	decodeView,
	detectionViews,
	normalize,
	normalizeView,
	sourceSpan,
	type TextView,
} from "../../../privacy/src/normalize.js";
import { mergeFindings } from "../../../privacy/src/spans.js";
import type { Evidence, Finding as PrivacyFinding } from "../../../privacy/src/types.js";
import {
	type DetectionEngine,
	type DetectionOptions,
	ENTITY_TYPES,
	type EntityType,
	type Finding,
	type LiteralRule,
	type ScanResult,
	type SignalCode,
} from "../types.js";
import { createExactDataMatcher, type ExactDataMatcher } from "./exact-data.js";

/** Largest supported `maxInputChars` (the privacy normaliser's own view limit). */
const MAX_INPUT_CHARS_LIMIT = 1_048_576;
/** Raw (pre-merge) findings per scan; more marks the scan incomplete. */
const MAX_RAW_FINDINGS = 10_000;

const PRIVACY_SIGNALS: ReadonlySet<string> = new Set<SignalCode>([
	"INSTRUCTION_OVERRIDE",
	"PROMPT_EXTRACTION",
	"ROLE_DELIMITER",
	"ROLE_SPOOF",
	"ACTIVE_CONTENT",
	"SOURCE_CODE_HINT",
]);

type RawFinding = PrivacyFinding & { readonly source: Finding["source"] };

export class DetectionConfigError extends TypeError {
	readonly code: string;
	constructor(code: string) {
		super(code);
		this.name = "DetectionConfigError";
		this.code = code;
	}
}

/** Thrown internally when the raw finding cap is reached. */
class FindingLimit extends Error {}

interface EngineConfig {
	readonly enabled: ReadonlySet<EntityType>;
	readonly matcher: LiteralMatcher | null;
	readonly exact: ExactDataMatcher | null;
	readonly detectSignals: boolean;
	readonly maxInputChars: number;
	readonly maxScanMs: number;
}

const isEntityType = (value: unknown): value is EntityType =>
	typeof value === "string" && (ENTITY_TYPES as readonly string[]).includes(value);

/** Literal matching treats I, ı, İ and i as the same letter (Turkish and English users mix them). */
const foldI = (text: string): string => text.replace(/[Iı]/g, "i");

function buildMatcher(literals: readonly LiteralRule[]): LiteralMatcher | null {
	if (!Array.isArray(literals)) throw new DetectionConfigError("INVALID_LITERALS");
	const rules: LiteralRule[] = [];
	const seen = new Set<string>();
	for (const rule of literals) {
		if (!rule || typeof rule.value !== "string" || !isEntityType(rule.type)) {
			throw new DetectionConfigError("INVALID_LITERALS");
		}
		let value: string;
		try {
			value = foldI(normalize(rule.value).text);
		} catch {
			throw new DetectionConfigError("INVALID_LITERALS");
		}
		// A blank literal can never identify anything; ignore it rather than failing the policy.
		if (!value.trim()) continue;
		const key = `${rule.type}\u0000${value.toLocaleLowerCase("tr")}`;
		if (seen.has(key)) continue;
		seen.add(key);
		rules.push({ value, type: rule.type });
	}
	if (rules.length === 0) return null;
	try {
		return new LiteralMatcher(rules);
	} catch (error) {
		throw new DetectionConfigError(
			error instanceof PrivacyError ? `LITERAL_${error.code}` : "INVALID_LITERALS",
		);
	}
}

function configure(options: DetectionOptions): EngineConfig {
	if (!options || typeof options !== "object") throw new DetectionConfigError("INVALID_OPTIONS");
	if (!Array.isArray(options.enabledEntities) || !options.enabledEntities.every(isEntityType)) {
		throw new DetectionConfigError("INVALID_ENABLED_ENTITIES");
	}
	const { maxInputChars, maxScanMs } = options;
	if (
		!Number.isSafeInteger(maxInputChars) ||
		maxInputChars < 1 ||
		maxInputChars > MAX_INPUT_CHARS_LIMIT
	) {
		throw new DetectionConfigError("INVALID_MAX_INPUT_CHARS");
	}
	if (
		typeof maxScanMs !== "number" ||
		!Number.isFinite(maxScanMs) ||
		maxScanMs <= 0 ||
		maxScanMs > 60_000
	) {
		throw new DetectionConfigError("INVALID_MAX_SCAN_MS");
	}
	if (!Array.isArray(options.exactData)) throw new DetectionConfigError("INVALID_EXACT_DATA");
	return {
		enabled: new Set(options.enabledEntities),
		matcher: buildMatcher(options.literals),
		exact: options.exactData.length > 0 ? createExactDataMatcher(options.exactData) : null,
		detectSignals: options.detectSignals === true,
		maxInputChars,
		maxScanMs,
	};
}

/** Cut at `limit` UTF-16 units without splitting a surrogate pair. */
function truncate(text: string, limit: number): string {
	let end = limit;
	const code = text.charCodeAt(end - 1);
	if (code >= 0xd800 && code <= 0xdbff) end--;
	return text.slice(0, end);
}

/**
 * Length-preserving cleanup so the privacy layer never rejects the input outright: C0 controls
 * (other than tab/CR/LF) and DEL become spaces, lone surrogates become U+FFFD.
 */
function sanitize(text: string): string {
	return text
		.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ")
		.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, "�");
}

const ENCODED = /(?:%[0-9a-fA-F]{2})+|\\u\{[0-9a-fA-F]{1,6}\}|&#(?:x[0-9a-fA-F]{1,6}|[0-9]{1,7});/g;

function decodable(raw: string): boolean {
	if (raw.startsWith("%")) {
		try {
			decodeURIComponent(raw);
			return true;
		} catch {
			return false;
		}
	}
	const cp = raw.startsWith("\\u{")
		? Number.parseInt(raw.slice(3, -1), 16)
		: raw[2] === "x"
			? Number.parseInt(raw.slice(3, -1), 16)
			: Number(raw.slice(2, -1));
	return cp > 0 && cp <= 0x10ffff;
}

/** Replace undecodable escape sequences (e.g. `%ff`) with U+FFFD so the rest still decodes. */
function neutralizeEncodings(text: string): string {
	return text.replace(ENCODED, (raw) => {
		if (decodable(raw)) return raw;
		return raw.startsWith("%") ? raw.replaceAll("%", "�") : `�${raw.slice(1)}`;
	});
}

function tolerantDecode(view: TextView): TextView {
	try {
		return decodeView(view);
	} catch (error) {
		if (!(error instanceof PrivacyError)) throw error;
		return decodeView({
			text: neutralizeEncodings(view.text),
			starts: view.starts,
			ends: view.ends,
		});
	}
}

/**
 * `detectionViews` from the privacy layer, falling back to a tolerant replica when the text holds
 * undecodable escapes or is nested deeper than the privacy layer decodes. `complete` is false
 * only when encoded content remains after the maximum decoding depth.
 */
function buildViews(text: string): { views: TextView[]; complete: boolean } {
	try {
		return { views: detectionViews(text), complete: true };
	} catch (error) {
		if (!(error instanceof PrivacyError) || error.code === "NORMALIZATION_LIMIT") throw error;
	}
	const base = normalize(text);
	const views = [base];
	let last = base;
	for (let i = 0; i < 3; i++) {
		const next = normalizeView(tolerantDecode(last));
		if (next.text === last.text) return { views, complete: true };
		views.push(next);
		last = next;
	}
	return { views, complete: normalizeView(tolerantDecode(last)).text === last.text };
}

const PEM_BEGIN = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g;
const PEM_END = /-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g;
const QUOTED_VALUE = /[:=#][ \t]*(["'])/g;
const SECRET_LABEL =
	/(?:api[_ -]?key|client[_ -]?secret|access[_ -]?token|refresh[_ -]?token|password|passwd|pwd|secret|şifre|sifre)["']?[ \t]*[:=][ \t]*$/iu;

type Span = readonly [start: number, end: number, type: EntityType];

function closingQuote(text: string, from: number, quote: string): boolean {
	let escaped = false;
	for (let i = from; i < text.length; i++) {
		const c = text[i];
		if (!escaped && c === quote) return true;
		escaped = !escaped && c === "\\";
	}
	return false;
}

function lineEnd(text: string, from: number): number {
	const match = /[\r\n]/.exec(text.slice(from));
	return match ? from + match.index : text.length;
}

/**
 * The privacy detectors abort on an unterminated quoted field/secret or a PEM key without its
 * END line. Instead, protect those values up to the end of the line (quoted values) or the end of
 * the text (keys), and hand the detectors a length-preserving copy they can scan.
 */
function patchUnterminated(text: string): { text: string; spans: Span[] } {
	const spans: Span[] = [];
	const chars = [...text.matchAll(QUOTED_VALUE)].flatMap((m) => {
		const at = m.index + m[0].length - 1;
		const quote = m[1] as string;
		if (closingQuote(text, at + 1, quote)) return [];
		const end = lineEnd(text, at + 1);
		const label = text.slice(Math.max(0, at - 64), at).replace(/[İı]/g, "i");
		if (end > at + 1 && SECRET_LABEL.test(label)) spans.push([at + 1, end, "SECRET"]);
		return [at];
	});
	let patched = text;
	if (chars.length) {
		const out = text.split("");
		for (const at of chars) out[at] = " ";
		patched = out.join("");
	}
	for (const m of patched.matchAll(PEM_BEGIN)) {
		PEM_END.lastIndex = m.index + m[0].length;
		if (PEM_END.exec(patched)) continue;
		spans.push([m.index, text.length, "PRIVATE_KEY"]);
		patched =
			patched.slice(0, m.index) + " ".repeat(m[0].length) + patched.slice(m.index + m[0].length);
	}
	return { text: patched, spans };
}

/** A Luhn-valid digit run without a card label must start with a card-network digit. */
function plausibleCard(value: string): boolean {
	return /^[2-6]/.test(value.replace(/[^0-9]/g, ""));
}

const isPrecise = (f: RawFinding): boolean => f.evidence === "pattern" || f.evidence === "checksum";

/** `scheme://user:pass@host`: the privacy layer also reads `pass@host` as an email address. */
function isUrlHostEmail(f: RawFinding, urlCredentials: readonly RawFinding[]): boolean {
	return (
		f.type === "EMAIL" &&
		isPrecise(f) &&
		urlCredentials.some((s) => s.start < f.start && f.start < s.end && s.end <= f.end)
	);
}

/** Punctuation and whitespace between a name and the value that follows it. */
const NAME_SEPARATOR = /[\s,;:.!?/|(\-–—]/u;
/** Longest separator run still read as "right after" a name (`Ayşe Yılmaz, (` then the value). */
const MAX_NAME_GAP = 4;
/** A label word; multi-word labels (`T.C. Kimlik No`) are separated by spaces only. */
const LABEL_CHAR = /[^\s,;:()]/u;
const MAX_LABEL_WORDS = 3;

function trimSeparators(text: string, start: number, end: number): number {
	while (end > start && NAME_SEPARATOR.test(text[end - 1] as string)) end--;
	return end;
}

/** Start of the label of `type` (`TCKN`, `IBAN`, `T.C. Kimlik No`) that ends at `end`, else `end`. */
function labelStart(text: string, start: number, end: number, type: EntityType): number {
	let at = end;
	for (let words = 0; words < MAX_LABEL_WORDS; words++) {
		const wordEnd = at;
		while (at > start && LABEL_CHAR.test(text[at - 1] as string)) at--;
		if (at === wordEnd) break;
		if (keyType(text.slice(at, end)) === type) return at;
		const wordStart = at;
		while (at > start && (text[at - 1] === " " || text[at - 1] === "\t")) at--;
		if (at === wordStart) break;
	}
	return end;
}

/**
 * End of a contextual PERSON span. The privacy layer protects a labelled `Full name:` field to the
 * end of its line (and reads any capitalised word after `Sayın` as part of the name), so in
 * `Full name: Ayşe Yılmaz, TCKN 10000000146` the PERSON span covers the TCKN; `mergeFindings` then
 * unions both under the higher-priority type and the name is masked as `[TCKN_1]`. A name never
 * contains a validated/pattern value, so it ends before the first one that starts inside or right
 * after it, less the separators and that value's own label (`, TCKN`, `e-posta`) in between.
 * Only PERSON is narrowed: an address may continue after an embedded number and a secret must
 * never be split, so those keep the privacy layer's conservative span.
 */
function personEnd(text: string, f: RawFinding, values: readonly RawFinding[]): number {
	let next: RawFinding | undefined;
	for (const v of values) {
		if (v.start <= f.start || (next && v.start >= next.start)) continue;
		if (v.start > f.end) {
			const gap = text.slice(f.end, v.start);
			if (gap.length > MAX_NAME_GAP || trimSeparators(gap, 0, gap.length) > 0) continue;
		}
		next = v;
	}
	if (!next) return f.end;
	const end = trimSeparators(text, f.start, Math.min(f.end, next.start));
	return trimSeparators(text, f.start, labelStart(text, f.start, end, next.type));
}

/**
 * Tightens rule spans (source offsets) so a reversible placeholder replaces only the value:
 * - a labelled field (`Email: a@b.com, card ...`) runs to the end of the line in the privacy
 *   layer; when a validated/pattern value of the same type starts the field, clip the field to it;
 * - a contextual name stops before a validated value of another type (see `personEnd`);
 * - the host part of `scheme://user:pass@host` is not an email address;
 * - a phone number written `(0212) 555 12 34` includes its opening parenthesis.
 * A span left empty (a name field holding only the next value's label) is dropped.
 */
function refineSpans(text: string, raw: readonly RawFinding[]): RawFinding[] {
	const rules = raw.filter((f) => f.source === "rule");
	const urlCredentials = rules.filter(
		(f) => f.type === "SECRET" && f.evidence === "context" && text[f.end - 1] === "@",
	);
	const values = rules.filter(
		(p) => p.type !== "PERSON" && isPrecise(p) && !isUrlHostEmail(p, urlCredentials),
	);
	const refine = (f: RawFinding): RawFinding[] => {
		let { start, end } = f;
		const value =
			f.evidence === "context" &&
			rules.find((p) => p.type === f.type && isPrecise(p) && p.start === start && p.end < end);
		if (value) end = value.end;
		if (f.type === "PERSON" && f.evidence === "context") end = personEnd(text, f, values);
		if (f.type === "PHONE" && text[start - 1] === "(" && /^[^(]*\)/.test(text.slice(start, end))) {
			start--;
		}
		if (end <= start) return [];
		return [start === f.start && end === f.end ? f : { ...f, start, end }];
	};
	return raw.flatMap((f) => {
		if (f.source !== "rule") return [f];
		return isUrlHostEmail(f, urlCredentials) ? [] : refine(f);
	});
}

function collectSignals(
	text: string,
	views: readonly TextView[],
): { codes: SignalCode[]; ok: boolean } {
	const codes = new Set<SignalCode>();
	const add = (found: readonly string[]) => {
		for (const code of found) if (PRIVACY_SIGNALS.has(code)) codes.add(code as SignalCode);
	};
	try {
		add(inspectSignals(text));
		return { codes: [...codes], ok: true };
	} catch {
		// Undecodable escapes: inspect each tolerant view on its own instead.
	}
	let ok = false;
	for (const view of views) {
		try {
			add(inspectSignals(view.text));
			ok = true;
		} catch {
			// This view could not be inspected; another view may still cover its content.
		}
	}
	return { codes: [...codes], ok };
}

/** Mutable state of one scan. Every stage records gaps in `incomplete` instead of throwing. */
class Scan {
	readonly started = performance.now();
	readonly deadline: number;
	readonly raw: RawFinding[] = [];
	readonly signals = new Set<SignalCode>();
	incomplete = false;
	/** The (possibly truncated) original text all offsets refer to. */
	input = "";
	/** `input` after length-preserving control/surrogate cleanup. */
	clean = "";
	readonly #seen = new Set<string>();

	constructor(readonly config: EngineConfig) {
		this.deadline = this.started + config.maxScanMs;
	}

	expired(): boolean {
		return performance.now() > this.deadline;
	}

	push(finding: RawFinding): void {
		const key = `${finding.start}:${finding.end}:${finding.type}:${finding.source}`;
		if (this.#seen.has(key)) return;
		if (this.raw.length >= MAX_RAW_FINDINGS) throw new FindingLimit();
		this.#seen.add(key);
		this.raw.push(finding);
	}

	pushView(
		view: TextView,
		[a, b]: readonly [number, number],
		type: EntityType,
		score: number,
		evidence: Evidence,
		source: Finding["source"],
	): void {
		const [start, end] = sourceSpan(view, a, b);
		this.push({ start, end, type, score, evidence, source });
	}

	/** Truncates, sanitises and builds the detection views. */
	prepare(text: unknown): TextView[] {
		if (typeof text !== "string") throw new TypeError("INVALID_INPUT");
		this.input = text;
		if (text.length > this.config.maxInputChars) {
			this.incomplete = true;
			this.input = truncate(text, this.config.maxInputChars);
		}
		this.clean = sanitize(this.input);
		assertWellFormed(this.clean);
		const { views, complete } = buildViews(this.clean);
		if (!complete) this.incomplete = true;
		return views;
	}

	scanView(view: TextView): void {
		const { enabled, matcher } = this.config;
		const patched = patchUnterminated(view.text);
		for (const [a, b, type] of patched.spans) {
			this.pushView(view, [a, b], type, 0.95, "context", "rule");
		}
		try {
			detectRules(patched.text, (a, b, type, score, evidence) => {
				if (!enabled.has(type)) return;
				const card = type === "CREDIT_CARD" && evidence === "checksum";
				if (card && !plausibleCard(view.text.slice(a, b))) return;
				this.pushView(view, [a, b], type, score, evidence, "rule");
			});
		} catch (error) {
			if (error instanceof FindingLimit) throw error;
			// A rule aborted on this view; keep what was found and report the gap.
			this.incomplete = true;
		}
		matcher?.scan(foldI(view.text), (a, b, type) =>
			this.pushView(view, [a, b], type, 1, "dictionary", "literal"),
		);
	}

	scanSignals(views: readonly TextView[]): void {
		const found = collectSignals(this.clean, views);
		for (const code of found.codes) this.signals.add(code);
		if (!found.ok) this.incomplete = true;
	}

	async scanExactData(exact: ExactDataMatcher, views: readonly TextView[]): Promise<void> {
		const result = await exact.scan(views, this.deadline);
		if (result.incomplete) this.incomplete = true;
		for (const hit of result.hits) {
			this.push({ ...hit, score: 1, evidence: "dictionary", source: "exact-data" });
		}
		if (result.hits.length > 0) this.signals.add("EXACT_DATA_MATCH");
	}

	async run(text: unknown): Promise<void> {
		const views = this.prepare(text);
		for (const view of views) {
			if (this.expired()) {
				this.incomplete = true;
				return;
			}
			this.scanView(view);
		}
		if (this.config.detectSignals) {
			if (this.expired()) this.incomplete = true;
			else this.scanSignals(views);
		}
		if (this.config.exact) {
			if (this.expired()) this.incomplete = true;
			else await this.scanExactData(this.config.exact, views);
		}
	}

	result(): ScanResult {
		// Rule findings for disabled types are already dropped; patched spans are rules too.
		const kept = this.raw.filter((f) => f.source !== "rule" || this.config.enabled.has(f.type));
		const merged = mergeFindings(refineSpans(this.input, kept)) as RawFinding[];
		const counts: Partial<Record<EntityType, number>> = {};
		const findings: Finding[] = merged.map((f) => {
			counts[f.type] = (counts[f.type] ?? 0) + 1;
			const { type, start, end, score, source } = f;
			return Object.freeze({ type, start, end, score, source });
		});
		return Object.freeze({
			findings: Object.freeze(findings),
			signals: Object.freeze([...this.signals].sort()),
			counts: Object.freeze(counts),
			incomplete: this.incomplete,
			elapsedMs: Math.round((performance.now() - this.started) * 1000) / 1000,
		});
	}
}

async function runScan(config: EngineConfig, text: string): Promise<ScanResult> {
	const scan = new Scan(config);
	try {
		await scan.run(text);
	} catch {
		// Limits, malformed input or an unexpected rule failure: report what was found so far and
		// let the caller fail closed on `incomplete`. Error details may contain input; drop them.
		scan.incomplete = true;
	}
	return scan.result();
}

/**
 * Creates a detection engine. Throws `DetectionConfigError` (or `ExactDataConfigError`) for
 * malformed options so a broken policy surfaces instead of silently weakening protection.
 * `scan` itself never throws; it reports `incomplete: true` when it could not finish.
 */
export function createDetectionEngine(options: DetectionOptions): DetectionEngine {
	const config = configure(options);
	return Object.freeze({ scan: (text: string) => runScan(config, text) });
}
