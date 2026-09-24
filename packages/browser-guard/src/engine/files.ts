/**
 * File / document sanitisation for uploads, drops and file pastes.
 *
 * `sanitizeFile` turns an uploaded file into a {@link FileDecision}: allow it untouched,
 * replace it with a masked copy (same name, same MIME type, UTF-8 bytes), or block it.
 *
 * Decision order:
 *   1. `policy.fileHandling === "allow"`  -> allow, nothing is read.
 *      `policy.fileHandling === "block"`  -> block `FILE_BLOCKED_BY_POLICY`.
 *   2. `bytes.length > policy.maxFileBytes` -> block `FILE_TOO_LARGE`.
 *   3. Classification. A file is scanned as text when its content decodes as strict UTF-8
 *      (UTF-8 BOM stripped; UTF-16 with a BOM is also accepted) and contains no NUL, AND
 *      either its extension is a known text/source extension, or its extension is unknown
 *      and its MIME type is not a binary media type. Known binary extensions (pdf, docx,
 *      xlsx, images, archives...) are binary. Scanning an extension-less text file is
 *      strictly safer than passing it through unscanned, so "unknown but decodable" is
 *      scanned rather than treated as binary.
 *      A TEXT-NAMED file (known text extension or dotenv name) or a TEXT-MIME file
 *      (`text/*`, JSON, XML, CSV, YAML...) that is not valid UTF-8 is never treated as
 *      binary: Excel and most Windows tools write CSV/TXT in the ANSI code page, so the
 *      content is decoded with a single-byte fallback - windows-1254 (Turkish), or
 *      windows-1252 (Western) when that leaves fewer undefined C1 control characters
 *      (the two differ only in six Turkish letters and Ž/ž) - and scanned like any text
 *      file. A masked copy of such a file is re-encoded as UTF-8 (CSV/TSV with a UTF-8
 *      BOM so spreadsheet tools detect the new encoding; a MIME `charset` parameter, if
 *      any, is rewritten to utf-8); an unchanged file keeps its original bytes.
 *      A text-named/text-MIME file that contains a NUL byte (e.g. UTF-16 without a BOM,
 *      or binary content behind a text name) cannot be decoded safely: it is blocked with
 *      `TEXT_FILE_NOT_DECODABLE` in auto/confirm/block mode (monitor mode, which never
 *      blocks, allows it with that reason so the event is recorded).
 *   4. Binary files cannot be inspected in the browser:
 *        `policy.mode === "block"` -> block `BINARY_FILE_UNSCANNABLE`;
 *        any other mode            -> allow `BINARY_FILE_UNSCANNED` so the content script can
 *                                     warn (and record) instead of silently passing it.
 *   5. Text formats:
 *        - CSV/TSV: parsed (quotes, escaped quotes, CRLF/LF/CR), masked cell by cell with the
 *          column header as detection context, re-serialised with the original delimiter,
 *          quoting and line endings. Columns whose header names a sensitive field (see
 *          `sensitiveKeyType`) are masked wholesale. Spreadsheet formula injection is
 *          neutralised by prefixing `'` to cells that start with `= + - @ \t \r` (plain
 *          numbers such as `-12.5` are left alone) -> reason `FORMULA_CELL`.
 *        - JSON / JSONL: only string (and number) leaves are rewritten in place, so keys,
 *          structure and formatting survive and the output is still valid JSON. Values under
 *          sensitive keys (password, token, api_key, tckn, iban...) are masked even when no
 *          rule matched. Invalid JSON falls back to plain-text masking.
 *        - `.env` files: every assigned value is masked as SECRET, whatever the policy's
 *          enabled entities are (a dotenv file is a secrets file by definition).
 *        - Everything else: plain-text masking.
 *      Findings -> action "mask", reason `SENSITIVE_DATA`. No findings and no formula cells
 *      -> allow (the original bytes are used unchanged).
 *   6. Risk signals (prompt injection, source code...): with `policy.signalAction === "block"`
 *      the file is blocked with `SIGNAL_<CODE>` reasons; with "warn" the reasons are attached
 *      to the decision without changing the action.
 *
 * Failure policy (fail closed): an incomplete scan (engine limit/timeout, even after retrying
 * in smaller chunks) blocks with `SCAN_INCOMPLETE`; any internal error blocks with
 * `FILE_SCAN_ERROR`. The function never throws.
 *
 * `sanitizeFile` does not interpret `auto` / `confirm` / `monitor`; the content script applies
 * the guard mode to the returned decision (e.g. `confirm` asks before substituting the masked
 * copy). The only mode-dependent rule here is binary handling (step 4).
 */
import { keyType } from "../../../privacy/src/detectors.js";
import type {
	DetectionEngine,
	EntityType,
	FileDecision,
	Finding,
	GuardPolicy,
	PlaceholderVault,
	SignalCode,
} from "../types.js";

export interface GuardFile {
	readonly name: string;
	readonly type: string;
	readonly bytes: Uint8Array;
}

export interface SanitizeDeps {
	readonly engine: DetectionEngine;
	readonly vault: PlaceholderVault;
	readonly policy: GuardPolicy;
}

type Counts = Partial<Record<EntityType, number>>;
type TextKind = "text" | "csv" | "tsv" | "json" | "jsonl" | "env";

const TEXT_EXTENSIONS: Readonly<Record<string, TextKind>> = {
	txt: "text",
	text: "text",
	md: "text",
	markdown: "text",
	log: "text",
	xml: "text",
	yaml: "text",
	yml: "text",
	ini: "text",
	cfg: "text",
	conf: "text",
	toml: "text",
	properties: "text",
	sql: "text",
	csv: "csv",
	tsv: "tsv",
	tab: "tsv",
	json: "json",
	jsonl: "jsonl",
	ndjson: "jsonl",
	env: "env",
	js: "text",
	mjs: "text",
	cjs: "text",
	jsx: "text",
	ts: "text",
	mts: "text",
	cts: "text",
	tsx: "text",
	py: "text",
	java: "text",
	go: "text",
	rs: "text",
	cs: "text",
	php: "text",
	rb: "text",
	sh: "text",
	bash: "text",
	zsh: "text",
	ps1: "text",
	psm1: "text",
	bat: "text",
	cmd: "text",
	c: "text",
	cc: "text",
	cpp: "text",
	cxx: "text",
	h: "text",
	hpp: "text",
	kt: "text",
	kts: "text",
	swift: "text",
	scala: "text",
	html: "text",
	htm: "text",
	css: "text",
	scss: "text",
	vue: "text",
	svelte: "text",
	graphql: "text",
	tf: "text",
	pem: "text",
	key: "text",
	crt: "text",
	svg: "text",
};

const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
	"pdf",
	"doc",
	"docx",
	"docm",
	"dot",
	"dotx",
	"xls",
	"xlsx",
	"xlsm",
	"xlsb",
	"ppt",
	"pptx",
	"pptm",
	"odt",
	"ods",
	"odp",
	"pages",
	"numbers",
	"png",
	"jpg",
	"jpeg",
	"gif",
	"webp",
	"bmp",
	"tif",
	"tiff",
	"heic",
	"heif",
	"ico",
	"avif",
	"psd",
	"zip",
	"gz",
	"tgz",
	"bz2",
	"xz",
	"7z",
	"rar",
	"tar",
	"jar",
	"war",
	"apk",
	"exe",
	"dll",
	"so",
	"dylib",
	"bin",
	"class",
	"wasm",
	"mp3",
	"mp4",
	"m4a",
	"wav",
	"ogg",
	"flac",
	"mov",
	"avi",
	"mkv",
	"webm",
	"sqlite",
	"db",
	"parquet",
	"avro",
	"pkl",
	"npy",
	"msg",
]);

const BINARY_MIME =
	/^(?:image|audio|video|font)\/|^application\/(?:pdf|zip|gzip|x-(?:7z|rar|tar|bzip2)|octet-stream-binary|msword|vnd\.(?:ms-|openxmlformats|oasis))/i;

/** Scan window sizes tried, largest first, when a whole-text scan comes back incomplete. */
const CHUNK_SIZES = [16384, 4096, 1024] as const;
/** Separator between structured values in a batched scan. */
const SEGMENT_SEPARATOR = "\n\n";
const PLACEHOLDER_ONLY = /^\[[A-Z_]+_\d+\]$/;
const UTF8_BOM = new Uint8Array([0xef, 0xbb, 0xbf]);

/**
 * Sensitive field names beyond the privacy layer's `keyType` dictionary (normalised: lower-case
 * ASCII letters/digits only). Suffix matches catch `db_password`, `github_token`, ...
 */
const EXTRA_SENSITIVE_KEYS: Readonly<Record<string, EntityType>> = {
	token: "SECRET",
	authtoken: "SECRET",
	bearertoken: "SECRET",
	idtoken: "SECRET",
	sessiontoken: "SECRET",
	sessionid: "SECRET",
	csrftoken: "SECRET",
	apisecret: "SECRET",
	secretkey: "SECRET",
	accesskey: "SECRET",
	accesskeyid: "SECRET",
	secretaccesskey: "SECRET",
	passphrase: "SECRET",
	credential: "SECRET",
	credentials: "SECRET",
	connectionstring: "SECRET",
	cvv: "SECRET",
	cvc: "SECRET",
	pin: "SECRET",
	otp: "SECRET",
	tckimliknumarasi: "TC_KIMLIK",
	ibanno: "IBAN",
};
const SENSITIVE_KEY_SUFFIXES: ReadonlyArray<readonly [string, EntityType]> = [
	["password", "SECRET"],
	["passwd", "SECRET"],
	["secret", "SECRET"],
	["secretkey", "SECRET"],
	["token", "SECRET"],
	["apikey", "SECRET"],
	["accesskey", "SECRET"],
	["privatekey", "PRIVATE_KEY"],
];
/** Field names too generic to force-mask in JSON (`"name": "my-package"`); CSV columns still use them. */
const AMBIGUOUS_JSON_KEYS: ReadonlySet<string> = new Set(["name", "ad", "tc"]);

function normaliseKey(key: string): string {
	return key
		.normalize("NFKD")
		.replace(/\p{M}/gu, "")
		.replace(/[ıİ]/g, "i")
		.toLowerCase()
		.replace(/[^a-z0-9]/g, "");
}

/**
 * Entity type implied by a field name (JSON key / CSV header), or undefined.
 * Reuses the AIDR Privacy dictionary and adds credential-style keys and suffixes.
 */
export function sensitiveKeyType(key: string, ambiguousAllowed = true): EntityType | undefined {
	const k = normaliseKey(key);
	if (!k || k.length > 64) return undefined;
	if (!ambiguousAllowed && AMBIGUOUS_JSON_KEYS.has(k)) return undefined;
	const direct = keyType(key) ?? EXTRA_SENSITIVE_KEYS[k];
	if (direct) return direct;
	for (const [suffix, type] of SENSITIVE_KEY_SUFFIXES) if (k.endsWith(suffix)) return type;
	return undefined;
}

// ---------------------------------------------------------------------------------------------
// Classification and decoding
// ---------------------------------------------------------------------------------------------

function baseName(name: string): string {
	const parts = name.split(/[\\/]/);
	return (parts[parts.length - 1] ?? "").trim().toLowerCase();
}

function isEnvFileName(base: string): boolean {
	return base === ".env" || base.startsWith(".env.") || base.endsWith(".env");
}

function extensionOf(base: string): string {
	const dot = base.lastIndexOf(".");
	return dot > 0 ? base.slice(dot + 1) : "";
}

interface DecodedText {
	readonly text: string;
	readonly bom: boolean;
	/** Single-byte code page the text was decoded from (legacy fallback), if any. */
	readonly legacy?: "windows-1254" | "windows-1252";
}

/** MIME types that declare text content (parameters such as `; charset=` are ignored). */
const TEXT_MIME =
	/^(?:text\/[\w.+-]+|application\/(?:json|x-ndjson|ndjson|jsonl|xml|csv|x-csv|yaml|x-yaml|toml|x-toml|javascript|x-javascript|ecmascript|x-sh|x-shellscript|sql|x-sql|graphql|[\w.-]+\+(?:json|xml)))\s*(?:;|$)/i;

/** Legacy single-byte code pages tried, in order, for text files that are not UTF-8. */
const LEGACY_ENCODINGS = ["windows-1254", "windows-1252"] as const;

/** Strict decode: UTF-8 (BOM aware) or BOM-marked UTF-16. Null for invalid bytes or any NUL. */
export function decodeTextFile(bytes: Uint8Array): DecodedText | null {
	let encoding = "utf-8";
	let bom = false;
	if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) bom = true;
	else if (bytes[0] === 0xff && bytes[1] === 0xfe) {
		encoding = "utf-16le";
		bom = true;
	} else if (bytes[0] === 0xfe && bytes[1] === 0xff) {
		encoding = "utf-16be";
		bom = true;
	}
	let text: string;
	try {
		// ignoreBOM: false (default) strips the matching BOM from the decoded text.
		text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
	} catch {
		return null;
	}
	if (text.includes("\u0000")) return null;
	return { text, bom };
}

const C1_CONTROL = /[\u0080-\u009f]/g;

/**
 * Single-byte fallback for text files that are not UTF-8: windows-1254, or windows-1252
 * when it leaves fewer undefined bytes (decoded as C1 controls). Null when the bytes hold
 * a NUL (not a single-byte text file) or no legacy decoder is available.
 */
export function decodeLegacyTextFile(bytes: Uint8Array): DecodedText | null {
	if (bytes.includes(0)) return null;
	let best: DecodedText | null = null;
	let bestControls = Number.POSITIVE_INFINITY;
	for (const encoding of LEGACY_ENCODINGS) {
		let text: string;
		try {
			text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
		} catch {
			continue; // decoder unavailable in this runtime (or it rejected the bytes)
		}
		const controls = text.match(C1_CONTROL)?.length ?? 0;
		if (controls < bestControls) {
			best = { text, bom: false, legacy: encoding };
			bestControls = controls;
		}
	}
	return best;
}

const UNDECODABLE_TEXT = Symbol("UNDECODABLE_TEXT");

/**
 * Strict UTF-8/UTF-16 decode; for a declared text file that fails it, the legacy
 * single-byte fallback, or UNDECODABLE_TEXT. Null: not text (classified as binary).
 */
function decodeUpload(file: GuardFile): DecodedText | null | typeof UNDECODABLE_TEXT {
	const strict = decodeTextFile(file.bytes);
	if (strict || !isDeclaredText(file)) return strict;
	return decodeLegacyTextFile(file.bytes) ?? UNDECODABLE_TEXT;
}

/** Known text extension, dotenv name, or a MIME type that declares text. */
export function isDeclaredText(file: Pick<GuardFile, "name" | "type">): boolean {
	const base = baseName(file.name);
	const ext = extensionOf(base);
	if (BINARY_EXTENSIONS.has(ext)) return false;
	return isEnvFileName(base) || TEXT_EXTENSIONS[ext] !== undefined || TEXT_MIME.test(file.type);
}

function classify(file: GuardFile, decoded: DecodedText | null): TextKind | "binary" {
	const base = baseName(file.name);
	const ext = extensionOf(base);
	if (BINARY_EXTENSIONS.has(ext)) return "binary";
	if (!decoded) return "binary";
	if (isEnvFileName(base)) return "env";
	const known = TEXT_EXTENSIONS[ext];
	if (known) return known;
	if (BINARY_MIME.test(file.type)) return "binary";
	return "text";
}

// ---------------------------------------------------------------------------------------------
// Scanning helpers
// ---------------------------------------------------------------------------------------------

class ScanIncomplete extends Error {}

interface TextScan {
	readonly findings: readonly Finding[];
	readonly signals: ReadonlySet<SignalCode>;
}

function isValidFinding(f: Finding, length: number): boolean {
	return (
		Number.isInteger(f.start) &&
		Number.isInteger(f.end) &&
		f.start >= 0 &&
		f.end > f.start &&
		f.end <= length
	);
}

/** Sorted, non-overlapping findings; overlapping ones are unioned, keeping the strongest type. */
export function mergeFindings(findings: readonly Finding[], length: number): Finding[] {
	const sorted = findings
		.filter((f) => isValidFinding(f, length))
		.sort((a, b) => a.start - b.start || b.end - a.end);
	const out: Finding[] = [];
	for (const f of sorted) {
		const last = out[out.length - 1];
		if (last && f.start < last.end) {
			const stronger =
				f.score > last.score || (f.score === last.score && f.end - f.start > last.end - last.start);
			const winner = stronger ? f : last;
			out[out.length - 1] = { ...winner, start: last.start, end: Math.max(last.end, f.end) };
		} else out.push(f);
	}
	return out;
}

function isLowSurrogateAt(text: string, i: number): boolean {
	const c = text.charCodeAt(i);
	return c >= 0xdc00 && c <= 0xdfff;
}

async function scanChunked(
	engine: DetectionEngine,
	text: string,
	size: number,
): Promise<TextScan | null> {
	const overlap = Math.floor(size / 4);
	const findings: Finding[] = [];
	const signals = new Set<SignalCode>();
	let start = 0;
	while (start < text.length) {
		let end = Math.min(text.length, start + size);
		if (end < text.length && isLowSurrogateAt(text, end)) end--;
		const result = await engine.scan(text.slice(start, end));
		if (result.incomplete) return null;
		for (const f of result.findings)
			findings.push({ ...f, start: f.start + start, end: f.end + start });
		for (const s of result.signals) signals.add(s);
		if (end >= text.length) break;
		let next = end - overlap;
		if (isLowSurrogateAt(text, next)) next--;
		start = Math.max(next, start + 1);
	}
	return { findings, signals };
}

/**
 * Scans the whole text; if the engine reports an incomplete scan, retries in overlapping windows
 * of decreasing size. Throws {@link ScanIncomplete} when no window size completes.
 */
async function scanText(engine: DetectionEngine, text: string): Promise<TextScan> {
	if (!text) return { findings: [], signals: new Set() };
	const whole = await engine.scan(text);
	if (!whole.incomplete) return { findings: whole.findings, signals: new Set(whole.signals) };
	for (const size of CHUNK_SIZES) {
		if (size >= text.length) continue;
		const chunked = await scanChunked(engine, text, size);
		if (chunked) return chunked;
	}
	throw new ScanIncomplete();
}

interface Segment {
	/** Detection context (field name / column header) scanned in front of the value. */
	readonly context: string;
	readonly value: string;
}

/** Binary search over sorted, disjoint ranges: first index whose end is past `pos`. */
function firstRangeEndingAfter(
	ranges: ReadonlyArray<readonly [number, number]>,
	pos: number,
): number {
	let lo = 0;
	let hi = ranges.length;
	while (lo < hi) {
		const mid = (lo + hi) >> 1;
		if ((ranges[mid]?.[1] ?? 0) <= pos) lo = mid + 1;
		else hi = mid;
	}
	return lo;
}

/**
 * Scans many small values in one batch (`context: value` joined by blank lines) and maps the
 * findings back onto each value. Findings that straddle a value boundary are clipped to the
 * part inside the value, so they over-mask rather than leak.
 */
async function scanSegments(
	engine: DetectionEngine,
	segments: readonly Segment[],
): Promise<{ perSegment: Finding[][]; signals: ReadonlySet<SignalCode> }> {
	const ranges: Array<readonly [number, number]> = [];
	let combined = "";
	for (const seg of segments) {
		if (combined) combined += SEGMENT_SEPARATOR;
		if (seg.context) combined += `${seg.context}: `;
		ranges.push([combined.length, combined.length + seg.value.length]);
		combined += seg.value;
	}
	const perSegment: Finding[][] = segments.map(() => []);
	const scan = await scanText(engine, combined);
	for (const f of scan.findings) {
		if (isValidFinding(f, combined.length)) distributeFinding(f, ranges, perSegment);
	}
	return { perSegment, signals: scan.signals };
}

/** Clips a finding in the combined text onto every segment range it overlaps. */
function distributeFinding(
	f: Finding,
	ranges: ReadonlyArray<readonly [number, number]>,
	perSegment: Finding[][],
): void {
	for (let i = firstRangeEndingAfter(ranges, f.start); i < ranges.length; i++) {
		const range = ranges[i];
		if (!range || range[0] >= f.end) break;
		const start = Math.max(f.start, range[0]) - range[0];
		const end = Math.min(f.end, range[1]) - range[0];
		if (end > start) perSegment[i]?.push({ ...f, start, end });
	}
}

function addCounts(target: Counts, source: Readonly<Counts>): void {
	for (const [type, n] of Object.entries(source) as Array<[EntityType, number | undefined]>) {
		if (n) target[type] = (target[type] ?? 0) + n;
	}
}

function countFindings(findings: readonly Finding[]): Counts {
	const counts: Counts = {};
	for (const f of findings) counts[f.type] = (counts[f.type] ?? 0) + 1;
	return counts;
}

function wholeValueFinding(value: string, type: EntityType): Finding | null {
	if (!value.trim() || PLACEHOLDER_ONLY.test(value.trim())) return null;
	return { type, start: 0, end: value.length, score: 1, source: "rule" };
}

// ---------------------------------------------------------------------------------------------
// Format handlers. Each returns the (possibly) rewritten text plus bookkeeping.
// ---------------------------------------------------------------------------------------------

interface Outcome {
	readonly output: string;
	readonly changed: boolean;
	readonly counts: Counts;
	/** Findings before masking (used for counts when the file ends up blocked). */
	readonly findings: number;
	readonly findingCounts: Counts;
	readonly signals: ReadonlySet<SignalCode>;
	readonly formulaCells: number;
}

interface Ctx {
	readonly engine: DetectionEngine;
	readonly vault: PlaceholderVault;
	readonly enabled: ReadonlySet<EntityType>;
}

/** Masks `value` with `findings`; returns the value unchanged when there is nothing to mask. */
function maskValue(ctx: Ctx, value: string, findings: readonly Finding[], counts: Counts): string {
	const merged = mergeFindings(findings, value.length);
	if (!merged.length) return value;
	const result = ctx.vault.mask(value, merged);
	addCounts(counts, result.counts);
	return result.masked;
}

async function handlePlainText(
	ctx: Ctx,
	text: string,
	forced: readonly Finding[] = [],
): Promise<Outcome> {
	const scan = await scanText(ctx.engine, text);
	const findings = mergeFindings([...scan.findings, ...forced], text.length);
	const counts: Counts = {};
	const output = maskValue(ctx, text, findings, counts);
	return {
		output,
		changed: output !== text,
		counts,
		findings: findings.length,
		findingCounts: countFindings(findings),
		signals: scan.signals,
		formulaCells: 0,
	};
}

// --- .env ------------------------------------------------------------------------------------

const ENV_ASSIGNMENT = /^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_.-]*[ \t]*=[ \t]*/;

/** Closing-quote index of a dotenv quoted value opening at `open`, or -1 when unterminated. */
function envClosingQuote(text: string, open: number): number {
	const quote = text[open];
	let i = open + 1;
	while (i < text.length && text[i] !== quote) i += text[i] === "\\" && quote !== "'" ? 2 : 1;
	return i < text.length ? i : -1;
}

/** Unquoted value length: up to a ` #comment`, without trailing whitespace. */
function envUnquotedLength(rest: string): number {
	const comment = /[ \t]#/.exec(rest);
	return (comment ? rest.slice(0, comment.index) : rest).replace(/[ \t\r]+$/, "").length;
}

/** Value spans (UTF-16 offsets into `text`) of every `KEY=value` assignment in a dotenv file. */
export function envValueSpans(text: string): Array<readonly [number, number]> {
	const spans: Array<readonly [number, number]> = [];
	let pos = 0;
	while (pos < text.length) pos = envLine(text, pos, spans);
	return spans;
}

/** Parses the dotenv line starting at `pos`, records its value span, returns the next line start. */
function envLine(text: string, pos: number, spans: Array<readonly [number, number]>): number {
	const newline = text.indexOf("\n", pos);
	const eol = newline < 0 ? text.length : newline;
	const line = text.slice(pos, eol);
	const m = ENV_ASSIGNMENT.exec(line);
	if (!m) return eol + 1;
	const valueStart = pos + m[0].length;
	const close = /["'`]/.test(text[valueStart] ?? "") ? envClosingQuote(text, valueStart) : -1;
	if (close < 0) {
		const length = envUnquotedLength(line.slice(m[0].length));
		if (length > 0) spans.push([valueStart, valueStart + length]);
		return eol + 1;
	}
	// Quoted values may span lines; resume after the line holding the closing quote.
	if (close > valueStart + 1) spans.push([valueStart + 1, close]);
	const closeEol = text.indexOf("\n", close);
	return closeEol < 0 ? text.length : closeEol + 1;
}

async function handleEnv(ctx: Ctx, text: string): Promise<Outcome> {
	const forced: Finding[] = [];
	for (const [start, end] of envValueSpans(text)) {
		const value = text.slice(start, end);
		if (PLACEHOLDER_ONLY.test(value)) continue;
		forced.push({ type: "SECRET", start, end, score: 1, source: "rule" });
	}
	return handlePlainText(ctx, text, forced);
}

// --- CSV / TSV -------------------------------------------------------------------------------

export interface CsvCell {
	value: string;
	quoted: boolean;
}
export interface CsvRow {
	readonly cells: CsvCell[];
	/** Original line terminator ("\r\n", "\n", "\r", or "" for a final unterminated row). */
	readonly eol: string;
}

/**
 * Lenient RFC 4180 parser that never throws: quoted fields with `""` escapes and embedded
 * newlines, CRLF/LF/CR row endings, ragged rows. Characters after a closing quote are kept
 * literally (spreadsheet behaviour); an unterminated quote runs to end of input.
 */
export function parseDelimitedLenient(text: string, delimiter: "," | "\t"): CsvRow[] {
	const rows: CsvRow[] = [];
	let cells: CsvCell[] = [];
	let i = 0;
	const n = text.length;
	while (i < n) {
		const quoted = text[i] === '"';
		let value = "";
		if (quoted) [value, i] = readQuotedField(text, i);
		const rawEnd = unquotedFieldEnd(text, i, delimiter);
		value += text.slice(i, rawEnd);
		i = rawEnd;
		cells.push({ value, quoted });
		if (text[i] === delimiter) {
			i++;
			// A trailing delimiter still opens one last (empty) cell.
			if (i >= n) cells.push({ value: "", quoted: false });
			continue;
		}
		const eol = lineEndingAt(text, i);
		i += eol.length;
		rows.push({ cells, eol });
		cells = [];
	}
	if (cells.length) rows.push({ cells, eol: "" });
	return rows;
}

/** Index of the next delimiter or line break at or after `from` (or end of text). */
function unquotedFieldEnd(text: string, from: number, delimiter: "," | "\t"): number {
	let i = from;
	while (i < text.length && text[i] !== delimiter && text[i] !== "\n" && text[i] !== "\r") i++;
	return i;
}

/** The line terminator at `i` ("\r\n", "\n", "\r"), or "" at end of text. */
function lineEndingAt(text: string, i: number): string {
	if (i >= text.length) return "";
	return text[i] === "\r" && text[i + 1] === "\n" ? "\r\n" : (text[i] as string);
}

/** Reads a quoted field opening at `open`; returns the unescaped value and the index after it. */
function readQuotedField(text: string, open: number): [string, number] {
	let value = "";
	let i = open + 1;
	while (i < text.length) {
		if (text[i] !== '"') value += text[i++];
		else if (text[i + 1] === '"') {
			value += '"';
			i += 2;
		} else return [value, i + 1];
	}
	return [value, i];
}

export function serializeDelimitedPreserving(
	rows: readonly CsvRow[],
	delimiter: "," | "\t",
): string {
	let out = "";
	for (const row of rows) {
		out += row.cells
			.map((cell) => {
				const needsQuote =
					cell.quoted ||
					cell.value.includes(delimiter) ||
					cell.value.includes('"') ||
					cell.value.includes("\n") ||
					cell.value.includes("\r");
				return needsQuote ? `"${cell.value.replace(/"/g, '""')}"` : cell.value;
			})
			.join(delimiter);
		out += row.eol;
	}
	return out;
}

const FORMULA_START = /^(?:[=+\-@\t\r]|[\s​-‏⁠﻿]+[=+\-@])/u;
const PLAIN_NUMBER = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;

/** True when a spreadsheet would treat the cell as a formula (plain signed numbers excluded). */
export function isFormulaCell(value: string): boolean {
	return FORMULA_START.test(value) && !PLAIN_NUMBER.test(value);
}

async function handleDelimited(ctx: Ctx, text: string, delimiter: "," | "\t"): Promise<Outcome> {
	const rows = parseDelimitedLenient(text, delimiter);
	const headers = rows[0]?.cells.map((c) => c.value) ?? [];
	const columnTypes = headers.map((h) => {
		const type = sensitiveKeyType(h, true);
		return type && ctx.enabled.has(type) ? type : undefined;
	});
	const segments: Segment[] = [];
	const cellRefs: CsvCell[] = [];
	const forcedTypes: Array<EntityType | undefined> = [];
	rows.forEach((row, r) => {
		row.cells.forEach((cell, c) => {
			if (!cell.value) return;
			segments.push({ context: r === 0 ? "" : (headers[c] ?? ""), value: cell.value });
			cellRefs.push(cell);
			forcedTypes.push(r === 0 ? undefined : columnTypes[c]);
		});
	});
	const { perSegment, signals } = await scanSegments(ctx.engine, segments);
	const counts: Counts = {};
	const findingCounts: Counts = {};
	let findings = 0;
	let changed = false;
	cellRefs.forEach((cell, i) => {
		const forcedType = forcedTypes[i];
		const forced = forcedType ? wholeValueFinding(cell.value, forcedType) : null;
		const cellFindings = mergeFindings(
			[...(perSegment[i] ?? []), ...(forced ? [forced] : [])],
			cell.value.length,
		);
		if (!cellFindings.length) return;
		findings += cellFindings.length;
		addCounts(findingCounts, countFindings(cellFindings));
		const masked = maskValue(ctx, cell.value, cellFindings, counts);
		if (masked !== cell.value) {
			cell.value = masked;
			changed = true;
		}
	});
	let formulaCells = 0;
	for (const row of rows) {
		for (const cell of row.cells) {
			if (isFormulaCell(cell.value)) {
				cell.value = `'${cell.value}`;
				formulaCells++;
				changed = true;
			}
		}
	}
	return {
		output: changed ? serializeDelimitedPreserving(rows, delimiter) : text,
		changed,
		counts,
		findings,
		findingCounts,
		signals,
		formulaCells,
	};
}

// --- JSON / JSONL ----------------------------------------------------------------------------

export interface JsonLeaf {
	/** Raw token span in the source (a string token includes its quotes). */
	readonly start: number;
	readonly end: number;
	readonly kind: "string" | "number" | "key";
	readonly value: string;
	/** Nearest enclosing object key (inherited through arrays), or "" at top level. */
	readonly key: string;
}

interface Frame {
	readonly array: boolean;
	key: string;
	expectKey: boolean;
}

const NUMBER_TOKEN = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

/**
 * Lists string/number leaves and object keys of an already-validated JSON document with their
 * raw source spans, so values can be rewritten in place without re-serialising the document.
 */
export function jsonLeaves(text: string, offset = 0, end = text.length): JsonLeaf[] {
	const leaves: JsonLeaf[] = [];
	const stack: Frame[] = [];
	let i = offset;
	while (i < end) {
		const c = text[i] as string;
		const top = stack[stack.length - 1];
		if (c === '"') i = readJsonString(text, i, end, top, leaves);
		else if (c === "-" || (c >= "0" && c <= "9")) i = readJsonNumber(text, i, top, leaves);
		else {
			applyJsonPunctuation(stack, c);
			i++;
		}
	}
	return leaves;
}

/** Records the string token (object key or value) opening at `i`; returns the index after it. */
function readJsonString(
	text: string,
	i: number,
	end: number,
	top: Frame | undefined,
	leaves: JsonLeaf[],
): number {
	const close = stringTokenEnd(text, i, end);
	const value = JSON.parse(text.slice(i, close)) as string;
	const isKey = top !== undefined && !top.array && top.expectKey;
	leaves.push({
		start: i,
		end: close,
		kind: isKey ? "key" : "string",
		value,
		key: isKey ? "" : (top?.key ?? ""),
	});
	if (isKey) top.key = value;
	return close;
}

/** Records the number token starting at `i`; returns the index after it. */
function readJsonNumber(
	text: string,
	i: number,
	top: Frame | undefined,
	leaves: JsonLeaf[],
): number {
	NUMBER_TOKEN.lastIndex = i;
	const len = NUMBER_TOKEN.exec(text)?.[0].length || 1;
	leaves.push({
		start: i,
		end: i + len,
		kind: "number",
		value: text.slice(i, i + len),
		key: top?.key ?? "",
	});
	return i + len;
}

/** Index just past the closing quote of the string token opening at `open`. */
function stringTokenEnd(text: string, open: number, end: number): number {
	let j = open + 1;
	while (j < end && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
	return j + 1;
}

function applyJsonPunctuation(stack: Frame[], c: string): void {
	const top = stack[stack.length - 1];
	if (c === "{" || c === "[")
		stack.push({ array: c === "[", key: top?.key ?? "", expectKey: c === "{" });
	else if (c === "}" || c === "]") stack.pop();
	else if (c === "," && top && !top.array) top.expectKey = true;
	else if (c === ":" && top) top.expectKey = false;
}

/** Top-level JSON documents as [start, end) spans, or null if the text is not valid JSON/JSONL. */
function jsonDocuments(
	text: string,
	kind: "json" | "jsonl",
): Array<readonly [number, number]> | null {
	try {
		if (kind === "json") {
			JSON.parse(text);
			return [[0, text.length]];
		}
		const docs: Array<readonly [number, number]> = [];
		let pos = 0;
		while (pos <= text.length) {
			let eol = text.indexOf("\n", pos);
			if (eol < 0) eol = text.length;
			const line = text.slice(pos, eol);
			if (line.trim()) {
				JSON.parse(line);
				docs.push([pos, eol]);
			}
			pos = eol + 1;
		}
		return docs.length ? docs : null;
	} catch {
		return null;
	}
}

async function handleJson(ctx: Ctx, text: string, kind: "json" | "jsonl"): Promise<Outcome> {
	const docs = jsonDocuments(text, kind);
	if (!docs) return handlePlainText(ctx, text);
	const leaves = docs.flatMap(([start, end]) => jsonLeaves(text, start, end));
	const { perSegment, signals } = await scanSegments(
		ctx.engine,
		leaves.map((leaf) => ({ context: leaf.kind === "key" ? "" : leaf.key, value: leaf.value })),
	);
	const counts: Counts = {};
	const findingCounts: Counts = {};
	let findings = 0;
	const replacements: Array<{ start: number; end: number; raw: string }> = [];
	leaves.forEach((leaf, i) => {
		let forced: Finding | null = null;
		if (leaf.kind !== "key" && leaf.key) {
			const type = sensitiveKeyType(leaf.key, false);
			if (type && ctx.enabled.has(type)) forced = wholeValueFinding(leaf.value, type);
		}
		const leafFindings = mergeFindings(
			[...(perSegment[i] ?? []), ...(forced ? [forced] : [])],
			leaf.value.length,
		);
		if (!leafFindings.length) return;
		findings += leafFindings.length;
		addCounts(findingCounts, countFindings(leafFindings));
		const masked = maskValue(ctx, leaf.value, leafFindings, counts);
		if (masked !== leaf.value)
			replacements.push({ start: leaf.start, end: leaf.end, raw: JSON.stringify(masked) });
	});
	let output = text;
	for (const r of replacements.sort((a, b) => b.start - a.start))
		output = output.slice(0, r.start) + r.raw + output.slice(r.end);
	// Structural invariant: masking only swaps leaf tokens for JSON string literals.
	if (jsonDocuments(output, kind)?.length !== docs.length) throw new Error("JSON_MASK_INVALID");
	return {
		output,
		changed: output !== text,
		counts,
		findings,
		findingCounts,
		signals,
		formulaCells: 0,
	};
}

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

function block(reasons: readonly string[], counts: Readonly<Counts> = {}): FileDecision {
	return { action: "block", counts, reasons };
}

/** MIME type of a re-encoded (UTF-8) copy: a declared charset parameter becomes utf-8. */
function utf8MimeType(type: string): string {
	return type.replace(/(;\s*charset\s*=\s*)(?:"[^"]*"|[^;\s]*)/i, "$1utf-8");
}

function encodeOutput(text: string, bom: boolean): Uint8Array {
	const body = new TextEncoder().encode(text);
	if (!bom) return body;
	const out = new Uint8Array(UTF8_BOM.length + body.length);
	out.set(UTF8_BOM, 0);
	out.set(body, UTF8_BOM.length);
	return out;
}

/**
 * Decide what happens to an uploaded/dropped/pasted file. See the module comment for the full
 * decision table. Never throws: internal errors block (`FILE_SCAN_ERROR`).
 */
export async function sanitizeFile(file: GuardFile, deps: SanitizeDeps): Promise<FileDecision> {
	const { engine, vault, policy } = deps;
	try {
		if (policy.fileHandling === "allow") return { action: "allow", counts: {}, reasons: [] };
		if (policy.fileHandling !== "scan") return block(["FILE_BLOCKED_BY_POLICY"]);
		if (!(file.bytes.length <= policy.maxFileBytes)) return block(["FILE_TOO_LARGE"]);

		const decoded = decodeUpload(file);
		if (decoded === UNDECODABLE_TEXT) {
			// A text file that cannot be decoded must never pass through unscanned.
			return policy.mode === "monitor"
				? { action: "allow", counts: {}, reasons: ["TEXT_FILE_NOT_DECODABLE"] }
				: block(["TEXT_FILE_NOT_DECODABLE"]);
		}
		const kind = classify(file, decoded);
		if (kind === "binary" || !decoded) {
			return policy.mode === "block"
				? block(["BINARY_FILE_UNSCANNABLE"])
				: { action: "allow", counts: {}, reasons: ["BINARY_FILE_UNSCANNED"] };
		}
		const ctx: Ctx = { engine, vault, enabled: new Set(policy.enabledEntities) };
		const outcome = await runHandler(ctx, kind, decoded.text);
		return decide(file, decoded, kind, outcome, policy);
	} catch (error) {
		return block([error instanceof ScanIncomplete ? "SCAN_INCOMPLETE" : "FILE_SCAN_ERROR"]);
	}
}

function runHandler(ctx: Ctx, kind: TextKind, text: string): Promise<Outcome> {
	switch (kind) {
		case "csv":
			return handleDelimited(ctx, text, ",");
		case "tsv":
			return handleDelimited(ctx, text, "\t");
		case "json":
		case "jsonl":
			return handleJson(ctx, text, kind);
		case "env":
			return handleEnv(ctx, text);
		default:
			return handlePlainText(ctx, text);
	}
}

function decide(
	file: GuardFile,
	decoded: DecodedText,
	kind: TextKind,
	outcome: Outcome,
	policy: GuardPolicy,
): FileDecision {
	const signalReasons =
		policy.signalAction === "off" ? [] : [...outcome.signals].sort().map((s) => `SIGNAL_${s}`);
	if (signalReasons.length && policy.signalAction === "block")
		return block(signalReasons, outcome.findingCounts);

	const reasons: string[] = [];
	if (outcome.findings > 0) reasons.push("SENSITIVE_DATA");
	if (outcome.formulaCells > 0) reasons.push("FORMULA_CELL");
	reasons.push(...signalReasons);
	if (!outcome.changed) return { action: "allow", counts: outcome.findingCounts, reasons };
	// Legacy code-page input is re-encoded as UTF-8; delimited files get a BOM so that
	// spreadsheet tools do not read the new encoding as the ANSI code page.
	const legacy = decoded.legacy !== undefined;
	const bom = decoded.bom || (legacy && (kind === "csv" || kind === "tsv"));
	return {
		action: "mask",
		masked: {
			name: file.name,
			type: legacy ? utf8MimeType(file.type) : file.type,
			bytes: encodeOutput(outcome.output, bom),
		},
		counts: outcome.counts,
		reasons,
	};
}
