/**
 * Optional bridge to the AIDR Privacy native host (`com.singularity.aidr_privacy`,
 * shipped by packages/privacy). The host adds learned NER (PERSON / ADDRESS /
 * LOCATION in free text) on top of the rule layer Browser Guard already runs in the
 * page. Without the host every scan still works rules-only: `scanText` resolves to
 * `null` and callers keep their local findings.
 *
 * Protocol (packages/privacy/src/native/session.ts, one document per host process):
 *   hello  -> {protocol:1, local:true, ocr, policyId, policyDigest}
 *   begin  {kind:"text", size, sha256, policyDigest} -> {}
 *   write  {offset, data:base64(<=192 KiB)}           -> {received}
 *   commit                                            -> {decision, reasons, counts, outputBytes, sha256, ...}
 *   read   {offset}                                   -> {offset, data, done}
 * Every request carries `{v:1, id, op}`; every response echoes `{v:1, id, ok:true}`.
 * The host returns a sanitised copy of the text, not spans, so findings are recovered
 * by aligning the host output (literal text + `[TYPE]` markers) against the input.
 *
 * Images (`scanImage`, only when hello reports `ocr: true`):
 *   begin  {kind:"image-scan", size, sha256, policyDigest} -> {}
 *   write  ... as above
 *   commit -> {decision: allow|block|review, reasons, counts, coverage, outputBytes: 0}
 * The host OCRs the image and runs the text engine over it; nothing is read back (no pixels,
 * no OCR text): the reply is a decision plus per-type counts.
 *
 * Privacy: only the text passed to `scanText` is sent, nothing is persisted, and
 * transfer buffers are zeroed after use. The host is local stdio (no network).
 */
import {
	CHUNK_BYTES,
	fromBase64,
	sha256,
	toBase64,
} from "../../../privacy/src/browser/transport.js";
import {
	ENTITY_TYPES,
	type EntityType,
	type Finding,
	type ImageInspection,
	type NativeBridge,
} from "../types.js";

export const NATIVE_HOST_NAME = "com.singularity.aidr_privacy";
/** Upper bound for one complete scan exchange (connect, handshake, upload, commit, read). */
export const NATIVE_TIMEOUT_MS = 2_000;
/** After repeated failures (or a failed probe) the host is not contacted for this long. */
export const NATIVE_RETRY_AFTER_MS = 60_000;
/** Consecutive scan failures that mark the host unavailable. */
export const NATIVE_MAX_FAILURES = 3;
/** Host `begin` limit for kind "image-scan" (NativeSession). */
export const NATIVE_MAX_IMAGE_BYTES = 8_388_608;
/** Upper bound for one OCR exchange (upload, OCR - the host's own OCR timeout is 45 s - commit). */
const NATIVE_IMAGE_TIMEOUT_MS = 60_000;
/** Host `begin` limit for kind "text" (NativeSession). */
const NATIVE_MAX_TEXT_BYTES = 1_048_576;
/** protectDocument refuses to emit more than twice its input limit. */
const MAX_OUTPUT_BYTES = 2 * NATIVE_MAX_TEXT_BYTES;
/** The host does not export per-span scores; its redactions are policy decisions. */
const NATIVE_FINDING_SCORE = 0.9;
/** Each scan starts its own host process; cap concurrent processes. */
const MAX_IN_FLIGHT = 2;

const HEX64 = /^[a-f0-9]{64}$/;
const REASON_CODE = /^[A-Z0-9_]{1,64}$/;
/** Host reasons that mean the engine itself failed (not a policy outcome). */
const ENGINE_FAILURE_REASON = /^(?:NER_[A-Z0-9_]+|SCAN_BUDGET|CONCURRENCY_LIMIT|DISPOSED)$/;
const TYPE_ALTERNATION = ENTITY_TYPES.join("|");
/** `[TYPE]` (label), `[TYPE~keyId~token]` (token) and `[REDACTED]` (redact) markers. */
const MARKER_SOURCE = `\\[(?:(${TYPE_ALTERNATION})(?:~[A-Za-z0-9_.-]{1,32}~[A-Za-z0-9_-]{24})?|REDACTED)\\]`;

interface NativeEvent<T extends (...args: never[]) => void> {
	addListener(listener: T): void;
}

export interface NativePort {
	postMessage(message: unknown): void;
	disconnect(): void;
	readonly onMessage: NativeEvent<(message: unknown) => void>;
	readonly onDisconnect: NativeEvent<() => void>;
}

/** The subset of the WebExtension API this bridge uses. */
export interface NativeChromeApi {
	readonly runtime?: {
		connectNative?(application: string): NativePort;
		sendNativeMessage?(application: string, message: object): Promise<unknown>;
		readonly lastError?: unknown;
	};
	readonly permissions?: {
		contains?(permissions: { permissions: string[] }): Promise<boolean>;
	};
}

export interface NativeBridgeOptions {
	/** Defaults to `globalThis.chrome`, resolved on each use. */
	readonly chrome?: NativeChromeApi;
	readonly timeoutMs?: number;
	readonly imageTimeoutMs?: number;
	readonly retryAfterMs?: number;
	readonly now?: () => number;
}

type Json = Record<string, unknown>;

interface Hello {
	readonly policyDigest: string;
	readonly ocr: boolean;
}

interface Commit {
	readonly decision: "allow" | "redact" | "review" | "block";
	readonly reasons: readonly string[];
	readonly counts: Readonly<Partial<Record<EntityType, number>>>;
	readonly outputBytes: number;
	readonly sha256: string | undefined;
}

/** `failure` counts towards backoff; `unmapped` is a healthy host that produced no spans. */
type Outcome =
	| { readonly kind: "findings"; readonly findings: readonly Finding[] }
	| { readonly kind: "unmapped" }
	| { readonly kind: "failure" };

/** `unavailable`: a healthy host without OCR. */
type ImageOutcome =
	| { readonly kind: "inspection"; readonly inspection: ImageInspection }
	| { readonly kind: "unavailable" }
	| { readonly kind: "failure" };

const FAILURE = Object.freeze({ kind: "failure" as const });

class ProtocolError extends Error {
	constructor() {
		super("NATIVE_PROTOCOL_INVALID");
	}
}

function invalid(): never {
	throw new ProtocolError();
}

function isRecord(value: unknown): value is Json {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Json, allowed: readonly string[]): void {
	for (const key of Object.keys(value)) {
		if (key !== "v" && key !== "id" && key !== "ok" && !allowed.includes(key)) invalid();
	}
}

function isEntityType(value: unknown): value is EntityType {
	return typeof value === "string" && (ENTITY_TYPES as readonly string[]).includes(value);
}

/** True when the string has no lone surrogates (UTF-8 encoding would be lossy). */
function isWellFormed(text: string): boolean {
	for (let i = 0; i < text.length; i++) {
		const c = text.charCodeAt(i);
		if (c >= 0xd800 && c <= 0xdbff) {
			const next = text.charCodeAt(i + 1);
			if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
			i++;
		} else if (c >= 0xdc00 && c <= 0xdfff) {
			return false;
		}
	}
	return true;
}

function parseHello(m: Json): Hello {
	onlyKeys(m, ["protocol", "local", "ocr", "policyId", "policyDigest"]);
	if (m.protocol !== 1 || m.local !== true || typeof m.ocr !== "boolean") invalid();
	if (typeof m.policyId !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(m.policyId)) invalid();
	if (typeof m.policyDigest !== "string" || !HEX64.test(m.policyDigest)) invalid();
	return { policyDigest: m.policyDigest, ocr: m.ocr };
}

function parseCounts(value: unknown): Partial<Record<EntityType, number>> {
	if (!isRecord(value)) invalid();
	const counts: Partial<Record<EntityType, number>> = {};
	for (const [key, n] of Object.entries(value)) {
		if (!isEntityType(key) || !Number.isSafeInteger(n) || (n as number) < 0) invalid();
		counts[key] = n as number;
	}
	return counts;
}

const DECISIONS: readonly Commit["decision"][] = ["allow", "redact", "review", "block"];

function parseReasons(value: unknown): string[] {
	if (!Array.isArray(value) || value.length > 64) invalid();
	return value.map((r) => (typeof r === "string" && REASON_CODE.test(r) ? r : invalid()));
}

/** Output size and hash must agree with each other and with the decision. */
function parseOutput(
	m: Json,
	decision: Commit["decision"],
): Pick<Commit, "outputBytes" | "sha256"> {
	const { outputBytes, sha256: hash } = m;
	if (!Number.isSafeInteger(outputBytes)) invalid();
	const size = outputBytes as number;
	if (size < 0 || size > MAX_OUTPUT_BYTES) invalid();
	if (hash !== undefined && (typeof hash !== "string" || !HEX64.test(hash))) invalid();
	const hasOutput = size > 0;
	if (hasOutput !== (hash !== undefined)) invalid();
	if (hasOutput !== (decision === "allow" || decision === "redact")) invalid();
	return { outputBytes: size, sha256: hash as string | undefined };
}

function parseCommit(m: Json, hello: Hello): Commit {
	onlyKeys(m, [
		"decision",
		"reasons",
		"filename",
		"contentType",
		"coverage",
		"counts",
		"policyId",
		"policyDigest",
		"outputBytes",
		"sha256",
	]);
	const decision = DECISIONS.find((d) => d === m.decision) ?? invalid();
	if (m.policyDigest !== hello.policyDigest) invalid();
	if (m.coverage !== undefined && m.coverage !== "rules-only" && m.coverage !== "rules-and-ner")
		invalid();
	return {
		decision,
		reasons: parseReasons(m.reasons),
		counts: parseCounts(m.counts),
		...parseOutput(m, decision),
	};
}

const IMAGE_RESULTS: Readonly<Record<string, ImageInspection["result"]>> = {
	allow: "clean",
	block: "sensitive",
	review: "incomplete",
};

/** An `image-scan` commit: a decision and counts, never output bytes. */
function parseImageCommit(m: Json, hello: Hello): ImageInspection {
	onlyKeys(m, [
		"decision",
		"reasons",
		"coverage",
		"counts",
		"policyId",
		"policyDigest",
		"outputBytes",
	]);
	const result = (typeof m.decision === "string" && IMAGE_RESULTS[m.decision]) || invalid();
	if (m.policyDigest !== hello.policyDigest || m.outputBytes !== 0) invalid();
	if (
		m.coverage !== undefined &&
		m.coverage !== "unknown" &&
		m.coverage !== "rules-only" &&
		m.coverage !== "rules-and-ner"
	)
		invalid();
	const counts = parseCounts(m.counts);
	if (result === "clean" && Object.values(counts).some((n) => (n ?? 0) > 0)) invalid();
	return { result, counts, reasons: parseReasons(m.reasons) };
}

interface Marker {
	readonly index: number;
	readonly length: number;
	readonly type: EntityType;
}

/** Parses host markers in document order; `null` when a `[REDACTED]` marker cannot be typed. */
function collectMarkers(
	output: string,
	counts: Readonly<Partial<Record<EntityType, number>>>,
): Marker[] | null {
	const counted = ENTITY_TYPES.filter((t) => (counts[t] ?? 0) > 0);
	const markers: Marker[] = [];
	for (const match of output.matchAll(new RegExp(MARKER_SOURCE, "g"))) {
		// `[REDACTED]` carries no type; attribute it only when the host counted one type.
		const type = match[1] ?? (counted.length === 1 ? counted[0] : undefined);
		if (type === undefined) return null;
		if (!isEntityType(type) || (counts[type] ?? 0) < 1) invalid();
		markers.push({ index: match.index, length: match[0].length, type });
	}
	const total = counted.reduce((n, t) => n + (counts[t] ?? 0), 0);
	if (markers.length > total) invalid();
	return markers;
}

/** Earliest feasible start offset in the input of each literal between markers. */
function earliestStarts(input: string, literals: readonly string[], tailAt: number): number[] {
	const n = literals.length - 1;
	const earliest: number[] = [0];
	let cursor = (literals[0] ?? "").length;
	for (let i = 1; i < n; i++) {
		const lit = literals[i] ?? "";
		const at = input.indexOf(lit, cursor + 1);
		if (at < 0) invalid();
		earliest.push(at);
		cursor = at + lit.length;
	}
	if (tailAt < cursor + 1) invalid();
	earliest.push(tailAt);
	return earliest;
}

/** Latest feasible start offset in the input of each literal between markers. */
function latestStarts(input: string, literals: readonly string[], tailAt: number): number[] {
	const n = literals.length - 1;
	const latest: number[] = new Array(n + 1).fill(0);
	latest[n] = tailAt;
	let bound = tailAt;
	for (let i = n - 1; i >= 1; i--) {
		const lit = literals[i] ?? "";
		const from = bound - 1 - lit.length;
		if (from < 0) invalid();
		const at = input.lastIndexOf(lit, from);
		if (at < 0) invalid();
		latest[i] = at;
		bound = at;
	}
	if (bound < (literals[0] ?? "").length + 1) invalid();
	return latest;
}

/** The literal text before, between and after the markers (`markers.length + 1` parts). */
function splitLiterals(output: string, markers: readonly Marker[]): string[] {
	const literals: string[] = [];
	let pos = 0;
	for (const m of markers) {
		literals.push(output.slice(pos, m.index));
		pos = m.index + m.length;
	}
	literals.push(output.slice(pos));
	return literals;
}

/** Marker i spans from the earliest end of literal i-1 to the latest start of literal i. */
function widestSpans(
	markers: readonly Marker[],
	literals: readonly string[],
	earliest: readonly number[],
	latest: readonly number[],
): Finding[] {
	const findings: Finding[] = [];
	for (let i = 1; i <= markers.length; i++) {
		const start = (earliest[i - 1] ?? 0) + (literals[i - 1] ?? "").length;
		const end = latest[i] ?? 0;
		const prev = findings.at(-1);
		if (prev && start < prev.end) {
			// Overlapping feasible spans cannot be told apart: merge them.
			findings[findings.length - 1] = { ...prev, end: Math.max(prev.end, end) };
			continue;
		}
		const type = (markers[i - 1] as Marker).type;
		findings.push({ type, start, end, score: NATIVE_FINDING_SCORE, source: "native-ner" });
	}
	return findings;
}

/**
 * Recovers finding spans from the host's sanitised output. The host output is the
 * input with each merged finding replaced by a marker; the text between markers is
 * copied verbatim. When an alignment is ambiguous (a literal gap also occurs inside a
 * redacted value, or two findings are adjacent) the union of every possible span is
 * returned, which over-masks rather than leaking. Returns `null` when the output
 * cannot be mapped; throws `ProtocolError` when it contradicts the input.
 */
export function recoverNativeFindings(
	input: string,
	output: string,
	counts: Readonly<Partial<Record<EntityType, number>>>,
): Finding[] | null {
	// A marker already present in the input would make the alignment unsound.
	if (new RegExp(MARKER_SOURCE).test(input)) return null;
	const markers = collectMarkers(output, counts);
	if (!markers) return null;
	if (!markers.length) return output === input ? [] : invalid();

	const literals = splitLiterals(output, markers);
	const n = markers.length;
	const first = literals[0] ?? "";
	const last = literals[n] ?? "";
	const tailAt = input.length - last.length;
	if (!input.startsWith(first) || !input.endsWith(last) || tailAt < first.length + n) invalid();

	const earliest = earliestStarts(input, literals, tailAt);
	const latest = latestStarts(input, literals, tailAt);
	return widestSpans(markers, literals, earliest, latest);
}

/** One host process, one outstanding request at a time (as packages/privacy's client). */
function openSession(api: NativeChromeApi, connect: (application: string) => NativePort) {
	const port = connect(NATIVE_HOST_NAME);
	let pending: { id: string; resolve: (m: Json) => void; reject: (e: Error) => void } | undefined;
	let closed = false;
	const fail = () => {
		closed = true;
		const p = pending;
		pending = undefined;
		p?.reject(new Error("NATIVE_UNAVAILABLE"));
	};
	const close = () => {
		fail();
		try {
			port.disconnect();
		} catch {
			// already disconnected
		}
	};
	port.onDisconnect.addListener(() => {
		// Reading lastError marks it handled; its text is never surfaced.
		void api.runtime?.lastError;
		fail();
	});
	port.onMessage.addListener((m: unknown) => {
		const p = pending;
		if (!p || !isRecord(m) || m.v !== 1 || m.id !== p.id || m.ok !== true) {
			close();
			return;
		}
		pending = undefined;
		p.resolve(m);
	});
	const rpc = (op: string, payload: Json = {}): Promise<Json> =>
		new Promise((resolve, reject) => {
			if (closed || pending) {
				reject(new Error("NATIVE_UNAVAILABLE"));
				return;
			}
			const id = crypto.randomUUID();
			pending = { id, resolve, reject };
			try {
				port.postMessage({ v: 1, id, op, ...payload });
			} catch {
				close();
			}
		});
	return { rpc, close };
}

type Session = ReturnType<typeof openSession>;

/** Streams the input in host-sized chunks; every acknowledgement must match exactly. */
async function upload(session: Session, bytes: Uint8Array): Promise<void> {
	for (let at = 0; at < bytes.length; at += CHUNK_BYTES) {
		const chunk = bytes.subarray(at, at + CHUNK_BYTES);
		const ack = await session.rpc("write", { offset: at, data: toBase64(chunk) });
		onlyKeys(ack, ["received"]);
		if (ack.received !== at + chunk.length) invalid();
	}
}

/** Reads the sanitised output into `output`, which is sized from the commit metadata. */
async function download(session: Session, output: Uint8Array): Promise<void> {
	let read = 0;
	while (read < output.length) {
		const part = await session.rpc("read", { offset: read });
		onlyKeys(part, ["offset", "data", "done"]);
		const data = fromBase64(part.data, CHUNK_BYTES);
		if (part.offset !== read || !data.length || read + data.length > output.length) invalid();
		output.set(data, read);
		data.fill(0);
		read += data.length;
		if (part.done !== (read === output.length)) invalid();
	}
}

async function runScan(
	session: Session,
	text: string,
	offset: number,
	isOpen: () => boolean,
): Promise<Outcome> {
	const bytes = new TextEncoder().encode(text);
	let output: Uint8Array | undefined;
	try {
		const hello = parseHello(await session.rpc("hello"));
		const inputHash = await sha256(bytes);
		const begun = await session.rpc("begin", {
			kind: "text",
			size: bytes.length,
			sha256: inputHash,
			policyDigest: hello.policyDigest,
		});
		onlyKeys(begun, []);
		await upload(session, bytes);
		const meta = parseCommit(await session.rpc("commit"), hello);
		if (meta.decision === "block" || meta.decision === "review") {
			return meta.reasons.some((r) => ENGINE_FAILURE_REASON.test(r))
				? FAILURE
				: { kind: "unmapped" };
		}
		if (meta.decision === "allow") {
			// The host returns the input unchanged; its hash proves it without reading it back.
			if (meta.sha256 !== inputHash || meta.outputBytes !== bytes.length) invalid();
			return { kind: "findings", findings: [] };
		}
		output = new Uint8Array(meta.outputBytes);
		await download(session, output);
		if ((await sha256(output)) !== meta.sha256) invalid();
		if (!isOpen()) return FAILURE;
		const sanitized = new TextDecoder("utf-8", { fatal: true }).decode(output);
		const spans = recoverNativeFindings(text, sanitized, meta.counts);
		if (!spans) return { kind: "unmapped" };
		return {
			kind: "findings",
			findings: spans.map((f) => ({ ...f, start: f.start + offset, end: f.end + offset })),
		};
	} catch {
		return FAILURE;
	} finally {
		bytes.fill(0);
		output?.fill(0);
	}
}

async function runImageScan(
	session: Session,
	bytes: Uint8Array,
	isOpen: () => boolean,
): Promise<ImageOutcome> {
	try {
		const hello = parseHello(await session.rpc("hello"));
		if (!hello.ocr) return { kind: "unavailable" };
		const begun = await session.rpc("begin", {
			kind: "image-scan",
			size: bytes.length,
			sha256: await sha256(bytes),
			policyDigest: hello.policyDigest,
		});
		onlyKeys(begun, []);
		await upload(session, bytes);
		const inspection = parseImageCommit(await session.rpc("commit"), hello);
		return isOpen() ? { kind: "inspection", inspection } : FAILURE;
	} catch {
		return FAILURE;
	}
}

interface HostInput {
	readonly body: string;
	/** UTF-16 offset of `body` in the caller's text (1 when a leading BOM was dropped). */
	readonly offset: number;
}

/** Per-scan state shared with the timeout handler. */
interface RunState {
	open: boolean;
	session: Session | undefined;
}

/**
 * Drops a leading BOM (the host strips it too) and checks the host limits and lossless
 * UTF-8. These are preconditions, not host failures: `null` does not count towards backoff.
 */
function prepareInput(text: unknown): HostInput | null {
	if (typeof text !== "string") return null;
	const offset = text.charCodeAt(0) === 0xfeff ? 1 : 0;
	const body = offset ? text.slice(offset) : text;
	if (body.length > NATIVE_MAX_TEXT_BYTES || !isWellFormed(body)) return null;
	if (new TextEncoder().encode(body).length > NATIVE_MAX_TEXT_BYTES) return null;
	return { body, offset };
}

function defaultChrome(): NativeChromeApi | undefined {
	return (globalThis as unknown as { chrome?: NativeChromeApi }).chrome;
}

export function createNativeBridge(
	enabled: boolean,
	options: NativeBridgeOptions = {},
): NativeBridge {
	const timeoutMs = options.timeoutMs ?? NATIVE_TIMEOUT_MS;
	const imageTimeoutMs = options.imageTimeoutMs ?? NATIVE_IMAGE_TIMEOUT_MS;
	const retryAfterMs = options.retryAfterMs ?? NATIVE_RETRY_AFTER_MS;
	const now = options.now ?? (() => Date.now());
	const api = (): NativeChromeApi | undefined => options.chrome ?? defaultChrome();

	let state: "connected" | "unavailable" = "unavailable";
	let failures = 0;
	let retryAt = 0;
	let probing = false;
	let inFlight = 0;

	const backOff = () => {
		state = "unavailable";
		retryAt = now() + retryAfterMs;
	};
	const healthy = () => {
		state = "connected";
		failures = 0;
	};
	const failed = () => {
		failures++;
		if (failures >= NATIVE_MAX_FAILURES) backOff();
	};
	const inBackoff = () => state === "unavailable" && now() < retryAt;

	/** Bounds a promise; the timer is always cleared. */
	const bounded = <T>(
		task: Promise<T>,
		onTimeout: () => void,
		limitMs = timeoutMs,
	): Promise<T | "timeout"> => {
		let timer: ReturnType<typeof setTimeout> | undefined;
		const timeout = new Promise<"timeout">((resolve) => {
			timer = setTimeout(() => {
				onTimeout();
				resolve("timeout");
			}, limitMs);
		});
		return Promise.race([task, timeout]).finally(() => clearTimeout(timer));
	};

	const permitted = async (chrome: NativeChromeApi | undefined): Promise<boolean> => {
		const contains = chrome?.permissions?.contains;
		if (!contains) return false;
		try {
			const result = await bounded(
				Promise.resolve(contains.call(chrome.permissions, { permissions: ["nativeMessaging"] })),
				() => {},
			);
			return result === true;
		} catch {
			return false;
		}
	};

	/** One hello round trip; sendNativeMessage when available, else a short-lived port. */
	const helloReply = async (chrome: NativeChromeApi): Promise<unknown> => {
		const runtime = chrome.runtime;
		const send = runtime?.sendNativeMessage;
		if (send) {
			const id = crypto.randomUUID();
			const answer = Promise.resolve(
				send.call(runtime, NATIVE_HOST_NAME, { v: 1, id, op: "hello" }),
			);
			answer.catch(() => {});
			const reply = await bounded(answer, () => {});
			if (!isRecord(reply) || reply.v !== 1 || reply.id !== id || reply.ok !== true) invalid();
			return reply;
		}
		const connect = runtime?.connectNative;
		if (!connect) invalid();
		const session = openSession(chrome, (name) => connect.call(runtime, name));
		const answer = session.rpc("hello");
		answer.catch(() => {});
		try {
			return await bounded(answer, session.close);
		} finally {
			session.close();
		}
	};

	const probe = async (): Promise<void> => {
		const chrome = api();
		try {
			if (!chrome || !(await permitted(chrome))) return backOff();
			const reply = await helloReply(chrome);
			if (!isRecord(reply)) invalid();
			parseHello(reply);
			healthy();
		} catch {
			backOff();
		}
	};

	/** Permission check, a fresh host process and `exchange` on it. */
	const attempt = async <T>(
		run: RunState,
		exchange: (session: Session, isOpen: () => boolean) => Promise<T | typeof FAILURE>,
	): Promise<T | typeof FAILURE | "denied"> => {
		const chrome = api();
		if (!(await permitted(chrome))) return "denied";
		const runtime = chrome?.runtime;
		const connect = runtime?.connectNative;
		if (!chrome || !connect) return "denied";
		if (!run.open) return FAILURE;
		try {
			run.session = openSession(chrome, (name) => connect.call(runtime, name));
		} catch {
			return FAILURE;
		}
		return exchange(run.session, () => run.open);
	};

	/** One bounded host exchange (one deadline covers the permission check too). */
	const guarded = async <T>(
		limitMs: number,
		exchange: (session: Session, isOpen: () => boolean) => Promise<T | typeof FAILURE>,
	): Promise<T | typeof FAILURE | "denied" | "timeout"> => {
		inFlight++;
		const run: RunState = { open: true, session: undefined };
		const stop = () => {
			run.open = false;
			run.session?.close();
		};
		try {
			return await bounded(attempt(run, exchange), stop, limitMs);
		} finally {
			stop();
			inFlight--;
		}
	};

	/** Applies an exchange's outcome to the health state; the outcome when the host answered. */
	const settle = <T extends { readonly kind: string }>(
		outcome: T | "denied" | "timeout",
	): T | null => {
		if (outcome === "denied") {
			backOff();
			return null;
		}
		if (outcome === "timeout" || outcome.kind === "failure") {
			failed();
			return null;
		}
		healthy();
		return outcome;
	};

	return {
		status() {
			if (!enabled) return "disabled";
			if (state === "unavailable" && !probing && now() >= retryAt) {
				probing = true;
				void probe().finally(() => {
					probing = false;
				});
			}
			return state;
		},

		async scanText(text: string): Promise<readonly Finding[] | null> {
			if (!enabled || inBackoff()) return null;
			const input = prepareInput(text);
			if (!input) return null;
			if (!input.body.length) return [];
			if (inFlight >= MAX_IN_FLIGHT) return null;
			try {
				const outcome = settle<Outcome>(
					await guarded(timeoutMs, (session, isOpen) =>
						runScan(session, input.body, input.offset, isOpen),
					),
				);
				return outcome?.kind === "findings" ? outcome.findings : null;
			} catch {
				failed();
				return null;
			}
		},

		async scanImage(bytes: Uint8Array): Promise<ImageInspection | null> {
			if (!enabled || inBackoff()) return null;
			if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > NATIVE_MAX_IMAGE_BYTES)
				return null;
			if (inFlight >= MAX_IN_FLIGHT) return null;
			try {
				const outcome = settle<ImageOutcome>(
					await guarded(imageTimeoutMs, (session, isOpen) => runImageScan(session, bytes, isOpen)),
				);
				return outcome?.kind === "inspection" ? outcome.inspection : null;
			} catch {
				failed();
				return null;
			}
		},
	};
}
