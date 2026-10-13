import { readSync } from "node:fs";
import { readBoundedStdinAsync } from "@singularityrd/aidr-core";

/**
 * Default PostToolUse input ceiling. Input up to it is parsed, so even a result
 * too large to scan in full is replaced with its own (shape-preserving)
 * quarantine notice; only input beyond it falls back to a by-tool-name
 * replacement. `AIDR_POST_TOOL_USE_MAX_INPUT_BYTES` overrides it within
 * [MIN, MAX].
 */
export const MAX_POST_TOOL_INPUT_BYTES = 16 * 1024 * 1024;
const MIN_POST_TOOL_INPUT_BYTES = 1024 * 1024;
const MAX_CONFIGURABLE_POST_TOOL_INPUT_BYTES = 64 * 1024 * 1024;
const POST_TOOL_INPUT_LIMIT_ENV = "AIDR_POST_TOOL_USE_MAX_INPUT_BYTES";
/** Leading bytes kept while reading, so the tool name survives an incomplete read. */
const INPUT_PREFIX_BYTES = 64 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

/** Read at most the configured limit plus one byte so oversized hook input is detectable. */
export function readBoundedStdin(fd = 0, maxBytes = MAX_POST_TOOL_INPUT_BYTES): string | null {
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
		throw new RangeError("maxBytes must be a non-negative safe integer");
	}
	const chunks: Buffer[] = [];
	const buffer = Buffer.alloc(READ_CHUNK_BYTES);
	let total = 0;

	while (true) {
		const length = Math.min(buffer.length, maxBytes + 1 - total);
		const read = readSync(fd, buffer, 0, length, null);
		// Strict decoding: hosts serialize hook input with JSON.stringify, which
		// always yields valid UTF-8. Invalid bytes would decode to U+FFFD and
		// change what is inspected relative to what the host executes, so they
		// throw and the caller fails closed.
		if (read === 0) return STRICT_UTF8.decode(Buffer.concat(chunks, total));
		total += read;
		if (total > maxBytes) return null;
		chunks.push(Buffer.from(buffer.subarray(0, read)));
	}
}

export type BoundedJsonResult<T> =
	| { status: "parsed"; value: T }
	| { status: "oversized" }
	| { status: "invalid" };

/** Do not parse unbounded hook input: the byte ceiling is checked first. */
export function readBoundedJson<T = unknown>(
	fd = 0,
	maxBytes = MAX_POST_TOOL_INPUT_BYTES,
	parse: (text: string) => T = JSON.parse,
): BoundedJsonResult<T> {
	const text = readBoundedStdin(fd, maxBytes);
	if (text === null) return { status: "oversized" };
	try {
		return { status: "parsed", value: parse(text) };
	} catch {
		return { status: "invalid" };
	}
}

/**
 * The entry points' stdin reader: like {@link readBoundedJson}, but it does not
 * block the event loop, so the internal deadline still fires when the host
 * never closes stdin. Invalid UTF-8 throws (the caller fails closed).
 */
export async function readStdinJson<T = unknown>(
	maxBytes = MAX_POST_TOOL_INPUT_BYTES,
	parse: (text: string) => T = JSON.parse,
): Promise<BoundedJsonResult<T>> {
	const input = await readBoundedStdinAsync(maxBytes);
	if (input.status === "oversized") return { status: "oversized" };
	const text = STRICT_UTF8.decode(input.bytes);
	try {
		return { status: "parsed", value: parse(text) };
	} catch {
		return { status: "invalid" };
	}
}

export function resolvePostToolInputLimit(env: Record<string, string | undefined> = {}): number {
	return resolveBoundedInteger(
		env[POST_TOOL_INPUT_LIMIT_ENV],
		MAX_POST_TOOL_INPUT_BYTES,
		MIN_POST_TOOL_INPUT_BYTES,
		MAX_CONFIGURABLE_POST_TOOL_INPUT_BYTES,
	);
}

export type PostToolInput =
	| { status: "parsed"; value: unknown }
	| { status: "oversized" }
	| { status: "invalid" };

/** The first bytes received so far, kept while the input is still being read. */
export interface PostToolInputProgress {
	prefix: string;
}

/**
 * Claude Code serialises `tool_name` before `tool_input`/`tool_response`, so
 * the first unescaped `"tool_name"` key in the prefix is the top-level one. A
 * JSON string value cannot contain an unescaped quote, so a value cannot forge
 * it; a wrong guess only yields a replacement shape the host rejects.
 */
export function toolNameFromInputPrefix(prefix: string): string | undefined {
	const match = /"tool_name"\s*:\s*("(?:[^"\\]|\\.)*")/.exec(prefix);
	if (!match) return undefined;
	try {
		const value: unknown = JSON.parse(match[1] ?? "");
		return typeof value === "string" ? value : undefined;
	} catch {
		return undefined;
	}
}

/**
 * The PostToolUse stdin reader: bounded like {@link readStdinJson}, and it
 * keeps the first bytes in `progress` so input that is oversized or never
 * finishes still names its tool, letting the hook withhold the output instead
 * of only annotating it.
 */
export function readPostToolStdin(
	maxBytes = MAX_POST_TOOL_INPUT_BYTES,
	stream: NodeJS.ReadableStream = process.stdin,
	progress: PostToolInputProgress = { prefix: "" },
): Promise<PostToolInput> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		let total = 0;
		let settled = false;
		const settle = () => {
			settled = true;
			stream.removeListener("data", onData);
		};
		const onData = (chunk: Buffer | string) => {
			if (settled) return;
			const bytes = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
			if (total < INPUT_PREFIX_BYTES) {
				progress.prefix = Buffer.concat([...chunks, bytes])
					.subarray(0, INPUT_PREFIX_BYTES)
					.toString("utf8");
			}
			chunks.push(bytes);
			total += bytes.length;
			if (total <= maxBytes) return;
			settle();
			stream.pause();
			resolve({ status: "oversized" });
		};
		stream.on("data", onData);
		stream.once("end", () => {
			if (settled) return;
			settle();
			try {
				const text = STRICT_UTF8.decode(Buffer.concat(chunks, total));
				try {
					resolve({ status: "parsed", value: JSON.parse(text) });
				} catch {
					resolve({ status: "invalid" });
				}
			} catch (error) {
				reject(error);
			}
		});
		stream.once("error", (error) => {
			if (settled) return;
			settle();
			reject(error);
		});
	});
}

/**
 * PreToolUse input ceiling. A Write of a big file carries the whole file in
 * `tool_input`; anything beyond it cannot be inspected in full and is denied
 * rather than parsed without bound.
 */
export const MAX_PRE_TOOL_INPUT_BYTES = 8 * 1024 * 1024;

/**
 * Host timeout for the PreToolUse hook, in milliseconds (`hooks/hooks.json`
 * sets 15 s). When Claude Code kills a hook for exceeding it the call proceeds
 * uninspected, so the hook must answer — with a deny — before that happens.
 */
const PRE_TOOL_USE_HOST_TIMEOUT_MS = 15_000;
const DEFAULT_PRE_TOOL_USE_DEADLINE_MS = 10_000;
const MIN_PRE_TOOL_USE_DEADLINE_MS = 100;
/** Leave headroom for writing the deny and exiting before the host timeout. */
const MAX_PRE_TOOL_USE_DEADLINE_MS = PRE_TOOL_USE_HOST_TIMEOUT_MS - 1_000;
const PRE_TOOL_USE_DEADLINE_ENV = "AIDR_PRE_TOOL_USE_DEADLINE_MS";

/**
 * Internal PreToolUse deadline. Configurable through
 * `AIDR_PRE_TOOL_USE_DEADLINE_MS`; a value that is not an integer within
 * [MIN, MAX] falls back to the default so a typo can never push the deadline
 * past the host timeout (which would fail open).
 */
export function resolvePreToolUseDeadlineMs(env: Record<string, string | undefined> = {}): number {
	return resolveBoundedInteger(
		env[PRE_TOOL_USE_DEADLINE_ENV],
		DEFAULT_PRE_TOOL_USE_DEADLINE_MS,
		MIN_PRE_TOOL_USE_DEADLINE_MS,
		MAX_PRE_TOOL_USE_DEADLINE_MS,
	);
}

/**
 * Host timeout for the UserPromptSubmit hook, in milliseconds
 * (`hooks/hooks.json` sets 10 s). A killed prompt hook cannot block, so the
 * prompt would be sent uninspected; the hook must answer before this.
 */
export const USER_PROMPT_SUBMIT_HOST_TIMEOUT_MS = 10_000;
export const DEFAULT_USER_PROMPT_SUBMIT_DEADLINE_MS = 7_000;
const MIN_USER_PROMPT_SUBMIT_DEADLINE_MS = 100;
/** Leave headroom for writing the response and exiting before the host timeout. */
const MAX_USER_PROMPT_SUBMIT_DEADLINE_MS = USER_PROMPT_SUBMIT_HOST_TIMEOUT_MS - 1_000;
const USER_PROMPT_SUBMIT_DEADLINE_ENV = "AIDR_USER_PROMPT_SUBMIT_DEADLINE_MS";

/**
 * Internal UserPromptSubmit deadline. Configurable through
 * `AIDR_USER_PROMPT_SUBMIT_DEADLINE_MS` with the same fallback rules as the
 * PreToolUse deadline.
 */
export function resolveUserPromptSubmitDeadlineMs(
	env: Record<string, string | undefined> = {},
): number {
	return resolveBoundedInteger(
		env[USER_PROMPT_SUBMIT_DEADLINE_ENV],
		DEFAULT_USER_PROMPT_SUBMIT_DEADLINE_MS,
		MIN_USER_PROMPT_SUBMIT_DEADLINE_MS,
		MAX_USER_PROMPT_SUBMIT_DEADLINE_MS,
	);
}

function resolveBoundedInteger(
	rawValue: string | undefined,
	fallback: number,
	min: number,
	max: number,
): number {
	const raw = rawValue?.trim();
	if (!raw || !/^\d+$/.test(raw)) return fallback;
	const value = Number(raw);
	return value >= min && value <= max ? value : fallback;
}
