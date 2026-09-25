import { readSync } from "node:fs";

export const MAX_POST_TOOL_INPUT_BYTES = 1024 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;

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
		if (read === 0) return Buffer.concat(chunks, total).toString("utf8");
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
 * PreToolUse input ceiling. Larger than the PostToolUse one because a Write of
 * a big file carries the whole file in `tool_input`; anything beyond it cannot
 * be inspected in full and is denied rather than parsed without bound.
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
	return resolveDeadlineMs(
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
	return resolveDeadlineMs(
		env[USER_PROMPT_SUBMIT_DEADLINE_ENV],
		DEFAULT_USER_PROMPT_SUBMIT_DEADLINE_MS,
		MIN_USER_PROMPT_SUBMIT_DEADLINE_MS,
		MAX_USER_PROMPT_SUBMIT_DEADLINE_MS,
	);
}

function resolveDeadlineMs(
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
