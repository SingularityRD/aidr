/**
 * Shared deadline and input-hygiene helpers for connector entry points.
 *
 * A hook host kills a hook that outlives its timeout, and for most hosts a
 * killed hook means the call proceeds uninspected (Codex additionally drops the
 * output of a timed-out hook). An entry point therefore needs:
 *
 *   - an internal deadline set below the host budget, which answers with a
 *     block on its own; and
 *   - an explicit `process.exit` once the verdict has been flushed, because
 *     pending sockets and timers (reputation lookups, telemetry) otherwise keep
 *     the process alive for seconds after the answer was written.
 *
 * In-process connectors (OpenClaw, OpenCode) cannot exit; they race the
 * evaluation against the same kind of deadline with {@link withHookDeadline}.
 */

import { canonicalToolName } from "./tool-normalization.js";

/** Host hook timeouts, in milliseconds, as registered by each connector's installer. */
export const HOOK_HOST_TIMEOUT_MS = {
	/** `hooks/hooks.json`: PreToolUse `timeout: 15`. */
	claudeCode: 15_000,
	/** `~/.codex/config.toml`: `timeout = 10`. */
	codex: 10_000,
	/** Cursor and VS Code managed installers register 30 s. */
	cursor: 30_000,
	vscode: 30_000,
} as const;

/** Floor for a configured deadline: anything lower would deny nearly every call. */
export const MIN_HOOK_DEADLINE_MS = 100;
/** Headroom kept between the internal deadline and the host timeout for write + exit. */
export const HOOK_DEADLINE_HEADROOM_MS = 1_000;
/** Longest wait for stdout to flush after an answer before the process exits anyway. */
export const EXIT_FLUSH_BACKSTOP_MS = 500;

export interface HookDeadlineSpec {
	/** Environment variable that may override the deadline (integer milliseconds). */
	envVar: string;
	/** The host's timeout for this hook. */
	hostTimeoutMs: number;
	/** Deadline used when the variable is absent or invalid. */
	defaultMs: number;
}

/**
 * Internal deadline for a hook. A configured value that is not an integer in
 * [MIN_HOOK_DEADLINE_MS, hostTimeoutMs - HOOK_DEADLINE_HEADROOM_MS] falls back
 * to the default, so a typo can never push the deadline past the host timeout
 * (which would fail open).
 */
export function resolveHookDeadlineMs(
	spec: HookDeadlineSpec,
	env: Record<string, string | undefined> = {},
): number {
	const max = spec.hostTimeoutMs - HOOK_DEADLINE_HEADROOM_MS;
	const fallback = Math.min(spec.defaultMs, max);
	const raw = env[spec.envVar]?.trim();
	if (!raw || !/^\d+$/.test(raw)) return fallback;
	const value = Number(raw);
	return value >= MIN_HOOK_DEADLINE_MS && value <= max ? value : fallback;
}

/** One answer on stdout, plus the exit code the process should end with. */
export interface HookAnswer {
	/** Text written to stdout; empty for an answer that is "no output". */
	stdout: string;
	/** Optional stderr line (Codex reads stderr as a block reason on exit 2). */
	stderr?: string;
	exitCode?: number;
}

export interface HookResponderOptions {
	/** Milliseconds from now until the deadline answer is written. */
	deadlineMs: number;
	/** The block written when the deadline passes first. */
	onDeadline: () => HookAnswer;
	/** Injected for tests; defaults to process streams, `process.exit` and timers. */
	io?: {
		writeStdout?: (text: string, done: () => void) => void;
		writeStderr?: (text: string) => void;
		exit?: (code: number) => void;
		setTimer?: (fn: () => void, ms: number) => unknown;
		clearTimer?: (timer: unknown) => void;
	};
}

export interface HookResponder {
	/**
	 * Write the answer, then exit once stdout has flushed. Returns false when an
	 * answer was already written (a late result after the deadline is dropped).
	 */
	answer(answer: HookAnswer): boolean;
	/** True once an answer (the deadline's or the caller's) has been written. */
	readonly answered: boolean;
}

/**
 * Single-answer stdout responder with a watchdog. Whichever comes first, the
 * caller's answer or the deadline's block, is written; the process then exits
 * after the write has been flushed so lingering handles cannot keep it alive
 * past the host timeout.
 */
export function createHookResponder(options: HookResponderOptions): HookResponder {
	const io = options.io ?? {};
	const writeStdout =
		io.writeStdout ??
		((text: string, done: () => void) => {
			if (text) process.stdout.write(text, () => done());
			else done();
		});
	const writeStderr = io.writeStderr ?? ((text: string) => process.stderr.write(text));
	const exit = io.exit ?? ((code: number) => process.exit(code));
	const setTimer = io.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms));
	const clearTimer = io.clearTimer ?? ((timer: unknown) => clearTimeout(timer as NodeJS.Timeout));

	let answered = false;
	const write = (answer: HookAnswer): boolean => {
		if (answered) return false;
		answered = true;
		clearTimer(timer);
		const code = answer.exitCode ?? 0;
		try {
			if (answer.stderr)
				writeStderr(answer.stderr.endsWith("\n") ? answer.stderr : `${answer.stderr}\n`);
		} catch {
			// stderr is only a secondary channel.
		}
		// Backstop: a write whose callback never fires (host not draining stdout)
		// must not keep the hook alive until the host kills it.
		let exited = false;
		const exitOnce = () => {
			if (exited) return;
			exited = true;
			clearTimer(backstop);
			exit(code);
		};
		const backstop = setTimer(exitOnce, EXIT_FLUSH_BACKSTOP_MS);
		(backstop as { unref?: () => void } | undefined)?.unref?.();
		try {
			writeStdout(answer.stdout, exitOnce);
		} catch {
			exitOnce();
		}
		return true;
	};
	const timer = setTimer(() => {
		let deadlineAnswer: HookAnswer;
		try {
			deadlineAnswer = options.onDeadline();
		} catch {
			deadlineAnswer = {
				stdout: "",
				exitCode: 2,
				stderr: "Singularity AIDR inspection timed out.",
			};
		}
		write(deadlineAnswer);
	}, options.deadlineMs);

	return {
		answer: write,
		get answered() {
			return answered;
		},
	};
}

/**
 * End a hook process once everything already written to stdout has been
 * flushed. A hook's answer is complete when its handler returns; lingering
 * sockets or timers must not hold the process open until the host kills it.
 * Uses `process.exitCode` when no code is given.
 */
export function exitAfterStdoutFlush(code?: number): void {
	const exit = () => process.exit(code ?? (Number(process.exitCode) || 0));
	try {
		process.stdout.write("", exit);
	} catch {
		exit();
	}
}

export type BoundedStdinResult = { status: "read"; bytes: Buffer } | { status: "oversized" };

/**
 * Read hook input without blocking the event loop, up to `maxBytes`. A
 * synchronous read (`readFileSync(0)` / `readSync`) would hold off the
 * watchdog for as long as the host keeps stdin open, so the host's timeout
 * would fire first and the call would proceed uninspected. Resolves
 * `oversized` as soon as the limit is exceeded; rejects on a stream error.
 */
export function readBoundedStdinAsync(
	maxBytes: number,
	stream: NodeJS.ReadableStream = process.stdin,
): Promise<BoundedStdinResult> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		let total = 0;
		let settled = false;
		const finish = (result: BoundedStdinResult) => {
			if (settled) return;
			settled = true;
			stream.removeListener("data", onData);
			resolve(result);
		};
		const onData = (chunk: Buffer | string) => {
			const bytes = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
			total += bytes.length;
			if (total > maxBytes) {
				stream.pause();
				finish({ status: "oversized" });
				return;
			}
			chunks.push(bytes);
		};
		stream.on("data", onData);
		stream.once("end", () => finish({ status: "read", bytes: Buffer.concat(chunks, total) }));
		stream.once("error", (error) => {
			if (settled) return;
			settled = true;
			reject(error);
		});
	});
}

/** Raised (as a value, never thrown) when {@link withHookDeadline} timed out. */
export const HOOK_DEADLINE_EXCEEDED: unique symbol = Symbol("aidr.hookDeadlineExceeded");

/**
 * Race an in-process evaluation against a deadline. Resolves to the work's
 * result, or to `onTimeout()` when the deadline passes first. The timer is
 * always cleared; a rejection of `work` is propagated unchanged.
 */
export async function withHookDeadline<T>(
	work: Promise<T>,
	deadlineMs: number,
	onTimeout: () => T,
): Promise<T> {
	let timer: NodeJS.Timeout | undefined;
	const timeout = new Promise<typeof HOOK_DEADLINE_EXCEEDED>((resolve) => {
		timer = setTimeout(() => resolve(HOOK_DEADLINE_EXCEEDED), deadlineMs);
		timer.unref?.();
	});
	try {
		const result = await Promise.race([work, timeout]);
		return result === HOOK_DEADLINE_EXCEEDED ? onTimeout() : (result as T);
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Deadline for in-process tool-call hooks (OpenClaw, OpenCode). Those hosts do
 * not kill the plugin, but a hung evaluation stalls the agent; the call is
 * blocked instead. `AIDR_TOOL_CALL_DEADLINE_MS` overrides it.
 */
export const IN_PROCESS_TOOL_CALL_DEADLINE: HookDeadlineSpec = {
	envVar: "AIDR_TOOL_CALL_DEADLINE_MS",
	hostTimeoutMs: 30_000,
	defaultMs: 20_000,
};

/** Lone UTF-16 surrogate: what a truncated or unpaired `\uD8xx` JSON escape decodes to. */
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * True when a command string cannot be what a shell would execute verbatim:
 * a NUL byte (C-string truncation means the host and our parser disagree on
 * where the command ends) or a lone surrogate (not encodable as UTF-8, so the
 * host must alter it before the shell sees it). Such a command is malformed
 * and denied, never downgraded to a review prompt.
 *
 * U+FFFD is deliberately NOT treated as malformed: it is an ordinary, validly
 * encoded code point (output of a lossy decode upstream, pasted text, test
 * fixtures) and reaches the shell unchanged. Undecodable input is refused one
 * layer down instead: every entry point that reads raw hook bytes decodes them
 * strictly ({@link isValidUtf8} or a fatal `TextDecoder`) and fails closed
 * before any string reaches this check, so a U+FFFD seen here is one the host
 * itself sent.
 */
export function hasMalformedCommandText(command: string): boolean {
	return command.includes("\u0000") || LONE_SURROGATE_RE.test(command);
}

/** Strict UTF-8 validity of raw hook input bytes. */
export function isValidUtf8(bytes: Uint8Array): boolean {
	try {
		new TextDecoder("utf-8", { fatal: true }).decode(bytes);
		return true;
	} catch {
		return false;
	}
}

/**
 * Validate the shape every PreToolUse-style hook payload must have: a
 * non-empty string tool name and an object (not array, not null) tool input.
 * Mirrors the Codex entry point's check so all connectors refuse the same
 * malformed shapes instead of evaluating an empty call as "no artifacts".
 */
export function isWellFormedToolCall(
	toolName: unknown,
	toolInput: unknown,
): toolInput is Record<string, unknown> {
	return (
		typeof toolName === "string" &&
		toolName.trim() !== "" &&
		toolInput !== null &&
		typeof toolInput === "object" &&
		!Array.isArray(toolInput)
	);
}

/** Shell command fields (core's `Bash` vocabulary: `command` plus its aliases). */
const COMMAND_FIELDS = ["command", "cmd", "shellCommand", "shell_command"] as const;

/**
 * Why a shell tool call cannot be inspected, or null when it is not a shell
 * tool or every present command field is well formed. A non-string,
 * non-argv command, an argv with a non-string element, or a command containing
 * malformed text (see {@link hasMalformedCommandText}) is refused.
 */
export function malformedShellCommandReason(
	toolName: string,
	toolInput: Record<string, unknown>,
): string | null {
	if (canonicalToolName(toolName) !== "Bash") return null;
	for (const field of COMMAND_FIELDS) {
		const value = toolInput[field];
		if (value === undefined) continue;
		const parts =
			typeof value === "string"
				? [value]
				: Array.isArray(value) &&
						value.length > 0 &&
						value.every((part) => typeof part === "string")
					? (value as string[])
					: null;
		if (!parts) return `shell ${field} is neither a string nor a string argv`;
		if (parts.some(hasMalformedCommandText)) {
			return `shell ${field} contains NUL or an unpaired surrogate (not encodable as UTF-8)`;
		}
	}
	return null;
}
