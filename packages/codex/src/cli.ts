#!/usr/bin/env node
/**
 * Singularity AIDR Codex PreToolUse hook entry point.
 *
 * Wired into Codex via `~/.codex/config.toml`:
 *
 *   [[hooks.PreToolUse]]
 *   matcher = "^(Bash|apply_patch)$"
 *   [[hooks.PreToolUse.hooks]]
 *   type = "command"
 *   command = 'aidr-codex-hook'
 *   timeout = 10
 *
 * or equivalently via `~/.codex/hooks.json`. The same command registered for
 * `[[hooks.UserPromptSubmit]]` (no matcher) inspects the user's prompt before
 * it starts a turn (prompt protection, see prompt-protection.ts), and registered
 * for `[[hooks.PostToolUse]]` it inspects tool output before the model reads it
 * (see output-protection.ts).
 *
 * Codex fails OPEN on malformed or missing hook output. This entry point uses
 * empty stdout for an evaluated allow (the 0.141.0 no-op shape) and emits a
 * well-formed explicit deny for every blocked or failed evaluation. Even an
 * unexpected throw is converted into a deny on stdout, with a secondary stderr
 * write so that a partially-broken stdout still blocks (Codex treats `exit 2`
 * with a non-empty stderr as a block).
 */

import {
	ArtifactIntegrityError,
	createHostObservation,
	createLogger,
	exitAfterStdoutFlush,
	HOOK_HOST_TIMEOUT_MS,
	isValidUtf8,
	isWellFormedToolCall,
	type Logger,
	malformedShellCommandReason,
	readBoundedStdinAsync,
	recordHostObservation,
	resolveHookDeadlineMs,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import { getCodexConnectorCoverageEvidence } from "./coverage.js";
import { type CodexWireResult, DENY_HEADLINE, enforceCodexPreToolUse } from "./enforcement.js";
import { CODEX_POST_TOOL_USE, enforceCodexPostToolUse } from "./output-protection.js";
import { CODEX_USER_PROMPT_SUBMIT, enforceCodexUserPromptSubmit } from "./prompt-protection.js";

/** Measured from process start: Codex's hook timeout runs from launch. */
const startedAt = Date.now();

// Codex surfaces stderr on a non-zero exit as the block reason, so diagnostics
// must never share the channel that carries a decision.
const logger: Logger = createLogger({ name: "aidr-codex", level: "warn" });
const hostObservation = createHostObservation();

/**
 * Codex drops the output of a hook that outlives its `timeout` (10 s as
 * installed) and runs the call. The watchdog answers with a block first; once
 * any answer is written, later writes are dropped, and the process exits after
 * stdout flushes so lingering sockets cannot hold it open past the timeout.
 * `AIDR_CODEX_HOOK_DEADLINE_MS` overrides the deadline (max 9 s).
 */
const CODEX_HOOK_DEADLINE = {
	envVar: "AIDR_CODEX_HOOK_DEADLINE_MS",
	hostTimeoutMs: HOOK_HOST_TIMEOUT_MS.codex,
	defaultMs: 8_000,
};
let answered = false;
/** Hook input ceiling (same as the Claude Code PreToolUse one). */
const MAX_CODEX_HOOK_INPUT_BYTES = 8 * 1024 * 1024;
/** Event being answered, so a deadline block uses that event's shape. */
let currentEvent = "PreToolUse";

function emit(text: string): void {
	if (answered) return;
	process.stdout.write(text);
}

function write(wire: CodexWireResult): void {
	// Codex 0.141.0 treats a bare `permissionDecision: "allow"` as an
	// unsupported output and fails open. Empty stdout is its documented no-op
	// allow shape, so only deny decisions are written.
	if (!wire.hookSpecificOutput) return;
	emit(`${JSON.stringify(wire)}\n`);
}

/**
 * Writes a block on both channels Codex can honour: `stdoutPayload` as JSON on
 * stdout, and `reason` on stderr with exit 2 (Codex's secondary block signal),
 * so a partially-broken stdout still blocks.
 */
function blockOnBothChannels(stdoutPayload: object, reason: string): void {
	if (answered) return;
	try {
		process.stdout.write(`${JSON.stringify(stdoutPayload)}\n`);
	} catch {
		// stdout is gone; fall through to the stderr/exit-2 channel below.
	}
	try {
		process.stderr.write(`${reason}\n`);
	} catch {
		// Nothing further we can do.
	}
	process.exitCode = 2;
}

/** Last-resort PreToolUse block. */
function blockUnconditionally(reason: string): void {
	blockOnBothChannels(
		{
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "deny",
				permissionDecisionReason: reason,
			},
		},
		reason,
	);
}

/**
 * UserPromptSubmit prompt protection (see prompt-protection.ts). The shared
 * runner never throws; if anything around it does, the prompt is blocked with
 * the Claude-style `decision: "block"` shape plus exit 2 and a stderr reason.
 */
async function handleUserPromptSubmit(input: Record<string, unknown>): Promise<void> {
	try {
		const { outcome, wire } = await enforceCodexUserPromptSubmit(input, { startedAt, logger });
		if (wire) emit(`${JSON.stringify(wire)}\n`);
		recordHostObservation(hostObservation, {
			connector: "codex",
			event: CODEX_USER_PROMPT_SUBMIT,
			decision: outcome.decision === "block" ? "deny" : "allow",
		});
	} catch {
		const reason =
			"🛡️ Singularity AIDR failed while inspecting this prompt, so it was not sent. Try again; if this persists, run `aidr status`.";
		blockOnBothChannels({ decision: "block", reason }, reason);
	}
}

/**
 * PostToolUse output inspection (see output-protection.ts). The inspector never
 * throws; if anything around it does, the output is withheld with the block
 * shape plus exit 2 and a stderr reason, never passed through as clean.
 */
async function handlePostToolUse(input: Record<string, unknown>): Promise<void> {
	try {
		const result = await enforceCodexPostToolUse(input, { logger });
		if (result.wire) emit(`${JSON.stringify(result.wire)}\n`);
		recordHostObservation(hostObservation, {
			connector: "codex",
			event: CODEX_POST_TOOL_USE,
			toolName: typeof input.tool_name === "string" ? input.tool_name : undefined,
			decision: result.status === "clean" ? "allow" : "deny",
		});
	} catch {
		const reason =
			"Singularity AIDR failed while inspecting this tool output, so it was withheld from the model and not classified as clean.";
		blockOnBothChannels({ decision: "block", reason }, reason);
	}
}

async function main(): Promise<void> {
	await verifyArtifactIntegrityAndLog({ artifactDir: __dirname, artifactId: "codex/dist", logger });

	if (process.argv.includes("--health") || process.argv.includes("--coverage")) {
		process.stdout.write(`${JSON.stringify(getCodexConnectorCoverageEvidence(), null, 2)}\n`);
		return;
	}

	let raw = "";
	try {
		// Asynchronous: a synchronous read would hold off the watchdog for as
		// long as the host keeps stdin open, and Codex then drops the hook.
		const input = await readBoundedStdinAsync(MAX_CODEX_HOOK_INPUT_BYTES);
		if (input.status === "oversized") {
			blockUnconditionally(
				`${DENY_HEADLINE}\nSingularity AIDR could not inspect the tool call: its input exceeded the ${MAX_CODEX_HOOK_INPUT_BYTES}-byte limit, so it was blocked.`,
			);
			return;
		}
		const bytes = input.bytes;
		// Codex serializes hook input as UTF-8 JSON. Invalid bytes would decode
		// to U+FFFD and change what is inspected, so they are refused.
		if (!isValidUtf8(bytes)) {
			blockUnconditionally(
				`${DENY_HEADLINE}\nSingularity AIDR received hook input that is not valid UTF-8, so it was blocked.`,
			);
			return;
		}
		raw = bytes.toString("utf-8");
	} catch (error) {
		// We could not even read the tool call, so we cannot judge it.
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR could not read the tool call, so it was blocked.`,
		);
		logger.error("codex hook could not read stdin", { error: String(error) });
		return;
	}

	let input: Record<string, unknown>;
	try {
		const parsed: unknown = JSON.parse(raw);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
			throw new Error("hook input is not a JSON object");
		}
		input = parsed as Record<string, unknown>;
	} catch {
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR could not parse the tool call, so it was blocked.`,
		);
		return;
	}

	// Registered events: PreToolUse (tool calls), UserPromptSubmit (prompt
	// protection) and PostToolUse (tool output). Any other event means our
	// configuration is wrong; blocking is the safe reading.
	const event = typeof input.hook_event_name === "string" ? input.hook_event_name : "PreToolUse";
	currentEvent = event;
	if (event === CODEX_USER_PROMPT_SUBMIT) {
		await handleUserPromptSubmit(input);
		return;
	}
	if (event === CODEX_POST_TOOL_USE) {
		await handlePostToolUse(input);
		return;
	}
	if (event !== "PreToolUse") {
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR received an unsupported hook event, so the tool call was blocked.`,
		);
		return;
	}

	// Codex's payload schema marks every field required, so a PreToolUse event
	// always names the tool it is about to run and carries an object
	// `tool_input`. A payload missing either is not something the host can send,
	// and we cannot judge a call we cannot identify: without this check the
	// payload falls through to the detection core, which correctly finds no
	// artifacts and returns an allow, so Codex would run the call uninspected.
	// This mirrors the shape check the Claude Code entry point performs.
	if (!isWellFormedToolCall(input.tool_name, input.tool_input)) {
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR could not identify the tool call, so it was blocked.`,
		);
		return;
	}
	// NUL, unpaired surrogates or U+FFFD in a shell command: the inspected text
	// may differ from what runs, so it is denied rather than reviewed.
	if (malformedShellCommandReason(input.tool_name as string, input.tool_input)) {
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR blocked this command: it is malformed (not a string or argv, or it contains NUL or invalid UTF-8 text) and cannot be inspected reliably.`,
		);
		return;
	}

	try {
		const outcome = await enforceCodexPreToolUse(input, { logger });
		write(outcome.wire);
		recordHostObservation(hostObservation, {
			connector: "codex",
			event: "PreToolUse",
			toolName: input.tool_name as string,
			decision: outcome.decision,
		});
	} catch {
		// enforceCodexPreToolUse already fails closed internally; reaching here
		// means something outside it broke, which must still block.
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR failed while evaluating this tool call, so it was blocked.`,
		);
	}
}

/** Deadline block in the shape of the event being answered, plus exit 2 + stderr. */
function blockOnDeadline(): void {
	if (currentEvent === CODEX_USER_PROMPT_SUBMIT || currentEvent === CODEX_POST_TOOL_USE) {
		const reason =
			currentEvent === CODEX_USER_PROMPT_SUBMIT
				? "🛡️ Singularity AIDR could not finish inspecting this prompt in time, so it was not sent."
				: "Singularity AIDR could not finish inspecting this tool output in time, so it was withheld from the model and not classified as clean.";
		blockOnBothChannels({ decision: "block", reason }, reason);
		return;
	}
	blockUnconditionally(
		`${DENY_HEADLINE}\nSingularity AIDR could not finish inspecting this tool call in time, so it was blocked.`,
	);
}

const watchdog = setTimeout(
	() => {
		if (answered) return;
		blockOnDeadline();
		answered = true;
		exitAfterStdoutFlush(2);
	},
	Math.max(0, resolveHookDeadlineMs(CODEX_HOOK_DEADLINE, process.env) - (Date.now() - startedAt)),
);

main()
	.catch((error: unknown) => {
		const integrityFailure =
			error instanceof Error &&
			(error instanceof ArtifactIntegrityError || error.name === "ArtifactIntegrityError");
		const reason = integrityFailure
			? `${DENY_HEADLINE}\n${(error as Error).message}; this tool call was blocked.`
			: `${DENY_HEADLINE}\nSingularity AIDR failed to start, so the tool call was blocked.`;
		blockUnconditionally(reason);
	})
	.finally(() => {
		if (answered) return;
		answered = true;
		clearTimeout(watchdog);
		// The answer (or the empty allow) is written: exit once stdout flushes.
		exitAfterStdoutFlush();
	});
