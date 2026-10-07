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

import { readFileSync } from "node:fs";
import {
	ArtifactIntegrityError,
	createHostObservation,
	createLogger,
	type Logger,
	recordHostObservation,
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

function write(wire: CodexWireResult): void {
	// Codex 0.141.0 treats a bare `permissionDecision: "allow"` as an
	// unsupported output and fails open. Empty stdout is its documented no-op
	// allow shape, so only deny decisions are written.
	if (!wire.hookSpecificOutput) return;
	process.stdout.write(`${JSON.stringify(wire)}\n`);
}

/**
 * Writes a block on both channels Codex can honour: `stdoutPayload` as JSON on
 * stdout, and `reason` on stderr with exit 2 (Codex's secondary block signal),
 * so a partially-broken stdout still blocks.
 */
function blockOnBothChannels(stdoutPayload: object, reason: string): void {
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
		if (wire) process.stdout.write(`${JSON.stringify(wire)}\n`);
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
		if (result.wire) process.stdout.write(`${JSON.stringify(result.wire)}\n`);
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
		raw = readFileSync(0, "utf-8");
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
	if (
		typeof input.tool_name !== "string" ||
		input.tool_name.trim() === "" ||
		input.tool_input === null ||
		typeof input.tool_input !== "object" ||
		Array.isArray(input.tool_input)
	) {
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR could not identify the tool call, so it was blocked.`,
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

main().catch((error: unknown) => {
	const integrityFailure =
		error instanceof Error &&
		(error instanceof ArtifactIntegrityError || error.name === "ArtifactIntegrityError");
	const reason = integrityFailure
		? `${DENY_HEADLINE}\n${(error as Error).message}; this tool call was blocked.`
		: `${DENY_HEADLINE}\nSingularity AIDR failed to start, so the tool call was blocked.`;
	blockUnconditionally(reason);
});
