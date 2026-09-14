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
 * or equivalently via `~/.codex/hooks.json`.
 *
 * Codex fails OPEN in every failure mode except a well-formed explicit deny, so
 * this entry point is written to always produce a decision. Even an unexpected
 * throw is converted into a deny on stdout, with a secondary stderr write so
 * that a partially-broken stdout still blocks (Codex treats `exit 2` with a
 * non-empty stderr as a block).
 */

import { readFileSync } from "node:fs";
import { createLogger, type Logger } from "@singularityrd/aidr-core";
import { getCodexConnectorCoverageEvidence } from "./coverage.js";
import { type CodexWireResult, DENY_HEADLINE, enforceCodexPreToolUse } from "./enforcement.js";

// Codex surfaces stderr on a non-zero exit as the block reason, so diagnostics
// must never share the channel that carries a decision.
const logger: Logger = createLogger({ name: "aidr-codex", level: "warn" });

function write(wire: CodexWireResult): void {
	process.stdout.write(`${JSON.stringify(wire)}\n`);
}

/** Last-resort block. Writes both channels Codex can honour. */
function blockUnconditionally(reason: string): void {
	try {
		write({
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "deny",
				permissionDecisionReason: reason,
			},
		});
	} catch {
		// stdout is gone; fall through to the stderr/exit-2 channel below.
	}
	try {
		process.stderr.write(`${reason}\n`);
	} catch {
		// Nothing further we can do.
	}
	// Exit 2 with non-empty stderr is Codex's secondary block signal.
	process.exitCode = 2;
}

async function main(): Promise<void> {
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
	} catch (error) {
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR could not parse the tool call, so it was blocked. (${String(error)})`,
		);
		return;
	}

	// The Codex schema only ever sends PreToolUse here, but a mismatched event
	// means our configuration is wrong; blocking is the safe reading.
	const event = typeof input.hook_event_name === "string" ? input.hook_event_name : "PreToolUse";
	if (event !== "PreToolUse") {
		write({});
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
		(input.tool_input != null &&
			(typeof input.tool_input !== "object" || Array.isArray(input.tool_input)))
	) {
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR could not identify the tool call, so it was blocked.`,
		);
		return;
	}

	try {
		const outcome = await enforceCodexPreToolUse(input, { logger });
		write(outcome.wire);
	} catch (error) {
		// enforceCodexPreToolUse already fails closed internally; reaching here
		// means something outside it broke, which must still block.
		blockUnconditionally(
			`${DENY_HEADLINE}\nSingularity AIDR failed while evaluating this tool call, so it was blocked. (${String(error)})`,
		);
	}
}

main().catch((error) => {
	blockUnconditionally(
		`${DENY_HEADLINE}\nSingularity AIDR failed to start, so the tool call was blocked. (${String(error)})`,
	);
});
