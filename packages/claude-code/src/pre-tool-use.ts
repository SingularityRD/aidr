#!/usr/bin/env node
/**
 * Singularity AIDR PreToolUse hook entry point.
 * Reads tool call JSON from stdin, checks for threats, outputs verdict JSON to stdout.
 * Always exits 0. Input and hook failures emit a deny verdict.
 */

import { readFileSync } from "node:fs";
import {
	type Artifact,
	createHostObservation,
	evaluateToolCall,
	extractFromToolCall,
	initSentry,
	type Logger,
	recordHostObservation,
	type Verdict,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import pino from "pino";
import { addPendingApproval } from "./approval-tracker.js";
import { resolveAssetDir } from "./assets.js";
import { loadProvisionedDetectorContext } from "./detector-provisioning.js";
import { formatBlockReason } from "./format.js";

// Initialize Sentry
initSentry({ name: "aidr-claude-code-pre-tool-use" });

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

/** Gate observation contract, or null during an ordinary user session. */
const hostObservation = createHostObservation();

function makeResponse(verdict: Verdict): Record<string, unknown> {
	if (verdict.decision === "allow") return {};

	const banner = formatBlockReason(verdict);

	if (verdict.decision === "deny") {
		// For deny: short reason avoids Claude Code duplicating the banner.
		// Full banner goes in systemMessage, shown separately in the UI.
		return {
			systemMessage: banner,
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "deny",
				permissionDecisionReason: "🛡️ Singularity AIDR: Threat Blocked",
			},
		};
	}

	// For ask: full banner in permissionDecisionReason (shown once in dialog)
	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: verdict.decision,
			permissionDecisionReason: banner,
		},
	};
}

/** Fixed protocol response: never echo malformed input or exception details. */
function writeInspectionFailure(): void {
	process.stdout.write(
		`${JSON.stringify({
			systemMessage: "Singularity AIDR could not inspect this tool call. The action was blocked.",
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "deny",
				permissionDecisionReason: "Singularity AIDR inspection unavailable",
			},
		})}\n`,
	);
}

function parseToolCall(rawInput: string): Record<string, unknown> | null {
	try {
		const parsed: unknown = JSON.parse(rawInput);
		if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
		const fields = parsed as Record<string, unknown>;
		if (
			typeof fields.tool_name !== "string" ||
			fields.tool_name.trim() === "" ||
			(fields.tool_input != null &&
				(typeof fields.tool_input !== "object" || Array.isArray(fields.tool_input)))
		) {
			return null;
		}
		return fields;
	} catch {
		return null;
	}
}

async function main(): Promise<void> {
	await verifyArtifactIntegrityAndLog({
		artifactDir: __dirname,
		artifactId: "claude-code/dist",
		logger,
	});

	let rawInput: string;
	try {
		rawInput = readFileSync(0, "utf-8");
	} catch {
		writeInspectionFailure();
		return;
	}

	const toolCall = parseToolCall(rawInput);
	if (!toolCall) {
		writeInspectionFailure();
		return;
	}

	const toolName = toolCall.tool_name as string;
	const toolInput = (toolCall.tool_input ?? {}) as Record<string, unknown>;
	const sessionId = typeof toolCall.session_id === "string" ? toolCall.session_id : "unknown";
	const toolUseId = typeof toolCall.tool_use_id === "string" ? toolCall.tool_use_id : "";
	// Extraction is best-effort. Even without artifacts, the evaluator must see
	// the raw tool input for configured runtime inspection and MCP policy.
	const artifacts: Artifact[] = extractFromToolCall(toolName, toolInput);
	const provisionedDetectors = await loadProvisionedDetectorContext();
	const verdict = await evaluateToolCall(
		{ sessionId, toolName, toolInput, artifacts },
		{
			threatsDir: resolveAssetDir("threats"),
			allowlistsDir: resolveAssetDir("allowlists"),
			agentRuntime: "claude-code",
			logger,
			...provisionedDetectors,
		},
	);

	// Only track approvals for allowlistable types (content varies per call, not meaningful to allowlist)
	if (verdict.decision === "ask" && toolUseId) {
		const matched = artifacts
			.filter((a) => a.type !== "content" && verdict.artifacts.includes(a.value))
			.map((a) => ({ value: a.value, type: a.type }));
		if (matched.length > 0) {
			try {
				await addPendingApproval(
					sessionId,
					toolUseId,
					{
						threatId: verdict.matchedThreatId ?? "unknown",
						threatTitle: verdict.reasons[0] ?? verdict.category,
						artifacts: matched,
					},
					logger,
				);
			} catch {
				// Best-effort — failure doesn't affect the verdict
			}
		}
	}

	process.stdout.write(`${JSON.stringify(makeResponse(verdict))}\n`);

	// Native-host acceptance observation. Outside a gate run this is a no-op:
	// the gate's environment contract is absent, so nothing is written. Inside
	// one it records that this connector handled the case, which is the second of
	// the three observations the gate requires. It never writes the side-effect
	// sentinel, because only the host's own action may create that.
	recordHostObservation(hostObservation, {
		connector: "claude-code",
		event: "PreToolUse",
		toolName,
		decision: verdict.decision,
	});
}

main().catch(() => {
	writeInspectionFailure();
});
