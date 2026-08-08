#!/usr/bin/env node
/**
 * Singularity AIDR PreToolUse hook entry point.
 * Reads tool call JSON from stdin, checks for threats, outputs verdict JSON to stdout.
 * Always exits 0 — even on errors, outputs an allow verdict.
 */

import { readFileSync } from "node:fs";
import {
	type Artifact,
	allowVerdict,
	evaluateToolCall,
	extractFromToolCall,
	initSentry,
	type Logger,
	type Verdict,
} from "@singularityrd/aidr-core";
import pino from "pino";
import { addPendingApproval } from "./approval-tracker.js";
import { resolveAssetDir } from "./assets.js";
import { formatBlockReason } from "./format.js";

// Initialize Sentry
initSentry({ name: "aidr-claude-code-pre-tool-use" });

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

async function maybeVerifyIntegrity(): Promise<void> {
	try {
		// biome-ignore lint/suspicious/noExplicitAny: Transitional wiring
		const core = (await import("@singularityrd/aidr-core")) as any;
		const fn = core?.verifyArtifactIntegrityAndLog as
			| ((args: { artifactDir: string; artifactId: string; logger?: unknown }) => Promise<unknown>)
			| undefined;
		if (typeof fn === "function") {
			await fn({ artifactDir: __dirname, artifactId: "claude-code/dist", logger });
		}
	} catch {
		// Fail open
	}
}

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

async function main(): Promise<void> {
	await maybeVerifyIntegrity();

	let rawInput: string;
	try {
		rawInput = readFileSync(0, "utf-8");
	} catch {
		process.stdout.write("{}\n");
		return;
	}

	let toolCall: Record<string, unknown>;
	try {
		toolCall = JSON.parse(rawInput) as Record<string, unknown>;
	} catch (e) {
		process.stdout.write(
			`${JSON.stringify(makeResponse(allowVerdict(`Failed to parse input: ${e}`)))}\n`,
		);
		return;
	}

	const toolName = (toolCall.tool_name ?? "") as string;
	const toolInput = (toolCall.tool_input ?? {}) as Record<string, unknown>;
	const sessionId = (toolCall.session_id ?? "unknown") as string;
	const toolUseId = (toolCall.tool_use_id ?? "") as string;
	// Extract artifacts based on tool type (with MCP/unknown fallback)
	const artifacts: Artifact[] = extractFromToolCall(toolName, toolInput);

	if (artifacts.length === 0) {
		process.stdout.write("{}\n");
		return;
	}
	const verdict = await evaluateToolCall(
		{ sessionId, toolName, toolInput, artifacts },
		{
			threatsDir: resolveAssetDir("threats"),
			allowlistsDir: resolveAssetDir("allowlists"),
			agentRuntime: "claude-code",
			logger,
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
}

main().catch((e) => {
	process.stdout.write(`${JSON.stringify(makeResponse(allowVerdict(`Internal error: ${e}`)))}\n`);
});
