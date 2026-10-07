#!/usr/bin/env node
/**
 * Singularity AIDR PreToolUse hook entry point.
 * Reads tool call JSON from stdin, checks for threats, outputs verdict JSON to stdout.
 * Always exits 0. Input and hook failures emit a deny verdict, and so does an
 * evaluation that outlives the internal deadline (a host-side hook timeout
 * would otherwise let the call through uninspected).
 */

import {
	type Artifact,
	createHookResponder,
	createHostObservation,
	describeSecureCodeWarnings,
	evaluateToolCall,
	extractFromToolCall,
	formatDashboardApprovalNotice,
	initSentry,
	isWellFormedToolCall,
	type Logger,
	malformedShellCommandReason,
	recordHostObservation,
	resolveAskWithDashboardApproval,
	type Verdict,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import pino from "pino";
import { addPendingApproval } from "./approval-tracker.js";
import { resolveAssetDir } from "./assets.js";
import { loadProvisionedDetectorContext } from "./detector-provisioning.js";
import { formatBlockReason } from "./format.js";
import {
	MAX_PRE_TOOL_INPUT_BYTES,
	readStdinJson,
	resolvePreToolUseDeadlineMs,
} from "./hook-input.js";

// Initialize Sentry
initSentry({ name: "aidr-claude-code-pre-tool-use" });

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

/** Gate observation contract, or null during an ordinary user session. */
const hostObservation = createHostObservation();

/**
 * DLP redaction: hand Claude Code the redacted input with no permissionDecision.
 *
 * Verified against Claude Code 2.1.282: a PreToolUse `updatedInput` without a
 * `permissionDecision` replaces the tool input and the call then goes through
 * the user's normal permission flow. Adding `permissionDecision: "allow"` would
 * also auto-approve the call and bypass that flow, which a redaction must not do.
 */
function redactedResponse(verdict: Verdict, updatedInput: Record<string, unknown>) {
	const notice = secureCodeNotice(verdict);
	const systemMessage =
		`🛡️ Singularity AIDR redacted sensitive data from this tool call before it ran. ${verdict.reasons[0] ?? ""}`.trim();
	const additionalContext =
		"Singularity AIDR data-loss prevention replaced sensitive values in this tool input with redaction markers before it ran. Do not try to recover or re-insert the original values.";
	return {
		systemMessage: notice ? `${systemMessage}\n${notice.userMessage}` : systemMessage,
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			updatedInput,
			additionalContext: notice
				? `${additionalContext}\n${notice.modelContext}`
				: additionalContext,
		},
	};
}

/** Secure-code guardrail notice for the user and the model, when the verdict carries findings. */
function secureCodeNotice(verdict: Verdict): ReturnType<typeof describeSecureCodeWarnings> | null {
	return verdict.warnings && verdict.warnings.length > 0
		? describeSecureCodeWarnings(verdict.warnings)
		: null;
}

/**
 * An allowed call with secure-code findings (`secure_code.action: "warn"`):
 * no `permissionDecision`, so the call goes through the user's normal
 * permission flow unchanged; `systemMessage` tells the user and
 * `additionalContext` tells the model what to fix.
 */
function warnedResponse(verdict: Verdict): Record<string, unknown> {
	const notice = secureCodeNotice(verdict);
	if (!notice) return {};
	return {
		systemMessage: notice.userMessage,
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			additionalContext: notice.modelContext,
		},
	};
}

/** Managed-mode dashboard approval details for an `ask` (see `resolveAskWithDashboardApproval`). */
interface DashboardNote {
	/** User-facing request id / outcome line, or null when there is nothing to say. */
	notice: string | null;
	/** Only a dashboard approval may release the call: block instead of asking. */
	dashboardOnly: boolean;
}

function makeResponse(
	verdict: Verdict,
	dashboard: DashboardNote = { notice: null, dashboardOnly: false },
): Record<string, unknown> {
	if (verdict.decision === "allow") {
		return verdict.transformedInput
			? redactedResponse(verdict, verdict.transformedInput)
			: warnedResponse(verdict);
	}

	// A blocked or held call that also carries secure-code findings lists them
	// under the banner.
	const banner = verdict.warnings?.length
		? `${formatBlockReason(verdict)}\n${describeSecureCodeWarnings(verdict.warnings, false).userMessage}`
		: formatBlockReason(verdict);

	if (verdict.decision === "ask" && dashboard.dashboardOnly) {
		// operator_approvals.dashboard_only: the native dialog would let the local
		// user approve, so the call is blocked and only the dashboard can release it.
		const notice = dashboard.notice ?? "Only an AIDR dashboard approval can release this action.";
		return {
			systemMessage: `${banner}\n${notice}`,
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "deny",
				permissionDecisionReason: `🛡️ Singularity AIDR: approval required in the AIDR dashboard\n${notice}`,
			},
		};
	}

	if (verdict.decision === "deny") {
		// For deny: short reason avoids Claude Code duplicating the banner.
		// Full banner goes in systemMessage, shown separately in the UI.
		return {
			systemMessage: banner,
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "deny",
				permissionDecisionReason:
					verdict.source === "agent_profile"
						? "🛡️ Singularity AIDR: Blocked by agent permission profile"
						: "🛡️ Singularity AIDR: Threat Blocked",
			},
		};
	}

	// For ask: full banner in permissionDecisionReason (shown once in dialog)
	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: verdict.decision,
			permissionDecisionReason: dashboard.notice ? `${banner}\n${dashboard.notice}` : banner,
		},
	};
}

/**
 * The hook answers exactly once, then exits once stdout has flushed: pending
 * sockets or timers from the evaluation must not keep the process alive past
 * the host timeout. The internal deadline, shorter than the host's hook
 * timeout, denies a hung evaluation (e.g. a stalled reputation lookup) instead
 * of letting the host kill the hook, which would let the call through
 * uninspected. A late evaluation result after the deadline is dropped.
 */
const responder = createHookResponder({
	deadlineMs: resolvePreToolUseDeadlineMs(process.env),
	onDeadline: () => ({
		stdout: `${JSON.stringify(
			denyResponse(
				"Singularity AIDR could not finish inspecting this tool call in time. The action was blocked.",
				"Singularity AIDR inspection timed out",
			),
		)}\n`,
	}),
});

function respond(response: Record<string, unknown>): boolean {
	return responder.answer({ stdout: `${JSON.stringify(response)}\n` });
}

/** Fixed deny response: never echo malformed input or exception details. */
function denyResponse(systemMessage: string, reason: string): Record<string, unknown> {
	return {
		systemMessage,
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
			permissionDecisionReason: reason,
		},
	};
}

function writeInspectionFailure(): void {
	respond(
		denyResponse(
			"Singularity AIDR could not inspect this tool call. The action was blocked.",
			"Singularity AIDR inspection unavailable",
		),
	);
}

/**
 * Claude Code always sends a tool name and an object `tool_input`. A payload
 * missing either (or with a null/array/string input) is not something the host
 * sends and cannot be judged, so it is denied (the shape check every connector
 * shares, see `isWellFormedToolCall`).
 */
function parseToolCall(parsed: unknown): Record<string, unknown> | null {
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
	const fields = parsed as Record<string, unknown>;
	return isWellFormedToolCall(fields.tool_name, fields.tool_input) ? fields : null;
}

/**
 * Read and validate the hook payload from stdin under the byte ceiling. On any
 * failure the fixed deny response has already been written and null returned.
 */
async function readToolCall(): Promise<Record<string, unknown> | null> {
	let input: Awaited<ReturnType<typeof readStdinJson>>;
	try {
		input = await readStdinJson(MAX_PRE_TOOL_INPUT_BYTES);
	} catch {
		writeInspectionFailure();
		return null;
	}
	if (input.status === "oversized") {
		respond(
			denyResponse(
				`Singularity AIDR could not inspect this tool call: its input exceeded the ${MAX_PRE_TOOL_INPUT_BYTES}-byte inspection limit. The action was blocked.`,
				"Singularity AIDR input too large to inspect",
			),
		);
		return null;
	}
	const toolCall = input.status === "parsed" ? parseToolCall(input.value) : null;
	if (!toolCall) writeInspectionFailure();
	return toolCall;
}

async function main(): Promise<void> {
	await verifyArtifactIntegrityAndLog({
		artifactDir: __dirname,
		artifactId: "claude-code/dist",
		logger,
	});

	const toolCall = await readToolCall();
	if (!toolCall) return;

	const toolName = toolCall.tool_name as string;
	const toolInput = toolCall.tool_input as Record<string, unknown>;
	// NUL, unpaired surrogates or U+FFFD in a shell command mean the text we
	// inspect may not be what the shell runs: deny, never downgrade to ask.
	if (malformedShellCommandReason(toolName, toolInput)) {
		respond(
			denyResponse(
				"Singularity AIDR blocked this command: it is malformed (not a string or argv, or it contains NUL or invalid UTF-8 text) and cannot be inspected reliably.",
				"Singularity AIDR malformed command",
			),
		);
		return;
	}
	const sessionId = typeof toolCall.session_id === "string" ? toolCall.session_id : "unknown";
	const toolUseId = typeof toolCall.tool_use_id === "string" ? toolCall.tool_use_id : "";
	// Host-reported session directory: selects repository-scoped agent profiles.
	const workingDirectory = typeof toolCall.cwd === "string" ? toolCall.cwd : undefined;
	// Extraction is best-effort. Even without artifacts, the evaluator must see
	// the raw tool input for configured runtime inspection and MCP policy.
	const artifacts: Artifact[] = extractFromToolCall(toolName, toolInput);
	const provisionedDetectors = await loadProvisionedDetectorContext();
	const evaluated = await evaluateToolCall(
		{ sessionId, toolName, toolInput, artifacts },
		{
			threatsDir: resolveAssetDir("threats"),
			allowlistsDir: resolveAssetDir("allowlists"),
			agentRuntime: "claude-code",
			workingDirectory,
			logger,
			// Claude Code applies PreToolUse `updatedInput` (see redactedResponse).
			supportsInputRewrite: true,
			...provisionedDetectors,
		},
	);
	// The deadline already denied this call; do not record approvals for it.
	if (responder.answered) return;

	// Managed mode: submit the ask to the AIDR dashboard, or release it with a
	// verified single-use approval token (this hook is one process per call, so
	// the request id and the spent nonce are persisted by core). Bounded, and a
	// failure leaves the verdict unchanged.
	const resolution = await resolveAskWithDashboardApproval(
		{ sessionId, toolName, toolInput, artifacts },
		evaluated,
		{ agentRuntime: "claude-code", logger },
	);
	if (responder.answered) return;
	const verdict = resolution.verdict;
	const dashboard: DashboardNote = {
		notice: formatDashboardApprovalNotice(resolution.dashboardApproval),
		dashboardOnly: resolution.dashboardOnly,
	};

	// Only track approvals for allowlistable types (content varies per call, not meaningful to allowlist).
	// Under dashboard_only the native dialog is never shown, so there is nothing to track.
	if (verdict.decision === "ask" && toolUseId && !dashboard.dashboardOnly) {
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

	if (!respond(makeResponse(verdict, dashboard))) return;

	// Native-host acceptance observation. Outside a gate run this is a no-op:
	// the gate's environment contract is absent, so nothing is written. Inside
	// one it records that this connector handled the case, which is the second of
	// the three observations the gate requires. It never writes the side-effect
	// sentinel, because only the host's own action may create that. The record
	// is synchronous, so it completes before the flushed answer exits.
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
