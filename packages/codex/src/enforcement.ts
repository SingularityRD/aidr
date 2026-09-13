/**
 * Local enforcement for the Codex connector.
 *
 * DESIGN NOTE — Codex fails OPEN, so this hook must never rely on the host.
 *
 * Verified against codex-cli 0.141.0 (live binary, isolated CODEX_HOME):
 *   - An explicit `permissionDecision: "deny"` DOES block the tool call.
 *   - `permissionDecision: "ask"` is NOT a supported value; the hook result is
 *     treated as an error and the call PROCEEDS.
 *   - A hook that crashes, times out, or writes malformed/partial JSON is
 *     dropped and the call PROCEEDS.
 *   - An untrusted hook is not registered at all and silently does not run.
 *
 * Every one of those is fail-open. AIDR's own convention is that connector
 * entry points fail CLOSED, so this module is written so that the only way the
 * host fails open is if this process dies before it can write anything. It
 * therefore:
 *   1. runs the shared local detection core (never a remote call on the
 *      critical path),
 *   2. converts `ask` into an explicit `deny` carrying the approval reference,
 *      because Codex cannot express `ask`,
 *   3. converts internal errors into an explicit `deny` as well, so a failure
 *      in our own logic still blocks rather than passing the call through.
 */

import {
	type ApprovalStore,
	ApprovalStore as ApprovalStoreClass,
	type Artifact,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	type Logger,
	nullLogger,
} from "@singularityrd/aidr-core";
import { resolveAssetDir } from "./assets.js";
import { extractFromCodexTool } from "./extractors.js";

/**
 * Codex runs each hook in a fresh process, so an in-memory approval can never
 * survive from the blocked call to the retry. This store therefore exists for
 * API compatibility with `guardToolCall`; it is intentionally NOT a working
 * approval channel. The real, persistent, operator-controlled channel is the
 * allowlist, which the block message points at.
 */
const EPHEMERAL_APPROVALS = new ApprovalStoreClass();

export interface CodexEnforcementOptions {
	logger?: Logger;
	threatsDir?: string;
	allowlistsDir?: string;
	approvalStore?: ApprovalStore;
}

/** The wire shape Codex accepts for a PreToolUse decision. */
export interface CodexHookWireOutput {
	hookSpecificOutput: {
		hookEventName: "PreToolUse";
		permissionDecision: "deny";
		/** Must be non-empty: Codex fails open on an empty reason. */
		permissionDecisionReason: string;
	};
}

export type CodexWireResult = CodexHookWireOutput | Record<string, never>;

export interface CodexEnforcementResult {
	/** What AIDR decided, before translation to Codex's dialect. */
	decision: "allow" | "deny" | "ask";
	reasonCode: string;
	/** Exact object to print on stdout. */
	wire: CodexWireResult;
}

export const DENY_HEADLINE = "🛡️ Singularity AIDR: Threat Blocked";

/**
 * Convert a verdict into Codex's wire format.
 *
 * Returns `{}` for allow — Codex ignores an empty result and proceeds, which is
 * the intended meaning of allow.
 */
export function toWireOutput(decision: "allow" | "deny" | "ask", message: string): CodexWireResult {
	if (decision === "allow") return {};

	// Both deny and ask become an explicit deny. Codex has no working `ask`
	// verb: the documented "ask" enum value is rejected and fails open, so
	// sending it would let the call through. The approval reference travels in
	// the reason instead, which is the only channel Codex gives us. The model
	// cannot act on that reference — approval is operator-held and out-of-band.
	const reason = message.trim() || DENY_HEADLINE;
	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
			permissionDecisionReason: reason,
		},
	};
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

/**
 * Evaluate one Codex PreToolUse payload and return the decision plus the exact
 * object to print on stdout.
 */
export async function enforceCodexPreToolUse(
	input: Record<string, unknown>,
	options: CodexEnforcementOptions = {},
): Promise<CodexEnforcementResult> {
	const logger = options.logger ?? nullLogger;
	const toolName = typeof input.tool_name === "string" ? input.tool_name : "";
	const toolInput =
		input.tool_input && typeof input.tool_input === "object" && !Array.isArray(input.tool_input)
			? (input.tool_input as Record<string, unknown>)
			: {};
	const sessionId = typeof input.session_id === "string" ? input.session_id : "codex-session";

	try {
		const artifacts: Artifact[] = extractFromCodexTool(toolName, toolInput);
		// Core normalizes connector aliases before deciding whether the call has
		// inspectable artifacts. An empty connector result is not an allow verdict.
		const { verdict, actionId, responseActions } = await guardToolCall(
			{ sessionId, toolName, toolInput, artifacts },
			{
				threatsDir: options.threatsDir ?? resolveAssetDir("threats"),
				allowlistsDir: options.allowlistsDir ?? resolveAssetDir("allowlists"),
				logger,
				agentRuntime: "codex",
			},
			options.approvalStore ?? EPHEMERAL_APPROVALS,
		);

		if (verdict.decision === "allow") {
			return { decision: "allow", reasonCode: "allowed", wire: {} };
		}

		if (verdict.decision === "deny") {
			return {
				decision: "deny",
				reasonCode: verdict.category || "aidr_denied",
				wire: toWireOutput("deny", formatDenyMessage(verdict, responseActions)),
			};
		}

		// ask -> explicit deny. The banner already tells the operator what to do
		// and states that the model cannot approve its own action.
		return {
			decision: "ask",
			reasonCode: "aidr_requires_approval",
			wire: toWireOutput(
				"ask",
				formatAskMessage(actionId as string, verdict, artifacts, responseActions),
			),
		};
	} catch (error) {
		// Fail closed. An explicit deny is the only reliable block Codex offers,
		// so an internal error must produce one rather than an empty response.
		logger.error("Singularity AIDR codex hook failed closed", {
			error: errorMessage(error),
			tool: toolName,
		});
		return {
			decision: "deny",
			reasonCode: "aidr_internal_error",
			wire: toWireOutput(
				"deny",
				`${DENY_HEADLINE}\nSingularity AIDR could not evaluate this tool call, so it was blocked. (${errorMessage(error)})`,
			),
		};
	}
}
