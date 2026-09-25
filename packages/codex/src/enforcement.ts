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
	type GuardResult,
	guardToolCall,
	type Logger,
	loadProvisionedDetectorContext,
	nullLogger,
} from "@singularityrd/aidr-core";
import { resolveAssetDir } from "./assets.js";
import { extractFromCodexTool } from "./extractors.js";

/**
 * Codex runs each hook in a fresh process, so an in-memory approval can never
 * survive from the blocked call to the retry. This store therefore exists for
 * API compatibility with `guardToolCall`; it is intentionally NOT a working
 * approval channel. The real, persistent, operator-controlled channel is the
 * file-backed operator approval store that `guardToolCall` writes every ask to:
 * the operator runs `aidr approve <actionId>` in their own terminal and the
 * next identical call (same tool, input and Codex session) is released once.
 */
const EPHEMERAL_APPROVALS = new ApprovalStoreClass();

export interface CodexEnforcementOptions {
	logger?: Logger;
	threatsDir?: string;
	allowlistsDir?: string;
	approvalStore?: ApprovalStore;
}

/** The wire shape Codex accepts for a PreToolUse block. */
export interface CodexHookWireOutput {
	/** Absent for allow: Codex 0.141.0 accepts empty stdout as a no-op allow. */
	hookSpecificOutput?: {
		hookEventName: "PreToolUse";
		permissionDecision: "deny";
		permissionDecisionReason: string;
	};
}

export type CodexWireResult = CodexHookWireOutput;

export interface CodexEnforcementResult {
	/** What AIDR decided, before translation to Codex's dialect. */
	decision: "allow" | "deny" | "ask";
	reasonCode: string;
	/** Host wire result; an empty object means the CLI emits no stdout on allow. */
	wire: CodexWireResult;
}

export const DENY_HEADLINE = "🛡️ Singularity AIDR: Threat Blocked";

/**
 * Convert a verdict into Codex's wire format.
 *
 * Codex 0.141.0 has no supported bare allow response: it treats
 * `permissionDecision: "allow"` without `updatedInput` as an error and passes
 * the call through. For an allowed call, return an empty object so the CLI
 * emits the host's documented empty-stdout no-op; blocks use explicit deny.
 */
export function toWireOutput(decision: "allow" | "deny" | "ask", message: string): CodexWireResult {
	if (decision === "allow") {
		return {};
	}

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

/** Translate a guard result into Codex's decision and wire output. */
function resultForGuard(guard: GuardResult, artifacts: Artifact[]): CodexEnforcementResult {
	const { verdict, actionId, responseActions } = guard;
	if (verdict.decision === "allow" && verdict.transformedInput) {
		// Unreachable while supportsInputRewrite is unset; never run the
		// original input if a redacted replacement was produced anyway.
		return {
			decision: "deny",
			reasonCode: "dlp",
			wire: toWireOutput(
				"deny",
				`${DENY_HEADLINE}\nDLP redaction required; Codex cannot safely rewrite tool input.`,
			),
		};
	}

	if (verdict.decision === "allow") {
		return {
			decision: "allow",
			reasonCode: "allowed",
			wire: toWireOutput("allow", ""),
		};
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
			formatAskMessage(
				actionId as string,
				verdict,
				artifacts,
				responseActions,
				guard.pendingRecorded,
				guard.dashboardApproval,
			),
		),
	};
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
		// Operator-provisioned tenant detector policy for this runtime. Absent
		// policy means an empty context (unchanged evaluation); a present-but-
		// invalid policy throws and the catch below converts it into an explicit
		// deny, which is the only reliable block Codex offers.
		const provisioned = await loadProvisionedDetectorContext("codex");
		// DLP redaction is deliberately NOT applied through Codex `updatedInput`,
		// so `supportsInputRewrite` is not set and core enforces a redact outcome
		// as a deny. Codex 0.141.0 documents `permissionDecision:"allow"` +
		// `updatedInput`, but (CODEX_HOOKS_0.141.0_REFERENCE.md §4.4, §4.7, §8):
		//   - a rewrite Codex rejects (e.g. a Bash/apply_patch input without a
		//     string `command`) marks the hook Failed and the ORIGINAL input runs;
		//   - competing rewrites resolve by completion order, so another hook's
		//     rewrite, built from the original input, can replace ours;
		//   - the rewrite round trip has not been observed in a live session.
		// Each of those would release the unredacted value, so a deny is the only
		// enforcement Codex offers for a redaction today.
		// Core normalizes connector aliases before deciding whether the call has
		// inspectable artifacts. An empty connector result is not an allow verdict.
		const guardResult = await guardToolCall(
			{ sessionId, toolName, toolInput, artifacts },
			{
				threatsDir: options.threatsDir ?? resolveAssetDir("threats"),
				allowlistsDir: options.allowlistsDir ?? resolveAssetDir("allowlists"),
				logger,
				agentRuntime: "codex",
				// Codex reports the session directory; it selects repository-scoped profiles.
				workingDirectory: typeof input.cwd === "string" ? input.cwd : undefined,
				...provisioned,
			},
			options.approvalStore ?? EPHEMERAL_APPROVALS,
		);

		return resultForGuard(guardResult, artifacts);
	} catch (error) {
		// Fail closed. An explicit deny is the only reliable block Codex offers,
		// so an internal error must produce one even if diagnostic logging fails.
		// Exception messages can contain tool input or secrets; never return them
		// to the model in the hook decision.
		try {
			logger.error("Singularity AIDR codex hook failed closed", {
				errorType: error instanceof Error ? error.name : typeof error,
				tool: toolName,
			});
		} catch {
			// A broken logger must not turn a deny into a crashed, fail-open hook.
		}
		return {
			decision: "deny",
			reasonCode: "aidr_internal_error",
			wire: toWireOutput(
				"deny",
				`${DENY_HEADLINE}\nSingularity AIDR could not evaluate this tool call, so it was blocked.`,
			),
		};
	}
}
