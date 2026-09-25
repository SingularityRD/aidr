/**
 * before_tool_call handler: extracts artifacts from tool calls,
 * evaluates them through guardToolCall, returns block/pass decisions.
 */

import {
	type ApprovalStore,
	type Artifact,
	createHostObservation,
	extractFromBash,
	extractFromEdit,
	extractFromUnknownTool,
	extractFromWebFetch,
	extractFromWrite,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	type Logger,
	loadProvisionedDetectorContext,
	recordHostObservation,
} from "@singularityrd/aidr-core";

export interface ToolCallEvent {
	toolName: string;
	params: Record<string, unknown>;
}

export interface ToolCallContext {
	sessionKey?: string;
}

export interface BlockResult {
	block: true;
	blockReason: string;
}

function extractFilePaths(patch: string): Artifact[] {
	// OpenClaw apply_patch uses unified diff format; extract file paths from --- and +++ lines
	const artifacts: Artifact[] = [];
	for (const line of patch.split("\n")) {
		const match = line.match(/^(?:---|\+\+\+)\s+(?:a\/|b\/)?(.+)/);
		if (match?.[1] && match[1] !== "/dev/null") {
			artifacts.push({ type: "file_path", value: match[1], context: "apply_patch" });
		}
	}
	return artifacts;
}

function mapToolToArtifacts(toolName: string, params: Record<string, unknown>): Artifact[] | null {
	switch (toolName) {
		case "exec": {
			const command = (params.command ?? "") as string;
			return command ? extractFromBash(command) : null;
		}
		case "web_fetch":
			return extractFromWebFetch({ url: params.url });
		case "write":
			return extractFromWrite({ file_path: params.path, content: params.content });
		case "edit":
			return extractFromEdit({ file_path: params.path, new_string: params.new_string });
		case "read": {
			const path = (params.path ?? "") as string;
			return path ? [{ type: "file_path", value: path, context: "read" }] : null;
		}
		case "apply_patch": {
			const patch = (params.patch ?? "") as string;
			return patch ? extractFilePaths(patch) : null;
		}
		default:
			return extractFromUnknownTool(`openclaw:${toolName || "unknown"}`, params);
	}
}

export function createToolCallHandler(
	approvalStore: ApprovalStore,
	logger: Logger,
	threatsDir: string,
	allowlistsDir: string,
): (event: ToolCallEvent, ctx?: ToolCallContext) => Promise<BlockResult | undefined> {
	const hostObservation = createHostObservation();
	async function handleToolCall(
		event: ToolCallEvent,
		ctx?: ToolCallContext,
	): Promise<BlockResult | undefined> {
		const toolName = typeof event?.toolName === "string" ? event.toolName : "unknown";
		// Record delivery to the enforcement boundary before any parsing, policy
		// loading or evaluation can fail. The outcome is a separate, optional row.
		recordHostObservation(hostObservation, {
			connector: "openclaw",
			event: "before_tool_call",
			toolName,
		});
		try {
			const params = event.params;

			// Core may find artifacts after normalizing connector-specific fields.
			const artifacts = mapToolToArtifacts(toolName, params) ?? [];
			const sessionId = ctx?.sessionKey ?? "unknown";

			// Operator-provisioned tenant detector policy for this runtime. No
			// provisioned policy means an empty context, exactly as before; a
			// provisioning failure throws and is caught below, which denies the
			// call instead of evaluating it without the tenant's policy.
			const provisioned = await loadProvisionedDetectorContext("openclaw");

			const { verdict, actionId, responseActions, pendingRecorded, dashboardApproval } =
				await guardToolCall(
					{ sessionId, toolName, toolInput: params, artifacts },
					{ threatsDir, allowlistsDir, logger, agentRuntime: "openclaw", ...provisioned },
					approvalStore,
				);
			recordHostObservation(hostObservation, {
				connector: "openclaw",
				event: "before_tool_call_outcome",
				toolName,
				decision: verdict.decision,
			});

			if (verdict.decision === "allow") return undefined;

			// Pass the response actions through so the user is told what the runtime
			// actually did (e.g. that a copy of the file was preserved). Without this
			// the response happens silently.
			if (verdict.decision === "deny") {
				return { block: true, blockReason: formatDenyMessage(verdict, responseActions) };
			}

			// ask — actionId is always set for ask verdicts
			return {
				block: true,
				blockReason: formatAskMessage(
					actionId as string,
					verdict,
					artifacts,
					responseActions,
					pendingRecorded,
					dashboardApproval,
				),
			};
		} catch (e) {
			// Evaluation failures must never authorize execution.
			logger.error("tool-handler error, failing closed", { error: String(e) });
			return {
				block: true,
				blockReason: "Singularity AIDR could not evaluate this tool call; execution was denied.",
			};
		}
	}

	return handleToolCall;
}
