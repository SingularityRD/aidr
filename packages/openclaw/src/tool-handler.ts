/**
 * before_tool_call handler: extracts artifacts from tool calls,
 * evaluates them through guardToolCall, returns block/pass decisions.
 */

import {
	type ApprovalStore,
	type Artifact,
	extractFromBash,
	extractFromEdit,
	extractFromUnknownTool,
	extractFromWebFetch,
	extractFromWrite,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	type Logger,
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
	async function handleToolCall(
		event: ToolCallEvent,
		ctx?: ToolCallContext,
	): Promise<BlockResult | undefined> {
		try {
			const { toolName, params } = event;

			// Core may find artifacts after normalizing connector-specific fields.
			const artifacts = mapToolToArtifacts(toolName, params) ?? [];
			const sessionId = ctx?.sessionKey ?? "unknown";
			const { verdict, actionId, responseActions } = await guardToolCall(
				{ sessionId, toolName, toolInput: params, artifacts },
				{ threatsDir, allowlistsDir, logger, agentRuntime: "openclaw" },
				approvalStore,
			);

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
				blockReason: formatAskMessage(actionId as string, verdict, artifacts, responseActions),
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
