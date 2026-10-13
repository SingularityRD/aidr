/**
 * before_tool_call handler: extracts artifacts from tool calls,
 * evaluates them through guardToolCall, returns block/pass decisions.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import {
	type ApprovalStore,
	type Artifact,
	canonicalMcpToolName,
	commandFromValue,
	createHostObservation,
	extractFromBash,
	extractFromEdit,
	extractFromUnknownTool,
	extractFromWebFetch,
	extractFromWrite,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	isWellFormedToolCall,
	type Logger,
	loadKnownMcpServers,
	loadProvisionedDetectorContext,
	malformedShellCommandReason,
	mcpIdentityFromOpenClawName,
	recordHostObservation,
} from "@singularityrd/aidr-core";
import {
	type ExecSurfaceResolution,
	PASSTHROUGH,
	PendingInputLines,
	replInputArtifacts,
	resolveExecNamedTool,
	resolveNodes,
	resolveProcess,
	resolveTerminal,
} from "./process-input.js";

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
			// String or argv command; anything else yields no artifacts here and is
			// denied as `malformed_command` by core's shell normalization.
			const result = commandFromValue(params.command);
			return result.ok && result.command ? extractFromBash(result.command) : null;
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
		case "ls": {
			// Directory listing: the listed path goes through the same file-path
			// rules as a read.
			const path = typeof params.path === "string" ? params.path : "";
			return path ? [{ type: "file_path", value: path, context: "list" }] : null;
		}
		default: {
			const artifacts = extractFromUnknownTool(`openclaw:${toolName || "unknown"}`, params);
			// The generic extractor types a string `command` as a command but never
			// joins an argv array; do that here so `command: ["rm", "-rf", "/"]`
			// is inspected as the command it runs.
			if (Array.isArray(params.command)) {
				const argv = commandFromValue(params.command);
				if (argv.ok && argv.command) artifacts.push(...extractFromBash(argv.command));
			}
			return artifacts;
		}
	}
}

/**
 * Route tools that run commands or write to a running process onto the shell
 * inspection path (see process-input.ts). `process`, `terminal` and `nodes` are
 * OpenClaw built-ins; any other tool whose name says it executes commands is
 * held to the same rule.
 */
function resolveExecSurface(
	toolName: string,
	params: Record<string, unknown>,
	pendingLines: PendingInputLines,
	scope: string,
): ExecSurfaceResolution {
	switch (toolName) {
		case "process":
			return resolveProcess(params, pendingLines, scope);
		case "terminal":
			return resolveTerminal(params, pendingLines, scope);
		case "nodes":
			return resolveNodes(params);
		case "exec":
		case "web_fetch":
		case "write":
		case "edit":
		case "read":
		case "apply_patch":
		case "ls":
			return PASSTHROUGH;
		default:
			return resolveExecNamedTool(toolName, params);
	}
}

interface EvaluatedCall {
	toolName: string;
	params: Record<string, unknown>;
	extraArtifacts: Artifact[];
}

/**
 * The call core evaluates: shell input becomes an `exec` of that input (plus
 * its REPL inline-code forms when it was written to a running process); any
 * other call is evaluated as sent.
 */
function evaluatedCall(
	toolName: string,
	params: Record<string, unknown>,
	surface: ExecSurfaceResolution,
): EvaluatedCall {
	if (surface.kind !== "shell") return { toolName, params, extraArtifacts: [] };
	return {
		toolName: "exec",
		params: { command: surface.command },
		extraArtifacts: surface.stdin ? replInputArtifacts(surface.command) : [],
	};
}

/**
 * OpenClaw registers bundle MCP tools as `<server>__<tool>` (server sanitized
 * `[^A-Za-z0-9_-]` → `-`); built-in tools never contain `__`. Such a call is
 * evaluated under the canonical `mcp__<server>__<tool>` name so MCP server and
 * tool policy applies; the arguments are unchanged.
 */
async function policyToolName(toolName: string): Promise<string> {
	if (!toolName.includes("__") || toolName.startsWith("mcp__")) return toolName;
	const known = await loadKnownMcpServers([join(homedir(), ".openclaw", "openclaw.json")]);
	const identity = mcpIdentityFromOpenClawName(toolName, known.names);
	return identity ? canonicalMcpToolName(identity) : toolName;
}

export function createToolCallHandler(
	approvalStore: ApprovalStore,
	logger: Logger,
	threatsDir: string,
	allowlistsDir: string,
): (event: ToolCallEvent, ctx?: ToolCallContext) => Promise<BlockResult | undefined> {
	const hostObservation = createHostObservation();
	const pendingLines = new PendingInputLines();
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
		// A call without a tool name or with non-object params (a string, array,
		// null or missing value) cannot be judged and is blocked, as every
		// connector does (isWellFormedToolCall).
		const params: unknown = event && typeof event === "object" ? event.params : undefined;
		if (!isWellFormedToolCall(event?.toolName, params)) {
			logger.error("tool-handler received a malformed tool call, failing closed");
			return {
				block: true,
				blockReason: "Singularity AIDR could not identify this tool call; execution was denied.",
			};
		}
		// Input written to a running process (or a command sent to a node) is
		// evaluated as the shell command it becomes; input that cannot be
		// reconstructed is refused rather than passed through.
		const surface = resolveExecSurface(toolName, params, pendingLines, ctx?.sessionKey ?? "");
		if (surface.kind === "deny") {
			return {
				block: true,
				blockReason: `Singularity AIDR blocked this action: ${surface.reason}; it cannot be inspected reliably, so execution was denied.`,
			};
		}
		if (surface.kind === "shell")
			logger.debug(`evaluating ${surface.via} input as a shell command`);
		const call = evaluatedCall(toolName, params, surface);
		if (malformedShellCommandReason(call.toolName, call.params)) {
			return {
				block: true,
				blockReason:
					"Singularity AIDR blocked this command: it is malformed (not a string or argv, or it contains NUL or invalid UTF-8 text) and cannot be inspected reliably.",
			};
		}
		// The deadline that blocks a hung evaluation wraps this handler in index.ts.
		const result = await evaluate(call.toolName, call.params, ctx, call.extraArtifacts);
		// Only input the host will actually deliver extends the session's line.
		if (result === undefined && surface.kind === "shell") surface.commit?.();
		return result;
	}

	async function evaluate(
		toolName: string,
		params: Record<string, unknown>,
		ctx: ToolCallContext | undefined,
		extraArtifacts: Artifact[],
	): Promise<BlockResult | undefined> {
		try {
			// Core may find artifacts after normalizing connector-specific fields.
			const artifacts = [...(mapToolToArtifacts(toolName, params) ?? []), ...extraArtifacts];
			const sessionId = ctx?.sessionKey ?? "unknown";
			// OpenClaw bundle MCP tools are `<server>__<tool>`; evaluate them under
			// the canonical `mcp__<server>__<tool>` name so MCP policy applies.
			const evaluatedToolName = await policyToolName(toolName);

			// Operator-provisioned tenant detector policy for this runtime. No
			// provisioned policy means an empty context, exactly as before; a
			// provisioning failure throws and is caught below, which denies the
			// call instead of evaluating it without the tenant's policy.
			const provisioned = await loadProvisionedDetectorContext("openclaw");

			const { verdict, actionId, responseActions, pendingRecorded, dashboardApproval } =
				await guardToolCall(
					{ sessionId, toolName: evaluatedToolName, toolInput: params, artifacts },
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
				return { block: true, blockReason: formatDenyMessage(verdict, responseActions, artifacts) };
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
