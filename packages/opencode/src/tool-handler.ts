import {
	type ApprovalStore,
	canonicalMcpToolName,
	createHostObservation,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	IN_PROCESS_TOOL_CALL_DEADLINE,
	isWellFormedToolCall,
	type Logger,
	loadKnownMcpServers,
	loadProvisionedDetectorContext,
	malformedShellCommandReason,
	mcpIdentityFromOpenCodeName,
	recordHostObservation,
	resolveHookDeadlineMs,
	withHookDeadline,
} from "@singularityrd/aidr-core";
import { openCodeMcpConfigPaths } from "./config-paths.js";
import { AidrVerdictBlockError, AidrVerdictError } from "./error.js";
import { extractFromOpenCodeTool } from "./extractors.js";

/**
 * Apply a DLP-redacted input to the args object OpenCode will execute.
 *
 * OpenCode passes `output.args` to the tool after `tool.execute.before`
 * returns, so the object must be changed in place; assigning a new object to
 * `output.args` would leave the original, unredacted args in the caller's hands.
 * The rewrite is verified afterwards, and any failure blocks the call.
 */
function applyRedactedArgs(
	output: { args: Record<string, unknown> },
	transformedInput: Record<string, unknown>,
): void {
	const args = output.args;
	for (const key of Object.keys(args)) delete args[key];
	Object.assign(args, transformedInput);
	if (JSON.stringify(args) !== JSON.stringify(transformedInput)) {
		throw new Error("OpenCode tool args could not be rewritten");
	}
}

/**
 * OpenCode names MCP tools `<server>_<tool>` (both sanitized, `[^A-Za-z0-9_-]`
 * → `_`), and built-in and plugin tools also contain `_`. A tool is treated as
 * MCP only when its name starts with a declared or policy-named server, and is
 * then evaluated under the canonical `mcp__<server>__<tool>` name so MCP
 * server/tool policy applies. The arguments are not changed.
 */
async function policyToolName(toolName: string, directory?: string): Promise<string> {
	if (!toolName.includes("_")) return toolName;
	const known = await loadKnownMcpServers(openCodeMcpConfigPaths(directory));
	const identity = mcpIdentityFromOpenCodeName(toolName, known.names);
	return identity ? canonicalMcpToolName(identity) : toolName;
}

const DEADLINE_MESSAGE =
	"Singularity AIDR could not finish evaluating this tool call in time; execution was denied.";

export function createToolHandlers(
	logger: Logger,
	approvalStore: ApprovalStore,
	threatsDir: string,
	allowlistsDir: string,
	options: { directory?: string } = {},
) {
	const hostObservation = createHostObservation();
	const beforeToolUse = async (
		input: { tool: string; sessionID: string; callID: string },
		output: { args: Record<string, unknown> },
	): Promise<void> => {
		// Validate the host payload before touching it: a null input or output, a
		// missing tool name, or non-object args (undefined, string, array) cannot
		// be judged and is denied, as every connector does (isWellFormedToolCall).
		const tool: unknown = input && typeof input === "object" ? input.tool : undefined;
		const rawArgs: unknown = output && typeof output === "object" ? output.args : undefined;
		if (!isWellFormedToolCall(tool, rawArgs)) {
			logger.error("Singularity AIDR opencode hook received a malformed tool call");
			throw new AidrVerdictBlockError(
				"Singularity AIDR could not identify this tool call; execution was denied.",
			);
		}
		const toolName = tool as string;
		logger.debug(`tool.execute.before hook invoked (tool=${toolName})`);
		if (malformedShellCommandReason(toolName, rawArgs)) {
			throw new AidrVerdictBlockError(
				"Singularity AIDR blocked this command: it is malformed (not a string or argv, or it contains NUL or invalid UTF-8 text) and cannot be inspected reliably.",
			);
		}

		const deadlineMs = resolveHookDeadlineMs(IN_PROCESS_TOOL_CALL_DEADLINE, process.env);
		const evaluation = evaluate(input, output, toolName);
		// A hung evaluation blocks the call instead of stalling the agent; the
		// late result is ignored (its own rejection is swallowed below).
		evaluation.catch(() => undefined);
		const timedOut = await withHookDeadline(
			evaluation.then(() => false),
			deadlineMs,
			() => true,
		);
		if (timedOut) {
			logger.error("Singularity AIDR opencode hook timed out, failing closed", {
				tool: toolName,
				deadlineMs,
			});
			throw new AidrVerdictBlockError(DEADLINE_MESSAGE);
		}
	};

	const evaluate = async (
		input: { tool: string; sessionID: string; callID: string },
		output: { args: Record<string, unknown> },
		toolName: string,
	): Promise<void> => {
		try {
			const args = output.args;
			const artifacts = extractFromOpenCodeTool(toolName, args) ?? [];
			const evaluatedToolName = await policyToolName(toolName, options.directory);

			// Operator-provisioned tenant detector policy for this runtime. An
			// unprovisioned install yields an empty context, so evaluation is
			// byte-for-byte the same as before. A present-but-invalid or
			// entitlement-required-but-missing policy throws, and the catch below
			// fails closed rather than evaluating without it.
			const provisioned = await loadProvisionedDetectorContext("opencode");

			const { verdict, actionId, responseActions, pendingRecorded, dashboardApproval } =
				await guardToolCall(
					{
						sessionId: input.sessionID,
						toolName: evaluatedToolName,
						toolInput: args,
						artifacts,
					},
					{
						threatsDir,
						allowlistsDir,
						logger,
						agentRuntime: "opencode",
						// tool.execute.before may rewrite output.args (see applyRedactedArgs).
						supportsInputRewrite: true,
						...provisioned,
					},
					approvalStore,
				);
			recordHostObservation(hostObservation, {
				connector: "opencode",
				event: "tool.execute.before",
				toolName,
				decision: verdict.decision,
			});

			if (verdict.decision === "allow") {
				if (verdict.transformedInput) {
					// Not an AidrVerdictError: a failed rewrite falls to the catch below
					// and denies, so the unredacted args never run.
					applyRedactedArgs(output, verdict.transformedInput);
				}
				return;
			}

			if (verdict.decision === "deny") {
				throw new AidrVerdictBlockError(
					formatDenyMessage(verdict, responseActions, artifacts, actionId),
				);
			}

			// ask — actionId is always set for ask verdicts
			throw new AidrVerdictBlockError(
				formatAskMessage(
					actionId as string,
					verdict,
					artifacts,
					responseActions,
					pendingRecorded,
					dashboardApproval,
				),
			);
		} catch (error) {
			// Verdict errors are expected (blocks and asks); internal errors deny execution.
			if (error instanceof AidrVerdictError) throw error;
			logger.error("Singularity AIDR opencode hook failed closed", {
				error: String(error),
				tool: toolName,
			});
			throw new AidrVerdictBlockError(
				"Singularity AIDR could not evaluate this tool call; execution was denied.",
			);
		}
	};

	return {
		"tool.execute.before": beforeToolUse,
	};
}
