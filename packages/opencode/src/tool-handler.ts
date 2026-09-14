import {
	type ApprovalStore,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	type Logger,
	loadProvisionedDetectorContext,
} from "@singularityrd/aidr-core";
import { AidrVerdictBlockError, AidrVerdictError } from "./error.js";
import { extractFromOpenCodeTool } from "./extractors.js";

export function createToolHandlers(
	logger: Logger,
	approvalStore: ApprovalStore,
	threatsDir: string,
	allowlistsDir: string,
) {
	const beforeToolUse = async (
		input: { tool: string; sessionID: string; callID: string },
		output: { args: Record<string, unknown> },
	): Promise<void> => {
		logger.debug(`tool.execute.before hook invoked (tool=${input.tool})`);

		try {
			const args = output.args ?? {};
			const artifacts = extractFromOpenCodeTool(input.tool, args) ?? [];

			// Operator-provisioned tenant detector policy for this runtime. An
			// unprovisioned install yields an empty context, so evaluation is
			// byte-for-byte the same as before. A present-but-invalid or
			// entitlement-required-but-missing policy throws, and the catch below
			// fails closed rather than evaluating without it.
			const provisioned = await loadProvisionedDetectorContext("opencode");

			const { verdict, actionId, responseActions } = await guardToolCall(
				{
					sessionId: input.sessionID,
					toolName: input.tool,
					toolInput: args,
					artifacts,
				},
				{
					threatsDir,
					allowlistsDir,
					logger,
					agentRuntime: "opencode",
					...provisioned,
				},
				approvalStore,
			);

			if (verdict.decision === "allow") {
				return;
			}

			if (verdict.decision === "deny") {
				throw new AidrVerdictBlockError(formatDenyMessage(verdict, responseActions));
			}

			// ask — actionId is always set for ask verdicts
			throw new AidrVerdictBlockError(
			formatAskMessage(actionId as string, verdict, artifacts, responseActions),
		);
		} catch (error) {
			// Verdict errors are expected (blocks and asks); internal errors deny execution.
			if (error instanceof AidrVerdictError) throw error;
			logger.error("Singularity AIDR opencode hook failed closed", {
				error: String(error),
				tool: input.tool,
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
