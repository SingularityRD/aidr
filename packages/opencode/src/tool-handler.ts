import {
	type ApprovalStore,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	type Logger,
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

			const { verdict, actionId } = await guardToolCall(
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
				},
				approvalStore,
			);

			if (verdict.decision === "allow") {
				return;
			}

			if (verdict.decision === "deny") {
				throw new AidrVerdictBlockError(formatDenyMessage(verdict));
			}

			// ask — actionId is always set for ask verdicts
			throw new AidrVerdictBlockError(formatAskMessage(actionId as string, verdict, artifacts));
		} catch (error) {
			// Verdict errors are expected (blocks and asks); others are logged as fail-open
			if (error instanceof AidrVerdictError) throw error;
			logger.error("Singularity AIDR opencode hook failed open", {
				error: String(error),
				tool: input.tool,
			});
		}
	};

	return {
		"tool.execute.before": beforeToolUse,
	};
}
