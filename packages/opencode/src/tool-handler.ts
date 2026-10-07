import {
	type ApprovalStore,
	createHostObservation,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	type Logger,
	loadProvisionedDetectorContext,
	recordHostObservation,
} from "@singularityrd/aidr-core";
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

export function createToolHandlers(
	logger: Logger,
	approvalStore: ApprovalStore,
	threatsDir: string,
	allowlistsDir: string,
) {
	const hostObservation = createHostObservation();
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

			const { verdict, actionId, responseActions, pendingRecorded, dashboardApproval } =
				await guardToolCall(
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
						// tool.execute.before may rewrite output.args (see applyRedactedArgs).
						supportsInputRewrite: true,
						...provisioned,
					},
					approvalStore,
				);
			recordHostObservation(hostObservation, {
				connector: "opencode",
				event: "tool.execute.before",
				toolName: input.tool,
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
				throw new AidrVerdictBlockError(formatDenyMessage(verdict, responseActions));
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
