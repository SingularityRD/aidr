/**
 * Shared tool-definition shape for OpenClaw tool registrations.
 *
 * SECURITY: Singularity AIDR intentionally registers **no** approval tool.
 * Approval authority must never be reachable by the agent being policed, so
 * there is no `aidr_approve` tool and no equivalent. See `index.ts` for how the
 * `ask` verdict is surfaced instead, and the package README for the
 * operator-facing approval paths and their current limitations.
 */

export interface ToolDefinition {
	name: string;
	description: string;
	parameters: Record<string, unknown>;
	execute(
		toolCallId: string,
		params: Record<string, unknown>,
	): Promise<{ content: Array<{ type: string; text: string }> }>;
}
