/**
 * aidr_allowlist_add and aidr_allowlist_remove tools for OpenClaw.
 *
 * These tools cannot grant an approval: `aidr_allowlist_add` only succeeds when
 * a human already approved the exact artifact — an in-process `ApprovalStore`
 * approval, or an operator approval recorded with
 * `aidr approve <actionId> --permit-allowlist` in the operator approval store.
 * Both can only be recorded out of band. The agent has no way to create one.
 */

import {
	type ApprovalStore,
	addToAllowlist,
	type Logger,
	removeFromAllowlist,
} from "@singularityrd/aidr-core";
import type { ToolDefinition } from "./tool-types.js";

export function createAllowlistAddTool(
	approvalStore: ApprovalStore,
	logger?: Logger,
): ToolDefinition {
	return {
		name: "aidr_allowlist_add",
		description:
			"Permanently allow a URL, command, or file path after recent user approval through Singularity AIDR.",
		parameters: {
			type: "object",
			properties: {
				type: {
					type: "string",
					enum: ["url", "command", "file_path"],
					description: "Artifact type",
				},
				value: {
					type: "string",
					description: "Exact URL, command, or file path to allowlist",
				},
				reason: {
					type: "string",
					description: "Optional reason for allowlist entry",
				},
			},
			required: ["type", "value"],
		},
		async execute(_toolCallId, params) {
			const { type, value, reason } = params as unknown as {
				type: "url" | "command" | "file_path";
				value: string;
				reason?: string;
			};
			const msg = await addToAllowlist(approvalStore, type, value, reason, undefined, logger);
			return { content: [{ type: "text", text: msg }] };
		},
	};
}

export function createAllowlistRemoveTool(logger?: Logger): ToolDefinition {
	return {
		name: "aidr_allowlist_remove",
		description: "Remove a URL, command, or file path from the Singularity AIDR allowlist.",
		parameters: {
			type: "object",
			properties: {
				type: {
					type: "string",
					enum: ["url", "command", "file_path"],
					description: "Artifact type",
				},
				value: {
					type: "string",
					description: "URL/file path, or command text/command hash for command entries",
				},
			},
			required: ["type", "value"],
		},
		async execute(_toolCallId, params) {
			const { type, value } = params as unknown as {
				type: "url" | "command" | "file_path";
				value: string;
			};
			const msg = await removeFromAllowlist(type, value, undefined, logger);
			return { content: [{ type: "text", text: msg }] };
		},
	};
}
