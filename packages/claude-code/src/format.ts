/**
 * Formatting for Singularity AIDR Claude Code alerts.
 * Shared formatting (severityEmoji, formatThreatBanner, etc.) lives in @singularityrd/aidr-core.
 * This file keeps Claude Code-specific verdict formatting.
 */

import type { Artifact, Verdict } from "@singularityrd/aidr-core";
import { formatBlockMessage } from "@singularityrd/aidr-core";
import type { PendingApproval } from "./approval-tracker.js";

export function artifactTypeLabel(type: string): string {
	if (type === "url") return "URL";
	if (type === "command") return "command";
	if (type === "file_path") return "file path";
	return type;
}

/**
 * The person-facing block or ask text for a PreToolUse verdict, in the shared
 * shape (core `block-message.ts`): what was stopped, why, and what to do. A
 * deny goes in `systemMessage`; an ask is shown in Claude Code's own
 * confirmation dialog, where the user's next step is Yes or No. Neither is
 * the agent's field: on a deny the agent reads `formatAgentBlockReason`.
 */
export function formatBlockReason(
	verdict: Verdict,
	artifacts?: readonly Artifact[],
	dashboardNotice?: string | null,
	actionId?: string,
): string {
	return formatBlockMessage(verdict, {
		approval: verdict.decision === "ask" ? { kind: "host_dialog" } : { kind: "none" },
		artifacts,
		dashboardNotice,
		actionId,
		audience: "user",
	});
}

/**
 * Context handed to Claude after the user approved a flagged call in the native
 * dialog. It names the real operator command for a permanent exception.
 */
export function approvedActionContext(entry: PendingApproval): string {
	const artifactList = entry.artifacts
		.map((artifact) => `${artifactTypeLabel(artifact.type)} '${artifact.value}'`)
		.join(", ");
	const typeSet = [...new Set(entry.artifacts.map((artifact) => artifactTypeLabel(artifact.type)))];
	const typeStr = typeSet.join("/");
	const noun =
		typeStr === "URL"
			? "these URLs"
			: typeStr === "command"
				? "these commands"
				: `these ${typeStr}s`;
	const cliTypes = [...new Set(entry.artifacts.map((artifact) => artifact.type))].join("|");
	// The allowlist command is operator-only: it asks for confirmation in the
	// user's own terminal, and the agent running it is itself flagged (CLT-SELF-007).
	return `Singularity AIDR: The user approved a flagged action (threat ${entry.threatId}: ${entry.threatTitle}, artifacts: ${artifactList}). This approval covered this call only. To permanently allow ${noun} in the future, the user can run \`aidr allowlist add ${cliTypes} <value>\` in their own terminal (\`aidr allowlist list\` shows existing entries); do not run it on their behalf.`;
}
