/**
 * Formatting for Singularity AIDR Claude Code alerts.
 * Shared formatting (severityEmoji, formatThreatBanner, etc.) lives in @singularityrd/aidr-core.
 * This file keeps Claude Code-specific verdict formatting.
 */

import type { Verdict } from "@singularityrd/aidr-core";
import { kv, PAD, SEPARATOR_WIDTH, separatorLine, severityEmoji } from "@singularityrd/aidr-core";
import type { PendingApproval } from "./approval-tracker.js";

export function artifactTypeLabel(type: string): string {
	if (type === "url") return "URL";
	if (type === "command") return "command";
	if (type === "file_path") return "file path";
	return type;
}

/** Append category and artifact details to lines array. */
function appendVerdictDetails(lines: string[], verdict: Verdict): void {
	// The rule's own severity when a rule decided, so the label matches the rule id.
	lines.push(kv("Severity", (verdict.ruleSeverity ?? verdict.severity).toUpperCase()));
	if (verdict.matchedThreatId) lines.push(kv("Rule", verdict.matchedThreatId));
	if (verdict.artifacts.length > 0) {
		// biome-ignore lint/style/noNonNullAssertion: length check above guarantees index 0 exists
		lines.push(kv("Artifact", verdict.artifacts[0]!));
		for (const a of verdict.artifacts.slice(1)) {
			lines.push(kv("", a));
		}
	}
	if (verdict.source && verdict.source !== "none") {
		lines.push(kv("Source", verdict.source));
	}
}

/**
 * Format block/ask reason for PreToolUse verdicts.
 * For deny: details-only block (branding goes in permissionDecisionReason, this goes in systemMessage).
 * For ask: full branded banner with separator (shown once in confirmation dialog).
 */
export function formatBlockReason(verdict: Verdict): string {
	const isDeny = verdict.decision === "deny";
	const emoji = severityEmoji(verdict.ruleSeverity ?? verdict.severity);
	const reasonText = verdict.reasons.length > 0 ? verdict.reasons[0] : verdict.category;

	if (isDeny) {
		const lines: string[] = [" "];
		lines.push(`${emoji} ${"Threat".padEnd(PAD)}${reasonText}`);
		appendVerdictDetails(lines, verdict);
		lines.push(kv("Action", "Blocked"));
		return lines.join("\n");
	}

	const header = `🛡️ Singularity AIDR: Suspicious Activity Detected`;
	const lines: string[] = [header, separatorLine(SEPARATOR_WIDTH)];
	lines.push(`${emoji} ${"Threat".padEnd(PAD)}${reasonText}`);
	appendVerdictDetails(lines, verdict);
	lines.push(kv("Action", "Requires confirmation"));
	return lines.join("\n");
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
