/**
 * The one shape every connector uses to tell a person (and the agent) that a
 * call was blocked or is waiting for approval:
 *
 *   🛡️ headline            blocked / stopped until you approve it
 *   [approval step]        ask only: the user's own terminal command, the
 *                          dashboard, or the host's own dialog — first, so it
 *                          is the line people read
 *   Stopped: …             what was stopped
 *   Why: …                 the rule title in plain words (Turkish `title_tr`
 *                          when the locale is Turkish), severity and rule id
 *   What Singularity AIDR did: …   response actions, when any ran
 *   What you can do / Details: …   false-positive report and where to look
 *   For the AI agent: …    never an approval mechanism the agent can use
 *
 * Internal labels (`heuristic`, `toxic_flow`, `package_check`, the word
 * `actionId`) stay in the verdict, the audit log and JSON fields; they are
 * not part of the text.
 */

import { categoryLabel, displayReason, ruleTitleById, sourceLabel } from "./i18n/display.js";
import { severityLabel, t } from "./i18n/index.js";
import { type ResponseActionRecord, summarizeResponseActions } from "./response-actions.js";
import type { Artifact, Verdict } from "./types.js";

/** How the user can release an `ask`, or `none` for a deny. */
export type BlockApproval =
	| { kind: "none" }
	/** Recorded for `aidr approve` in the user's own terminal. */
	| { kind: "cli"; actionId: string }
	/** Could not be recorded: nothing can release it from the terminal. */
	| { kind: "not_recorded" }
	/** `operator_approvals.dashboard_only`: only the dashboard releases it. */
	| { kind: "dashboard" }
	/** The host shows its own confirmation dialog to the user. */
	| { kind: "host_dialog" };

export interface BlockMessageOptions {
	approval?: BlockApproval;
	/** Extracted artifacts with their types; the verdict's own values are used otherwise. */
	artifacts?: readonly Artifact[];
	responseActions?: readonly ResponseActionRecord[];
	/** Managed-mode dashboard request line (see `formatDashboardApprovalNotice`). */
	dashboardNotice?: string | null;
	/**
	 * `user` leaves out the line addressed to the agent, for host fields only a
	 * person reads (Claude Code `systemMessage`, a native confirmation dialog).
	 */
	audience?: "both" | "user";
}

const MAX_ARTIFACT_LENGTH = 120;
const MAX_REASONS = 3;

/**
 * Characters of the action id shown in the approval command. `aidr approve`
 * accepts a unique prefix of at least 8 hex characters in an interactive
 * terminal (an ambiguous prefix is refused and listed), so the user types
 * eight characters instead of 64. The full id stays in the message's
 * reference line, the JSON fields and the audit log.
 */
const SHORT_ACTION_ID_LENGTH = 8;

/** The command a person runs in their own terminal to allow one retry. */
export function approveCommand(actionId: string): string {
	return `aidr approve ${actionId.slice(0, SHORT_ACTION_ID_LENGTH)}`;
}

function truncate(value: string): string {
	const singleLine = value.replaceAll("\n", "\\n").trim();
	return singleLine.length <= MAX_ARTIFACT_LENGTH
		? singleLine
		: `${singleLine.slice(0, MAX_ARTIFACT_LENGTH)}…`;
}

/** An artifact worth showing: has a letter or digit (drops `;`, `|`, `/`). */
function meaningful(value: string): boolean {
	return /[\p{L}\p{N}]/u.test(value);
}

function artifactTypeWord(type: string | undefined): string | null {
	switch (type) {
		case "command":
			return t("block.artifact.command");
		case "url":
			return t("block.artifact.url");
		case "file_path":
			return t("block.artifact.file_path");
		case "content":
			return t("block.artifact.content");
		default:
			return null;
	}
}

/** Artifact types a message may name: never inline `content` (file bodies, prompts). */
const SHOWN_ARTIFACT_TYPES: ReadonlySet<string> = new Set(["command", "url", "file_path"]);

/**
 * Verdicts whose matched values are themselves sensitive (a secret, a value
 * DLP redacts, a decoy credential): the message names the finding, never the
 * value, so it is not echoed back into the model's context or the terminal.
 */
function valueIsSensitive(verdict: Verdict): boolean {
	const marks = [verdict.source, verdict.category].map((value) => value.toLowerCase());
	return marks.some(
		(value) =>
			value === "secrets" ||
			value.startsWith("dlp") ||
			value.includes("canary") ||
			value === "credential_access",
	);
}

/**
 * What was stopped: the tool call's own command, URL or file path that the
 * verdict matched, with a count of the other matched ones (all of them stay in
 * the audit log). Only typed, non-content artifacts the connector extracted
 * are named; derived detection views (normalized paths, punctuation) and
 * duplicates are not listed. Null when there is nothing safe to name.
 */
function stoppedItem(verdict: Verdict, artifacts?: readonly Artifact[]): string | null {
	if (!artifacts || artifacts.length === 0 || valueIsSensitive(verdict)) return null;
	const typed = artifacts.filter(
		(artifact) => SHOWN_ARTIFACT_TYPES.has(artifact.type) && meaningful(artifact.value),
	);
	const matched = new Set(verdict.artifacts.map((value) => value.trim()));
	const inVerdict = typed.filter((artifact) => matched.has(artifact.value.trim()));
	const candidates = inVerdict.length > 0 ? inVerdict : typed.slice(0, 1);
	const seen = new Set<string>();
	const shown: Artifact[] = [];
	for (const artifact of candidates) {
		const key = artifact.value.trim();
		if (seen.has(key)) continue;
		seen.add(key);
		shown.push(artifact);
	}
	const first = shown[0];
	if (!first) return null;
	const word = artifactTypeWord(first.type);
	const what = word ? `${word} '${truncate(first.value)}'` : `'${truncate(first.value)}'`;
	return shown.length > 1 ? t("block.more", { what, count: shown.length - 1 }) : what;
}

/**
 * The reasons in plain words, without a trailing full stop. The deciding
 * rule's own title comes first, so the "Why" line and the rule id next to it
 * describe the same finding; the rest are the other findings.
 */
function plainReasons(verdict: Verdict): { primary: string; others: string[] } {
	const deciding = ruleTitleById(verdict.matchedThreatId);
	const ordered =
		deciding && verdict.reasons.includes(deciding)
			? [deciding, ...verdict.reasons.filter((reason) => reason !== deciding)]
			: verdict.reasons;
	const seen = new Set<string>();
	const reasons: string[] = [];
	for (const raw of ordered) {
		const text = displayReason(raw)
			.trim()
			.replace(/[.。]+$/u, "");
		if (!text || seen.has(text)) continue;
		seen.add(text);
		reasons.push(text);
		if (reasons.length === MAX_REASONS) break;
	}
	const [primary, ...others] = reasons;
	return { primary: primary ?? categoryLabel(verdict.category), others };
}

function whyLines(verdict: Verdict): string[] {
	const details = [severityLabel(verdict.ruleSeverity ?? verdict.severity)];
	if (verdict.matchedThreatId) {
		details.push(t("block.detail.rule", { rule: verdict.matchedThreatId }));
	} else {
		const source = sourceLabel(verdict.source);
		if (source) details.push(source);
	}
	const { primary, others } = plainReasons(verdict);
	const lines = [t("block.line.why", { reason: primary, details: details.join(", ") })];
	if (others.length > 0) lines.push(t("block.line.also", { reasons: others.join("; ") }));
	return lines;
}

/**
 * What the runtime did, so a response action is visible rather than silent.
 * Null when nothing was attempted or every action was a deliberate skip.
 */
function responseText(actions?: readonly ResponseActionRecord[]): string | null {
	if (!actions || actions.length === 0) return null;
	const parts: string[] = [];
	const succeeded = summarizeResponseActions([...actions]);
	if (succeeded) parts.push(succeeded);
	// A failed action is reported even when nothing succeeded: the user must
	// learn that the runtime tried and failed to preserve anything.
	const failures = actions.filter((a) => a.outcome === "failure");
	if (failures.length > 0) {
		parts.push(
			t("block.response.failed", {
				failures: failures
					.map((f) => `${f.action} (${f.reason ?? t("common.unknown")})`)
					.join(", "),
			}),
		);
	}
	return parts.length > 0 ? parts.join("; ") : null;
}

function approvalLines(approval: BlockApproval, dashboardNotice: string | null): string[] {
	const lines: string[] = [];
	switch (approval.kind) {
		case "cli":
			lines.push(t("block.ask.cli", { command: approveCommand(approval.actionId) }));
			break;
		case "not_recorded":
			lines.push(t("block.ask.notRecorded"));
			break;
		case "dashboard":
			if (!dashboardNotice) lines.push(t("block.ask.dashboardOnly"));
			break;
		case "host_dialog":
			lines.push(t("block.ask.hostDialog"));
			break;
		case "none":
			break;
	}
	if (dashboardNotice) lines.push(dashboardNotice);
	return lines;
}

/** What the person can do next, after the facts: details, false-positive report, reference. */
function nextLines(
	verdict: Verdict,
	approval: BlockApproval,
	dashboardNotice?: string | null,
): string[] {
	const rule = verdict.matchedThreatId;
	if (approval.kind === "none") {
		return [
			...(dashboardNotice ? [dashboardNotice] : []),
			rule ? t("block.deny.next", { rule }) : t("block.deny.nextNoRule"),
		];
	}
	const lines = [rule ? t("block.ask.next", { rule }) : t("block.ask.nextNoRule")];
	// The full id, for the agent to pass on and for scripts; the user's command
	// above uses its short prefix.
	if (approval.kind === "cli") {
		lines.push(t("block.ask.reference", { actionId: approval.actionId }));
	}
	return lines;
}

/** The full block or ask message in the display locale. */
export function formatBlockMessage(verdict: Verdict, options: BlockMessageOptions = {}): string {
	const approval = options.approval ?? { kind: "none" };
	const isAsk = approval.kind !== "none";
	const lines = [t(isAsk ? "block.ask.headline" : "block.deny.headline")];
	if (isAsk) lines.push(...approvalLines(approval, options.dashboardNotice ?? null));

	const stopped = stoppedItem(verdict, options.artifacts);
	if (stopped) lines.push(t("block.line.stopped", { what: stopped }));
	lines.push(...whyLines(verdict));
	const response = responseText(options.responseActions);
	if (response) lines.push(t("block.line.response", { response }));
	lines.push(...nextLines(verdict, approval, options.dashboardNotice));
	if (options.audience !== "user") {
		lines.push(t(isAsk ? "block.agent.ask" : "block.agent.deny"));
	}
	return lines.join("\n");
}

/**
 * One line for a host field the model reads next to a separate user banner
 * (Claude Code `permissionDecisionReason`): the reason and rule, and that the
 * call must not be retried. `held` is an ask the user must release out of
 * band; the line says the agent cannot approve it.
 */
export function formatAgentBlockReason(verdict: Verdict, held = false): string {
	const reason = plainReasons(verdict).primary;
	const rule = verdict.matchedThreatId;
	return t(held ? "block.agent.askShort" : "block.agent.short", {
		reason: rule ? `${reason} (${t("block.detail.rule", { rule })})` : reason,
	});
}
