/**
 * Audit logger for Singularity AIDR verdicts.
 * Appends JSON Lines entries to ~/.singularity-aidr/audit.jsonl for forensics and debugging.
 */

import { appendFile, mkdir, rename, stat, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";
import type { ResponseActionRecord } from "./response-actions.js";
import { redactTelemetryData, redactTelemetryString } from "./telemetry-redaction.js";
import type { LoggingConfig, Verdict } from "./types.js";

const MAX_SUMMARY_LEN = 200;

/**
 * Bounded, credential-redacted one-line description of a tool call.
 *
 * The same text feeds the verdict entry and the signed response chain, so the two
 * can be correlated without the chain ever learning more than the plain log does.
 */
export function toolInputSummaryForAudit(
	toolName: string,
	toolInput: Record<string, unknown>,
): string {
	let summary: string;
	if (toolName === "Bash") {
		summary = String(toolInput.command ?? "");
	} else if (toolName === "WebFetch") {
		summary = String(toolInput.url ?? "");
	} else if (
		toolName === "Write" ||
		toolName === "Edit" ||
		toolName === "Read" ||
		toolName === "Delete"
	) {
		summary = String(toolInput.file_path ?? "");
	} else {
		summary = JSON.stringify(toolInput);
	}
	return redactTelemetryString(summary, MAX_SUMMARY_LEN);
}

function toolInputSummary(toolName: string, toolInput: Record<string, unknown>): string {
	return toolInputSummaryForAudit(toolName, toolInput);
}

export function buildRuntimeVerdictEntry(
	sessionId: string,
	toolName: string,
	toolInput: Record<string, unknown>,
	verdict: Verdict,
	userOverride = false,
): Record<string, unknown> {
	return {
		type: "runtime_verdict",
		timestamp: new Date().toISOString(),
		session_id: sessionId,
		tool_name: toolName,
		tool_input_summary: toolInputSummary(toolName, toolInput),
		artifacts: redactTelemetryData(verdict.artifacts),
		verdict: verdict.decision,
		severity: verdict.severity,
		reasons: redactTelemetryData(verdict.reasons),
		source: verdict.source,
		matched_threat_id: verdict.matchedThreatId,
		user_override: userOverride,
		// Verified user -> agent -> tool -> resource lineage, present only when the
		// call carried a delegated credential that verified. Without it an audited
		// event cannot be traced back to the resource it touched.
		//
		// Deliberately not passed through the generic credential redactor: the
		// lineage is a fixed projection of signed claims (never the bearer token,
		// which is not copied into a verdict at all), and the redactor blanks any
		// key containing "token" - which would erase `tokenId`, the join key to the
		// broker's own lineage record. Remote telemetry drops this field entirely
		// (see `redactRemoteEvent`), so nothing here reaches the control plane.
		...(verdict.delegation ? { delegation: verdict.delegation } : {}),
	};
}

export function buildIncidentEntry(
	params:
		| {
				incidentId: string;
				sessionId: string;
				toolName: string;
				toolInput: Record<string, unknown>;
				verdict: Verdict;
				recommendedActions: string[];
		  }
		| string,
	toolName?: string,
	verdict?: Verdict,
): Record<string, unknown> {
	// Back-compat: older call sites used (sessionId, toolName, verdict) without toolInput.
	if (typeof params === "string") {
		const sessionId = params;
		const safeToolName = toolName ?? "unknown";
		const safeVerdict = verdict ?? {
			decision: "ask",
			category: "unknown",
			confidence: 0.0,
			severity: "warning",
			source: "unknown",
			artifacts: [],
			matchedThreatId: null,
			reasons: [],
		};
		return {
			type: "incident",
			timestamp: new Date().toISOString(),
			incident_id: `inc_${sessionId}_${Date.now()}`,
			status: "open",
			session_id: sessionId,
			tool_name: safeToolName,
			tool_input_summary: "",
			artifacts: redactTelemetryData(safeVerdict.artifacts),
			decision: safeVerdict.decision,
			severity: safeVerdict.severity,
			reasons: redactTelemetryData(safeVerdict.reasons),
			source: safeVerdict.source,
			matched_threat_id: safeVerdict.matchedThreatId,
			recommended_actions: ["review"],
		};
	}

	return {
		type: "incident",
		timestamp: new Date().toISOString(),
		incident_id: params.incidentId,
		status: "open",
		session_id: params.sessionId,
		tool_name: params.toolName,
		tool_input_summary: toolInputSummary(params.toolName, params.toolInput),
		artifacts: redactTelemetryData(params.verdict.artifacts),
		decision: params.verdict.decision,
		severity: params.verdict.severity,
		reasons: redactTelemetryData(params.verdict.reasons),
		source: params.verdict.source,
		matched_threat_id: params.verdict.matchedThreatId,
		recommended_actions: params.recommendedActions,
		// Same lineage rule as the plain verdict entry: the incident is traceable to
		// the resource only when a delegated credential verified for the call.
		...(params.verdict.delegation ? { delegation: params.verdict.delegation } : {}),
	};
}

/**
 * Classic logrotate: shift numbered backups and rename active file to .1.
 * All renames wrapped in try/catch ignoring ENOENT for race safety.
 */
async function rotateIfNeeded(filePath: string, maxBytes: number, maxFiles: number): Promise<void> {
	if (maxBytes <= 0 || maxFiles <= 0) return;

	let size: number;
	try {
		const s = await stat(filePath);
		size = s.size;
	} catch {
		return; // File doesn't exist yet
	}

	if (size < maxBytes) return;

	// Delete oldest backup
	try {
		await unlink(`${filePath}.${maxFiles}`);
	} catch {
		// ENOENT OK
	}

	// Shift .N-1 → .N down to .1 → .2
	for (let i = maxFiles - 1; i >= 1; i--) {
		try {
			await rename(`${filePath}.${i}`, `${filePath}.${i + 1}`);
		} catch {
			// ENOENT OK
		}
	}

	// Active → .1
	try {
		await rename(filePath, `${filePath}.1`);
	} catch {
		// ENOENT OK (race: another process already renamed)
	}
}

async function appendEntry(config: LoggingConfig, entry: Record<string, unknown>): Promise<void> {
	const path = resolvePath(config.path);
	await mkdir(dirname(path), { recursive: true });
	await rotateIfNeeded(path, config.max_bytes, config.max_files);
	await appendFile(path, `${JSON.stringify(entry)}\n`);
}

export async function logVerdict(
	config: LoggingConfig,
	sessionId: string,
	toolName: string,
	toolInput: Record<string, unknown>,
	verdict: Verdict,
	userOverride = false,
): Promise<void> {
	if (!config.enabled) return;

	// Skip clean verdicts unless log_clean is on or this is a user override
	if (verdict.decision === "allow" && !config.log_clean && !userOverride) return;

	const entry = buildRuntimeVerdictEntry(sessionId, toolName, toolInput, verdict, userOverride);

	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open: logging errors swallowed
	}
}

/**
 * Serialize response actions for a log record: paths and outcomes only.
 *
 * Shared by the plain audit entry and the signed response chain so the two can
 * never disagree about what happened, and so there is exactly one place where the
 * "never record contents" rule is enforced.
 */
export function summarizeActionsForLog(actions: ResponseActionRecord[]): Array<{
	action: string;
	outcome: string;
	target: string;
	vault_path?: string;
	snapshot_id?: string;
	reason?: string;
	detail?: string;
	bytes?: number;
	skipped?: Array<{ path: string; reason: string; detail?: string }>;
}> {
	return actions.map((action) => ({
		action: action.action,
		outcome: action.outcome,
		target: redactTelemetryString(action.target, MAX_SUMMARY_LEN),
		vault_path: action.vaultPath
			? redactTelemetryString(action.vaultPath, MAX_SUMMARY_LEN)
			: undefined,
		snapshot_id: action.snapshotId,
		reason: action.reason,
		// `detail` carries error text. It is bounded and credential-scrubbed, but it
		// is never allowed to become a channel for file contents.
		detail: action.detail ? redactTelemetryString(action.detail, MAX_SUMMARY_LEN) : undefined,
		bytes: action.bytes,
		skipped: action.skipped?.map((skip) => ({
			path: redactTelemetryString(skip.path, MAX_SUMMARY_LEN),
			reason: skip.reason,
			detail: skip.detail ? redactTelemetryString(skip.detail, MAX_SUMMARY_LEN) : undefined,
		})),
	}));
}

/**
 * Build an audit entry describing what the runtime DID in response to a verdict.
 *
 * Response actions used to be invisible: they were returned to the caller and
 * then dropped, so there was no record that the runtime had preserved a copy of
 * a file. A response with no audit trail is worse than no response, because the
 * operator cannot tell whether anything was touched.
 *
 * Records contain paths and outcomes only - never file contents.
 */
export function buildResponseActionEntry(
	sessionId: string,
	toolName: string,
	verdict: Verdict,
	actions: ResponseActionRecord[],
): Record<string, unknown> {
	return {
		type: "response_action",
		timestamp: new Date().toISOString(),
		session_id: sessionId,
		tool_name: toolName,
		verdict: verdict.decision,
		severity: verdict.severity,
		matched_threat_id: verdict.matchedThreatId,
		actions: summarizeActionsForLog(actions),
	};
}

/**
 * Build the audit entry for a response taken on an ALLOWED call.
 *
 * A pre-operation snapshot happens when the runtime lets a destructive call
 * through, so the verdict is `allow` and the entry is filed under its own `type`.
 * Without the distinct type an operator scanning for `response_action` could not
 * tell "we blocked this and kept a copy" from "we allowed this and kept a copy
 * because it was about to destroy something".
 */
export function buildAllowedResponseActionEntry(
	sessionId: string,
	toolName: string,
	verdict: Verdict,
	actions: ResponseActionRecord[],
): Record<string, unknown> {
	return {
		type: "response_action_allowed",
		timestamp: new Date().toISOString(),
		session_id: sessionId,
		tool_name: toolName,
		verdict: verdict.decision,
		severity: verdict.severity,
		matched_threat_id: verdict.matchedThreatId,
		actions: summarizeActionsForLog(actions),
	};
}

/** Append a response-action record. Never throws: logging must not break a block. */
export async function logResponseActions(
	config: LoggingConfig,
	sessionId: string,
	toolName: string,
	verdict: Verdict,
	actions: ResponseActionRecord[],
): Promise<void> {
	if (!config.enabled || actions.length === 0) return;
	try {
		await appendEntry(config, buildResponseActionEntry(sessionId, toolName, verdict, actions));
	} catch {
		// Fail-open: a logging error must not turn into a hook failure.
	}
}

/**
 * Append the record for a response taken on an allowed call.
 *
 * Same guarantees as `logResponseActions`: never throws, and the allow is never
 * reconsidered because the log write failed.
 */
export async function logAllowedResponseActions(
	config: LoggingConfig,
	sessionId: string,
	toolName: string,
	verdict: Verdict,
	actions: ResponseActionRecord[],
): Promise<void> {
	if (!config.enabled || actions.length === 0) return;
	try {
		await appendEntry(
			config,
			buildAllowedResponseActionEntry(sessionId, toolName, verdict, actions),
		);
	} catch {
		// Fail-open: a logging error must not turn into a hook failure.
	}
}

export async function logPluginScan(
	config: LoggingConfig,
	pluginKey: string,
	pluginVersion: string,
	findings: Record<string, unknown>[],
): Promise<void> {
	if (!config.enabled) return;

	const entry = {
		type: "plugin_scan",
		timestamp: new Date().toISOString(),
		plugin_key: pluginKey,
		plugin_version: pluginVersion,
		findings_count: findings.length,
		findings: redactTelemetryData(findings),
	};

	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open
	}
}

export async function logIncident(
	config: LoggingConfig,
	entry: Record<string, unknown>,
): Promise<void> {
	if (!config.enabled) return;

	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open
	}
}

export async function getRecentEntries(config: LoggingConfig, limit = 100): Promise<unknown[]> {
	const path = resolvePath(config.path);

	try {
		const content = await getFileContent(path);
		const lines = content.trim().split("\n");
		const recent = lines.slice(-limit);
		const entries: unknown[] = [];
		for (const line of recent) {
			try {
				entries.push(JSON.parse(line));
			} catch {}
		}
		return entries;
	} catch {
		return [];
	}
}
