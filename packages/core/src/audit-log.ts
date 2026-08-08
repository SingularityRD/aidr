/**
 * Audit logger for Singularity AIDR verdicts.
 * Appends JSON Lines entries to ~/.singularity-aidr/audit.jsonl for forensics and debugging.
 */

import { appendFile, mkdir, rename, stat, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";
import { redactTelemetryData, redactTelemetryString } from "./telemetry-redaction.js";
import type { LoggingConfig, Verdict } from "./types.js";

const MAX_SUMMARY_LEN = 200;

function toolInputSummary(toolName: string, toolInput: Record<string, unknown>): string {
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
