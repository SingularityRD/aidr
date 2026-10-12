/**
 * Audit logger for Singularity AIDR verdicts.
 * Appends JSON Lines entries to ~/.singularity-aidr/audit.jsonl for forensics and debugging.
 */

import { lstatSync } from "node:fs";
import { chmod, open, rename, stat, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { appendChainedAuditRecord } from "./audit-chain.js";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import { frameworkRefsToJson } from "./framework-mappings.js";
import { preparePrivateLocalFile } from "./private-local-file.js";
import type { ResponseActionRecord } from "./response-actions.js";
import { SessionStateError, withExclusiveFileLock } from "./session-state-store.js";
import { redactTelemetryData, redactTelemetryString } from "./telemetry-redaction.js";
import type { LoggingConfig, Verdict } from "./types.js";

const MAX_SUMMARY_LEN = 200;
const MAX_HOST_TOOL_NAME_LEN = 128;
const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const preparedAuditPaths = new Set<string>();
const auditWriteQueues = new Map<string, Promise<void>>();

async function prepareAuditPath(path: string): Promise<void> {
	const directory = dirname(path);
	const normalized = resolve(path);
	const key = process.platform === "win32" ? normalized.toLowerCase() : normalized;
	if (!preparedAuditPaths.has(key)) {
		preparePrivateLocalFile(path);
		preparedAuditPaths.add(key);
		return;
	}

	const directoryInfo = lstatSync(directory);
	if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()) {
		throw new Error("audit_directory_not_private");
	}
	let fileInfo;
	try {
		fileInfo = lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		preparedAuditPaths.delete(key);
		preparePrivateLocalFile(path);
		preparedAuditPaths.add(key);
		return;
	}
	if (fileInfo.isSymbolicLink() || !fileInfo.isFile()) {
		throw new Error("audit_file_not_private");
	}
	if (process.platform !== "win32") {
		await chmod(directory, PRIVATE_DIRECTORY_MODE);
		await chmod(path, PRIVATE_FILE_MODE);
	}
}

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
	return redactTelemetryString(toolInputSummaryText(toolName, toolInput), MAX_SUMMARY_LEN);
}

/**
 * The unbounded, UNREDACTED text {@link toolInputSummaryForAudit} is built from.
 * Callers must redact and bound it themselves before it leaves the process.
 */
export function toolInputSummaryText(toolName: string, toolInput: Record<string, unknown>): string {
	if (toolName === "Bash") return String(toolInput.command ?? "");
	if (toolName === "WebFetch") return String(toolInput.url ?? "");
	if (toolName === "Write" || toolName === "Edit" || toolName === "Read" || toolName === "Delete") {
		return String(toolInput.file_path ?? "");
	}
	return JSON.stringify(toolInput) ?? "";
}

/**
 * Categories whose audit record names them. An allow in one of these still
 * describes an enforcement action (a redaction, a prompt warning) or an
 * uninspected leg, so it is recorded even when clean allows are not.
 */
const AUDITED_ALLOW_CATEGORIES: ReadonlySet<string> = new Set([
	"behavioral_unavailable",
	"canary_unavailable",
	"dlp_redacted",
	"prompt_protection",
	"prompt_protection_warning",
	// An allow whose runaway guard could not run is not a clean check.
	"runaway_guard_unavailable",
	"secure_code_warning",
	"toxic_flow_monitor",
	"toxic_flow_unavailable",
]);

/**
 * Categories every audit record names, whatever the decision: a canary trigger
 * must stay recognisable in the log and in `aidr canary status`.
 */
const NAMED_CATEGORIES: ReadonlySet<string> = new Set([
	...AUDITED_ALLOW_CATEGORIES,
	"canary_triggered",
]);

/**
 * Secure-code findings on a verdict, as counts and rule ids only: the titles
 * are in the rule catalog, and the matched source text is never recorded.
 */
function secureCodeSummary(verdict: Verdict): Record<string, unknown> {
	const warnings = verdict.warnings ?? [];
	if (warnings.length === 0) return {};
	return {
		secure_code: {
			findings: warnings.length,
			rule_ids: [...new Set(warnings.map((warning) => warning.ruleId))].sort(),
		},
	};
}

/**
 * `host_tool_name`: the tool name the host reported when the connector
 * evaluated the call as a canonical operation under a different name. Local
 * audit only; the remote ingest projection does not carry it.
 */
function hostToolNameField(toolName: string, hostToolName: string | undefined) {
	return hostToolName && hostToolName !== toolName
		? { host_tool_name: redactTelemetryString(hostToolName, MAX_HOST_TOOL_NAME_LEN) }
		: {};
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
	durationMs?: number,
	hostToolName?: string,
): Record<string, unknown> {
	return {
		type: "runtime_verdict",
		timestamp: new Date().toISOString(),
		session_id: sessionId,
		tool_name: toolName,
		...hostToolNameField(toolName, hostToolName),
		tool_input_summary: toolInputSummary(toolName, toolInput),
		artifacts: redactTelemetryData(verdict.artifacts),
		verdict: verdict.decision,
		...(NAMED_CATEGORIES.has(verdict.category) ? { category: verdict.category } : {}),
		severity: verdict.severity,
		reasons: redactTelemetryData(verdict.reasons),
		source: verdict.source,
		matched_threat_id: verdict.matchedThreatId,
		// Framework IDs of the matched rule (official identifiers only, no input data).
		...(verdict.frameworks ? { frameworks: frameworkRefsToJson(verdict.frameworks) } : {}),
		user_override: userOverride,
		...(durationMs !== undefined && Number.isFinite(durationMs) && durationMs >= 0
			? { duration_ms: durationMs }
			: {}),
		...secureCodeSummary(verdict),
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
				hostToolName?: string;
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
		...hostToolNameField(params.toolName, params.hostToolName),
		tool_input_summary: toolInputSummary(params.toolName, params.toolInput),
		artifacts: redactTelemetryData(params.verdict.artifacts),
		decision: params.verdict.decision,
		...(NAMED_CATEGORIES.has(params.verdict.category) ? { category: params.verdict.category } : {}),
		severity: params.verdict.severity,
		reasons: redactTelemetryData(params.verdict.reasons),
		source: params.verdict.source,
		matched_threat_id: params.verdict.matchedThreatId,
		...(params.verdict.frameworks
			? { frameworks: frameworkRefsToJson(params.verdict.frameworks) }
			: {}),
		recommended_actions: params.recommendedActions,
		// Same lineage rule as the plain verdict entry: the incident is traceable to
		// the resource only when a delegated credential verified for the call.
		...(params.verdict.delegation ? { delegation: params.verdict.delegation } : {}),
	};
}

async function renameIfPresent(from: string, to: string): Promise<void> {
	try {
		await rename(from, to);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
}

async function unlinkIfPresent(path: string): Promise<boolean> {
	try {
		await unlink(path);
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw error;
	}
}

/** How long an append waits for another process's rotation before appending anyway. */
const ROTATION_LOCK_TIMEOUT_MS = 2000;

/**
 * Classic logrotate: shift numbered backups and rename active file to .1.
 *
 * Every hook invocation is its own process, so two processes can see the
 * same oversized file. Rotation runs under a cross-process lock and re-checks
 * the size once it holds the lock: without it, both processes shifted the
 * backups, and the second rotation dropped a file the first had just created.
 * `beforeDrop` runs before the oldest backup is deleted (the signed chain anchors
 * the records it is about to lose).
 */
async function rotateIfNeeded(
	filePath: string,
	maxBytes: number,
	maxFiles: number,
	beforeDrop?: (path: string) => Promise<void>,
): Promise<void> {
	if (maxBytes <= 0 || maxFiles <= 0) return;

	// The path was hardened immediately before this; any stat failure means
	// the rotation state is unknown and must not be treated as clean.
	if ((await stat(filePath)).size < maxBytes) return;

	try {
		await withExclusiveFileLock(
			filePath,
			async () => {
				// Another process may have rotated while this one waited.
				let size: number;
				try {
					size = (await stat(filePath)).size;
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
					throw error;
				}
				if (size < maxBytes) return;

				// Delete oldest backup. A rotation that drops a file is data loss, so
				// it is counted (in this process and in the persisted counter that
				// `aidr status` reads) rather than performed silently; ENOENT means
				// there was nothing to drop and is not a loss.
				if (beforeDrop) await beforeDrop(`${filePath}.${maxFiles}`);
				if (await unlinkIfPresent(`${filePath}.${maxFiles}`)) {
					recordAuditRotationDrop();
					await persistAuditRotationDrop(filePath);
				}

				// Shift .N-1 → .N down to .1 → .2
				for (let i = maxFiles - 1; i >= 1; i--) {
					await renameIfPresent(`${filePath}.${i}`, `${filePath}.${i + 1}`);
				}

				// Active → .1
				await renameIfPresent(filePath, `${filePath}.1`);
			},
			{ timeoutMs: ROTATION_LOCK_TIMEOUT_MS },
		);
	} catch (error) {
		// Another process holds the rotation lock and is rotating this file; the
		// entry is appended to whichever file is active once this returns.
		if (error instanceof SessionStateError && error.code === "lock_timeout") return;
		throw error;
	}
}

/** Sidecar file holding the cross-process rotation-drop counter. */
function rotationLossPath(filePath: string): string {
	return `${filePath}.loss.json`;
}

interface PersistedRotationLoss {
	rotationDrops: number;
	lastDropAt: number | null;
}

async function readRotationLoss(filePath: string): Promise<PersistedRotationLoss> {
	let raw: string;
	try {
		raw = await getFileContent(rotationLossPath(filePath));
	} catch {
		return { rotationDrops: 0, lastDropAt: null };
	}
	const parsed = JSON.parse(raw) as { rotation_drops?: unknown; last_drop_at?: unknown };
	const drops = parsed.rotation_drops;
	const at = parsed.last_drop_at;
	if (typeof drops !== "number" || !Number.isSafeInteger(drops) || drops < 0) {
		throw new Error("audit_loss_counter_corrupt");
	}
	return { rotationDrops: drops, lastDropAt: typeof at === "number" ? at : null };
}

/** Called with the rotation lock held, so the read-modify-write is not lost. */
async function persistAuditRotationDrop(filePath: string, now = Date.now()): Promise<void> {
	let previous: PersistedRotationLoss;
	try {
		previous = await readRotationLoss(filePath);
	} catch {
		// A corrupt counter is restarted from this drop; the in-process counter
		// still reports the loss.
		previous = { rotationDrops: 0, lastDropAt: null };
	}
	await atomicWriteJson(rotationLossPath(filePath), {
		rotation_drops: previous.rotationDrops + 1,
		last_drop_at: now,
	});
}

/**
 * Rotation drops recorded by every process that wrote this audit log. The
 * in-process counter only sees this process's rotations, while hooks rotate
 * from short-lived processes. An unreadable counter is reported as such
 * (`null`), never as zero.
 */
export async function readPersistedAuditLossState(
	config: LoggingConfig,
): Promise<PersistedRotationLoss | null> {
	try {
		return await readRotationLoss(resolvePath(config.path));
	} catch {
		return null;
	}
}

async function appendEntry(config: LoggingConfig, entry: Record<string, unknown>): Promise<void> {
	const path = resolvePath(config.path);
	const key = process.platform === "win32" ? resolve(path).toLowerCase() : resolve(path);
	const previous = auditWriteQueues.get(key) ?? Promise.resolve();
	const result = previous.then(async () => {
		// Audit records are customer data. Use the same no-symlink and private ACL
		// boundary as the runtime logger, including on Windows where chmod alone does
		// not remove inherited NTFS read grants.
		await prepareAuditPath(path);
		const writeLine = async (line: string) => {
			const handle = await open(path, "a", PRIVATE_FILE_MODE);
			try {
				await handle.writeFile(line, "utf8");
				// logVerdict resolves only after the record reached stable storage; callers
				// still fail open, but a completed write is not merely in the OS cache.
				await handle.sync();
			} finally {
				await handle.close();
			}
		};
		if (config.signed_chain) {
			// Hash-chained and Ed25519-signed (audit-chain.ts). A signing problem never
			// drops the record: it is written chained-but-unsigned and verify reports it.
			await appendChainedAuditRecord(
				path,
				entry,
				{ keyStorage: config.chain_key_storage, epochHours: config.chain_epoch_hours },
				{
					rotate: (beforeDrop) =>
						rotateIfNeeded(path, config.max_bytes, config.max_files, beforeDrop),
					write: writeLine,
				},
			);
			return;
		}
		await rotateIfNeeded(path, config.max_bytes, config.max_files);
		await writeLine(`${JSON.stringify(entry)}\n`);
	});
	const queued = result.then(
		() => undefined,
		() => undefined,
	);
	auditWriteQueues.set(key, queued);
	void queued.then(() => {
		if (auditWriteQueues.get(key) === queued) auditWriteQueues.delete(key);
	});
	return result;
}

export async function logVerdict(
	config: LoggingConfig,
	sessionId: string,
	toolName: string,
	toolInput: Record<string, unknown>,
	verdict: Verdict,
	userOverride = false,
	durationMs?: number,
	hostToolName?: string,
): Promise<void> {
	if (!config.enabled) return;

	// Skip clean verdicts unless log_clean is on or this is a user override
	if (
		verdict.decision === "allow" &&
		!AUDITED_ALLOW_CATEGORIES.has(verdict.category) &&
		!config.log_clean &&
		!userOverride
	)
		return;

	const entry = buildRuntimeVerdictEntry(
		sessionId,
		toolName,
		toolInput,
		verdict,
		userOverride,
		durationMs,
		hostToolName,
	);

	try {
		await appendEntry(config, entry);
	} catch (error) {
		// Fail-open is deliberate: an audit-write failure must never turn into a
		// block (see CLAUDE.md). Staying silent about it is not. A full disk or a
		// read-only home used to lose records with no trace anywhere, so the loss
		// is counted here and surfaced by `aidr status`.
		recordAuditWriteFailure(error);
	}
}

/* ------------------------------------------------------------------ *
 * Loss accounting
 * ------------------------------------------------------------------ */

export interface AuditLogLossState {
	/** Appends that could not be written since this process started. */
	writeFailures: number;
	/** Rotations that had to drop the oldest file. */
	rotationDrops: number;
	/** The most recent failure's message, or null when none has occurred. */
	lastError: string | null;
	/** Epoch milliseconds of the most recent failure, or null. */
	lastErrorAt: number | null;
}

const lossState: AuditLogLossState = {
	writeFailures: 0,
	rotationDrops: 0,
	lastError: null,
	lastErrorAt: null,
};

/** Record a failed audit append. Exported so tests can exercise it directly. */
export function recordAuditWriteFailure(error: unknown, now = Date.now()): void {
	lossState.writeFailures += 1;
	lossState.lastError = error instanceof Error ? error.message : String(error);
	lossState.lastErrorAt = now;
}

/** Record that rotation dropped the oldest file to stay within `max_files`. */
export function recordAuditRotationDrop(now = Date.now()): void {
	lossState.rotationDrops += 1;
	lossState.lastErrorAt = lossState.lastErrorAt ?? now;
}

/**
 * The current loss counters. A clean log means both counters are zero; anything
 * else must be reported to the operator rather than presented as a complete
 * record.
 */
export function getAuditLogLossState(): AuditLogLossState {
	return { ...lossState };
}

/** Reset the counters. Tests only. */
export function resetAuditLogLossState(): void {
	lossState.writeFailures = 0;
	lossState.rotationDrops = 0;
	lossState.lastError = null;
	lossState.lastErrorAt = null;
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
	} catch (error) {
		// Fail-open: a logging error must not turn into a hook failure, but the
		// dropped record must remain visible to `aidr status`.
		recordAuditWriteFailure(error);
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
	} catch (error) {
		// Fail-open: a logging error must not turn into a hook failure, but the
		// dropped record must remain visible to `aidr status`.
		recordAuditWriteFailure(error);
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
	} catch (error) {
		// Fail-open: preserve the scan result while exposing the dropped record.
		recordAuditWriteFailure(error);
	}
}

/**
 * One step of a managed-mode dashboard approval (request submitted, decision
 * observed, token rejected or consumed). Carries identifiers and outcome codes
 * only: never the tool input, the token or the API key.
 */
export async function logDashboardApprovalEvent(
	config: LoggingConfig,
	event: {
		event: string;
		sessionId: string;
		toolName: string;
		actionId: string;
		requestId?: string;
		reason?: string;
		approverId?: string;
	},
): Promise<void> {
	if (!config.enabled) return;
	const entry: Record<string, unknown> = {
		type: "dashboard_approval",
		source: "dashboard_approval",
		timestamp: new Date().toISOString(),
		event: event.event,
		session_id: event.sessionId,
		tool_name: event.toolName,
		action_id: event.actionId,
		...(event.requestId ? { request_id: event.requestId } : {}),
		...(event.reason ? { reason: event.reason } : {}),
		...(event.approverId ? { approver_id: event.approverId } : {}),
	};
	try {
		await appendEntry(config, redactTelemetryData(entry));
	} catch (error) {
		// Fail-open for the audit write only; the approval decision is unaffected.
		recordAuditWriteFailure(error);
	}
}

/**
 * One use of a detection exception: a rule match it removed from this call's
 * decision. Identifiers only — the exception id, rule, subject kind, source and
 * a digest of the artifact — never the tool input.
 */
export async function logDetectionExceptionUse(
	config: LoggingConfig,
	event: {
		sessionId: string;
		toolName: string;
		exceptionId: string;
		ruleId: string;
		source: "local" | "managed";
		subjectKind: string;
		artifactSha256: string;
		expiresAt: string;
	},
): Promise<void> {
	if (!config.enabled) return;
	const entry: Record<string, unknown> = {
		type: "detection_exception",
		source: "detection_exception",
		timestamp: new Date().toISOString(),
		event: "applied",
		session_id: event.sessionId,
		tool_name: event.toolName,
		exception_id: event.exceptionId,
		rule_id: event.ruleId,
		exception_source: event.source,
		subject_kind: event.subjectKind,
		artifact_sha256: event.artifactSha256,
		expires_at: event.expiresAt,
	};
	try {
		await appendEntry(config, redactTelemetryData(entry));
	} catch (error) {
		// Fail-open for the audit write only; the decision is unaffected.
		recordAuditWriteFailure(error);
	}
}

export async function logIncident(
	config: LoggingConfig,
	entry: Record<string, unknown>,
): Promise<void> {
	if (!config.enabled) return;

	try {
		await appendEntry(config, entry);
	} catch (error) {
		// Fail-open: preserve the incident handling path while exposing the loss.
		recordAuditWriteFailure(error);
	}
}

/** Upper bound read per requested entry (entries are bounded summaries). */
const TAIL_BYTES_PER_ENTRY = 8 * 1024;
const MAX_TAIL_BYTES = 4 * 1024 * 1024;

/**
 * The last `maxBytes` of a file, starting at a line boundary. The audit log
 * can grow to `max_bytes`; reading all of it on every call is wasted work.
 */
async function readTail(path: string, maxBytes: number): Promise<string> {
	const handle = await open(path, "r");
	try {
		const { size } = await handle.stat();
		const start = Math.max(0, size - maxBytes);
		const buffer = Buffer.alloc(size - start);
		let offset = 0;
		while (offset < buffer.length) {
			const { bytesRead } = await handle.read(
				buffer,
				offset,
				buffer.length - offset,
				start + offset,
			);
			if (bytesRead === 0) break;
			offset += bytesRead;
		}
		const text = buffer.subarray(0, offset).toString("utf8");
		if (start === 0) return text;
		// Drop the partial first line.
		const newline = text.indexOf("\n");
		return newline === -1 ? "" : text.slice(newline + 1);
	} finally {
		await handle.close();
	}
}

export async function getRecentEntries(config: LoggingConfig, limit = 100): Promise<unknown[]> {
	const path = resolvePath(config.path);

	try {
		const content = await readTail(path, Math.min(MAX_TAIL_BYTES, limit * TAIL_BYTES_PER_ENTRY));
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
