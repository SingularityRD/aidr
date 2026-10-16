import { createHash } from "node:crypto";
import { closeSync, openSync, readSync, statSync } from "node:fs";
import type { AuditEvent, Decision, LogKind } from "../shared/contract.js";

/**
 * Reading `~/.singularity-aidr/audit.jsonl`, the log every AIDR connector
 * writes (packages/core/src/audit-log.ts, incidents/persist.ts). Records are
 * read, never written. Text shown comes from fields the logger already
 * redacted and bounded at write time (`tool_input_summary`, `reasons`,
 * `findings`), and nothing else of a record is displayed.
 */

export type AuditRecord = Record<string, unknown>;

/** Session id the app's self-test sends, so its records are labelled as such. */
export const SELF_TEST_SESSION_PREFIX = "aidr-desktop-self-test";

/**
 * Session ids of the canaries the CLI itself sends to a hook before it registers
 * it (`aidr setup`) or when verifying it (`aidr verify`). Those records are real
 * verdicts of the real hook, but not agent activity, so they are labelled.
 */
const SETUP_CANARY_SESSIONS = new Set(["aidr-setup-canary", "aidr-verify", "installer-canary"]);

export function originOf(sessionId: string): AuditEvent["origin"] {
	if (sessionId.startsWith(SELF_TEST_SESSION_PREFIX)) return "self-test";
	return SETUP_CANARY_SESSIONS.has(sessionId) ? "setup-canary" : null;
}

const DECISIONS = new Set<string>(["allow", "ask", "deny"]);
const MAX_INITIAL_BYTES = 16 * 1024 * 1024;
const MAX_READ_BYTES = 4 * 1024 * 1024;
const MAX_TEXT = 300;

function asString(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

function asDecision(value: unknown): Decision | null {
	return typeof value === "string" && DECISIONS.has(value) ? (value as Decision) : null;
}

function strings(value: unknown): string[] {
	return Array.isArray(value)
		? value.filter((entry): entry is string => typeof entry === "string")
		: [];
}

function bounded(text: string): string {
	return text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT)}…` : text;
}

function isObject(value: unknown): value is AuditRecord {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One JSONL line as a record object; anything else → null. */
export function parseRecord(line: string): AuditRecord | null {
	const trimmed = line.trim();
	if (!trimmed.startsWith("{")) return null;
	try {
		const parsed: unknown = JSON.parse(trimmed);
		return isObject(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

function kindOfVerdict(record: AuditRecord): LogKind {
	if (record.tool_name === "UserPromptSubmit") return "prompt";
	if (record.category === "canary_triggered") return "output";
	return "tool";
}

const KIND_BY_TYPE: Record<string, LogKind> = {
	incident: "incident",
	incident_record: "incident",
	plugin_scan: "plugin_scan",
	response_action: "response",
	response_action_allowed: "response",
	dashboard_approval: "approval",
	detection_exception: "exception",
};

function timestampOf(record: AuditRecord): string | null {
	const at = asString(record.timestamp);
	if (at && !Number.isNaN(Date.parse(at))) return at;
	const incident = isObject(record.incident) ? record.incident : null;
	const lastSeen = incident?.last_seen_ms;
	return typeof lastSeen === "number" && Number.isFinite(lastSeen)
		? new Date(lastSeen).toISOString()
		: null;
}

function pluginScanText(record: AuditRecord): {
	summary: string;
	ruleId: string | null;
	severity: string | null;
} {
	const findings = Array.isArray(record.findings) ? record.findings.filter(isObject) : [];
	const first = findings[0];
	const plugin = `${asString(record.plugin_key) ?? "?"}@${asString(record.plugin_version) ?? "?"}`;
	const count = typeof record.findings_count === "number" ? record.findings_count : findings.length;
	return {
		summary: `${count} finding(s) in ${plugin}`,
		ruleId: first
			? (asString(first.threat_id) ?? asString(first.threatId) ?? asString(first.id))
			: null,
		severity: first ? asString(first.severity) : null,
	};
}

/** The text of any other record: its scalar fields (already redacted by the logger). */
function genericText(record: AuditRecord): string {
	const parts: string[] = [];
	for (const [key, value] of Object.entries(record)) {
		if (key === "type" || key === "timestamp" || key === "session_id" || key === "chain") continue;
		if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
			parts.push(`${key}=${value}`);
		}
	}
	return bounded(parts.join(" "));
}

/** One audit record → a display row; records without a type or time → null. */
export function toLogRecord(record: AuditRecord, idSeed = ""): AuditEvent | null {
	const type = asString(record.type);
	const at = timestampOf(record);
	if (!type || !at) return null;
	const id = createHash("sha256")
		.update(idSeed)
		.update(JSON.stringify(record))
		.digest("hex")
		.slice(0, 24);
	const base = { id, at, recordType: type, durationMs: null as number | null };
	if (type === "runtime_verdict") {
		const decision = asDecision(record.verdict);
		if (!decision) return null;
		const sessionId = asString(record.session_id) ?? "";
		return {
			...base,
			kind: kindOfVerdict(record),
			decision,
			tool: asString(record.tool_name) ?? "?",
			summary: typeof record.tool_input_summary === "string" ? record.tool_input_summary : "",
			ruleId: asString(record.matched_threat_id),
			reason: strings(record.reasons)[0] ?? "",
			severity: asString(record.severity),
			sessionId,
			origin: originOf(sessionId),
			durationMs:
				typeof record.duration_ms === "number" && Number.isFinite(record.duration_ms)
					? record.duration_ms
					: null,
		};
	}
	if (type === "incident_record") {
		const incident = isObject(record.incident) ? record.incident : {};
		const events = Array.isArray(incident.events) ? incident.events.filter(isObject) : [];
		const sessionId = asString(incident.session_id) ?? "";
		return {
			...base,
			kind: "incident",
			decision: null,
			tool: asString(incident.connector) ?? "incident",
			summary: bounded(`${events.length} event(s): ${asString(events.at(-1)?.summary) ?? ""}`),
			ruleId: null,
			reason: asString(incident.status) ?? "",
			severity: asString(incident.severity),
			sessionId,
			origin: originOf(sessionId),
		};
	}
	if (type === "plugin_scan") {
		const text = pluginScanText(record);
		return {
			...base,
			kind: "plugin_scan",
			decision: null,
			tool: asString(record.plugin_key) ?? "plugin",
			summary: text.summary,
			ruleId: text.ruleId,
			reason: "",
			severity: text.severity,
			sessionId: "",
			origin: null,
		};
	}
	const sessionId = asString(record.session_id) ?? "";
	return {
		...base,
		kind: KIND_BY_TYPE[type] ?? "other",
		decision: asDecision(record.verdict) ?? asDecision(record.decision),
		tool: asString(record.tool_name) ?? type,
		summary:
			typeof record.tool_input_summary === "string"
				? record.tool_input_summary
				: genericText(record),
		ruleId: asString(record.matched_threat_id),
		reason: strings(record.reasons)[0] ?? "",
		severity: asString(record.severity),
		sessionId,
		origin: originOf(sessionId),
	};
}

/** One audit line → a display row (tests and simple callers). */
export function parseAuditLine(line: string, idSeed = ""): AuditEvent | null {
	const record = parseRecord(line);
	return record ? toLogRecord(record, idSeed) : null;
}

function readRange(path: string, start: number, end: number): string {
	const length = Math.max(0, Math.min(end - start, MAX_INITIAL_BYTES));
	if (length === 0) return "";
	const fd = openSync(path, "r");
	try {
		const buffer = Buffer.alloc(length);
		const read = readSync(fd, buffer, 0, length, start);
		return buffer.subarray(0, read).toString("utf8");
	} finally {
		closeSync(fd);
	}
}

/**
 * Incremental reader of the active log: remembers the byte offset and returns
 * the records appended since the last call. A file that shrank or was replaced
 * (the logger rotates it to `audit.jsonl.1`) is read again from the start.
 */
export class AuditReader {
	private offset = 0;
	private identity: string | null = null;
	private partial = "";

	constructor(private readonly path: string) {}

	/** The records already in the file (bounded), and position at its end. */
	initial(): AuditRecord[] {
		let size: number;
		let identity: string;
		try {
			const info = statSync(this.path);
			size = info.size;
			identity = `${info.ino}:${info.birthtimeMs}`;
		} catch {
			this.offset = 0;
			this.identity = null;
			return [];
		}
		const start = Math.max(0, size - MAX_INITIAL_BYTES);
		const lines = readRange(this.path, start, size).split("\n");
		if (start > 0) lines.shift();
		this.offset = size;
		this.identity = identity;
		// A line still being written is completed by the next poll.
		this.partial = lines.pop() ?? "";
		return toRecords(lines);
	}

	/** Records appended since the previous call. */
	poll(): AuditRecord[] {
		let info: ReturnType<typeof statSync>;
		try {
			info = statSync(this.path);
		} catch {
			this.offset = 0;
			this.identity = null;
			this.partial = "";
			return [];
		}
		const identity = `${info.ino}:${info.birthtimeMs}`;
		if (identity !== this.identity || info.size < this.offset) {
			this.identity = identity;
			this.offset = 0;
			this.partial = "";
		}
		if (info.size === this.offset) return [];
		const end = Math.min(info.size, this.offset + MAX_READ_BYTES);
		const text = this.partial + readRange(this.path, this.offset, end);
		this.offset = end;
		const lines = text.split("\n");
		this.partial = lines.pop() ?? "";
		return toRecords(lines);
	}
}

function toRecords(lines: string[]): AuditRecord[] {
	return lines.map(parseRecord).filter((record): record is AuditRecord => record !== null);
}

/** Poll an {@link AuditReader} and hand new records to `onRecords`. */
export function watchAudit(
	reader: AuditReader,
	onRecords: (records: AuditRecord[]) => void,
	intervalMs = 700,
): () => void {
	const timer = setInterval(() => {
		try {
			const records = reader.poll();
			if (records.length > 0) onRecords(records);
		} catch {
			// A transient read error (the logger holding the file) is retried next tick.
		}
	}, intervalMs);
	return () => clearInterval(timer);
}
