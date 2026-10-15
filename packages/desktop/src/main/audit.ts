import { createHash } from "node:crypto";
import { closeSync, openSync, readSync, statSync } from "node:fs";
import type { AuditEvent, Decision } from "../shared/contract.js";

/**
 * Following `~/.singularity-aidr/audit.jsonl`, the verdict log every AIDR
 * connector writes (packages/core/src/audit-log.ts). Records are read, never
 * written; the command text shown is the record's `tool_input_summary`, which
 * the logger already redacted and bounded before writing it.
 */

/** Session id the app's self-test sends, so its records are labelled as such. */
export const SELF_TEST_SESSION_PREFIX = "aidr-desktop-self-test";

/**
 * Session ids of the canaries the CLI itself sends to a hook before it registers
 * it (`aidr setup`) or when verifying it (`aidr verify`). Those records are real
 * verdicts of the real hook, but not agent activity, so they are labelled.
 */
const SETUP_CANARY_SESSIONS = new Set(["aidr-setup-canary", "aidr-verify", "installer-canary"]);

function originOf(sessionId: string): AuditEvent["origin"] {
	if (sessionId.startsWith(SELF_TEST_SESSION_PREFIX)) return "self-test";
	return SETUP_CANARY_SESSIONS.has(sessionId) ? "setup-canary" : null;
}

const DECISIONS = new Set<Decision>(["allow", "ask", "deny"]);
const MAX_INITIAL_BYTES = 512 * 1024;
const MAX_READ_BYTES = 4 * 1024 * 1024;

function asString(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

/** One audit line → a display event; anything that is not a verdict record → null. */
export function parseAuditLine(line: string, idSeed = ""): AuditEvent | null {
	const trimmed = line.trim();
	if (!trimmed.startsWith("{")) return null;
	let record: Record<string, unknown>;
	try {
		const parsed: unknown = JSON.parse(trimmed);
		if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
		record = parsed as Record<string, unknown>;
	} catch {
		return null;
	}
	if (record.type !== "runtime_verdict") return null;
	const decision = record.verdict;
	if (typeof decision !== "string" || !DECISIONS.has(decision as Decision)) return null;
	const at = asString(record.timestamp);
	if (!at || Number.isNaN(Date.parse(at))) return null;
	const reasons = Array.isArray(record.reasons)
		? record.reasons.filter((reason): reason is string => typeof reason === "string")
		: [];
	const sessionId = asString(record.session_id) ?? "";
	return {
		id: createHash("sha256").update(idSeed).update(trimmed).digest("hex").slice(0, 24),
		at,
		decision: decision as Decision,
		tool: asString(record.tool_name) ?? "?",
		summary: typeof record.tool_input_summary === "string" ? record.tool_input_summary : "",
		ruleId: asString(record.matched_threat_id),
		reason: reasons[0] ?? "",
		severity: asString(record.severity),
		sessionId,
		origin: originOf(sessionId),
		durationMs:
			typeof record.duration_ms === "number" && Number.isFinite(record.duration_ms)
				? record.duration_ms
				: null,
	};
}

function readRange(path: string, start: number, end: number): string {
	const length = Math.max(0, Math.min(end - start, MAX_READ_BYTES));
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
 * Incremental reader: remembers the byte offset and returns the verdicts
 * appended since the last call. A file that shrank or was replaced (the logger
 * rotates it to `audit.jsonl.1`) is read again from the start.
 */
export class AuditReader {
	private offset = 0;
	private identity: string | null = null;
	private partial = "";
	private sequence = 0;

	constructor(private readonly path: string) {}

	/** The last verdicts already in the file (bounded), and position at its end. */
	initial(limit = 500): AuditEvent[] {
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
		const text = readRange(this.path, start, size);
		const lines = text.split("\n");
		if (start > 0) lines.shift();
		this.offset = size;
		this.identity = identity;
		// A line still being written is completed by the next poll.
		this.partial = lines.pop() ?? "";
		return this.toEvents(lines).slice(-limit);
	}

	/** Verdicts appended since the previous call. */
	poll(): AuditEvent[] {
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
		const text = this.partial + readRange(this.path, this.offset, info.size);
		this.offset = Math.min(info.size, this.offset + MAX_READ_BYTES);
		const lines = text.split("\n");
		this.partial = lines.pop() ?? "";
		return this.toEvents(lines);
	}

	private toEvents(lines: string[]): AuditEvent[] {
		const events: AuditEvent[] = [];
		for (const line of lines) {
			this.sequence += 1;
			const event = parseAuditLine(line, `${this.sequence}`);
			if (event) events.push(event);
		}
		return events;
	}
}

/** Poll an {@link AuditReader} and hand new verdicts to `onEvents`. */
export function watchAudit(
	reader: AuditReader,
	onEvents: (events: AuditEvent[]) => void,
	intervalMs = 700,
): () => void {
	const timer = setInterval(() => {
		try {
			const events = reader.poll();
			if (events.length > 0) onEvents(events);
		} catch {
			// A transient read error (the logger holding the file) is retried next tick.
		}
	}, intervalMs);
	return () => clearInterval(timer);
}
