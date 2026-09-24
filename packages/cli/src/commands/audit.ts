import { createHash } from "node:crypto";
import { lstat, readFile, writeFile } from "node:fs/promises";
import {
	type LoggingConfig,
	loadConfig,
	redactTelemetryData,
	redactTelemetryString,
	resolvePath,
} from "@singularityrd/aidr-core";

/** Test seams; production callers pass nothing. */
export interface AuditCommandDeps {
	configPath?: string;
	now?: () => number;
}

type AuditEntry = Record<string, unknown>;

const MAX_TAIL = 10_000;

function fail(message: string): void {
	console.error(message);
	process.exitCode = 1;
}

/** Active log plus its rotated backups, oldest first. */
export function auditLogFiles(logging: Pick<LoggingConfig, "path" | "max_files">): string[] {
	const path = resolvePath(logging.path);
	const backups: string[] = [];
	for (let i = Math.max(0, logging.max_files); i >= 1; i--) backups.push(`${path}.${i}`);
	return [...backups, path];
}

export async function readAuditEntries(
	files: string[],
): Promise<{ entries: AuditEntry[]; skipped: number }> {
	const entries: AuditEntry[] = [];
	let skipped = 0;
	for (const file of files) {
		let content: string;
		try {
			const info = await lstat(file);
			// The log is private evidence; never follow a planted link.
			if (!info.isFile()) continue;
			content = await readFile(file, "utf8");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
			throw error;
		}
		for (const line of content.split("\n")) {
			if (line.trim().length === 0) continue;
			try {
				const parsed: unknown = JSON.parse(line);
				if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
					entries.push(parsed as AuditEntry);
				} else skipped++;
			} catch {
				skipped++;
			}
		}
	}
	return { entries, skipped };
}

function sessionDigest(value: unknown): string | undefined {
	if (typeof value !== "string" || value.length === 0) return undefined;
	return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

/**
 * The export shape: secrets redacted again (defence in depth over the write-time
 * redaction), the session id replaced by a short digest, and free text bounded.
 */
export function redactAuditEntry(entry: AuditEntry): AuditEntry {
	const { session_id: sessionId, ...rest } = entry;
	const redacted = redactTelemetryData(rest);
	if (typeof redacted.tool_input_summary === "string") {
		redacted.tool_input_summary = redactTelemetryString(redacted.tool_input_summary, 200);
	}
	const digest = sessionDigest(sessionId);
	return digest ? { ...redacted, session_digest: digest } : redacted;
}

function timestampOf(entry: AuditEntry): number {
	return typeof entry.timestamp === "string" ? Date.parse(entry.timestamp) : Number.NaN;
}

/** `24h`, `7d`, `30m` or an ISO-8601 date/time. */
export function parseSince(value: string, now: number): number | null {
	const relative = /^(\d{1,6})([mhd])$/i.exec(value.trim());
	if (relative) {
		const unit = { m: 60_000, h: 3_600_000, d: 86_400_000 }[
			(relative[2] as string).toLowerCase() as "m" | "h" | "d"
		];
		return now - Number(relative[1]) * unit;
	}
	const absolute = Date.parse(value);
	return Number.isFinite(absolute) ? absolute : null;
}

function field(entry: AuditEntry, key: string): string {
	const value = entry[key];
	if (value === undefined || value === null) return "";
	if (Array.isArray(value)) return value.map((v) => String(v)).join("; ");
	return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function decisionOf(entry: AuditEntry): string {
	return field(entry, "verdict") || field(entry, "decision");
}

const CSV_COLUMNS = [
	"timestamp",
	"type",
	"decision",
	"severity",
	"category",
	"tool_name",
	"matched_threat_id",
	"source",
	"user_override",
	"session_digest",
	"tool_input_summary",
	"reasons",
] as const;

/** RFC 4180 quoting plus spreadsheet formula neutralisation. */
function csvCell(value: string): string {
	const neutral = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
	return /[",\n\r]/.test(neutral) ? `"${neutral.replaceAll('"', '""')}"` : neutral;
}

export function toCsv(entries: AuditEntry[]): string {
	const lines = [CSV_COLUMNS.join(",")];
	for (const entry of entries) {
		lines.push(
			CSV_COLUMNS.map((column) =>
				csvCell(column === "decision" ? decisionOf(entry) : field(entry, column)),
			).join(","),
		);
	}
	return `${lines.join("\n")}\n`;
}

async function loadLogging(deps: AuditCommandDeps): Promise<LoggingConfig> {
	return (await loadConfig(deps.configPath)).logging;
}

function formatLine(entry: AuditEntry): string {
	const threat = field(entry, "matched_threat_id");
	return [
		field(entry, "timestamp"),
		(decisionOf(entry) || field(entry, "type")).padEnd(5),
		field(entry, "severity").padEnd(8),
		field(entry, "tool_name"),
		threat ? `[${threat}]` : "",
		field(entry, "tool_input_summary"),
	]
		.filter((part) => part.length > 0)
		.join("  ");
}

/** `aidr audit tail [-n N] [--json]` */
export async function auditTailCommand(
	options: { lines?: string; json?: boolean } = {},
	deps: AuditCommandDeps = {},
): Promise<void> {
	const count = options.lines === undefined ? 20 : Number(options.lines);
	if (!Number.isInteger(count) || count < 1 || count > MAX_TAIL) {
		fail(`-n must be a whole number between 1 and ${MAX_TAIL}.`);
		return;
	}
	let entries: AuditEntry[];
	try {
		const logging = await loadLogging(deps);
		entries = (await readAuditEntries(auditLogFiles(logging))).entries.slice(-count);
	} catch (error) {
		fail(`Could not read the audit log: ${error instanceof Error ? error.message : String(error)}`);
		return;
	}
	const redacted = entries.map(redactAuditEntry);
	if (options.json) {
		for (const entry of redacted) console.log(JSON.stringify(entry));
		return;
	}
	if (redacted.length === 0) {
		console.log("The audit log has no entries yet.");
		return;
	}
	for (const entry of redacted) console.log(formatLine(entry));
}

/** `aidr audit export [--since] [--format jsonl|csv] [--output file]` */
export async function auditExportCommand(
	options: { since?: string; format?: string; output?: string } = {},
	deps: AuditCommandDeps = {},
): Promise<void> {
	const format = (options.format ?? "jsonl").toLowerCase();
	if (format !== "jsonl" && format !== "csv") {
		fail('--format must be "jsonl" or "csv".');
		return;
	}
	const now = deps.now ? deps.now() : Date.now();
	let since: number | null = null;
	if (options.since !== undefined) {
		since = parseSince(options.since, now);
		if (since === null) {
			fail('--since must be an ISO-8601 date/time or a relative age such as "24h", "7d" or "30m".');
			return;
		}
	}

	let entries: AuditEntry[];
	let skipped: number;
	try {
		const logging = await loadLogging(deps);
		({ entries, skipped } = await readAuditEntries(auditLogFiles(logging)));
	} catch (error) {
		fail(`Could not read the audit log: ${error instanceof Error ? error.message : String(error)}`);
		return;
	}
	const selected = entries
		.filter((entry) => since === null || timestampOf(entry) >= since)
		.map(redactAuditEntry);
	const body =
		format === "csv"
			? toCsv(selected)
			: selected.map((entry) => JSON.stringify(entry)).join("\n") + (selected.length ? "\n" : "");

	if (options.output) {
		try {
			await writeFile(options.output, body, { encoding: "utf8", mode: 0o600, flag: "wx" });
		} catch (error) {
			fail(
				(error as NodeJS.ErrnoException).code === "EEXIST"
					? `${options.output} already exists; choose a new file name.`
					: `Could not write ${options.output}: ${error instanceof Error ? error.message : String(error)}`,
			);
			return;
		}
		console.error(
			`Exported ${selected.length} redacted audit entr${selected.length === 1 ? "y" : "ies"} to ${options.output}.`,
		);
	} else {
		process.stdout.write(body);
	}
	if (skipped > 0) {
		console.error(`${skipped} unreadable audit line(s) were skipped.`);
	}
}
