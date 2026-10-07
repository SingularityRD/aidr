import { createHash } from "node:crypto";
import { lstat, readFile, writeFile } from "node:fs/promises";
import {
	DEFAULT_RESPONSE_AUDIT_CONFIG,
	frameworkRefLabels,
	frameworkRefsFromJson,
	type LoggingConfig,
	loadConfig,
	ResponseAuditor,
	type ResponseChainBrokenLink,
	type ResponseChainVerification,
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

/** A log file's text; null when it is missing or not a regular file. */
async function readLogFile(file: string): Promise<string | null> {
	try {
		const info = await lstat(file);
		// The log is private evidence; never follow a planted link.
		if (!info.isFile()) return null;
		return await readFile(file, "utf8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw error;
	}
}

/** One JSONL line as an entry; null when it is not a JSON object. */
function parseAuditLine(line: string): AuditEntry | null {
	try {
		const parsed: unknown = JSON.parse(line);
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as AuditEntry)
			: null;
	} catch {
		return null;
	}
}

export async function readAuditEntries(
	files: string[],
): Promise<{ entries: AuditEntry[]; skipped: number }> {
	const entries: AuditEntry[] = [];
	let skipped = 0;
	for (const file of files) {
		const content = await readLogFile(file);
		if (content === null) continue;
		for (const line of content.split("\n")) {
			if (line.trim().length === 0) continue;
			const entry = parseAuditLine(line);
			if (entry) entries.push(entry);
			else skipped++;
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

/** Framework IDs of the matched rule as `LLM06:2025; ASI02:2026; AML.T0053`. */
function frameworksOf(entry: AuditEntry): string {
	const refs = frameworkRefsFromJson(entry.frameworks);
	return refs ? frameworkRefLabels(refs).join("; ") : "";
}

function csvField(entry: AuditEntry, column: (typeof CSV_COLUMNS)[number]): string {
	if (column === "decision") return decisionOf(entry);
	if (column === "frameworks") return frameworksOf(entry);
	return field(entry, column);
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
	"frameworks",
] as const;

/** RFC 4180 quoting plus spreadsheet formula neutralisation. */
function csvCell(value: string): string {
	const neutral = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
	return /[",\n\r]/.test(neutral) ? `"${neutral.replaceAll('"', '""')}"` : neutral;
}

export function toCsv(entries: AuditEntry[]): string {
	const lines = [CSV_COLUMNS.join(",")];
	for (const entry of entries) {
		lines.push(CSV_COLUMNS.map((column) => csvCell(csvField(entry, column))).join(","));
	}
	return `${lines.join("\n")}\n`;
}

async function loadLogging(deps: AuditCommandDeps): Promise<LoggingConfig> {
	return (await loadConfig(deps.configPath)).logging;
}

function errorText(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

/** Every entry of the active log and its backups; reports a failure and returns null. */
async function tryReadAllEntries(
	deps: AuditCommandDeps,
): Promise<{ entries: AuditEntry[]; skipped: number } | null> {
	try {
		const logging = await loadLogging(deps);
		return await readAuditEntries(auditLogFiles(logging));
	} catch (error) {
		fail(`Could not read the audit log: ${errorText(error)}`);
		return null;
	}
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
	const log = await tryReadAllEntries(deps);
	if (!log) return;
	const redacted = log.entries.slice(-count).map(redactAuditEntry);
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

function exportBody(entries: AuditEntry[], format: "jsonl" | "csv"): string {
	if (format === "csv") return toCsv(entries);
	return entries.map((entry) => JSON.stringify(entry)).join("\n") + (entries.length ? "\n" : "");
}

/** Writes the export to a new private file; reports a failure and returns false. */
async function writeExport(output: string, body: string, count: number): Promise<boolean> {
	try {
		await writeFile(output, body, { encoding: "utf8", mode: 0o600, flag: "wx" });
	} catch (error) {
		fail(
			(error as NodeJS.ErrnoException).code === "EEXIST"
				? `${output} already exists; choose a new file name.`
				: `Could not write ${output}: ${errorText(error)}`,
		);
		return false;
	}
	console.error(`Exported ${count} redacted audit entr${count === 1 ? "y" : "ies"} to ${output}.`);
	return true;
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

	const log = await tryReadAllEntries(deps);
	if (!log) return;
	const selected = log.entries
		.filter((entry) => since === null || timestampOf(entry) >= since)
		.map(redactAuditEntry);
	const body = exportBody(selected, format);

	if (options.output) {
		if (!(await writeExport(options.output, body, selected.length))) return;
	} else {
		process.stdout.write(body);
	}
	if (log.skipped > 0) {
		console.error(`${log.skipped} unreadable audit line(s) were skipped.`);
	}
}

/** Exit codes for `aidr audit verify`: 1 = the chain is broken, 2 = nothing could be verified. */
export const AUDIT_VERIFY_BROKEN = 1;
export const AUDIT_VERIFY_UNVERIFIABLE = 2;

const UNVERIFIABLE_REASONS = new Set([
	"audit_log_missing",
	"audit_log_unreadable",
	"signing_key_missing",
]);

function describeBrokenLink(link: ResponseChainBrokenLink): string {
	const where = link.line > 0 ? `line ${link.line}` : "chain metadata";
	const entry = link.entryId ? ` (${link.entryId})` : "";
	return `${where}${entry}: ${link.reason}`;
}

/** Resolve the response-action chain path: explicit argument first, then config. */
async function responseChainPath(
	path: string | undefined,
	deps: AuditCommandDeps,
): Promise<string> {
	if (path) return path;
	const config = await loadConfig(deps.configPath);
	return config.response?.audit?.path ?? DEFAULT_RESPONSE_AUDIT_CONFIG.path;
}

/**
 * `aidr audit verify [path] [--json]`
 *
 * Verifies the Ed25519-signed SHA-256 response-action chain offline, reports the
 * first broken link and exits non-zero on any failure. Verification never
 * creates a signing key: a chain without its key is reported as unverifiable,
 * never as valid.
 */
export async function auditVerifyCommand(
	path: string | undefined,
	options: { json?: boolean } = {},
	deps: AuditCommandDeps = {},
): Promise<ResponseChainVerification | null> {
	let chainPath: string;
	try {
		chainPath = await responseChainPath(path, deps);
	} catch (error) {
		fail(`Could not resolve the response audit chain path: ${errorText(error)}`);
		process.exitCode = AUDIT_VERIFY_UNVERIFIABLE;
		return null;
	}
	const result = await new ResponseAuditor(chainPath, { signEntries: true }).verifyChain({
		requireExistingKey: true,
	});
	const unverifiable = !result.valid && UNVERIFIABLE_REASONS.has(result.reason ?? "");
	if (!result.valid) {
		process.exitCode = unverifiable ? AUDIT_VERIFY_UNVERIFIABLE : AUDIT_VERIFY_BROKEN;
	}

	if (options.json) {
		console.log(JSON.stringify({ path: resolvePath(chainPath), ...result }));
		return result;
	}
	const target = resolvePath(chainPath);
	if (result.valid) {
		console.log(
			`Response audit chain intact: ${result.verifiedEntries} signed entr${result.verifiedEntries === 1 ? "y" : "ies"} verified (${target}).`,
		);
		return result;
	}
	if (unverifiable) {
		console.error(`Response audit chain NOT verified (${target}): ${result.reason}.`);
		return result;
	}
	console.error(
		`Response audit chain BROKEN (${target}): ${result.verifiedEntries}/${result.entries} entries verified before the first break.`,
	);
	if (result.firstBrokenLink) {
		console.error(`First broken link: ${describeBrokenLink(result.firstBrokenLink)}`);
	}
	if (result.tamperedEntries.length > 1) {
		console.error(`${result.tamperedEntries.length} link(s) fail verification in total.`);
	}
	return result;
}
