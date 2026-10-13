import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { arch, homedir, hostname, platform, release, userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import {
	DLP_DETECTOR_ENTITY_TYPES,
	type DlpDetector,
	DlpDetectorSchema,
	detectOutputSensitiveData,
	isInvalidConfig,
	loadConfig,
	PRIVACY_DETECTOR_MAX_CHARS,
	redactTelemetryString,
	resolvePath,
	scanPrivacyDetectors,
	VERSION,
} from "@singularityrd/aidr-core";
import { type ConnectorStatus, detectConnectorStatuses } from "../utils/connector-status.js";
import { resolveBundledDataDirs } from "../utils/test-protection.js";
import { auditLogFiles, readAuditEntries } from "./audit.js";
import { type DoctorDeps, runDoctor } from "./doctor.js";

/**
 * `aidr support-bundle` — a redacted diagnostic archive for connector problems.
 *
 * The bundle is a gzip-compressed tar of JSON files: versions and platform,
 * the `aidr doctor` health report, host/hook detection, the effective
 * configuration, a field-allowlisted summary of recent audit verdicts and a
 * hash manifest of the shipped threat rules. Nothing is uploaded; the operator
 * reviews the file and decides whether to hand it over.
 *
 * Redaction is applied to every string in every file, in this order:
 *   1. values under credential-like keys are replaced (the telemetry key-name
 *      redactor: api_key, token, cookie, prompt, tool_input, …);
 *   2. embedded credentials are replaced (Bearer, key=value, URL user-info and
 *      secret query parameters, known token formats, JWTs);
 *   3. the home directory becomes `~`, the account name `<user>` and the host
 *      name `<host>`;
 *   4. the AIDR Privacy rules (checksum TCKN/IBAN/Luhn, phone, e-mail, address,
 *      secrets, …) and the credential detector mask every finding as `[TYPE]`.
 * Audit entries are reduced to an allowlist of metadata fields first: tool
 * input summaries, artifacts, reasons, session ids and delegation records are
 * never copied. The finished archive is scanned once more with the
 * high-precision detectors; any residual finding aborts the bundle (nothing is
 * written) instead of shipping it.
 */

const SUPPORT_BUNDLE_SCHEMA_VERSION = 1;
const DEFAULT_AUDIT_ENTRIES = 50;
const MAX_AUDIT_ENTRIES = 1000;
/** There is no published support route yet; never invent one. */
export const SUPPORT_CHANNEL_NOTICE =
	"Support channel: to be provided by the vendor. This bundle is not sent anywhere; share it only through the route your Singularity AIDR agreement names.";

const ROOT_DIR = "aidr-support-bundle";
const NOT_INSPECTED = "[Redacted: not fully inspected]";

/** Test seams; production callers pass nothing. */
export interface SupportBundleDeps extends DoctorDeps {
	now?: () => Date;
	/** Identity strings to scrub (defaults to the OS values). */
	identity?: { home?: string; user?: string; host?: string };
	/** Bundled threat directory (defaults to the CLI's shipped copy). */
	threatsDir?: string;
	/** Output stream for the human/JSON summary. */
	stdout?: (text: string) => void;
}

export interface SupportBundleOptions {
	out?: string;
	auditEntries?: string | number;
	json?: boolean;
}

interface BundleFile {
	name: string;
	description: string;
	content: string;
}

export interface SupportBundleSummary {
	path: string;
	bytes: number;
	sha256: string;
	files: Array<{ name: string; description: string; bytes: number; sha256: string }>;
	support_channel: string;
}

class SupportBundleError extends Error {}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const DETECTORS: readonly DlpDetector[] = DlpDetectorSchema.options;
/** Detectors precise enough to fail the final archive check on any hit. */
const RESIDUAL_DETECTORS: readonly DlpDetector[] = [
	"tc_kimlik",
	"iban",
	"credit_card",
	"email",
	"secret",
	"private_key",
];

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

interface Identity {
	home: string;
	user: string;
	host: string;
}

function osIdentity(override: SupportBundleDeps["identity"] = {}): Identity {
	let user = "";
	try {
		user = userInfo().username;
	} catch {
		user = process.env.USER ?? process.env.USERNAME ?? "";
	}
	return {
		home: override.home ?? homedir(),
		user: override.user ?? user,
		host: override.host ?? hostname(),
	};
}

/** Replace the home directory, account name and host name in one string. */
function scrubIdentity(value: string, identity: Identity): string {
	let out = value;
	if (identity.home.length > 1) {
		out = out.replace(new RegExp(`${escapeRegExp(identity.home)}(?=$|[\\\\/])`, "g"), "~");
	}
	if (identity.user.length >= 2) {
		// Only as a whole path segment or token, so ordinary words survive.
		out = out.replace(
			new RegExp(`(^|[\\\\/@:\\s"'=])${escapeRegExp(identity.user)}(?=$|[\\\\/@:\\s"',;])`, "g"),
			"$1<user>",
		);
	}
	if (identity.host.length >= 3) {
		out = out.replace(
			new RegExp(`(?<![\\w-])${escapeRegExp(identity.host)}(?![\\w-])`, "gi"),
			"<host>",
		);
	}
	return out;
}

/** Mask every privacy-rule and credential finding as `[TYPE]`. */
function maskPrivacy(value: string): string {
	if (value.length > PRIVACY_DETECTOR_MAX_CHARS) return NOT_INSPECTED;
	const scan = scanPrivacyDetectors(value, DETECTORS);
	if (scan.incomplete) return NOT_INSPECTED;
	const spans: Array<{ start: number; end: number; type: string }> = scan.matches.map((match) => ({
		start: match.start,
		end: match.end,
		type: DLP_DETECTOR_ENTITY_TYPES[match.detector],
	}));
	for (const match of detectOutputSensitiveData(value)) {
		// A PEM header alone would leave the key body behind: drop the rest.
		const end = match.type === "private_key" ? value.length : match.index + match.value.length;
		spans.push({ start: match.index, end, type: "SECRET" });
	}
	if (spans.length === 0) return value;
	spans.sort((a, b) => a.start - b.start || b.end - a.end);
	let out = "";
	let cursor = 0;
	for (const span of spans) {
		if (span.end <= cursor) continue;
		out += value.slice(cursor, Math.max(cursor, span.start));
		out += `[${span.type}]`;
		cursor = span.end;
	}
	return out + value.slice(cursor);
}

function redactBundleString(value: string, identity: Identity): string {
	return maskPrivacy(scrubIdentity(redactTelemetryString(value, 4000), identity));
}

/**
 * Keys whose whole value is withheld: the credential vocabulary of the
 * telemetry redactor, matched on whole `_`/`-` separated words so diagnostic
 * fields (`state`, `signal_id`, `key_storage`) survive ...
 */
const CREDENTIAL_KEY_RE =
	/(?:^|[_-])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth(?:orization)?|bearer|cookies?|credentials?|password|passwd|private[_-]?key|secrets?|session[_-]?token|signature|token|client[_-]?secret|invite|grant|dsn)(?:$|[_-])/i;
/** ... and input/output carriers, matched as the key's last word (`content`, not `content_scan`). */
const PAYLOAD_KEY_RE =
	/(?:^|[_-])(?:prompts?|tool[_-]?input|tool[_-]?output|completion|response[_-]?body|request[_-]?body|body|content|env|headers?|command|arguments|args)$/i;

function isSensitiveKey(key: string): boolean {
	return CREDENTIAL_KEY_RE.test(key) || PAYLOAD_KEY_RE.test(key);
}

const MAX_DEPTH = 16;

function redactBundleNode(value: unknown, identity: Identity, depth: number): unknown {
	if (typeof value === "string") return redactBundleString(value, identity);
	if (depth > MAX_DEPTH) return "[Redacted: nested too deep]";
	if (Array.isArray(value)) return value.map((item) => redactBundleNode(item, identity, depth + 1));
	if (value && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
			out[redactBundleString(key, identity)] = isSensitiveKey(key)
				? "[Redacted]"
				: redactBundleNode(item, identity, depth + 1);
		}
		return out;
	}
	return value;
}

/** A detached, redacted copy: credential-named keys withheld, every string redacted. */
function redactForBundle(value: unknown, identity: Identity): unknown {
	return redactBundleNode(value, identity, 0);
}

/**
 * Residual findings in a redacted tree; any hit aborts the bundle. Every
 * string (keys included) is checked on its own, the way it will be read.
 * Numbers are not scanned: the collectors only emit counts, sizes, durations
 * and millisecond timestamps, and a 13-digit timestamp can pass a Luhn check.
 */
function residualFindings(value: unknown, found = new Set<string>()): Set<string> {
	const check = (text: string) => {
		for (const match of detectOutputSensitiveData(text)) found.add(match.type);
		const scan = scanPrivacyDetectors(text, RESIDUAL_DETECTORS);
		for (const match of scan.matches) found.add(DLP_DETECTOR_ENTITY_TYPES[match.detector]);
		if (scan.incomplete) found.add("not_fully_inspected");
		if (redactTelemetryString(text, Number.MAX_SAFE_INTEGER) !== text) {
			found.add("credential_pattern");
		}
	};
	if (typeof value === "string") check(value);
	else if (Array.isArray(value)) for (const item of value) residualFindings(item, found);
	else if (value && typeof value === "object") {
		for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
			check(key);
			residualFindings(item, found);
		}
	}
	return found;
}

// ---------------------------------------------------------------------------
// Collectors
// ---------------------------------------------------------------------------

function cliVersion(): string {
	try {
		const pkg = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "package.json");
		const parsed = JSON.parse(readFileSync(pkg, "utf8")) as { version?: unknown };
		return typeof parsed.version === "string" ? parsed.version : "unknown";
	} catch {
		return "unknown";
	}
}

function collectEnvironment(): Record<string, unknown> {
	return {
		core_version: VERSION,
		cli_version: cliVersion(),
		node_version: process.version,
		platform: platform(),
		arch: arch(),
		os_release: release(),
		// Names only: values can hold paths or credentials.
		aidr_environment_variables: Object.keys(process.env)
			.filter((name) => name.startsWith("AIDR_"))
			.sort(),
	};
}

function collectConnectors(connectors: ConnectorStatus[]): Record<string, unknown> {
	return {
		note: "Registration found on disk is not proof the host runs the hook; confirm with an agent-host canary.",
		connectors: connectors.map((c) => ({
			id: c.id,
			label: c.label,
			state: c.state,
			detail: c.detail,
			remedy: c.remedy,
			evidence: c.evidence,
		})),
	};
}

async function collectConfig(configPath: string | undefined): Promise<Record<string, unknown>> {
	const path = configPath ?? resolvePath("~/.singularity-aidr/config.json");
	try {
		const config = await loadConfig(configPath);
		let present = false;
		try {
			const handle = await open(path, "r");
			await handle.close();
			present = true;
		} catch {
			present = false;
		}
		return {
			path,
			state: isInvalidConfig(config) ? "invalid" : present ? "valid" : "defaults",
			effective: config,
		};
	} catch (error) {
		return {
			path,
			state: "unreadable",
			error: error instanceof Error ? error.name : "Error",
		};
	}
}

/** Audit fields copied into the bundle; everything else is dropped. */
const AUDIT_FIELDS = [
	"type",
	"timestamp",
	"tool_name",
	"verdict",
	"decision",
	"category",
	"severity",
	"source",
	"matched_threat_id",
	"frameworks",
	"user_override",
	"duration_ms",
	"agent_runtime",
	"runtime",
	"confidence",
] as const;

function safeToolName(value: unknown): string | undefined {
	if (typeof value !== "string") return undefined;
	return /^[\w.:\-/]{1,96}$/.test(value) ? value : "[unrecognised-tool-name]";
}

function summariseAuditEntry(entry: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const field of AUDIT_FIELDS) {
		const value = entry[field];
		if (value === undefined || value === null) continue;
		if (field === "tool_name") {
			out.tool_name = safeToolName(value);
			continue;
		}
		if (typeof value === "object" && field !== "frameworks") continue;
		out[field] = value;
	}
	if (Array.isArray(entry.artifacts)) {
		out.artifact_types = [
			...new Set(
				entry.artifacts
					.map((artifact) =>
						artifact && typeof artifact === "object"
							? (artifact as Record<string, unknown>).type
							: undefined,
					)
					.filter((type): type is string => typeof type === "string"),
			),
		].sort();
	}
	if (typeof entry.session_id === "string" && entry.session_id.length > 0) {
		out.session_digest = createHash("sha256").update(entry.session_id).digest("hex").slice(0, 16);
	}
	return out;
}

function countBy(entries: Record<string, unknown>[], field: string): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const entry of entries) {
		const key = typeof entry[field] === "string" ? (entry[field] as string) : "(none)";
		counts[key] = (counts[key] ?? 0) + 1;
	}
	return Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
}

async function collectAudit(limit: number, configPath: string | undefined) {
	const config = await loadConfig(configPath);
	if (!config.logging.enabled) return { logging_enabled: false, entries: [] };
	try {
		const { entries, skipped } = await readAuditEntries(auditLogFiles(config.logging));
		const recent = entries.slice(-limit).map(summariseAuditEntry);
		return {
			logging_enabled: true,
			total_entries_read: entries.length,
			skipped_lines: skipped,
			included: recent.length,
			omitted_fields:
				"tool_input_summary, artifacts (types kept), reasons, session_id (digest kept), delegation and any field not listed here are never copied",
			counts: {
				by_verdict: countBy(recent, "verdict"),
				by_tool: countBy(recent, "tool_name"),
				by_threat: countBy(recent, "matched_threat_id"),
			},
			entries: recent,
		};
	} catch (error) {
		return {
			logging_enabled: true,
			state: "unreadable",
			error: error instanceof Error ? error.name : "Error",
		};
	}
}

function sha256(data: string | Buffer): string {
	return createHash("sha256").update(data).digest("hex");
}

function collectThreats(threatsDir: string): Record<string, unknown> {
	let names: string[];
	try {
		names = readdirSync(threatsDir)
			.filter((name) => /\.ya?ml$/i.test(name))
			.sort();
	} catch {
		return { state: "missing", files: [] };
	}
	const files = names.map((name) => {
		const text = readFileSync(join(threatsDir, name), "utf8");
		return {
			file: name,
			sha256: sha256(text),
			rules: (text.match(/^- id:/gm) ?? []).length,
		};
	});
	return {
		state: files.length > 0 ? "present" : "empty",
		manifest_sha256: sha256(files.map((f) => `${f.sha256}  ${f.file}\n`).join("")),
		total_rules: files.reduce((total, f) => total + f.rules, 0),
		files,
	};
}

function parseAuditLimit(value: SupportBundleOptions["auditEntries"]): number {
	if (value === undefined) return DEFAULT_AUDIT_ENTRIES;
	const parsed = typeof value === "number" ? value : Number(String(value).trim());
	if (!Number.isInteger(parsed) || parsed < 0 || parsed > MAX_AUDIT_ENTRIES) {
		throw new SupportBundleError(
			`--audit-entries must be an integer from 0 to ${MAX_AUDIT_ENTRIES} (got "${value}")`,
		);
	}
	return parsed;
}

/** Collect and redact every bundle file. Pure apart from reads. */
async function collectSupportBundle(
	options: { auditEntries?: SupportBundleOptions["auditEntries"] } = {},
	deps: SupportBundleDeps = {},
): Promise<BundleFile[]> {
	const limit = parseAuditLimit(options.auditEntries);
	const identity = osIdentity(deps.identity);
	const connectors = deps.connectors
		? deps.connectors()
		: detectConnectorStatuses(deps.home ?? resolvePath("~"));
	const doctor = await runDoctor({ ...deps, connectors: () => connectors });
	const raw: Array<{ name: string; description: string; data: unknown }> = [
		{
			name: "environment.json",
			description: "AIDR core/CLI versions, Node.js version, OS platform/arch/release",
			data: collectEnvironment(),
		},
		{
			name: "doctor.json",
			description: "`aidr doctor` health checks (rules, hooks, mode, DLP, profiles, approvals)",
			data: doctor,
		},
		{
			name: "connectors.json",
			description: "Detected agent hosts and AIDR hook registrations",
			data: collectConnectors(connectors),
		},
		{
			name: "config.json",
			description: "Effective configuration with credential fields redacted",
			data: await collectConfig(deps.configPath),
		},
		{
			name: "audit-summary.json",
			description: `Last ${limit} audit verdicts: metadata fields only, no tool input, reasons or artifacts`,
			data: await collectAudit(limit, deps.configPath),
		},
		{
			name: "threats.json",
			description: "Hash manifest and rule counts of the shipped threat rules",
			data: collectThreats(deps.threatsDir ?? resolveBundledDataDirs().threatsDir),
		},
	];
	return raw.map(({ name, description, data }) => {
		const redacted = redactForBundle(data, identity);
		const residual = [...residualFindings(redacted)].sort();
		if (residual.length > 0) {
			throw new SupportBundleError(
				`Redaction check failed for ${name} (${residual.join(", ")}); no bundle was written.`,
			);
		}
		return { name, description, content: `${JSON.stringify(redacted, null, 2)}\n` };
	});
}

// ---------------------------------------------------------------------------
// Archive (POSIX ustar + gzip, no dependencies)
// ---------------------------------------------------------------------------

function tarHeader(name: string, size: number, mtime: number): Buffer {
	const header = Buffer.alloc(512, 0);
	const write = (text: string, offset: number, length: number) =>
		header.write(text.slice(0, length), offset, length, "utf8");
	const octal = (value: number, length: number) =>
		value
			.toString(8)
			.padStart(length - 1, "0")
			.slice(-(length - 1));
	write(name, 0, 100);
	write(octal(0o600, 8), 100, 8);
	write(octal(0, 8), 108, 8);
	write(octal(0, 8), 116, 8);
	write(octal(size, 12), 124, 12);
	write(octal(mtime, 12), 136, 12);
	header.fill(0x20, 148, 156); // checksum placeholder: spaces
	write("0", 156, 1);
	write("ustar\u000000", 257, 8);
	let checksum = 0;
	for (const byte of header) checksum += byte;
	write(`${octal(checksum, 7)}\u0000 `, 148, 8);
	return header;
}

function buildSupportArchive(files: readonly BundleFile[], mtime: Date): Buffer {
	const seconds = Math.floor(mtime.getTime() / 1000);
	const blocks: Buffer[] = [];
	for (const file of files) {
		const body = Buffer.from(file.content, "utf8");
		blocks.push(tarHeader(`${ROOT_DIR}/${file.name}`, body.length, seconds), body);
		const pad = (512 - (body.length % 512)) % 512;
		if (pad > 0) blocks.push(Buffer.alloc(pad, 0));
	}
	blocks.push(Buffer.alloc(1024, 0));
	return gzipSync(Buffer.concat(blocks), { level: 9 });
}

function defaultOutPath(now: Date): string {
	const stamp = now.toISOString().replace(/[:.]/g, "-");
	return resolve(process.cwd(), `aidr-support-bundle-${stamp}.tar.gz`);
}

/** Collect, redact, verify and write the archive; never overwrites an existing file. */
export async function createSupportBundle(
	options: SupportBundleOptions = {},
	deps: SupportBundleDeps = {},
): Promise<SupportBundleSummary> {
	const now = deps.now?.() ?? new Date();
	const inner = await collectSupportBundle(options, deps);
	const manifest: BundleFile = {
		name: "manifest.json",
		description: "Bundle index, per-file SHA-256 and the redaction applied",
		content: `${JSON.stringify(
			{
				schema_version: SUPPORT_BUNDLE_SCHEMA_VERSION,
				generator: "aidr support-bundle",
				created_at: now.toISOString(),
				core_version: VERSION,
				support_channel: SUPPORT_CHANNEL_NOTICE,
				redaction: [
					"credential-named keys replaced",
					"embedded credentials (Bearer, key=value, URL credentials, token formats, JWT) replaced",
					"home directory -> ~, account name -> <user>, host name -> <host>",
					"AIDR Privacy rules and credential detector findings masked as [TYPE]",
					"audit entries reduced to metadata fields; tool input, reasons and artifacts never copied",
					"final residual-finding scan; a hit aborts the bundle",
				],
				files: inner.map((file) => ({
					name: file.name,
					description: file.description,
					bytes: Buffer.byteLength(file.content),
					sha256: sha256(file.content),
				})),
			},
			null,
			2,
		)}\n`,
	};
	const files = [manifest, ...inner];
	const archive = buildSupportArchive(files, now);
	const path = resolve(options.out ?? defaultOutPath(now));
	let handle: Awaited<ReturnType<typeof open>>;
	try {
		handle = await open(path, "wx", 0o600);
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		throw new SupportBundleError(
			code === "EEXIST"
				? `${path} already exists; choose another --out path.`
				: `Cannot create ${path} (${code ?? "error"}).`,
		);
	}
	try {
		await handle.writeFile(archive);
	} finally {
		await handle.close();
	}
	return {
		path,
		bytes: archive.length,
		sha256: sha256(archive),
		files: files.map((file) => ({
			name: `${ROOT_DIR}/${file.name}`,
			description: file.description,
			bytes: Buffer.byteLength(file.content),
			sha256: sha256(file.content),
		})),
		support_channel: SUPPORT_CHANNEL_NOTICE,
	};
}

/** `aidr support-bundle` — exits non-zero when the bundle could not be produced. */
export default async function supportBundleCommand(
	options: SupportBundleOptions = {},
	deps: SupportBundleDeps = {},
): Promise<void> {
	const print = deps.stdout ?? ((text: string) => console.log(text));
	let summary: SupportBundleSummary;
	try {
		summary = await createSupportBundle(options, deps);
	} catch (error) {
		console.error(
			error instanceof SupportBundleError
				? error.message
				: `Support bundle failed: ${error instanceof Error ? error.message : String(error)}`,
		);
		process.exitCode = 1;
		return;
	}
	if (options.json) {
		print(JSON.stringify(summary, null, 2));
		return;
	}
	const lines = [
		`Wrote ${summary.path} (${summary.bytes} bytes, sha256 ${summary.sha256}).`,
		"Contents (review before sharing; every file is redacted):",
		...summary.files.map((file) => `  ${file.name}  ${file.bytes} B  ${file.description}`),
		"Not included: prompts, tool inputs/outputs, commands, audit reasons, credentials, file contents.",
		summary.support_channel,
	];
	print(lines.join("\n"));
}
