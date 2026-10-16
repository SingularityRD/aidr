import { open } from "node:fs/promises";
import {
	DLP_DETECTOR_ENTITY_TYPES,
	type DlpDetector,
	DlpDetectorSchema,
	detectOutputSensitiveData,
	PRIVACY_DETECTOR_MAX_CHARS,
	scanPrivacyDetectors,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";

/**
 * `aidr privacy scan` — local TR/EN personal-data and secret scan of one file or stdin.
 *
 * Detection is the core DLP rule layer (the drift-checked copy of AIDR Privacy's
 * checksum-validated TCKN, IBAN mod-97, Luhn card, phone, e-mail, labelled-field and
 * secret rules) plus the high-precision credential detector used for tool-output
 * quarantine. Everything runs in-process: nothing is uploaded and no matched value is
 * ever printed — reports carry the type, offsets and line numbers only.
 *
 * Exit codes: 0 no failing findings, 2 findings that meet `--fail-on`, 3 the input was
 * not fully inspected (never reported as clean), 1 usage or input error.
 */

export const PRIVACY_EXIT = Object.freeze({ clean: 0, error: 1, findings: 2, incomplete: 3 });

/** Read bound. Larger input is refused outright rather than partially scanned. */
export const PRIVACY_SCAN_MAX_BYTES = 4 * 1024 * 1024;

type PrivacyFailOn = "none" | "any" | "secret";

export interface PrivacyScanOptions {
	json?: boolean;
	mask?: boolean;
	types?: string;
	failOn?: string;
}

interface PrivacyFinding {
	/** Entity type, the same name used by the `[TYPE]` mask placeholder. */
	type: string;
	/** Half-open UTF-16 offsets into the decoded (UTF-8, BOM-stripped) text. */
	start: number;
	end: number;
	/** 1-based line of `start`. */
	line: number;
}

interface PrivacyScanReport {
	findings: PrivacyFinding[];
	counts: Record<string, number>;
	/** true when part of the input was not inspected; findings are then a lower bound. */
	incomplete: boolean;
	/** Static reason codes; never input text. */
	reasons: string[];
	/** Present only with --mask on a complete inspection. */
	masked?: string;
}

/** Injectable collaborators, for tests. Production callers pass nothing. */
export interface PrivacyScanDependencies {
	stdin?: NodeJS.ReadableStream & { isTTY?: boolean };
	stdout?: (text: string) => void;
	stderr?: (text: string) => void;
	maxBytes?: number;
	/** Privacy-rule working limit; capped at PRIVACY_DETECTOR_MAX_CHARS. */
	maxScanChars?: number;
}

const DETECTORS: readonly DlpDetector[] = DlpDetectorSchema.options;
const SECRET_TYPES = new Set(["SECRET", "PRIVATE_KEY"]);

const TYPE_ALIASES: Readonly<Record<string, DlpDetector>> = {
	tckn: "tc_kimlik",
	tc: "tc_kimlik",
	card: "credit_card",
	ssn: "us_ssn",
	ip: "ip_address",
	mac: "mac_address",
};

class PrivacyInputError extends Error {}

/** Parse `--types` into core detector names; an empty result means every detector. */
function parsePrivacyTypes(list: string | undefined): DlpDetector[] {
	if (list === undefined) return [...DETECTORS];
	const selected = new Set<DlpDetector>();
	for (const raw of list.split(",")) {
		const name = raw.trim().toLowerCase().replace(/-/g, "_");
		if (name.length === 0) continue;
		const detector =
			TYPE_ALIASES[name] ?? DETECTORS.find((candidate) => candidate === name) ?? undefined;
		if (!detector) {
			throw new PrivacyInputError(
				ct("privacy.unknownType", {
					type: raw.trim(),
					valid: DETECTORS.join(", "),
					aliases: Object.keys(TYPE_ALIASES).join(", "),
				}),
			);
		}
		selected.add(detector);
	}
	if (selected.size === 0) throw new PrivacyInputError(ct("privacy.typesEmpty"));
	return DETECTORS.filter((detector) => selected.has(detector));
}

function parseFailOn(value: string | undefined): PrivacyFailOn {
	const mode = (value ?? "any").trim().toLowerCase();
	if (mode === "none" || mode === "any" || mode === "secret") return mode;
	throw new PrivacyInputError(ct("privacy.badFailOn", { value: String(value) }));
}

/** Map a credential-detector type onto the privacy entity vocabulary. */
function credentialEntityType(type: string): string {
	if (type === "private_key") return "PRIVATE_KEY";
	if (type === "credit_card") return "CREDIT_CARD";
	if (type === "ssn") return "US_SSN";
	return "SECRET";
}

const PEM_END = /-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/;
const PEM_BODY_LINE = /^[ \t]*[A-Za-z0-9+/=:\-, ]*\r?$/;

/**
 * The credential detector reports only a PEM header; masking just the header would
 * leave the key body in the output, so a private-key span always runs through the
 * END marker (or, without one, through the contiguous key-body lines that follow).
 */
function privateKeyEnd(text: string, headerEnd: number): number {
	const rest = text.slice(headerEnd);
	const endMarker = PEM_END.exec(rest);
	if (endMarker) return headerEnd + endMarker.index + endMarker[0].length;
	const [headerRest = "", ...bodyLines] = rest.split("\n");
	let end = headerEnd + headerRest.length;
	let cursor = end + 1;
	for (const line of bodyLines) {
		if (line.trim().length === 0 || !PEM_BODY_LINE.test(line)) break;
		end = cursor + line.length;
		cursor = end + 1;
	}
	return end;
}

interface Span {
	type: string;
	start: number;
	end: number;
	rank: number;
}

/** Secrets win a type conflict on a merged span; otherwise the earliest match's type stays. */
function typeRank(type: string): number {
	if (type === "PRIVATE_KEY") return 0;
	if (type === "SECRET") return 1;
	return 2;
}

/** Union overlapping spans so a value is never partially exposed or double counted. */
function mergeSpans(spans: Span[]): Span[] {
	spans.sort((left, right) => left.start - right.start || right.end - left.end);
	const merged: Span[] = [];
	for (const span of spans) {
		const last = merged[merged.length - 1];
		if (last && span.start < last.end) {
			last.end = Math.max(last.end, span.end);
			if (span.rank < last.rank) {
				last.type = span.type;
				last.rank = span.rank;
			}
			continue;
		}
		merged.push({ ...span });
	}
	return merged;
}

function lineStarts(text: string): number[] {
	const starts = [0];
	for (let index = text.indexOf("\n"); index !== -1; index = text.indexOf("\n", index + 1)) {
		starts.push(index + 1);
	}
	return starts;
}

function lineOf(starts: readonly number[], offset: number): number {
	let low = 0;
	let high = starts.length - 1;
	while (low < high) {
		const middle = (low + high + 1) >> 1;
		if ((starts[middle] ?? 0) <= offset) low = middle;
		else high = middle - 1;
	}
	return low + 1;
}

/** Replace each finding with its constant `[TYPE]` placeholder. */
function maskPrivacyFindings(text: string, findings: readonly PrivacyFinding[]): string {
	let output = "";
	let cursor = 0;
	for (const finding of findings) {
		output += text.slice(cursor, finding.start);
		output += `[${finding.type}]`;
		cursor = finding.end;
	}
	return output + text.slice(cursor);
}

/**
 * Scan decoded text with the selected detectors. Pure: no I/O, and the returned report
 * never contains a matched value (except inside `masked`, where every match is replaced).
 */
function scanPrivacyText(
	text: string,
	detectors: readonly DlpDetector[],
	options: { mask?: boolean; maxScanChars?: number } = {},
): PrivacyScanReport {
	const maxScanChars = Math.min(
		options.maxScanChars ?? PRIVACY_DETECTOR_MAX_CHARS,
		PRIVACY_DETECTOR_MAX_CHARS,
	);
	const privacy = scanPrivacyDetectors(text, detectors, maxScanChars);
	const enabledTypes = new Set<string>(
		detectors.map((detector) => DLP_DETECTOR_ENTITY_TYPES[detector]),
	);
	const spans: Span[] = privacy.matches.map((match) => {
		const type = DLP_DETECTOR_ENTITY_TYPES[match.detector];
		return { type, start: match.start, end: match.end, rank: typeRank(type) };
	});
	// The credential detector has no input limit of its own and covers formats (JWT,
	// Slack webhooks, bearer tokens) the privacy rules do not name.
	for (const match of detectOutputSensitiveData(text)) {
		const type = credentialEntityType(match.type);
		if (!enabledTypes.has(type)) continue;
		const start = match.index;
		const end =
			type === "PRIVATE_KEY"
				? privateKeyEnd(text, start + match.value.length)
				: start + match.value.length;
		spans.push({ type, start, end, rank: typeRank(type) });
	}

	const starts = lineStarts(text);
	const findings: PrivacyFinding[] = mergeSpans(spans).map((span) => ({
		type: span.type,
		start: span.start,
		end: span.end,
		line: lineOf(starts, span.start),
	}));
	const counts: Record<string, number> = {};
	for (const finding of findings) counts[finding.type] = (counts[finding.type] ?? 0) + 1;

	const report: PrivacyScanReport = {
		findings,
		counts: Object.fromEntries(
			Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)),
		),
		incomplete: privacy.incomplete,
		reasons: [...privacy.reasons],
	};
	if (options.mask && !report.incomplete) report.masked = maskPrivacyFindings(text, findings);
	return report;
}

function formatBytes(bytes: number): string {
	return bytes >= 1024 * 1024
		? `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
		: `${Math.ceil(bytes / 1024)} KiB`;
}

async function readBoundedFile(path: string, maxBytes: number): Promise<Buffer> {
	let handle: Awaited<ReturnType<typeof open>>;
	try {
		handle = await open(path, "r");
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		throw new PrivacyInputError(
			code === "ENOENT"
				? ct("privacy.notFound", { path })
				: ct("privacy.cannotRead", { path, code: code ?? "error" }),
		);
	}
	try {
		const info = await handle.stat();
		if (!info.isFile()) throw new PrivacyInputError(ct("privacy.notRegular", { path }));
		if (info.size > maxBytes) {
			throw new PrivacyInputError(
				ct("privacy.tooLarge", { size: formatBytes(info.size), max: formatBytes(maxBytes) }),
			);
		}
		const buffer = Buffer.alloc(maxBytes + 1);
		let length = 0;
		while (length <= maxBytes) {
			const { bytesRead } = await handle.read(buffer, length, maxBytes + 1 - length, null);
			if (bytesRead === 0) break;
			length += bytesRead;
		}
		if (length > maxBytes) {
			throw new PrivacyInputError(ct("privacy.grew", { max: formatBytes(maxBytes) }));
		}
		return buffer.subarray(0, length);
	} finally {
		await handle.close();
	}
}

async function readBoundedStream(stream: NodeJS.ReadableStream, maxBytes: number): Promise<Buffer> {
	const chunks: Buffer[] = [];
	let length = 0;
	for await (const chunk of stream) {
		const buffer = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
		length += buffer.length;
		if (length > maxBytes) {
			throw new PrivacyInputError(ct("privacy.stdinTooLarge", { max: formatBytes(maxBytes) }));
		}
		chunks.push(buffer);
	}
	return Buffer.concat(chunks, length);
}

/** Decode UTF-8 text, refusing binary content instead of scanning mojibake. */
function decodePrivacyInput(buffer: Buffer): string {
	if (buffer.includes(0)) {
		throw new PrivacyInputError(ct("privacy.binary"));
	}
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
	} catch {
		throw new PrivacyInputError(ct("privacy.notUtf8"));
	}
}

function exitCodeFor(report: PrivacyScanReport, failOn: PrivacyFailOn): number {
	const failing =
		failOn === "any"
			? report.findings.length > 0
			: failOn === "secret"
				? report.findings.some((finding) => SECRET_TYPES.has(finding.type))
				: false;
	if (failing) return PRIVACY_EXIT.findings;
	if (report.incomplete) return PRIVACY_EXIT.incomplete;
	return PRIVACY_EXIT.clean;
}

function summarizeLines(lines: readonly number[]): string {
	const unique = [...new Set(lines)];
	const shown = unique.slice(0, 12).join(", ");
	return unique.length > 12
		? `${shown}, … ${ct("privacy.more", { count: unique.length - 12 })}`
		: shown;
}

function humanReport(report: PrivacyScanReport, source: string, bytes: number): string {
	const out: string[] = [ct("privacy.header", { source, bytes }), ""];
	if (report.findings.length === 0) {
		out.push(report.incomplete ? ct("privacy.noFindingsPartial") : ct("privacy.noFindings"));
	} else {
		const rows = Object.keys(report.counts).map((type) => [
			type,
			String(report.counts[type]),
			summarizeLines(report.findings.filter((f) => f.type === type).map((f) => f.line)),
		]);
		const typeHeader = ct("privacy.colType");
		const width = Math.max(typeHeader.length, ...rows.map(([type]) => (type ?? "").length));
		out.push(
			`${typeHeader.padEnd(width)}  ${ct("privacy.colCount").padStart(5)}  ${ct("privacy.colLines")}`,
		);
		for (const [type, count, lines] of rows) {
			out.push(`${(type ?? "").padEnd(width)}  ${(count ?? "").padStart(5)}  ${lines}`);
		}
		out.push("", ct("privacy.findings", { count: report.findings.length }));
	}
	if (report.incomplete) {
		out.push(
			"",
			ct("privacy.incomplete", { reasons: report.reasons.join(", ") || "UNKNOWN" }),
			ct("privacy.notClean"),
		);
	}
	return `${out.join("\n")}\n`;
}

interface Writers {
	stdout: (text: string) => void;
	stderr: (text: string) => void;
}

async function readPrivacyInput(
	file: string | undefined,
	dependencies: PrivacyScanDependencies,
): Promise<{ buffer: Buffer; source: string }> {
	const maxBytes = dependencies.maxBytes ?? PRIVACY_SCAN_MAX_BYTES;
	if (file !== undefined && file !== "-") {
		return { buffer: await readBoundedFile(file, maxBytes), source: file };
	}
	const stdin = dependencies.stdin ?? process.stdin;
	if (stdin.isTTY) {
		throw new PrivacyInputError(ct("privacy.noInput"));
	}
	return { buffer: await readBoundedStream(stdin, maxBytes), source: ct("privacy.stdinSource") };
}

function emitReport(
	report: PrivacyScanReport,
	options: PrivacyScanOptions,
	header: { source: string; bytes: number },
	{ stdout, stderr }: Writers,
): void {
	if (options.json) {
		const payload: Record<string, unknown> = {
			findings: report.findings,
			counts: report.counts,
			incomplete: report.incomplete,
			reasons: report.reasons,
		};
		if (options.mask) payload.masked = report.masked ?? null;
		stdout(`${JSON.stringify(payload, null, 2)}\n`);
		return;
	}
	const table = humanReport(report, header.source, header.bytes);
	if (!options.mask) {
		stdout(table);
		return;
	}
	// The table goes to stderr so stdout is exactly the redacted text.
	stderr(table);
	if (report.masked === undefined) {
		stderr(`${ct("privacy.refuseMask")}\n`);
	} else {
		stdout(report.masked);
	}
}

/**
 * Run the scan and return the exit code. Output goes through the injected writers so
 * tests can observe it; the Commander action applies the code to `process.exitCode`.
 */
export async function runPrivacyScan(
	file: string | undefined,
	options: PrivacyScanOptions,
	dependencies: PrivacyScanDependencies = {},
): Promise<number> {
	const writers: Writers = {
		stdout: dependencies.stdout ?? ((text) => void process.stdout.write(text)),
		stderr: dependencies.stderr ?? ((text) => void process.stderr.write(text)),
	};
	try {
		const detectors = parsePrivacyTypes(options.types);
		const failOn = parseFailOn(options.failOn);
		const { buffer, source } = await readPrivacyInput(file, dependencies);
		const report = scanPrivacyText(decodePrivacyInput(buffer), detectors, {
			mask: options.mask,
			maxScanChars: dependencies.maxScanChars,
		});
		emitReport(report, options, { source, bytes: buffer.length }, writers);
		return exitCodeFor(report, failOn);
	} catch (error) {
		// Only our own messages are printed; an unexpected error could quote input text.
		const message =
			error instanceof PrivacyInputError
				? error.message
				: ct("privacy.failed", { name: error instanceof Error ? error.name : "error" });
		writers.stderr(`aidr privacy scan: ${message}\n`);
		return PRIVACY_EXIT.error;
	}
}

async function privacyScanCommand(
	file: string | undefined,
	options: PrivacyScanOptions,
): Promise<void> {
	process.exitCode = await runPrivacyScan(file, options);
}

export default privacyScanCommand;
