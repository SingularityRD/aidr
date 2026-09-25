/**
 * Client-side exports of a compliance evidence report: section tables, a CSV
 * bundle packed into a ZIP archive, and the file names they are saved under.
 *
 * The signed JSON is the authoritative artifact; every CSV is derived from it
 * in the browser and says so in the bundle's README.
 */

import {
	COMPLIANCE_SECTION_KEYS,
	type ComplianceReport,
	type ComplianceSectionKey,
	type JsonValue,
} from "../lib/compliance-report";

export type Cell = string | number | boolean | null;

/** One renderable block of a section: key/value pairs or a table of records. */
export interface SectionBlock {
	/** Dotted path inside the section; "" for the section's top-level fields. */
	path: string;
	kind: "fields" | "table";
	headers: string[];
	rows: Cell[][];
}

function isObject(value: JsonValue): value is { [key: string]: JsonValue } {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scalar(value: JsonValue): Cell {
	if (Array.isArray(value)) return value.map((item) => String(scalar(item))).join("; ");
	if (isObject(value)) {
		return Object.entries(value)
			.map(([key, item]) => `${key}=${String(scalar(item))}`)
			.join("; ");
	}
	return value;
}

function isTable(value: JsonValue): value is { [key: string]: JsonValue }[] {
	return Array.isArray(value) && value.length > 0 && value.every(isObject);
}

function joinPath(path: string, key: string): string {
	return path ? `${path}.${key}` : key;
}

function isEmpty(value: JsonValue): boolean {
	return isObject(value) || (Array.isArray(value) && value.length === 0);
}

function recordTable(path: string, rows: { [key: string]: JsonValue }[]): SectionBlock {
	const headers = [...new Set(rows.flatMap((row) => Object.keys(row)))];
	return {
		path,
		kind: "table",
		headers,
		rows: rows.map((row) => headers.map((header) => scalar(row[header] ?? null))),
	};
}

/**
 * Flatten a section into blocks. Scalars (and maps of counts) become
 * `field,value` rows; arrays of records become their own table.
 */
export function sectionBlocks(section: { [key: string]: JsonValue }): SectionBlock[] {
	const fields: Cell[][] = [];
	const tables: SectionBlock[] = [];
	const walk = (value: JsonValue, path: string) => {
		if (isTable(value)) {
			tables.push(recordTable(path, value));
			return;
		}
		if (isObject(value) && Object.keys(value).length > 0) {
			for (const [key, child] of Object.entries(value)) walk(child, joinPath(path, key));
			return;
		}
		fields.push([path, isEmpty(value) ? "none" : scalar(value)]);
	};
	walk(section, "");
	const blocks: SectionBlock[] = [];
	if (fields.length > 0)
		blocks.push({ path: "", kind: "fields", headers: ["field", "value"], rows: fields });
	return [...blocks, ...tables];
}

/** RFC 4180 field; strings that a spreadsheet would run as a formula are neutralised. */
export function csvField(value: Cell): string {
	if (value === null) return "";
	let text = String(value);
	if (typeof value === "string" && /^[=+\-@\t\r]/.test(text)) text = `'${text}`;
	return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function toCsv(headers: string[], rows: Cell[][]): string {
	return `${[headers, ...rows].map((row) => row.map(csvField).join(",")).join("\r\n")}\r\n`;
}

export function reportFileStem(report: ComplianceReport): string {
	const day = (value: string) => value.slice(0, 10);
	return `aidr-compliance-${day(report.period.from)}_${day(report.period.to)}-${report.report_id.slice(0, 8)}`;
}

/** Every file of the CSV bundle, in archive order. */
export function csvBundleFiles(report: ComplianceReport): Array<{ name: string; content: string }> {
	const signature = report.integrity.signature;
	const files: Array<{ name: string; content: string }> = [
		{
			name: "README.txt",
			content: [
				"Singularity AIDR compliance evidence report - CSV bundle",
				"",
				`Report ID: ${report.report_id}`,
				`Period: ${report.period.from} .. ${report.period.to}`,
				`Generated: ${report.generated_at}`,
				`Report SHA-256: ${report.integrity.sha256}`,
				`Signature: ${signature ? `ed25519, key ${signature.key_id}` : "none (hash only)"}`,
				"",
				"These CSV files are derived in the browser from the JSON report and are not signed.",
				"The JSON report is the authoritative, verifiable artifact:",
				"  aidr compliance verify <report.json> [--public-key <issuer.pem>]",
				"",
				report.statement,
				"",
			].join("\r\n"),
		},
		{
			name: "00_report.csv",
			content: toCsv(
				["field", "value"],
				[
					["schema", report.schema],
					["report_id", report.report_id],
					["generated_at", report.generated_at],
					["generated_by.user_id", report.generated_by.user_id],
					["generated_by.role", report.generated_by.role],
					["period.from", report.period.from],
					["period.to", report.period.to],
					["period.days", report.period.days],
					["integrity.sha256", report.integrity.sha256],
					["integrity.signature.key_id", signature?.key_id ?? null],
					...report.limitations.map((text, index): Cell[] => [`limitations.${index + 1}`, text]),
				],
			),
		},
	];
	COMPLIANCE_SECTION_KEYS.forEach((key: ComplianceSectionKey, index) => {
		const prefix = `${String(index + 1).padStart(2, "0")}_${key}`;
		for (const block of sectionBlocks(report.sections[key])) {
			const name = block.path
				? `${prefix}__${block.path.replaceAll(".", "_")}.csv`
				: `${prefix}.csv`;
			files.push({ name, content: toCsv(block.headers, block.rows) });
		}
	});
	return files;
}

// ── ZIP (stored, no compression) ────────────────────────────────────────────

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n += 1) {
		let c = n;
		for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

export function crc32(bytes: Uint8Array): number {
	let crc = 0xffffffff;
	for (const byte of bytes) crc = (CRC_TABLE[(crc ^ byte) & 0xff] ?? 0) ^ (crc >>> 8);
	return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date: Date): { time: number; date: number } {
	const year = Math.max(1980, date.getUTCFullYear());
	return {
		time:
			(date.getUTCHours() << 11) |
			(date.getUTCMinutes() << 5) |
			Math.floor(date.getUTCSeconds() / 2),
		date: ((year - 1980) << 9) | ((date.getUTCMonth() + 1) << 5) | date.getUTCDate(),
	};
}

/**
 * Minimal ZIP writer (stored entries, UTF-8 names). CSV bundles are small, so
 * compression is not worth a dependency; every archive tool reads stored entries.
 */
function zipFiles(
	files: Array<{ name: string; content: string }>,
	modified: Date,
): Uint8Array {
	const encoder = new TextEncoder();
	const stamp = dosDateTime(modified);
	const locals: Uint8Array[] = [];
	const centrals: Uint8Array[] = [];
	let offset = 0;
	for (const file of files) {
		const name = encoder.encode(file.name);
		const data = encoder.encode(file.content);
		const crc = crc32(data);
		const local = new Uint8Array(30 + name.length + data.length);
		const lv = new DataView(local.buffer);
		lv.setUint32(0, 0x04034b50, true);
		lv.setUint16(4, 20, true);
		lv.setUint16(6, 0x0800, true); // UTF-8 file names
		lv.setUint16(8, 0, true); // stored
		lv.setUint16(10, stamp.time, true);
		lv.setUint16(12, stamp.date, true);
		lv.setUint32(14, crc, true);
		lv.setUint32(18, data.length, true);
		lv.setUint32(22, data.length, true);
		lv.setUint16(26, name.length, true);
		lv.setUint16(28, 0, true);
		local.set(name, 30);
		local.set(data, 30 + name.length);
		const central = new Uint8Array(46 + name.length);
		const cv = new DataView(central.buffer);
		cv.setUint32(0, 0x02014b50, true);
		cv.setUint16(4, 20, true);
		cv.setUint16(6, 20, true);
		cv.setUint16(8, 0x0800, true);
		cv.setUint16(10, 0, true);
		cv.setUint16(12, stamp.time, true);
		cv.setUint16(14, stamp.date, true);
		cv.setUint32(16, crc, true);
		cv.setUint32(20, data.length, true);
		cv.setUint32(24, data.length, true);
		cv.setUint16(28, name.length, true);
		cv.setUint32(42, offset, true);
		central.set(name, 46);
		locals.push(local);
		centrals.push(central);
		offset += local.length;
	}
	const centralSize = centrals.reduce((total, part) => total + part.length, 0);
	const end = new Uint8Array(22);
	const ev = new DataView(end.buffer);
	ev.setUint32(0, 0x06054b50, true);
	ev.setUint16(8, files.length, true);
	ev.setUint16(10, files.length, true);
	ev.setUint32(12, centralSize, true);
	ev.setUint32(16, offset, true);
	const out = new Uint8Array(offset + centralSize + end.length);
	let cursor = 0;
	for (const part of [...locals, ...centrals, end]) {
		out.set(part, cursor);
		cursor += part.length;
	}
	return out;
}

export function csvBundleZip(report: ComplianceReport): Uint8Array {
	return zipFiles(csvBundleFiles(report), new Date(report.generated_at));
}
