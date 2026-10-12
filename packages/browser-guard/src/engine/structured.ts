/**
 * Pasted structured data in a prompt: JSON / Python-dict objects and CSV, TSV, semicolon or
 * Markdown tables. A value is sensitive because of the key or column header it sits under
 * (`"fullName": "Deniz Aydın"`, a `soyad` column), which the free-text rules cannot see: a bare
 * `Yılmaz` cell or a `5051234567` value has no label of its own.
 *
 * File uploads get the same treatment from engine/files.ts with full parsers; this is the
 * lightweight in-prompt counterpart and shares its key dictionary (engine/keys.ts).
 * - JSON keys use the strict dictionary: `"name": "my-package"` is not a person.
 * - A table header needs at least one unambiguous sensitive column before ambiguous headers
 *   (`name`, `ad`, `tc`) count, so `name,version` stays a package list while `ad,soyad,tckn`
 *   and `| Name | Email |` are customer rows.
 * - Only data rows with the header's cell count directly below the header are read.
 */
import type { EntityType } from "../types.js";
import { sensitiveKeyType } from "./keys.js";

export type StructuredEmit = (start: number, end: number, type: EntityType) => void;

/** Longest header cell / JSON key considered a field name. */
const MAX_KEY_CHARS = 64;
const JSON_PAIR =
	/(["'])((?:(?!\1)[^\\\r\n]|\\.){1,64})\1[ \t]*:[ \t]*(?:(["'])((?:(?!\3)[^\\\r\n]|\\.)*)\3|(-?[0-9][0-9.]*))/g;
const MARKDOWN_RULE = /^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)*\|?\s*$/;
const DELIMITERS = ["|", "\t", ",", ";"] as const;
type Delimiter = (typeof DELIMITERS)[number];
type Cell = readonly [start: number, end: number];

export function detectStructured(
	text: string,
	enabled: ReadonlySet<EntityType>,
	emit: StructuredEmit,
): void {
	detectJsonPairs(text, enabled, emit);
	detectTables(text, enabled, emit);
}

function detectJsonPairs(
	text: string,
	enabled: ReadonlySet<EntityType>,
	emit: StructuredEmit,
): void {
	for (const m of text.matchAll(JSON_PAIR)) {
		const type = sensitiveKeyType(m[2] ?? "", false);
		if (!type || !enabled.has(type)) continue;
		const value = m[4] ?? m[5] ?? "";
		if (!value.trim()) continue;
		const end = m.index + m[0].length - (m[4] === undefined ? 0 : 1);
		emit(end - value.length, end, type);
	}
}

interface Line {
	readonly start: number;
	readonly text: string;
}

function splitLines(text: string): Line[] {
	const lines: Line[] = [];
	let start = 0;
	for (const m of text.matchAll(/\r\n|\n|\r/g)) {
		lines.push({ start, text: text.slice(start, m.index) });
		start = m.index + m[0].length;
	}
	lines.push({ start, text: text.slice(start) });
	return lines;
}

/** Trimmed cell spans (relative to the line); quotes around a cell are excluded. */
function splitCells(line: string, delimiter: Delimiter): Cell[] {
	let from = 0;
	let to = line.length;
	if (delimiter === "|") {
		const trimmed = line.trim();
		if (!trimmed.startsWith("|")) return [];
		from = line.indexOf("|") + 1;
		to = trimmed.endsWith("|") && trimmed.length > 1 ? line.lastIndexOf("|") : line.length;
	}
	const cells: Cell[] = [];
	let i = from;
	while (i <= to) {
		let end = i;
		let quoted = false;
		for (; end < to && (quoted || line[end] !== delimiter); end++) {
			if (line[end] === '"') quoted = !quoted;
		}
		let a = i;
		let b = end;
		while (a < b && /\s/.test(line[a] as string)) a++;
		while (b > a && /\s/.test(line[b - 1] as string)) b--;
		if (b - a >= 2 && line[a] === '"' && line[b - 1] === '"') {
			a++;
			b--;
		}
		cells.push([a, b]);
		i = end + 1;
	}
	return cells;
}

/** Column types of a header row, or null when it does not read as a sensitive table header. */
function headerTypes(
	line: string,
	cells: readonly Cell[],
	enabled: ReadonlySet<EntityType>,
): Array<EntityType | undefined> | null {
	if (cells.length < 2) return null;
	const names = cells.map(([a, b]) => line.slice(a, b));
	if (names.some((n) => !n || n.length > MAX_KEY_CHARS)) return null;
	const strict = names.map((n) => sensitiveKeyType(n, false));
	if (!strict.some((t) => t !== undefined)) return null;
	const types = names.map((n) => sensitiveKeyType(n, true));
	return types.some((t) => t && enabled.has(t))
		? types.map((t) => (t && enabled.has(t) ? t : undefined))
		: null;
}

function detectTables(text: string, enabled: ReadonlySet<EntityType>, emit: StructuredEmit): void {
	const lines = splitLines(text);
	for (let h = 0; h < lines.length - 1; h++) {
		const header = lines[h] as Line;
		for (const delimiter of DELIMITERS) {
			if (!header.text.includes(delimiter)) continue;
			const headerCells = splitCells(header.text, delimiter);
			const types = headerTypes(header.text, headerCells, enabled);
			if (!types) continue;
			let r = h + 1;
			if (delimiter === "|" && MARKDOWN_RULE.test(lines[r]?.text ?? "")) r++;
			for (; r < lines.length; r++) {
				const row = lines[r] as Line;
				const cells = splitCells(row.text, delimiter);
				if (cells.length !== headerCells.length) break;
				cells.forEach(([a, b], c) => {
					const type = types[c];
					if (type && b > a) emit(row.start + a, row.start + b, type);
				});
			}
			h = r - 1;
			break;
		}
	}
}
