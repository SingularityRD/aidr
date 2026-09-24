#!/usr/bin/env node
/**
 * Builds an exact-data-match dataset (`ExactDataSet`, see src/types.ts) from a
 * CSV of sensitive values, for distribution through managed policy (`exactData`).
 *
 * Only HMAC-SHA256 fingerprints leave this tool: the source values are never
 * written, logged or echoed. The HMAC key is part of the dataset (the extension
 * needs it to fingerprint prompt text), so the dataset itself is sensitive:
 * deliver it only through managed policy, never publish it.
 *
 * Normalisation (must stay byte-for-byte identical to the extension engine):
 *   1. String.prototype.normalize("NFKC")
 *   2. toLowerCase()
 *   3. remove zero-width / bidi marks U+200B-U+200F, U+2060, U+FEFF
 *   4. Turkish folding: "ı" (U+0131) -> "i", "i̇" ("i" + U+0307, from lowercasing "İ") -> "i"
 *   5. tokens = every match of /[\p{L}\p{N}]+/gu
 *   fingerprint = hex(HMAC-SHA256(key = base64decode(keyB64), message = UTF-8(JSON.stringify(tokens))))
 *
 * Usage:
 *   node scripts/fingerprint-dataset.mjs --in customers.csv --dataset-id crm-customers \
 *     --type PERSON --header --columns full_name [--key-file key.b64] [--out dataset.json]
 */
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Mirrors ENTITY_TYPES in src/types.ts (asserted by src/__tests__/build-tools.test.ts). */
export const ENTITY_TYPES = Object.freeze([
	"PERSON",
	"EMAIL",
	"PHONE",
	"TC_KIMLIK",
	"IBAN",
	"CREDIT_CARD",
	"ADDRESS",
	"US_SSN",
	"DATE_OF_BIRTH",
	"PASSPORT",
	"NATIONAL_ID",
	"TAX_ID",
	"BANK_ACCOUNT",
	"IP_ADDRESS",
	"MAC_ADDRESS",
	"SECRET",
	"PRIVATE_KEY",
	"INTERNAL",
	"CLASSIFIED",
	"LOCATION",
	"USERNAME",
	"HEALTH_ID",
	"LICENSE_PLATE",
]);

/** A value must normalise to 1..MAX_TOKENS tokens and at least MIN_CHARS token characters. */
export const MAX_TOKENS = 16;
export const MIN_CHARS = 3;
export const MAX_FINGERPRINTS = 250_000;
const DATASET_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** Normalises a value into the token sequence that is fingerprinted. */
export function normaliseTokens(value) {
	const normalised = String(value)
		.normalize("NFKC")
		.toLowerCase()
		.replace(/[\u200b-\u200f\u2060\ufeff]/gu, "")
		.replace(/\u0131/gu, "i")
		.replace(/i\u0307/gu, "i");
	return normalised.match(/[\p{L}\p{N}]+/gu) ?? [];
}

/** hex HMAC-SHA256 over JSON.stringify(tokens). */
export function fingerprintTokens(key, tokens) {
	return createHmac("sha256", key).update(JSON.stringify(tokens), "utf8").digest("hex");
}

/** RFC 4180 CSV parser (quoted fields, doubled quotes, CR/LF/CRLF line ends). */
export function parseCsv(text) {
	const rows = [];
	let row = [];
	let field = "";
	let quoted = false;
	const input = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
	for (let i = 0; i < input.length; i++) {
		const ch = input[i];
		if (quoted) {
			if (ch === '"') {
				if (input[i + 1] === '"') {
					field += '"';
					i++;
				} else quoted = false;
			} else field += ch;
		} else if (ch === '"' && field === "") quoted = true;
		else if (ch === ",") {
			row.push(field);
			field = "";
		} else if (ch === "\n" || ch === "\r") {
			if (ch === "\r" && input[i + 1] === "\n") i++;
			row.push(field);
			rows.push(row);
			row = [];
			field = "";
		} else field += ch;
	}
	if (quoted) throw new Error("CSV_UNTERMINATED_QUOTE");
	if (field !== "" || row.length > 0) {
		row.push(field);
		rows.push(row);
	}
	return rows.filter((r) => r.some((cell) => cell.trim() !== ""));
}

/**
 * Builds the ExactDataSet.
 * @param {{ rows: string[][]; datasetId: string; type: string; key: Buffer; header?: boolean; columns?: string[] }} input
 */
export function buildDataset({ rows, datasetId, type, key, header = false, columns = [] }) {
	if (!DATASET_ID.test(datasetId ?? "")) throw new Error("DATASET_ID_INVALID (1-64 chars: letters, digits, . _ -)");
	if (!ENTITY_TYPES.includes(type)) throw new Error(`TYPE_INVALID: expected one of ${ENTITY_TYPES.join(", ")}`);
	if (!Buffer.isBuffer(key) || key.length < 32) throw new Error("KEY_TOO_SHORT: need at least 32 random bytes");
	let body = rows;
	let indexes = null;
	if (header || columns.length > 0) {
		const [head = [], ...rest] = rows;
		body = rest;
		if (columns.length > 0) {
			const names = head.map((name) => name.trim());
			indexes = columns.map((column) => {
				const index = names.indexOf(column);
				if (index < 0) throw new Error(`COLUMN_NOT_FOUND: ${column}`);
				return index;
			});
		}
	}
	const fingerprints = new Set();
	const skipped = { tooShort: 0, tooManyTokens: 0 };
	let values = 0;
	for (const row of body) {
		const cells = indexes ? indexes.map((i) => row[i] ?? "") : row;
		for (const cell of cells) {
			if (cell.trim() === "") continue;
			values++;
			const tokens = normaliseTokens(cell);
			if (tokens.join("").length < MIN_CHARS) skipped.tooShort++;
			else if (tokens.length > MAX_TOKENS) skipped.tooManyTokens++;
			else fingerprints.add(fingerprintTokens(key, tokens));
		}
	}
	if (fingerprints.size === 0) throw new Error("DATASET_EMPTY: no usable values");
	if (fingerprints.size > MAX_FINGERPRINTS) throw new Error(`DATASET_TOO_LARGE: max ${MAX_FINGERPRINTS} fingerprints`);
	return {
		dataset: {
			datasetId,
			keyB64: key.toString("base64"),
			// Sorted so the file order reveals nothing about the source row order.
			fingerprints: [...fingerprints].sort(),
			type,
		},
		stats: { values, fingerprints: fingerprints.size, skipped },
	};
}

function parseArgs(argv) {
	const options = { header: false, columns: [] };
	const takesValue = new Set(["--in", "--out", "--dataset-id", "--type", "--key-b64", "--key-file", "--columns"]);
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === "--header") options.header = true;
		else if (arg === "--help" || arg === "-h") options.help = true;
		else if (takesValue.has(arg)) {
			const value = argv[++i];
			if (value === undefined) throw new Error(`${arg} needs a value`);
			options[arg.slice(2).replace(/-([a-z])/g, (_m, c) => c.toUpperCase())] = value;
		} else throw new Error(`unknown argument ${arg}`);
	}
	if (typeof options.columns === "string") options.columns = options.columns.split(",").map((c) => c.trim()).filter(Boolean);
	return options;
}

const USAGE = `Usage: node scripts/fingerprint-dataset.mjs --in <file.csv|-> --dataset-id <id> --type <ENTITY_TYPE>
         [--header] [--columns a,b] [--key-b64 <base64> | --key-file <file>] [--out <file.json>]
Without a key option a fresh 32-byte key is generated; reuse it (via --key-file) when you
regenerate the same dataset so existing deployments keep matching.`;

function decodeKey(text) {
	const trimmed = text.trim();
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) throw new Error("KEY_NOT_BASE64");
	return Buffer.from(trimmed, "base64");
}

function main(argv) {
	const options = parseArgs(argv);
	if (options.help) {
		console.log(USAGE);
		return 0;
	}
	if (!options.in || !options.datasetId || !options.type) {
		console.error(USAGE);
		return 2;
	}
	let key;
	if (options.keyB64) key = decodeKey(options.keyB64);
	else if (options.keyFile) key = decodeKey(readFileSync(options.keyFile, "utf8"));
	else {
		key = randomBytes(32);
		console.error("[fingerprint] generated a new 32-byte HMAC key (stored in the dataset as keyB64)");
	}
	const text = readFileSync(options.in === "-" ? 0 : options.in, "utf8");
	const { dataset, stats } = buildDataset({
		rows: parseCsv(text),
		datasetId: options.datasetId,
		type: options.type,
		key,
		header: options.header,
		columns: options.columns,
	});
	const json = `${JSON.stringify(dataset, null, 2)}\n`;
	if (options.out) writeFileSync(options.out, json, { mode: 0o600 });
	else process.stdout.write(json);
	console.error(
		`[fingerprint] ${stats.values} value(s) -> ${stats.fingerprints} fingerprint(s); skipped ${stats.skipped.tooShort} too short, ${stats.skipped.tooManyTokens} over ${MAX_TOKENS} tokens`,
	);
	return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		process.exitCode = main(process.argv.slice(2));
	} catch (error) {
		console.error(`[fingerprint] ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
}
