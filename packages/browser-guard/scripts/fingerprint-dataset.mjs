#!/usr/bin/env node
/**
 * Builds an exact-data-match dataset (`ExactDataSet`, see src/types.ts) from a
 * CSV of sensitive values, for distribution through managed policy (`exactData`).
 *
 * Only HMAC-SHA256 fingerprints leave this tool: the source values are never
 * written, logged or echoed, and neither is any key. Managed policy is readable
 * by every user of the endpoint (chrome://policy, the policy registry keys,
 * policies.json), so a dataset carries no key. Each dataset is fingerprinted with
 * its own key, derived from the organisation's EDM secret:
 *
 *   datasetKey = HMAC-SHA256(secret, UTF-8("aidr-edm-v2" || 0x00 || datasetId))
 *
 * The same secret is installed in the AIDR Privacy native host configuration
 * (`exactData.secretFile`, packages/privacy/src/native/edm.ts); the extension asks
 * the host for the dataset keys at runtime.
 *
 * A keyed hash only protects values that cannot be enumerated: whoever obtains a
 * dataset key (an endpoint user with a debugger, malware on the endpoint) can test
 * every candidate. So every value's entropy is estimated (estimateEntropyBits) and a
 * dataset with any value below MIN_ENTROPY_BITS is refused, unless --drop-low-entropy
 * leaves those values out. Low-entropy columns (customer numbers, TCKN, phone
 * numbers, names) can be combined into one high-entropy value per row with
 * --composite (name + customer number), or left to the built-in rules.
 *
 * Normalisation (must stay byte-for-byte identical to the extension engine):
 *   1. String.prototype.normalize("NFKC")
 *   2. toLowerCase()
 *   3. remove zero-width / bidi marks U+200B-U+200F, U+2060, U+FEFF
 *   4. Turkish folding: "ı" (U+0131) -> "i", "i̇" ("i" + U+0307, from lowercasing "İ") -> "i"
 *   5. tokens = every match of /[\p{L}\p{N}]+/gu
 *   fingerprint = hex(HMAC-SHA256(key = datasetKey, message = UTF-8(JSON.stringify(tokens))))
 *
 * Usage:
 *   node scripts/fingerprint-dataset.mjs --new-secret edm-secret.b64
 *   node scripts/fingerprint-dataset.mjs --in customers.csv --dataset-id crm-customers \
 *     --type PERSON --header --columns full_name,customer_no --composite \
 *     --secret-file edm-secret.b64 [--out dataset.json]
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
/** Mirrors EXACT_DATA_MIN_ENTROPY_BITS in src/background/policy.ts. */
export const MIN_ENTROPY_BITS = 64;
/** Mirrors EDM_KEY_LABEL in packages/privacy/src/native/edm.ts. */
export const EDM_KEY_LABEL = "aidr-edm-v2";
export const MIN_SECRET_BYTES = 32;
const DATASET_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Conservative entropy model. A run of digits is uniform at log2(10) bits per digit. A run of
 * letters is assumed to be a dictionary word (a name, street or city): 2 bits per letter, at most
 * WORD_CAP_BITS (a list of ~65 000 words). Mixed tokens are split into runs. Types whose values
 * have a fixed structure are capped at the entropy of that structure, because the digits are
 * not free: a TCKN has 9 free digits and 2 check digits (log2(9e8) ~ 29.7), a card number has a
 * public issuer prefix and a Luhn digit, a phone number has a few operator prefixes, a date of
 * birth is one of ~36 500 days. These are estimates for refusing guessable datasets, not proofs
 * of strength: a column that looks random but is sequential (customer numbers) is weaker still.
 */
const DIGIT_BITS = Math.log2(10);
const LETTER_BITS = 2;
const WORD_CAP_BITS = 16;
export const TYPE_CAP_BITS = Object.freeze({
	TC_KIMLIK: 30,
	CREDIT_CARD: 30,
	PHONE: 30,
	US_SSN: 30,
	DATE_OF_BIRTH: 16,
	MAC_ADDRESS: 24,
	LICENSE_PLATE: 32,
	TAX_ID: 34,
	IBAN: 56,
});

/** Estimated entropy in bits of one normalised value (its token list) of entity `type`. */
export function estimateEntropyBits(tokens, type) {
	let bits = 0;
	for (const token of tokens) {
		for (const run of token.match(/\p{N}+|\p{L}+/gu) ?? []) {
			bits += /^\p{N}+$/u.test(run)
				? run.length * DIGIT_BITS
				: Math.min(run.length * LETTER_BITS, WORD_CAP_BITS);
		}
	}
	const cap = TYPE_CAP_BITS[type];
	return cap === undefined ? bits : Math.min(bits, cap);
}

/** Normalises a value into the token sequence that is fingerprinted. */
export function normaliseTokens(value) {
	const normalised = String(value)
		.normalize("NFKC")
		.toLowerCase()
		.replace(/[​-‏⁠﻿]/gu, "")
		.replace(/ı/gu, "i")
		.replace(/i̇/gu, "i");
	return normalised.match(/[\p{L}\p{N}]+/gu) ?? [];
}

/** hex HMAC-SHA256 over JSON.stringify(tokens). */
export function fingerprintTokens(key, tokens) {
	return createHmac("sha256", key).update(JSON.stringify(tokens), "utf8").digest("hex");
}

/** The dataset's own key: HMAC-SHA256(secret, "aidr-edm-v2" 0x00 datasetId). */
export function deriveDatasetKey(secret, datasetId) {
	return createHmac("sha256", secret).update(`${EDM_KEY_LABEL}\u0000${datasetId}`, "utf8").digest();
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

/** Header handling and column selection: the data rows and the indexes to read. */
function selectColumns(rows, header, columns) {
	if (!header && columns.length === 0) return { body: rows, indexes: null };
	const [head = [], ...body] = rows;
	if (columns.length === 0) return { body, indexes: null };
	const names = head.map((name) => name.trim());
	const indexes = columns.map((column) => {
		const index = names.indexOf(column);
		if (index < 0) throw new Error(`COLUMN_NOT_FOUND: ${column}`);
		return index;
	});
	return { body, indexes };
}

/**
 * Builds the ExactDataSet. `secret` is the organisation's EDM secret (>= 32 bytes); the dataset
 * key is derived from it and never written. With `composite`, the selected cells of a row form
 * one value (in column order). Values below `minEntropyBits` refuse the dataset, or are left out
 * with `dropLowEntropy`.
 * @param {{ rows: string[][]; datasetId: string; type: string; secret: Buffer; header?: boolean; columns?: string[]; composite?: boolean; minEntropyBits?: number; dropLowEntropy?: boolean }} input
 */
export function buildDataset({
	rows,
	datasetId,
	type,
	secret,
	header = false,
	columns = [],
	composite = false,
	minEntropyBits = MIN_ENTROPY_BITS,
	dropLowEntropy = false,
}) {
	if (!DATASET_ID.test(datasetId ?? "")) throw new Error("DATASET_ID_INVALID (1-64 chars: letters, digits, . _ -)");
	if (!ENTITY_TYPES.includes(type)) throw new Error(`TYPE_INVALID: expected one of ${ENTITY_TYPES.join(", ")}`);
	if (!Buffer.isBuffer(secret) || secret.length < MIN_SECRET_BYTES)
		throw new Error(`SECRET_TOO_SHORT: need at least ${MIN_SECRET_BYTES} random bytes`);
	if (!Number.isSafeInteger(minEntropyBits) || minEntropyBits < MIN_ENTROPY_BITS)
		throw new Error(`MIN_ENTROPY_INVALID: the floor is ${MIN_ENTROPY_BITS} bits and cannot be lowered`);
	if (composite && columns.length < 2) throw new Error("COMPOSITE_NEEDS_COLUMNS: name at least two --columns");
	const { body, indexes } = selectColumns(rows, header, columns);
	const key = deriveDatasetKey(secret, datasetId);
	const fingerprints = new Set();
	const skipped = { tooShort: 0, tooManyTokens: 0, lowEntropy: 0 };
	let values = 0;
	let weakest = Number.POSITIVE_INFINITY;
	try {
		for (const row of body) {
			const cells = indexes ? indexes.map((i) => row[i] ?? "") : row;
			const candidates = composite
				? cells.some((cell) => cell.trim() === "")
					? []
					: [cells.join(" ")]
				: cells.filter((cell) => cell.trim() !== "");
			for (const cell of candidates) {
				values++;
				const tokens = normaliseTokens(cell);
				if (tokens.join("").length < MIN_CHARS) skipped.tooShort++;
				else if (tokens.length > MAX_TOKENS) skipped.tooManyTokens++;
				else {
					const bits = estimateEntropyBits(tokens, type);
					if (bits < minEntropyBits) skipped.lowEntropy++;
					else {
						weakest = Math.min(weakest, bits);
						fingerprints.add(fingerprintTokens(key, tokens));
					}
				}
			}
		}
	} finally {
		key.fill(0);
	}
	if (skipped.lowEntropy > 0 && !dropLowEntropy)
		throw new Error(
			`LOW_ENTROPY: ${skipped.lowEntropy} of ${values} value(s) have less than ${minEntropyBits} bits of estimated entropy, so anyone holding the dataset key could enumerate them. Combine columns with --composite (for example name + customer number), or pass --drop-low-entropy to leave them out`,
		);
	if (fingerprints.size === 0) throw new Error("DATASET_EMPTY: no usable values");
	if (fingerprints.size > MAX_FINGERPRINTS) throw new Error(`DATASET_TOO_LARGE: max ${MAX_FINGERPRINTS} fingerprints`);
	return {
		dataset: {
			datasetId,
			keySource: "native-host",
			minEntropyBits: Math.floor(weakest),
			// Sorted so the file order reveals nothing about the source row order.
			fingerprints: [...fingerprints].sort(),
			type,
		},
		stats: { values, fingerprints: fingerprints.size, skipped },
	};
}

function parseArgs(argv) {
	const options = { header: false, composite: false, dropLowEntropy: false, columns: [] };
	const flags = { "--header": "header", "--composite": "composite", "--drop-low-entropy": "dropLowEntropy" };
	const takesValue = new Set([
		"--in",
		"--out",
		"--dataset-id",
		"--type",
		"--secret-file",
		"--new-secret",
		"--columns",
		"--min-entropy-bits",
	]);
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (flags[arg]) options[flags[arg]] = true;
		else if (arg === "--help" || arg === "-h") options.help = true;
		else if (arg === "--key-b64" || arg === "--key-file")
			throw new Error(
				`${arg} is no longer supported: a dataset no longer carries its key (managed policy is readable by every user). Use --secret-file with the secret installed in the native host`,
			);
		else if (takesValue.has(arg)) {
			const value = argv[++i];
			if (value === undefined) throw new Error(`${arg} needs a value`);
			options[arg.slice(2).replace(/-([a-z])/g, (_m, c) => c.toUpperCase())] = value;
		} else throw new Error(`unknown argument ${arg}`);
	}
	if (typeof options.columns === "string") options.columns = options.columns.split(",").map((c) => c.trim()).filter(Boolean);
	if (options.minEntropyBits !== undefined) options.minEntropyBits = Number(options.minEntropyBits);
	return options;
}

const USAGE = `Usage: node scripts/fingerprint-dataset.mjs --new-secret <secret.b64>
       node scripts/fingerprint-dataset.mjs --in <file.csv|-> --dataset-id <id> --type <ENTITY_TYPE>
         --secret-file <secret.b64> [--header] [--columns a,b] [--composite]
         [--min-entropy-bits <n>=${MIN_ENTROPY_BITS}] [--drop-low-entropy] [--out <file.json>]
--new-secret writes a fresh 32-byte EDM secret (owner-only file). Install the same file in the
native host configuration ("exactData": {"secretFile": ...}); it never goes into browser policy.
Keep it: regenerating a dataset with the same secret and dataset id keeps its fingerprints.`;

/** Decodes the base64 EDM secret file. */
export function decodeSecret(text) {
	const trimmed = String(text).trim();
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) || trimmed.length % 4 !== 0) throw new Error("SECRET_NOT_BASE64");
	return Buffer.from(trimmed, "base64");
}

function main(argv) {
	const options = parseArgs(argv);
	if (options.help) {
		console.log(USAGE);
		return 0;
	}
	if (options.newSecret) {
		writeFileSync(options.newSecret, `${randomBytes(32).toString("base64")}\n`, { flag: "wx", mode: 0o600 });
		console.error(`[fingerprint] wrote a new 32-byte EDM secret to ${options.newSecret} (owner-only)`);
		return 0;
	}
	if (!options.in || !options.datasetId || !options.type || !options.secretFile) {
		console.error(USAGE);
		return 2;
	}
	const secret = decodeSecret(readFileSync(options.secretFile, "utf8"));
	const text = readFileSync(options.in === "-" ? 0 : options.in, "utf8");
	try {
		const { dataset, stats } = buildDataset({
			rows: parseCsv(text),
			datasetId: options.datasetId,
			type: options.type,
			secret,
			header: options.header,
			columns: options.columns,
			composite: options.composite,
			dropLowEntropy: options.dropLowEntropy,
			...(options.minEntropyBits !== undefined ? { minEntropyBits: options.minEntropyBits } : {}),
		});
		const json = `${JSON.stringify(dataset, null, 2)}\n`;
		if (options.out) writeFileSync(options.out, json, { mode: 0o600 });
		else process.stdout.write(json);
		console.error(
			`[fingerprint] ${stats.values} value(s) -> ${stats.fingerprints} fingerprint(s), weakest ${dataset.minEntropyBits} bits; skipped ${stats.skipped.tooShort} too short, ${stats.skipped.tooManyTokens} over ${MAX_TOKENS} tokens, ${stats.skipped.lowEntropy} below the entropy floor`,
		);
	} finally {
		secret.fill(0);
	}
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
