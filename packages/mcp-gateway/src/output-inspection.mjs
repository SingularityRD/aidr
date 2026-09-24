import { inflateSync, constants as zlibConstants } from "node:zlib";
import { McpGatewayRefusal } from "./coverage.mjs";

/**
 * Bounded inspection of MCP `tools/call` results.
 *
 * Text is scanned as before. Binary items (`image`, `audio`, and `resource`
 * blobs) are accepted only when their MIME type is on the operator allowlist,
 * their base64 encoding is canonical, their decoded size is within the limit,
 * and their leading bytes match the declared type. Text-like resource blobs are
 * decoded as strict UTF-8 and scanned as text. Printable runs extracted from
 * binary payloads (metadata chunks, embedded strings) are scanned too, so text
 * smuggled inside an image header is inspected like any other output. Runs of
 * UTF-16 (LE and BE) text are decoded as well, and compressed text containers
 * are inflated first: PNG `zTXt`, compressed `iTXt` and `iCCP` chunks and PDF
 * `FlateDecode` streams. Inflation is bounded per stream (ratio) and per item
 * (total); output that would exceed those bounds, or a compressed stream that
 * cannot be decoded, is refused rather than passed through uninspected.
 * Other PDF filters (ASCIIHex, ASCII85, LZW, RunLength, or FlateDecode behind
 * another filter) are not decoded. Pixel or audio semantics are not
 * interpreted; coverage events say so.
 */

const MAX_URI_LENGTH = 2048;
const MIN_PRINTABLE_RUN = 6;
/** A compressed stream may expand to at most this multiple of its compressed size... */
const MAX_INFLATE_RATIO = 200;
/** ...or to this many bytes, whichever is larger, so tiny streams are not refused. */
const MIN_INFLATE_ALLOWANCE = 64 * 1024;
/** Total inflated bytes for one binary item, as a multiple of the decoded-size limit. */
const INFLATE_BUDGET_FACTOR = 4;
/** Compressed streams inflated per binary item; more is refused, not skipped. */
const MAX_COMPRESSED_STREAMS = 256;
/** PNG chunks whose payload is zlib-compressed and may carry text. */
const PNG_COMPRESSED_CHUNKS = new Set(["zTXt", "iTXt", "iCCP"]);
/** How far before a PDF `stream` keyword its dictionary is searched for. */
const MAX_PDF_DICTIONARY = 64 * 1024;
const PDF_STREAM_KEYWORD = /(?<!end)stream(?:\r\n|\n|\r)/g;
const PDF_FLATE_FILTER = /\/Filter\s*(?:\[\s*)?\/FlateDecode\b/;
const utf8 = new TextDecoder("utf-8", { fatal: true });
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const TEXT_LIKE_MIME =
	/^(?:text\/[a-z0-9.+-]+|application\/(?:json|ld\+json|x-ndjson|xml|yaml|x-yaml|toml|javascript|ecmascript|graphql|sql)|image\/svg\+xml)$/;

function ascii(value) {
	return [...value].map((character) => character.charCodeAt(0));
}

function startsWith(bytes, signature, offset = 0) {
	if (bytes.length < offset + signature.length) return false;
	return signature.every((byte, index) => bytes[offset + index] === byte);
}

const SIGNATURES = {
	"image/png": (bytes) => startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
	"image/jpeg": (bytes) => startsWith(bytes, [0xff, 0xd8, 0xff]),
	"image/gif": (bytes) => startsWith(bytes, ascii("GIF87a")) || startsWith(bytes, ascii("GIF89a")),
	"image/webp": (bytes) => startsWith(bytes, ascii("RIFF")) && startsWith(bytes, ascii("WEBP"), 8),
	"audio/wav": (bytes) => startsWith(bytes, ascii("RIFF")) && startsWith(bytes, ascii("WAVE"), 8),
	"audio/mpeg": (bytes) =>
		startsWith(bytes, ascii("ID3")) ||
		(bytes.length >= 2 && bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0),
	"audio/ogg": (bytes) => startsWith(bytes, ascii("OggS")),
	"application/pdf": (bytes) => startsWith(bytes, ascii("%PDF-")),
};

function jsonObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function unsupported() {
	return new McpGatewayRefusal(
		"unsupported_tool_output",
		"MCP tool output representation is unsupported and was refused",
	);
}

function binaryRefusal(code) {
	const messages = {
		unsupported_binary_output:
			"MCP binary tool output type is not on the gateway allowlist and was refused",
		binary_output_oversize: "MCP binary tool output exceeds the inspection limit and was refused",
		invalid_binary_encoding: "MCP binary tool output is not canonical base64 and was refused",
		binary_content_mismatch:
			"MCP binary tool output does not match its declared type and was refused",
	};
	return new McpGatewayRefusal(code, messages[code]);
}

function normalizedMime(value) {
	if (typeof value !== "string" || value.length > 128) return null;
	const [type] = value.split(";");
	return type.trim().toLowerCase();
}

/** Decode canonical base64 without ever materialising more than `maxBytes`. */
function decodeBoundedBase64(value, maxBytes) {
	if (typeof value !== "string") throw binaryRefusal("invalid_binary_encoding");
	if (value.length > Math.ceil(maxBytes / 3) * 4) throw binaryRefusal("binary_output_oversize");
	if (!BASE64.test(value)) throw binaryRefusal("invalid_binary_encoding");
	const bytes = Buffer.from(value, "base64");
	if (bytes.length > maxBytes) throw binaryRefusal("binary_output_oversize");
	return bytes;
}

/** Printable ASCII runs inside binary bytes, capped at `maxChars` total. */
function printableRuns(bytes, maxChars) {
	const runs = [];
	let total = 0;
	let start = -1;
	const flush = (end) => {
		if (start >= 0 && end - start >= MIN_PRINTABLE_RUN && total < maxChars) {
			const run = bytes
				.subarray(start, Math.min(end, start + (maxChars - total)))
				.toString("latin1");
			runs.push(run);
			total += run.length;
		}
		start = -1;
	};
	for (let index = 0; index < bytes.length; index += 1) {
		const byte = bytes[index];
		const printable = (byte >= 0x20 && byte <= 0x7e) || byte === 0x09;
		if (printable && start < 0) start = index;
		else if (!printable) flush(index);
	}
	flush(bytes.length);
	return runs.join("\n");
}

/** Printable ASCII text encoded as UTF-16 (either byte order, either alignment). */
function utf16Runs(bytes) {
	const runs = [];
	for (const bigEndian of [false, true]) {
		for (const alignment of [0, 1]) collectUtf16Runs(bytes, bigEndian, alignment, runs);
	}
	return runs.join("\n");
}

function collectUtf16Runs(bytes, bigEndian, alignment, runs) {
	let run = "";
	for (let index = alignment; index + 1 < bytes.length; index += 2) {
		const code = bigEndian
			? (bytes[index] << 8) | bytes[index + 1]
			: bytes[index] | (bytes[index + 1] << 8);
		if ((code >= 0x20 && code <= 0x7e) || code === 0x09) {
			run += String.fromCharCode(code);
			continue;
		}
		if (run.length >= MIN_PRINTABLE_RUN) runs.push(run);
		run = "";
	}
	if (run.length >= MIN_PRINTABLE_RUN) runs.push(run);
}

/** All text recoverable from raw bytes: printable ASCII runs and UTF-16 runs. */
function binaryText(bytes) {
	return [printableRuns(bytes, bytes.length), utf16Runs(bytes)].filter(Boolean).join("\n");
}

function inflationRefusal() {
	return new McpGatewayRefusal(
		"binary_inflation_limit",
		"MCP binary tool output contains compressed data beyond the inspection bounds and was refused",
	);
}

/**
 * A zlib inflater bounded for one binary item. Each stream may expand at most
 * MAX_INFLATE_RATIO times (or MIN_INFLATE_ALLOWANCE bytes), and all streams
 * together at most INFLATE_BUDGET_FACTOR times the decoded-size limit. Output
 * is capped by zlib itself (`maxOutputLength`), so a decompression bomb never
 * materialises; exceeding a bound refuses the output.
 */
function createInflater(policy) {
	let remaining = policy.maxDecodedBytes * INFLATE_BUDGET_FACTOR;
	let streams = 0;
	return (compressed) => {
		streams += 1;
		if (streams > MAX_COMPRESSED_STREAMS) throw inflationRefusal();
		const cap = Math.min(
			remaining,
			Math.max(MIN_INFLATE_ALLOWANCE, compressed.length * MAX_INFLATE_RATIO),
		);
		if (cap < 1) throw inflationRefusal();
		let inflated;
		try {
			// A sync flush tolerates a truncated stream and trailing bytes, the
			// way readers do; the partial text is inspected, not skipped.
			inflated = inflateSync(compressed, {
				finishFlush: zlibConstants.Z_SYNC_FLUSH,
				maxOutputLength: cap,
			});
		} catch (cause) {
			if (cause?.code === "ERR_BUFFER_TOO_LARGE") throw inflationRefusal();
			throw binaryRefusal("binary_content_mismatch");
		}
		remaining -= inflated.length;
		return inflated;
	};
}

/** The zlib payload of a compressed PNG text chunk, or null when it carries none. */
function pngChunkPayload(type, data) {
	const keywordEnd = data.indexOf(0);
	if (keywordEnd < 0) throw binaryRefusal("binary_content_mismatch");
	if (type !== "iTXt") return data.subarray(keywordEnd + 2); // keyword, NUL, method, zlib
	if (data[keywordEnd + 1] !== 1) return null; // uncompressed iTXt is scanned as raw bytes
	const languageEnd = data.indexOf(0, keywordEnd + 3);
	const translatedEnd = languageEnd < 0 ? -1 : data.indexOf(0, languageEnd + 1);
	if (translatedEnd < 0) throw binaryRefusal("binary_content_mismatch");
	return data.subarray(translatedEnd + 1);
}

/** zlib payloads of the PNG's compressed text chunks (zTXt, compressed iTXt, iCCP). */
function pngCompressedPayloads(bytes) {
	const payloads = [];
	let offset = 8;
	while (offset + 12 <= bytes.length) {
		const length = bytes.readUInt32BE(offset);
		const type = bytes.toString("latin1", offset + 4, offset + 8);
		const dataStart = offset + 8;
		const dataEnd = dataStart + length;
		// A chunk that runs past the end cannot be read by any decoder either.
		if (dataEnd + 4 > bytes.length) break;
		if (PNG_COMPRESSED_CHUNKS.has(type)) {
			const payload = pngChunkPayload(type, bytes.subarray(dataStart, dataEnd));
			if (payload) payloads.push(payload);
		}
		if (type === "IEND") break;
		offset = dataEnd + 4;
	}
	return payloads;
}

/** Data of every PDF stream whose (first) filter is FlateDecode. */
function pdfFlateStreams(bytes) {
	const text = bytes.toString("latin1");
	const streams = [];
	PDF_STREAM_KEYWORD.lastIndex = 0;
	for (;;) {
		const keyword = PDF_STREAM_KEYWORD.exec(text);
		if (!keyword) break;
		const objectStart = text.lastIndexOf("obj", keyword.index);
		const dictionaryStart = Math.max(objectStart, keyword.index - MAX_PDF_DICTIONARY, 0);
		const dataStart = keyword.index + keyword[0].length;
		const endStream = text.indexOf("endstream", dataStart);
		const dataEnd = endStream < 0 ? text.length : endStream;
		if (PDF_FLATE_FILTER.test(text.slice(dictionaryStart, keyword.index))) {
			streams.push(bytes.subarray(dataStart, dataEnd));
		}
		// Stream data is opaque: the next keyword is searched after it.
		PDF_STREAM_KEYWORD.lastIndex = Math.max(dataEnd, dataStart);
	}
	return streams;
}

function compressedPayloads(mime, bytes) {
	if (mime === "image/png") return pngCompressedPayloads(bytes);
	if (mime === "application/pdf") return pdfFlateStreams(bytes);
	return [];
}

function inspectBinary(mimeType, data, policy) {
	const mime = normalizedMime(mimeType);
	if (!mime || !policy.allowedMimeTypes.includes(mime))
		throw binaryRefusal("unsupported_binary_output");
	const bytes = decodeBoundedBase64(data, policy.maxDecodedBytes);
	if (!SIGNATURES[mime]?.(bytes)) throw binaryRefusal("binary_content_mismatch");
	const inflate = createInflater(policy);
	const texts = [
		binaryText(bytes),
		...compressedPayloads(mime, bytes).map((payload) => binaryText(inflate(payload))),
	];
	return {
		mimeType: mime,
		bytes: bytes.length,
		extractedText: texts.filter(Boolean).join("\n"),
	};
}

function inspectResource(resource, policy) {
	if (
		!jsonObject(resource) ||
		typeof resource.uri !== "string" ||
		resource.uri.length === 0 ||
		resource.uri.length > MAX_URI_LENGTH ||
		(resource.mimeType !== undefined && normalizedMime(resource.mimeType) === null) ||
		"text" in resource === "blob" in resource
	) {
		throw unsupported();
	}
	const mime = resource.mimeType === undefined ? undefined : normalizedMime(resource.mimeType);
	const { blob, text, ...metadata } = resource;
	if (typeof text === "string") {
		if (mime !== undefined && !TEXT_LIKE_MIME.test(mime)) throw unsupported();
		return { view: { ...metadata, text }, binary: false };
	}
	if (mime !== undefined && TEXT_LIKE_MIME.test(mime)) {
		const bytes = decodeBoundedBase64(blob, policy.maxDecodedBytes);
		let decoded;
		try {
			decoded = utf8.decode(bytes);
		} catch {
			throw binaryRefusal("binary_content_mismatch");
		}
		return { view: { ...metadata, text: decoded }, binary: false };
	}
	const inspected = inspectBinary(resource.mimeType, blob, policy);
	return { view: { ...metadata, ...inspected }, binary: true };
}

/**
 * Validate a `tools/call` result and return the view the output scanner reads
 * plus a count of binary items (for coverage reporting). The original result
 * is what the client receives; the view replaces base64 payloads with the text
 * that was decoded or extracted from them so the scanner never reads raw base64.
 */
export function inspectToolResult(result, policy) {
	if (
		!jsonObject(result) ||
		!Array.isArray(result.content) ||
		result.content.length > 4096 ||
		(result.isError !== undefined && typeof result.isError !== "boolean")
	) {
		throw new McpGatewayRefusal(
			"invalid_tool_result",
			"MCP tool output has an invalid result envelope and was refused",
		);
	}
	let binaryItems = 0;
	const content = result.content.map((item) => {
		if (!jsonObject(item)) throw unsupported();
		if (item.type === "text") {
			if (typeof item.text !== "string") throw unsupported();
			return item;
		}
		if (item.type === "image" || item.type === "audio") {
			const { data, mimeType, ...metadata } = item;
			binaryItems += 1;
			return { ...metadata, ...inspectBinary(mimeType, data, policy) };
		}
		if (item.type === "resource") {
			const { resource, ...metadata } = item;
			const inspected = inspectResource(resource, policy);
			if (inspected.binary) binaryItems += 1;
			return { ...metadata, resource: inspected.view };
		}
		throw unsupported();
	});
	if (result.structuredContent !== undefined && !jsonObject(result.structuredContent)) {
		throw new McpGatewayRefusal(
			"unsupported_structured_output",
			"MCP structured tool output is outside the gateway response coverage and was refused",
		);
	}
	return { view: { ...result, content }, binaryItems };
}
