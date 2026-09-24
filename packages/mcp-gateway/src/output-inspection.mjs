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
 * smuggled inside an image header is inspected like any other output. Pixel or
 * audio semantics are not interpreted; coverage events say so.
 */

const MAX_URI_LENGTH = 2048;
const MIN_PRINTABLE_RUN = 6;
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

function inspectBinary(mimeType, data, policy) {
	const mime = normalizedMime(mimeType);
	if (!mime || !policy.allowedMimeTypes.includes(mime))
		throw binaryRefusal("unsupported_binary_output");
	const bytes = decodeBoundedBase64(data, policy.maxDecodedBytes);
	if (!SIGNATURES[mime]?.(bytes)) throw binaryRefusal("binary_content_mismatch");
	return {
		mimeType: mime,
		bytes: bytes.length,
		extractedText: printableRuns(bytes, policy.maxDecodedBytes),
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
