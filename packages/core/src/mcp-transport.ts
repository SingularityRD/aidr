import { createHash } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { Readable, Transform } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";

import { redactTelemetryString } from "./telemetry-redaction.js";

const MCP_TRANSPORT_LIMITS = {
	maxFrameBytes: 1024 * 1024,
	maxHeaderBytes: 16 * 1024,
	maxBufferedBytes: 2 * 1024 * 1024,
	maxHttpBodyBytes: 4 * 1024 * 1024,
	maxMethodBytes: 512,
	dnsLookupTimeoutMs: 5_000,
	responseHeadersTimeoutMs: 30_000,
} as const;

type JsonRpcId = string | number | null;

export interface JsonRpcMessage {
	jsonrpc: "2.0";
	[key: string]: unknown;
}

interface JsonRpcRequest extends JsonRpcMessage {
	method: string;
	params?: unknown;
	id?: JsonRpcId;
}

export interface StdioFramerOptions {
	maxFrameBytes?: number;
	maxHeaderBytes?: number;
	maxBufferedBytes?: number;
}

/** Error contract consumed by the packaged MCP gateway. @public */
export class McpTransportError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "McpTransportError";
		this.code = code;
	}
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
	const result = new Uint8Array(left.length + right.length);
	result.set(left);
	result.set(right, left.length);
	return result;
}

function findBytes(haystack: Uint8Array, needle: number[], from = 0): number {
	outer: for (let index = from; index <= haystack.length - needle.length; index += 1) {
		for (let offset = 0; offset < needle.length; offset += 1) {
			if (haystack[index + offset] !== needle[offset]) continue outer;
		}
		return index;
	}
	return -1;
}

function parseJsonRpcMessage(bytes: Uint8Array, maxFrameBytes: number): JsonRpcMessage {
	if (bytes.length === 0 || bytes.length > maxFrameBytes) {
		throw new McpTransportError(
			"frame_too_large",
			"MCP JSON-RPC frame exceeds the configured limit",
		);
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(textDecoder.decode(bytes));
	} catch {
		throw new McpTransportError("invalid_json", "MCP JSON-RPC frame is not valid UTF-8 JSON");
	}

	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC frame must be an object");
	}
	const message = parsed as Record<string, unknown>;
	if (message.jsonrpc !== "2.0") {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC frame must use version 2.0");
	}
	validateJsonRpcMethod(message);
	validateJsonRpcId(message);
	validateJsonRpcEnvelope(message);
	return message as JsonRpcMessage;
}

function validateJsonRpcMethod(message: Record<string, unknown>): void {
	if ("method" in message && (typeof message.method !== "string" || message.method.length === 0)) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC method is invalid");
	}
	if ("method" in message && ("result" in message || "error" in message)) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC request cannot be a response");
	}
	if (
		typeof message.method === "string" &&
		textEncoder.encode(message.method).length > MCP_TRANSPORT_LIMITS.maxMethodBytes
	) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC method is too long");
	}
}

function validateJsonRpcId(message: Record<string, unknown>): void {
	if (
		"id" in message &&
		message.id !== null &&
		typeof message.id !== "string" &&
		typeof message.id !== "number"
	) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC id is invalid");
	}
	if (typeof message.id === "number" && !Number.isSafeInteger(message.id)) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC numeric id is invalid");
	}
}

function validateJsonRpcEnvelope(message: Record<string, unknown>): void {
	if (!("method" in message) && !("result" in message) && !("error" in message)) {
		throw new McpTransportError(
			"invalid_json_rpc",
			"MCP JSON-RPC frame is neither a request nor a response",
		);
	}
	if (
		!("method" in message) &&
		(!("id" in message) || "result" in message === "error" in message)
	) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC response is invalid");
	}
}

/** Incremental parser for newline-delimited MCP stdio and Content-Length frames. */
export class JsonRpcStdioFramer {
	private buffer: Uint8Array<ArrayBufferLike> = new Uint8Array();
	private readonly maxFrameBytes: number;
	private readonly maxHeaderBytes: number;
	private readonly maxBufferedBytes: number;

	constructor(options: StdioFramerOptions = {}) {
		this.maxFrameBytes = options.maxFrameBytes ?? MCP_TRANSPORT_LIMITS.maxFrameBytes;
		this.maxHeaderBytes = options.maxHeaderBytes ?? MCP_TRANSPORT_LIMITS.maxHeaderBytes;
		this.maxBufferedBytes = options.maxBufferedBytes ?? MCP_TRANSPORT_LIMITS.maxBufferedBytes;
		if (
			this.maxFrameBytes < 1 ||
			this.maxHeaderBytes < 1 ||
			this.maxBufferedBytes < this.maxFrameBytes
		) {
			throw new McpTransportError("invalid_limits", "MCP stdio limits are inconsistent");
		}
	}

	push(chunk: string | Uint8Array): JsonRpcMessage[] {
		const bytes = typeof chunk === "string" ? textEncoder.encode(chunk) : chunk;
		this.buffer = concatBytes(this.buffer, bytes);
		if (this.buffer.length > this.maxBufferedBytes) {
			throw new McpTransportError(
				"buffer_too_large",
				"MCP stdio input buffer exceeds the configured limit",
			);
		}

		const messages: JsonRpcMessage[] = [];
		while (this.buffer.length > 0) {
			const frame = this.readNextFrame();
			if (frame === "incomplete") break;
			this.buffer = this.buffer.slice(frame.consumedBytes);
			if (frame.body.length > 0) messages.push(parseJsonRpcMessage(frame.body, this.maxFrameBytes));
		}
		return messages;
	}

	reset(): void {
		this.buffer = new Uint8Array();
	}

	private readNextFrame(): { body: Uint8Array; consumedBytes: number } | "incomplete" {
		const contentLength = this.readContentLengthFrame();
		if (contentLength !== null) return contentLength;
		const newline = this.buffer.indexOf(0x0a);
		if (newline === -1) {
			if (this.buffer.length > this.maxFrameBytes) {
				throw new McpTransportError(
					"frame_too_large",
					"MCP newline-delimited frame exceeds the configured limit",
				);
			}
			return "incomplete";
		}
		const line = this.buffer.slice(0, newline);
		const body = line[line.length - 1] === 0x0d ? line.slice(0, -1) : line;
		return { body, consumedBytes: newline + 1 };
	}

	private readContentLengthFrame():
		| { body: Uint8Array; consumedBytes: number }
		| "incomplete"
		| null {
		const headerEnd = findBytes(this.buffer, [0x0d, 0x0a, 0x0d, 0x0a]);
		const startsWithHeader = this.startsWithAscii("content-length:");
		if (!startsWithHeader) return null;
		if (headerEnd === -1) {
			if (this.buffer.length > this.maxHeaderBytes) {
				throw new McpTransportError(
					"header_too_large",
					"MCP Content-Length header exceeds the configured limit",
				);
			}
			return "incomplete";
		}
		if (headerEnd + 4 > this.maxHeaderBytes) {
			throw new McpTransportError(
				"header_too_large",
				"MCP Content-Length header exceeds the configured limit",
			);
		}
		let headerText: string;
		try {
			headerText = textDecoder.decode(this.buffer.slice(0, headerEnd));
		} catch {
			throw new McpTransportError("invalid_header", "MCP stdio headers are not valid UTF-8");
		}
		const headers = headerText.split(/\r?\n/);
		const lengthHeaders = headers.filter((header) => /^content-length\s*:/i.test(header));
		if (lengthHeaders.length !== 1) {
			throw new McpTransportError(
				"invalid_content_length",
				"MCP Content-Length header must appear exactly once",
			);
		}
		const lengthHeader = lengthHeaders[0];
		if (!lengthHeader) return null;
		const rawLength = lengthHeader.slice(lengthHeader.indexOf(":") + 1).trim();
		if (!/^\d+$/.test(rawLength)) {
			throw new McpTransportError(
				"invalid_content_length",
				"MCP Content-Length is not a non-negative integer",
			);
		}
		const contentLength = Number(rawLength);
		if (!Number.isSafeInteger(contentLength) || contentLength > this.maxFrameBytes) {
			throw new McpTransportError(
				"frame_too_large",
				"MCP Content-Length exceeds the configured limit",
			);
		}
		const bodyStart = headerEnd + 4;
		const bodyEnd = bodyStart + contentLength;
		if (this.buffer.length < bodyEnd) return "incomplete";
		return { body: this.buffer.slice(bodyStart, bodyEnd), consumedBytes: bodyEnd };
	}

	private startsWithAscii(value: string): boolean {
		const prefix = value.toLowerCase();
		if (this.buffer.length < prefix.length) return false;
		for (let index = 0; index < prefix.length; index += 1) {
			const byte = this.buffer[index];
			if (byte === undefined || String.fromCharCode(byte).toLowerCase() !== prefix[index])
				return false;
		}
		return true;
	}
}

export function encodeMcpStdioFrame(message: JsonRpcMessage, contentLength = false): Uint8Array {
	const json = JSON.stringify(message);
	const bytes = textEncoder.encode(json);
	if (bytes.length > MCP_TRANSPORT_LIMITS.maxFrameBytes) {
		throw new McpTransportError(
			"frame_too_large",
			"MCP JSON-RPC message exceeds the configured limit",
		);
	}
	return contentLength
		? textEncoder.encode(`Content-Length: ${bytes.length}\r\n\r\n${json}`)
		: textEncoder.encode(`${json}\n`);
}

export interface McpHttpRequest {
	method: string;
	url: string | URL;
	headers?: Headers | Record<string, string | undefined>;
	body?: string | Uint8Array | null;
}

export interface McpHttpValidationOptions {
	maxBodyBytes?: number;
	requireHttps?: boolean;
	allowedOrigins?: readonly string[];
	/** Permit the MCP Streamable HTTP DELETE used to terminate one bound session. */
	acceptSessionTerminationResponse?: boolean;
}

export interface McpValidationResult {
	ok: boolean;
	error?: string;
}

function headerValue(
	headers: Headers | Record<string, string | undefined> | undefined,
	name: string,
): string {
	if (!headers) return "";
	if (headers instanceof Headers) return headers.get(name) ?? "";
	const target = name.toLowerCase();
	const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === target);
	return entry?.[1] ?? "";
}

function mediaTypes(header: string): Set<string> {
	return new Set(
		header
			.split(",")
			.map((part) => part.trim().split(";", 1)[0]?.toLowerCase())
			.filter((part): part is string => Boolean(part)),
	);
}

function bodyByteLength(body: string | Uint8Array | null | undefined): number {
	return body === undefined || body === null
		? 0
		: typeof body === "string"
			? textEncoder.encode(body).length
			: body.byteLength;
}

export function validateMcpHttpRequest(
	request: McpHttpRequest,
	options: McpHttpValidationOptions = {},
): McpValidationResult {
	const maxBodyBytes = options.maxBodyBytes ?? MCP_TRANSPORT_LIMITS.maxHttpBodyBytes;
	let url: URL;
	try {
		url = request.url instanceof URL ? new URL(request.url.href) : new URL(request.url);
	} catch {
		return { ok: false, error: "invalid_url" };
	}
	const urlValidation = validateHttpUrl(url, options);
	if (!urlValidation.ok) return urlValidation;
	const method = request.method.toUpperCase();
	const bodyLength = bodyByteLength(request.body);
	if (bodyLength > maxBodyBytes) return { ok: false, error: "body_too_large" };
	if (method === "POST") return validatePostRequest(request.headers, bodyLength);
	if (method === "GET") return validateGetRequest(request.headers, bodyLength);
	if (method === "DELETE" && options.acceptSessionTerminationResponse) {
		if (bodyLength > 0) return { ok: false, error: "body_forbidden" };
		return /^[\x21-\x7e]{8,256}$/.test(headerValue(request.headers, "mcp-session-id"))
			? { ok: true }
			: { ok: false, error: "invalid_session" };
	}
	return { ok: false, error: "method_not_allowed" };
}

function validateHttpUrl(url: URL, options: McpHttpValidationOptions): McpValidationResult {
	if (url.protocol !== "https:" && !(url.protocol === "http:" && options.requireHttps === false))
		return { ok: false, error: "insecure_scheme" };
	if (url.username || url.password) return { ok: false, error: "url_credentials_forbidden" };
	return options.allowedOrigins && !options.allowedOrigins.includes(url.origin)
		? { ok: false, error: "origin_not_allowed" }
		: { ok: true };
}

function validatePostRequest(
	headers: Headers | Record<string, string | undefined> | undefined,
	bodyLength: number,
): McpValidationResult {
	if (bodyLength === 0) return { ok: false, error: "missing_body" };
	if (!mediaTypes(headerValue(headers, "content-type")).has("application/json"))
		return { ok: false, error: "invalid_content_type" };
	const accepted = mediaTypes(headerValue(headers, "accept"));
	return accepted.size > 0 &&
		!accepted.has("application/json") &&
		!accepted.has("text/event-stream") &&
		!accepted.has("*/*")
		? { ok: false, error: "invalid_accept" }
		: { ok: true };
}

function validateGetRequest(
	headers: Headers | Record<string, string | undefined> | undefined,
	bodyLength: number,
): McpValidationResult {
	if (bodyLength > 0) return { ok: false, error: "body_forbidden" };
	return mediaTypes(headerValue(headers, "accept")).has("text/event-stream")
		? { ok: true }
		: { ok: false, error: "sse_accept_required" };
}

export function validateMcpHttpResponse(
	response: Pick<Response, "status" | "headers">,
	mode: "json" | "sse" | "auto",
): McpValidationResult {
	if (response.status < 200 || response.status >= 300)
		return { ok: false, error: "upstream_http_error" };
	const contentType = mediaTypes(response.headers.get("content-type") ?? "");
	const expected = mode === "json" ? "application/json" : "text/event-stream";
	return contentType.has(expected) || (mode === "auto" && contentType.has("application/json"))
		? { ok: true }
		: { ok: false, error: "invalid_upstream_content_type" };
}

function normalizeIpv4(value: string): number[] | null {
	const parts = value.split(".");
	if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
	const numbers = parts.map(Number);
	return numbers.every((part) => part >= 0 && part <= 255) ? numbers : null;
}

function isPrivateIpv4(value: string): boolean {
	const parts = normalizeIpv4(value);
	if (!parts) return false;
	const [first, second] = parts;
	return (
		first === 0 ||
		first === 10 ||
		first === 127 ||
		(first === 100 && second !== undefined && second >= 64 && second <= 127) ||
		(first === 169 && second === 254) ||
		(first === 172 && second !== undefined && second >= 16 && second <= 31) ||
		(first === 192 && second === 0) ||
		(first === 192 && second === 168) ||
		(first === 192 && second === 88) ||
		(first === 198 && second !== undefined && (second === 18 || second === 19)) ||
		(first === 198 && second === 51) ||
		(first === 203 && second === 0) ||
		(first !== undefined && first >= 224)
	);
}

function replaceEmbeddedIpv4(value: string): string | null {
	if (!value.includes(".")) return value;
	const separator = value.lastIndexOf(":");
	const ipv4 = separator === -1 ? null : normalizeIpv4(value.slice(separator + 1));
	if (!ipv4) return null;
	const high = ((ipv4[0] ?? 0) << 8) | (ipv4[1] ?? 0);
	const low = ((ipv4[2] ?? 0) << 8) | (ipv4[3] ?? 0);
	return `${value.slice(0, separator)}:${high.toString(16)}:${low.toString(16)}`;
}

function parseIpv6Half(half: string): number[] | null {
	if (half === "") return [];
	const parts = half.split(":");
	if (parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
	return parts.map((part) => Number.parseInt(part, 16));
}

function normalizeIpv6(value: string): number[] | null {
	if (value.includes("%")) return null;
	const candidate = replaceEmbeddedIpv4(value.toLowerCase());
	if (!candidate) return null;
	const halves = candidate.split("::");
	if (halves.length > 2) return null;
	const left = parseIpv6Half(halves[0] ?? "");
	const right = parseIpv6Half(halves[1] ?? "");
	if (!left || !right) return null;
	if (halves.length === 1) return left.length === 8 ? left : null;
	const omitted = 8 - left.length - right.length;
	return omitted >= 1 ? [...left, ...Array<number>(omitted).fill(0), ...right] : null;
}

function embeddedIpv4(words: readonly number[], offset: number): string {
	const high = words[offset] ?? 0;
	const low = words[offset + 1] ?? 0;
	return `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`;
}

function hasIpv6Prefix(words: readonly number[], prefix: readonly number[], bits: number): boolean {
	const wholeWords = Math.floor(bits / 16);
	for (let index = 0; index < wholeWords; index += 1) {
		if (words[index] !== prefix[index]) return false;
	}
	const remaining = bits % 16;
	if (remaining === 0) return true;
	const mask = (0xffff << (16 - remaining)) & 0xffff;
	return ((words[wholeWords] ?? 0) & mask) === ((prefix[wholeWords] ?? 0) & mask);
}

export function isPrivateIpAddress(value: string): boolean {
	const normalized =
		value
			.trim()
			.replace(/^\[|\]$/g, "")
			.split("%", 1)[0]
			?.toLowerCase() ?? "";
	if (isIP(normalized) === 4) return isPrivateIpv4(normalized);
	if (isIP(normalized) !== 6) return false;
	const words = normalizeIpv6(normalized);
	if (!words) return true;
	const firstSixZero = words.slice(0, 6).every((word) => word === 0);
	if (firstSixZero) return isPrivateIpv4(embeddedIpv4(words, 6));
	const ipv4Mapped = words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
	if (ipv4Mapped) return isPrivateIpv4(embeddedIpv4(words, 6));
	const nat64 = hasIpv6Prefix(words, [0x0064, 0xff9b, 0, 0, 0, 0], 96);
	if (nat64) return isPrivateIpv4(embeddedIpv4(words, 6));
	const sixToFour = words[0] === 0x2002;
	if (sixToFour) return isPrivateIpv4(embeddedIpv4(words, 1));
	return (
		hasIpv6Prefix(words, [0xfc00], 7) ||
		hasIpv6Prefix(words, [0xfe80], 10) ||
		hasIpv6Prefix(words, [0xfec0], 10) ||
		hasIpv6Prefix(words, [0xff00], 8) ||
		hasIpv6Prefix(words, [0x0100, 0, 0, 0], 64) ||
		hasIpv6Prefix(words, [0x0100, 0, 0, 1], 64) ||
		hasIpv6Prefix(words, [0x0064, 0xff9b, 0x0001], 48) ||
		hasIpv6Prefix(words, [0x2001, 0x0000], 32) ||
		hasIpv6Prefix(words, [0x2001, 0x0002, 0], 48) ||
		hasIpv6Prefix(words, [0x2001, 0x0010], 28) ||
		hasIpv6Prefix(words, [0x2001, 0x0020], 28) ||
		hasIpv6Prefix(words, [0x2001, 0x0db8], 32) ||
		hasIpv6Prefix(words, [0x3fff, 0], 20) ||
		hasIpv6Prefix(words, [0x5f00], 16)
	);
}

export interface SsrfValidationOptions {
	requireHttps?: boolean;
	lookup?: (hostname: string) => Promise<readonly string[]>;
	/** Operator-pinned IP addresses; DNS answers outside this set are refused. */
	allowedAddresses?: readonly string[];
}

interface McpPinnedFetchRequest {
	url: URL;
	init: RequestInit;
	/** Every address was resolved and classified before this transport is invoked. */
	addresses: readonly string[];
	responseHeadersTimeoutMs: number;
	/** Independent wire-byte ceiling, enforced before any content decoding. */
	maxEncodedBodyBytes: number;
}

type McpPinnedFetch = (request: McpPinnedFetchRequest) => Promise<Response>;

const privateHostnames = new Set([
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata.google.internal",
	"metadata.google.com",
	"instance-data.ec2.internal",
]);

interface ResolvedMcpRemoteUrl {
	validation: McpValidationResult;
	url?: URL;
	addresses?: readonly string[];
}

function normalizedUrlHostname(url: URL): string {
	return url.hostname
		.toLowerCase()
		.replace(/^\[|\]$/g, "")
		.replace(/\.+$/, "");
}

async function resolveMcpRemoteUrl(
	value: string | URL,
	options: SsrfValidationOptions,
): Promise<ResolvedMcpRemoteUrl> {
	let url: URL;
	try {
		url = value instanceof URL ? new URL(value.href) : new URL(value);
	} catch {
		return { validation: { ok: false, error: "invalid_url" } };
	}
	if (url.protocol !== "https:" && !(url.protocol === "http:" && options.requireHttps === false)) {
		return { validation: { ok: false, error: "insecure_scheme" } };
	}
	if (url.username || url.password)
		return { validation: { ok: false, error: "url_credentials_forbidden" } };
	const hostname = normalizedUrlHostname(url);
	if (!hostname || privateHostnames.has(hostname) || isPrivateIpAddress(hostname))
		return { validation: { ok: false, error: "private_address" } };
	if (isIP(hostname) !== 0) return { validation: { ok: true }, url, addresses: [hostname] };
	const lookup =
		options.lookup ??
		(async (host: string) =>
			(await dnsLookup(host, { all: true, verbatim: true })).map((item) => item.address));
	try {
		const resolved = await lookup(hostname);
		const addresses = [...new Set(resolved.map((address) => address.trim().toLowerCase()))];
		if (addresses.length === 0 || addresses.some((address) => isIP(address) === 0))
			return { validation: { ok: false, error: "dns_lookup_failed" } };
		if (addresses.some(isPrivateIpAddress))
			return { validation: { ok: false, error: "private_address" } };
		return { validation: { ok: true }, url, addresses };
	} catch {
		return { validation: { ok: false, error: "dns_lookup_failed" } };
	}
}

export async function validateMcpRemoteUrl(
	value: string | URL,
	options: SsrfValidationOptions = {},
): Promise<McpValidationResult> {
	return (await resolveMcpRemoteUrl(value, options)).validation;
}

export interface McpFetchOptions extends SsrfValidationOptions {
	mode?: "json" | "sse" | "auto";
	maxBodyBytes?: number;
	/** Maximum time spent waiting for DNS before any connection is attempted. */
	dnsLookupTimeoutMs?: number;
	/** Maximum time spent waiting for upstream HTTP response headers. */
	responseHeadersTimeoutMs?: number;
	/** Permit a bodyless HTTP 202 acknowledgement for a JSON-RPC notification only. */
	acceptNotificationResponse?: boolean;
	/** Accept a bodyless 202 only for a valid JSON-RPC response to a pending server request. */
	acceptJsonRpcResponse?: boolean;
	/** Startup negative probe: require 401/403, never interpret another status as isolation. */
	acceptUnauthorizedResponse?: boolean;
	/** Permit and accept the bounded MCP Streamable HTTP session-termination DELETE. */
	acceptSessionTerminationResponse?: boolean;
	/** Trusted transport hook for embedders/tests; it must connect only to one supplied address. */
	pinnedFetch?: McpPinnedFetch;
}

interface CompleteResolvedMcpRemoteUrl {
	url: URL;
	addresses: readonly string[];
}

function requireResolvedMcpRemoteUrl(resolved: ResolvedMcpRemoteUrl): CompleteResolvedMcpRemoteUrl {
	if (resolved.validation.ok && resolved.url && resolved.addresses) {
		return { url: resolved.url, addresses: resolved.addresses };
	}
	throw new McpTransportError(
		resolved.validation.error ?? "invalid_url",
		"MCP upstream URL rejected",
	);
}

function validatedHttpBodyLimit(options: McpFetchOptions): number {
	const limit = options.maxBodyBytes ?? MCP_TRANSPORT_LIMITS.maxHttpBodyBytes;
	if (!Number.isSafeInteger(limit) || limit < 0)
		throw new McpTransportError("invalid_limits", "MCP HTTP body limit is invalid");
	return limit;
}

function validatedNetworkTimeout(value: number, name: string): number {
	if (!Number.isSafeInteger(value) || value < 1 || value > 120_000)
		throw new McpTransportError("invalid_limits", `MCP ${name} timeout is invalid`);
	return value;
}

async function withDnsDeadline<T>(work: Promise<T>, timeoutMs: number): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			work,
			new Promise<never>((_resolve, reject) => {
				timer = setTimeout(
					() => reject(new McpTransportError("dns_lookup_timeout", "MCP DNS lookup timed out")),
					timeoutMs,
				);
			}),
		]);
	} finally {
		if (timer) clearTimeout(timer);
	}
}

function validatedMcpHttpRequest(
	url: URL,
	init: RequestInit,
	options: McpFetchOptions,
): McpHttpRequest & { method: string; url: URL; headers: Headers } {
	const body = normalizeRequestBody(init.body);
	if (body === "unsupported")
		throw new McpTransportError("unsupported_body", "MCP HTTP body type is not supported");
	const request = {
		method: (init.method ?? "GET").toUpperCase(),
		url,
		headers: init.headers instanceof Headers ? init.headers : new Headers(init.headers),
		body,
	};
	const validation = validateMcpHttpRequest(request, options);
	if (!validation.ok)
		throw new McpTransportError(validation.error ?? "invalid_request", "MCP HTTP request rejected");
	return request;
}

/** Fetch an upstream MCP HTTP/SSE endpoint with DNS, redirect and media-type enforcement. */
export async function fetchMcpEndpoint(
	url: string | URL,
	init: RequestInit = {},
	options: McpFetchOptions = {},
): Promise<Response> {
	const maxBodyBytes = validatedHttpBodyLimit(options);
	const dnsLookupTimeoutMs = validatedNetworkTimeout(
		options.dnsLookupTimeoutMs ?? MCP_TRANSPORT_LIMITS.dnsLookupTimeoutMs,
		"DNS lookup",
	);
	const responseHeadersTimeoutMs = validatedNetworkTimeout(
		options.responseHeadersTimeoutMs ?? MCP_TRANSPORT_LIMITS.responseHeadersTimeoutMs,
		"response headers",
	);
	const resolved = requireResolvedMcpRemoteUrl(
		await withDnsDeadline(resolveMcpRemoteUrl(url, options), dnsLookupTimeoutMs),
	);
	if (
		options.allowedAddresses &&
		(options.allowedAddresses.length === 0 ||
			resolved.addresses.some((address) => !options.allowedAddresses?.includes(address)))
	)
		throw new McpTransportError(
			"address_not_pinned",
			"MCP DNS address is outside the operator pin set",
		);
	const request = validatedMcpHttpRequest(resolved.url, init, options);
	if (options.acceptNotificationResponse && !isJsonRpcNotification(request))
		throw new McpTransportError(
			"invalid_notification_request",
			"MCP HTTP 202 acknowledgement requires a JSON-RPC notification",
		);
	if (options.acceptJsonRpcResponse && !isJsonRpcResponse(request))
		throw new McpTransportError(
			"invalid_response_request",
			"MCP response acknowledgement requires a JSON-RPC response",
		);
	if (options.acceptSessionTerminationResponse && request.method !== "DELETE")
		throw new McpTransportError(
			"invalid_session_termination_request",
			"MCP session termination requires DELETE",
		);
	const requestInit = { ...init, redirect: "error" as const };
	const response = await (options.pinnedFetch ?? performPinnedFetch)({
		url: resolved.url,
		init: requestInit,
		addresses: resolved.addresses,
		responseHeadersTimeoutMs,
		maxEncodedBodyBytes: maxBodyBytes,
	});
	return validateAndBoundMcpResponse(
		response,
		options.mode ?? (request.method === "GET" ? "sse" : "json"),
		maxBodyBytes,
		options.acceptNotificationResponse === true || options.acceptJsonRpcResponse === true,
		options.acceptSessionTerminationResponse === true,
		options.acceptUnauthorizedResponse === true,
	);
}

function isJsonRpcResponse(request: McpHttpRequest): boolean {
	if (request.method !== "POST" || !request.body) return false;
	try {
		const bytes =
			typeof request.body === "string" ? textEncoder.encode(request.body) : request.body;
		const value = parseJsonRpcMessage(bytes, bytes.byteLength);
		return !("method" in value) && ("result" in value || "error" in value);
	} catch {
		return false;
	}
}

function isJsonRpcNotification(request: McpHttpRequest): boolean {
	if (
		request.method !== "POST" ||
		!request.body ||
		!(typeof request.body === "string" || request.body instanceof Uint8Array)
	)
		return false;
	try {
		const bytes =
			typeof request.body === "string" ? textEncoder.encode(request.body) : request.body;
		const value = parseJsonRpcMessage(bytes, bytes.byteLength);
		return typeof value.method === "string" && !("id" in value);
	} catch {
		return false;
	}
}

async function validateAndBoundMcpResponse(
	response: Response,
	mode: "json" | "sse" | "auto",
	maxBodyBytes: number,
	acceptNotificationResponse: boolean,
	acceptSessionTerminationResponse: boolean,
	acceptUnauthorizedResponse = false,
): Promise<Response> {
	if (acceptUnauthorizedResponse) {
		if (response.status !== 401 && response.status !== 403) {
			await cancelResponseBody(response);
			throw new McpTransportError(
				"upstream_isolation_unverified",
				"MCP upstream credential isolation was not verified",
			);
		}
		await boundResponseBody(response, maxBodyBytes).arrayBuffer();
		return cloneResponseMetadata(response, null);
	}
	if (response.status >= 300 && response.status < 400) {
		await cancelResponseBody(response);
		throw new McpTransportError("redirect_forbidden", "MCP upstream redirects are forbidden");
	}
	if (acceptNotificationResponse && response.status === 202) {
		const bounded = boundResponseBody(response, maxBodyBytes);
		const bytes = new Uint8Array(await bounded.arrayBuffer());
		if (bytes.byteLength !== 0)
			throw new McpTransportError(
				"notification_response_body",
				"MCP notification acknowledgement must not contain a body",
			);
		return cloneResponseMetadata(response, null);
	}
	if (acceptSessionTerminationResponse) {
		if (response.status < 200 || response.status >= 300) {
			await cancelResponseBody(response);
			throw new McpTransportError(
				"upstream_http_error",
				"MCP upstream session termination was rejected",
			);
		}
		if (responseBodyExceedsLimit(response, maxBodyBytes)) {
			await cancelResponseBody(response);
			throw new McpTransportError(
				"body_too_large",
				"MCP upstream response exceeds the configured limit",
			);
		}
		await boundResponseBody(response, maxBodyBytes).arrayBuffer();
		return cloneResponseMetadata(response, null);
	}
	const responseValidation = validateMcpHttpResponse(response, mode);
	if (!responseValidation.ok) {
		await cancelResponseBody(response);
		throw new McpTransportError(
			responseValidation.error ?? "invalid_response",
			"MCP upstream response rejected",
		);
	}
	if (responseBodyExceedsLimit(response, maxBodyBytes)) {
		await cancelResponseBody(response);
		throw new McpTransportError(
			"body_too_large",
			"MCP upstream response exceeds the configured limit",
		);
	}
	const bounded = boundResponseBody(response, maxBodyBytes);
	return response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() ===
		"application/json"
		? bufferBoundedResponse(bounded)
		: bounded;
}

/** Finite, UTF-8-strict SSE framing. No partial JSON or oversized event is ever yielded. */
export async function* readMcpSseMessages(
	response: Response,
	maxBytes: number,
	signal?: AbortSignal,
): AsyncGenerator<JsonRpcMessage> {
	const reader = response.body?.getReader();
	if (!reader) throw new McpTransportError("missing_sse_response", "MCP SSE body is missing");
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let buffer = "";
	let lines: string[] = [];
	let bytes = 0;
	const abort = () => {
		void reader.cancel(signal?.reason).catch(() => undefined);
	};
	signal?.addEventListener("abort", abort, { once: true });
	try {
		for (;;) {
			signal?.throwIfAborted();
			const item = await reader.read();
			signal?.throwIfAborted();
			if (!item.done) {
				bytes += item.value.byteLength;
				if (bytes > maxBytes)
					throw new McpTransportError("body_too_large", "MCP SSE byte limit exceeded");
			}
			buffer += decoder.decode(item.value, { stream: !item.done });
			for (;;) {
				const match = /[\r\n]/.exec(buffer);
				if (!match || (!item.done && match.index === buffer.length - 1 && match[0] === "\r")) break;
				const line = buffer.slice(0, match.index);
				buffer = buffer.slice(
					match.index + (buffer.slice(match.index, match.index + 2) === "\r\n" ? 2 : 1),
				);
				if (line !== "") {
					lines.push(line);
					continue;
				}
				const data: string[] = [];
				for (const field of lines) {
					if (field.startsWith(":")) continue;
					if (field.startsWith("data:")) data.push(field.slice(5).replace(/^ /, ""));
					else if (field.startsWith("event:") && field.slice(6).trim() !== "message")
						throw new McpTransportError(
							"unsupported_sse_event",
							"MCP SSE event type is unsupported",
						);
					else if (!/^(event|id|retry):/.test(field))
						throw new McpTransportError("invalid_sse_field", "MCP SSE field is invalid");
				}
				lines = [];
				if (data.length && data.join("\n") !== "")
					yield parseJsonRpcMessage(textEncoder.encode(data.join("\n")), maxBytes);
			}
			if (item.done) break;
		}
		if (buffer || lines.some((line) => !line.startsWith(":")))
			throw new McpTransportError("incomplete_sse_event", "MCP SSE ended inside an event");
	} finally {
		signal?.removeEventListener("abort", abort);
		await reader.cancel().catch(() => undefined);
		reader.releaseLock();
	}
}

function normalizeRequestBody(
	body: RequestInit["body"],
): string | Uint8Array | null | "unsupported" {
	if (body === null || body === undefined) return null;
	if (typeof body === "string") return body;
	if (body instanceof Uint8Array) return body;
	return "unsupported";
}

function responseBodyExceedsLimit(
	response: Pick<Response, "headers">,
	maxBodyBytes: number,
): boolean {
	const length = response.headers.get("content-length");
	return Boolean(length && /^\d+$/.test(length) && Number(length) > maxBodyBytes);
}

function normalizedComparableIp(value: string): string | null {
	const candidate = value.trim().toLowerCase().split("%", 1)[0] ?? "";
	if (isIP(candidate) === 4) return candidate;
	if (isIP(candidate) !== 6) return null;
	const words = normalizeIpv6(candidate);
	if (!words) return null;
	const mapped = words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
	return mapped
		? embeddedIpv4(words, 6)
		: words.map((word) => word.toString(16).padStart(4, "0")).join(":");
}

function pinnedLookup(address: string): LookupFunction {
	const family = isIP(address) as 4 | 6;
	return ((...args: unknown[]) => {
		const options = args[1];
		const callback = args.at(-1) as (...callbackArgs: unknown[]) => void;
		if (typeof options === "object" && options !== null && "all" in options && options.all) {
			callback(null, [{ address, family }]);
			return;
		}
		callback(null, address, family);
	}) as LookupFunction;
}

async function performPinnedFetch(request: McpPinnedFetchRequest): Promise<Response> {
	const address = request.addresses[0];
	if (!address)
		throw new McpTransportError("dns_lookup_failed", "MCP upstream has no resolved address");
	const headers = new Headers(request.init.headers);
	headers.delete("connection");
	headers.delete("host");
	headers.delete("transfer-encoding");
	if (!headers.has("accept-encoding")) headers.set("accept-encoding", "gzip, deflate, br");
	const body = normalizeRequestBody(request.init.body);
	if (body === "unsupported")
		throw new McpTransportError("unsupported_body", "MCP HTTP body type is not supported");
	if (body === null) headers.delete("content-length");
	else headers.set("content-length", String(bodyByteLength(body)));
	const headerRecord: Record<string, string> = {};
	headers.forEach((value, name) => {
		headerRecord[name] = value;
	});

	return new Promise<Response>((resolve, reject) => {
		let settled = false;
		let headersDeadline: ReturnType<typeof setTimeout> | undefined;
		const finishReject = (error: unknown) => {
			if (settled) return;
			settled = true;
			if (headersDeadline) clearTimeout(headersDeadline);
			reject(error);
		};
		const nodeRequest = (request.url.protocol === "https:" ? httpsRequest : httpRequest)(
			request.url,
			{
				method: request.init.method ?? "GET",
				headers: headerRecord,
				lookup: pinnedLookup(address),
				agent: false,
				...(request.url.protocol === "https:" ? { rejectUnauthorized: true } : {}),
				signal: request.init.signal ?? undefined,
			},
			(incoming) => {
				if (settled) {
					incoming.destroy();
					return;
				}
				try {
					const response = responseFromIncomingMessage(
						incoming,
						request.url,
						request.maxEncodedBodyBytes,
					);
					settled = true;
					if (headersDeadline) clearTimeout(headersDeadline);
					resolve(response);
				} catch (error) {
					incoming.destroy();
					finishReject(error);
				}
			},
		);
		headersDeadline = setTimeout(() => {
			nodeRequest.destroy(
				new McpTransportError(
					"response_headers_timeout",
					"MCP upstream response headers timed out",
				),
			);
		}, request.responseHeadersTimeoutMs);
		nodeRequest.once("socket", (socket) => {
			const verifyRemoteAddress = () => {
				const actual = socket.remoteAddress ? normalizedComparableIp(socket.remoteAddress) : null;
				if (actual !== normalizedComparableIp(address)) {
					nodeRequest.destroy(
						new McpTransportError(
							"dns_rebinding_detected",
							"MCP upstream connected to an address that was not pinned",
						),
					);
				}
			};
			if (socket.connecting) socket.once("connect", verifyRemoteAddress);
			else verifyRemoteAddress();
		});
		nodeRequest.once("error", finishReject);
		if (body !== null) nodeRequest.end(body);
		else nodeRequest.end();
	});
}

function headersFromIncomingMessage(incoming: import("node:http").IncomingMessage): Headers {
	const headers = new Headers();
	for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
		const name = incoming.rawHeaders[index];
		const value = incoming.rawHeaders[index + 1];
		if (name && value !== undefined) headers.append(name, value);
	}
	return headers;
}

function contentDecoder(encoding: string): Transform | null {
	if (encoding === "gzip" || encoding === "x-gzip") return createGunzip();
	if (encoding === "deflate") return createInflate();
	if (encoding === "br") return createBrotliDecompress();
	if (encoding === "identity") return null;
	throw new McpTransportError(
		"unsupported_content_encoding",
		"MCP upstream content encoding is not supported",
	);
}

/** @internal Exposed for focused transport-boundary tests. */
export function decodedIncomingBody(
	incoming: import("node:http").IncomingMessage,
	encodings: readonly string[],
	maxEncodedBodyBytes: number,
): Readable {
	let encodedBytes = 0;
	const byteLimit = new Transform({
		transform(chunk: Buffer, _encoding, callback) {
			encodedBytes += chunk.byteLength;
			if (encodedBytes > maxEncodedBodyBytes) {
				const error = new McpTransportError(
					"body_too_large",
					"MCP upstream encoded response exceeds the configured limit",
				);
				callback(error);
				incoming.destroy(error);
				return;
			}
			callback(null, chunk);
		},
	});
	incoming.once("error", (error) => byteLimit.destroy(error));
	let body: Readable = incoming.pipe(byteLimit);
	for (const encoding of [...encodings].reverse()) {
		const decoder = contentDecoder(encoding);
		if (!decoder) continue;
		const encoded = body;
		encoded.once("error", (error) => decoder.destroy(error));
		decoder.once("error", () => incoming.destroy());
		body = encoded.pipe(decoder);
	}
	return body;
}

function responseFromIncomingMessage(
	incoming: import("node:http").IncomingMessage,
	url: URL,
	maxEncodedBodyBytes: number,
): Response {
	const headers = headersFromIncomingMessage(incoming);
	const encodings = (headers.get("content-encoding") ?? "")
		.split(",")
		.map((encoding) => encoding.trim().toLowerCase())
		.filter(Boolean);
	if (encodings.length > 3)
		throw new McpTransportError(
			"unsupported_content_encoding",
			"MCP upstream content encoding chain is too deep",
		);
	const body = decodedIncomingBody(incoming, encodings, maxEncodedBodyBytes);
	if (encodings.length > 0) {
		headers.delete("content-encoding");
		headers.delete("content-length");
	}
	const status = incoming.statusCode ?? 502;
	const responseBody =
		status === 204 || status === 205 || status === 304
			? null
			: (Readable.toWeb(body) as ReadableStream<Uint8Array>);
	const response = new Response(responseBody, {
		status,
		statusText: incoming.statusMessage ?? "",
		headers,
	});
	Object.defineProperty(response, "url", {
		configurable: true,
		enumerable: true,
		value: url.href,
	});
	return response;
}

function boundResponseBody(response: Response, maxBodyBytes: number): Response {
	if (!response.body) return response;
	const reader = response.body.getReader();
	let bytesRead = 0;
	const body = new ReadableStream<Uint8Array>({
		async pull(controller) {
			try {
				const item = await reader.read();
				if (item.done) {
					controller.close();
					return;
				}
				bytesRead += item.value.byteLength;
				if (bytesRead > maxBodyBytes) {
					const error = new McpTransportError(
						"body_too_large",
						"MCP upstream response exceeds the configured limit",
					);
					await reader.cancel(error).catch(() => undefined);
					controller.error(error);
					return;
				}
				controller.enqueue(item.value);
			} catch (error) {
				controller.error(error);
			}
		},
		cancel(reason) {
			return reader.cancel(reason);
		},
	});
	return cloneResponseMetadata(response, body);
}

function cloneResponseMetadata(
	response: Response,
	body: ConstructorParameters<typeof Response>[0],
	headers: Headers = response.headers,
): Response {
	const clone = new Response(body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
	for (const property of ["url", "redirected", "type"] as const) {
		Object.defineProperty(clone, property, {
			configurable: true,
			enumerable: true,
			value: response[property],
		});
	}
	return clone;
}

async function bufferBoundedResponse(response: Response): Promise<Response> {
	const bytes = new Uint8Array(await response.arrayBuffer());
	parseJsonRpcMessage(bytes, Math.max(bytes.byteLength, 1));
	const headers = new Headers(response.headers);
	headers.set("content-length", String(bytes.byteLength));
	return cloneResponseMetadata(response, bytes, headers);
}

async function cancelResponseBody(response: Response): Promise<void> {
	if (!response.body || response.bodyUsed) return;
	await response.body.cancel().catch(() => undefined);
}

export interface McpToolCall {
	serverName: string;
	toolName: string;
	arguments?: unknown;
	schema?: unknown;
	requestId?: JsonRpcId;
}

interface McpPolicyRequest extends McpToolCall {
	inputHash: string;
	schemaHash?: string;
	signal: AbortSignal;
}

export interface McpPolicyClient {
	evaluateToolCall(request: McpPolicyRequest): Promise<unknown>;
}

interface McpSecurityEvent {
	type: "mcp_tool_call";
	timestamp: string;
	server: string;
	tool: string;
	decision: "allow" | "deny";
	reason: string;
	inputHash: string;
	schemaHash?: string;
}

type McpEventSink = (event: McpSecurityEvent) => void | Promise<void>;

export interface SchemaObservation {
	hash: string;
	drift: boolean;
	previousHash?: string;
}

function canonicalJson(value: unknown, active = new WeakSet<object>()): string {
	if (value === null || typeof value !== "object") {
		if (typeof value === "number" && !Number.isFinite(value))
			throw new McpTransportError("invalid_json", "MCP value is not JSON-compatible");
		return JSON.stringify(value);
	}
	if (active.has(value)) throw new McpTransportError("invalid_json", "MCP value contains a cycle");
	active.add(value);
	try {
		if (Array.isArray(value))
			return `[${value.map((item) => canonicalJson(item, active)).join(",")}]`;
		return `{${Object.keys(value as Record<string, unknown>)
			.sort()
			.map(
				(key) =>
					`${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key], active)}`,
			)
			.join(",")}}`;
	} finally {
		active.delete(value);
	}
}

export function hashMcpSchema(schema: unknown): string {
	return createHash("sha256").update(canonicalJson(schema), "utf8").digest("hex");
}

export class McpSchemaRegistry {
	private readonly hashes = new Map<string, string>();

	hasBaseline(serverName: string, toolName: string): boolean {
		return this.hashes.has(JSON.stringify([serverName, toolName]));
	}

	observe(serverName: string, toolName: string, schema: unknown): SchemaObservation {
		const key = JSON.stringify([serverName, toolName]);
		const hash = hashMcpSchema(schema);
		const previousHash = this.hashes.get(key);
		// Observation is not approval: keep the first baseline so repeating a
		// changed schema cannot silently make a rejected tool trusted again.
		if (previousHash === undefined) this.hashes.set(key, hash);
		return { hash, drift: previousHash !== undefined && previousHash !== hash, previousHash };
	}

	clear(): void {
		this.hashes.clear();
	}
}

const defaultMcpSchemaRegistry = new McpSchemaRegistry();

export interface McpInterceptionOptions {
	policyTimeoutMs?: number;
	eventSink?: McpEventSink;
	schemaRegistry?: McpSchemaRegistry;
	now?: () => Date;
}

export interface McpInterceptionResult {
	allowed: boolean;
	decision: "allow" | "deny";
	reason: string;
	inputHash: string;
	schemaHash?: string;
	event: McpSecurityEvent;
}

function safeName(value: string): string {
	return redactTelemetryString(value.replace(/[\r\n\t]/g, " ").slice(0, 256), 256);
}

function makeEvent(
	call: McpToolCall,
	decision: "allow" | "deny",
	reason: string,
	inputHash: string,
	schemaHash: string | undefined,
	now: () => Date,
): McpSecurityEvent {
	return {
		type: "mcp_tool_call",
		timestamp: now().toISOString(),
		server: safeName(call.serverName),
		tool: safeName(call.toolName),
		decision,
		reason,
		inputHash,
		...(schemaHash ? { schemaHash } : {}),
	};
}

async function emitEvent(event: McpSecurityEvent, sink: McpEventSink | undefined): Promise<void> {
	if (!sink) return;
	try {
		await sink(event);
	} catch {
		// Event delivery must not weaken the fail-closed decision.
	}
}

function malformedPolicyResponse(value: unknown): boolean {
	return (
		!value ||
		typeof value !== "object" ||
		Array.isArray(value) ||
		((value as Record<string, unknown>).decision !== "allow" &&
			(value as Record<string, unknown>).decision !== "deny")
	);
}

/** Intercept a tool call before forwarding it to an MCP server. */
export async function interceptMcpToolCall(
	call: McpToolCall,
	policyClient: McpPolicyClient,
	options: McpInterceptionOptions = {},
): Promise<McpInterceptionResult> {
	const inputHash = createHash("sha256")
		.update(canonicalJson(call.arguments ?? {}), "utf8")
		.digest("hex");
	const registry = options.schemaRegistry ?? defaultMcpSchemaRegistry;
	const missingSchema =
		call.schema === undefined && registry.hasBaseline(call.serverName, call.toolName);
	const schemaObservation =
		call.schema === undefined
			? undefined
			: registry.observe(call.serverName, call.toolName, call.schema);
	const schemaHash = schemaObservation?.hash;
	const reason = missingSchema
		? "schema_missing"
		: schemaObservation?.drift
			? "schema_drift"
			: await evaluateMcpPolicy(
					call,
					policyClient,
					inputHash,
					schemaHash,
					options.policyTimeoutMs ?? 1000,
				);

	const allowed = reason === "policy_allowed";
	const event = makeEvent(
		call,
		allowed ? "allow" : "deny",
		reason,
		inputHash,
		schemaHash,
		options.now ?? (() => new Date()),
	);
	await emitEvent(event, options.eventSink);
	return {
		allowed,
		decision: allowed ? "allow" : "deny",
		reason,
		inputHash,
		...(schemaHash ? { schemaHash } : {}),
		event,
	};
}

async function evaluateMcpPolicy(
	call: McpToolCall,
	policyClient: McpPolicyClient,
	inputHash: string,
	schemaHash: string | undefined,
	timeoutMs: number,
): Promise<string> {
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0)
		throw new McpTransportError("invalid_timeout", "MCP policy timeout must be positive");
	const controller = new AbortController();
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const policyPromise = policyClient.evaluateToolCall({
			...call,
			inputHash,
			schemaHash,
			signal: controller.signal,
		});
		const timeout = new Promise<never>((_, reject) => {
			timer = setTimeout(
				() => reject(new McpTransportError("policy_timeout", "MCP policy evaluation timed out")),
				timeoutMs,
			);
		});
		const policy = await Promise.race([policyPromise, timeout]);
		if (malformedPolicyResponse(policy)) return "malformed_policy_response";
		return (policy as { decision: string }).decision === "allow"
			? "policy_allowed"
			: "policy_denied";
	} catch (error) {
		return error instanceof McpTransportError && error.code === "policy_timeout"
			? "policy_timeout"
			: "policy_unavailable";
	} finally {
		if (timer) clearTimeout(timer);
		controller.abort();
	}
}

class McpTransportProxy {
	private readonly framer: JsonRpcStdioFramer;
	private readonly options: McpInterceptionOptions;
	private readonly policyClient: McpPolicyClient;

	constructor(
		policyClient: McpPolicyClient,
		options: McpInterceptionOptions & StdioFramerOptions = {},
	) {
		this.policyClient = policyClient;
		this.options = {
			...options,
			schemaRegistry: options.schemaRegistry ?? new McpSchemaRegistry(),
		};
		this.framer = new JsonRpcStdioFramer(options);
	}

	feedStdio(chunk: string | Uint8Array): JsonRpcMessage[] {
		return this.framer.push(chunk);
	}

	encodeStdio(message: JsonRpcMessage, contentLength = false): Uint8Array {
		return encodeMcpStdioFrame(message, contentLength);
	}

	interceptToolCall(call: McpToolCall): Promise<McpInterceptionResult> {
		return interceptMcpToolCall(call, this.policyClient, this.options);
	}

	async requestUpstream(
		url: string | URL,
		init: RequestInit = {},
		options: McpFetchOptions = {},
	): Promise<Response> {
		return fetchMcpEndpoint(url, init, options);
	}
}
