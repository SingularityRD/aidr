import { createHash } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

import { redactTelemetryString } from "./telemetry-redaction.js";

export const MCP_TRANSPORT_LIMITS = {
	maxFrameBytes: 1024 * 1024,
	maxHeaderBytes: 16 * 1024,
	maxBufferedBytes: 2 * 1024 * 1024,
	maxHttpBodyBytes: 4 * 1024 * 1024,
	maxMethodBytes: 512,
} as const;

export type JsonRpcId = string | number | null;

export interface JsonRpcMessage {
	jsonrpc: "2.0";
	[key: string]: unknown;
}

export interface JsonRpcRequest extends JsonRpcMessage {
	method: string;
	params?: unknown;
	id?: JsonRpcId;
}

export interface StdioFramerOptions {
	maxFrameBytes?: number;
	maxHeaderBytes?: number;
	maxBufferedBytes?: number;
}

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
	if ("method" in message && (typeof message.method !== "string" || message.method.length === 0)) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC method is invalid");
	}
	if (
		typeof message.method === "string" &&
		textEncoder.encode(message.method).length > MCP_TRANSPORT_LIMITS.maxMethodBytes
	) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC method is too long");
	}
	if (
		"id" in message &&
		message.id !== null &&
		typeof message.id !== "string" &&
		typeof message.id !== "number"
	) {
		throw new McpTransportError("invalid_json_rpc", "MCP JSON-RPC id is invalid");
	}
	if (!("method" in message) && !("result" in message) && !("error" in message)) {
		throw new McpTransportError(
			"invalid_json_rpc",
			"MCP JSON-RPC frame is neither a request nor a response",
		);
	}
	return message as JsonRpcMessage;
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
		const lengthHeader = headers.find((header) => /^content-length\s*:/i.test(header));
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
	mode: "json" | "sse",
): McpValidationResult {
	if (response.status < 200 || response.status >= 300)
		return { ok: false, error: "upstream_http_error" };
	const contentType = mediaTypes(response.headers.get("content-type") ?? "");
	const expected = mode === "json" ? "application/json" : "text/event-stream";
	return contentType.has(expected)
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

export function isPrivateIpAddress(value: string): boolean {
	const normalized =
		value
			.trim()
			.replace(/^\[|\]$/g, "")
			.split("%", 1)[0]
			?.toLowerCase() ?? "";
	if (isIP(normalized) === 4) return isPrivateIpv4(normalized);
	if (isIP(normalized) !== 6) return false;
	if (
		normalized === "::" ||
		normalized === "::1" ||
		normalized.startsWith("fc") ||
		normalized.startsWith("fd") ||
		normalized.startsWith("fe8") ||
		normalized.startsWith("fe9") ||
		normalized.startsWith("fea") ||
		normalized.startsWith("feb") ||
		normalized.startsWith("ff")
	)
		return true;
	const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
	return mapped ? isPrivateIpv4(mapped[1] ?? "") : false;
}

export interface SsrfValidationOptions {
	requireHttps?: boolean;
	lookup?: (hostname: string) => Promise<readonly string[]>;
}

const privateHostnames = new Set([
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata.google.internal",
	"metadata.google.com",
	"instance-data.ec2.internal",
]);

export async function validateMcpRemoteUrl(
	value: string | URL,
	options: SsrfValidationOptions = {},
): Promise<McpValidationResult> {
	let url: URL;
	try {
		url = value instanceof URL ? new URL(value.href) : new URL(value);
	} catch {
		return { ok: false, error: "invalid_url" };
	}
	if (url.protocol !== "https:" && !(url.protocol === "http:" && options.requireHttps === false)) {
		return { ok: false, error: "insecure_scheme" };
	}
	if (url.username || url.password) return { ok: false, error: "url_credentials_forbidden" };
	const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
	if (privateHostnames.has(hostname) || isPrivateIpAddress(hostname))
		return { ok: false, error: "private_address" };
	const lookup =
		options.lookup ??
		(async (host) =>
			(await dnsLookup(host, { all: true, verbatim: true })).map((item) => item.address));
	try {
		const addresses = await lookup(hostname);
		if (addresses.length === 0 || addresses.some(isPrivateIpAddress))
			return { ok: false, error: "private_address" };
	} catch {
		return { ok: false, error: "dns_lookup_failed" };
	}
	return { ok: true };
}

export interface McpFetchOptions extends SsrfValidationOptions {
	mode?: "json" | "sse";
	maxBodyBytes?: number;
}

/** Fetch an upstream MCP HTTP/SSE endpoint with DNS, redirect and media-type enforcement. */
export async function fetchMcpEndpoint(
	url: string | URL,
	init: RequestInit = {},
	options: McpFetchOptions = {},
): Promise<Response> {
	const safeUrl = await validateMcpRemoteUrl(url, options);
	if (!safeUrl.ok)
		throw new McpTransportError(safeUrl.error ?? "invalid_url", "MCP upstream URL rejected");
	const requestBody = normalizeRequestBody(init.body);
	if (requestBody === "unsupported")
		throw new McpTransportError("unsupported_body", "MCP HTTP body type is not supported");
	const request = {
		method: (init.method ?? "GET").toUpperCase(),
		url,
		headers: init.headers instanceof Headers ? init.headers : new Headers(init.headers),
		body: requestBody,
	};
	const requestValidation = validateMcpHttpRequest(request, options);
	if (!requestValidation.ok)
		throw new McpTransportError(
			requestValidation.error ?? "invalid_request",
			"MCP HTTP request rejected",
		);
	const response = await fetch(url, { ...init, redirect: "error" });
	if (response.status >= 300 && response.status < 400) {
		throw new McpTransportError("redirect_forbidden", "MCP upstream redirects are forbidden");
	}
	const responseValidation = validateMcpHttpResponse(
		response,
		options.mode ?? (request.method === "GET" ? "sse" : "json"),
	);
	if (!responseValidation.ok)
		throw new McpTransportError(
			responseValidation.error ?? "invalid_response",
			"MCP upstream response rejected",
		);
	if (
		responseBodyExceedsLimit(
			response,
			options.maxBodyBytes ?? MCP_TRANSPORT_LIMITS.maxHttpBodyBytes,
		)
	) {
		throw new McpTransportError(
			"body_too_large",
			"MCP upstream response exceeds the configured limit",
		);
	}
	return response;
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

export interface McpToolCall {
	serverName: string;
	toolName: string;
	arguments?: unknown;
	schema?: unknown;
	requestId?: JsonRpcId;
}

export interface McpPolicyRequest extends McpToolCall {
	inputHash: string;
	schemaHash?: string;
	signal: AbortSignal;
}

export interface McpPolicyClient {
	evaluateToolCall(request: McpPolicyRequest): Promise<unknown>;
}

export interface McpSecurityEvent {
	type: "mcp_tool_call";
	timestamp: string;
	server: string;
	tool: string;
	decision: "allow" | "deny";
	reason: string;
	inputHash: string;
	schemaHash?: string;
}

export type McpEventSink = (event: McpSecurityEvent) => void | Promise<void>;

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

	observe(serverName: string, toolName: string, schema: unknown): SchemaObservation {
		const key = `${serverName}\u0000${toolName}`;
		const hash = hashMcpSchema(schema);
		const previousHash = this.hashes.get(key);
		this.hashes.set(key, hash);
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
	const schemaObservation =
		call.schema === undefined
			? undefined
			: (options.schemaRegistry ?? defaultMcpSchemaRegistry).observe(
					call.serverName,
					call.toolName,
					call.schema,
				);
	const schemaHash = schemaObservation?.hash;
	const reason = schemaObservation?.drift
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

export class McpTransportProxy {
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
