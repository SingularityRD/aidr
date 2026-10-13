import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
	approveQuarantinedMcpToolset,
	assertPrivateMcpStateDirectory,
	attestMcpToolManifest,
	FileMcpAttestationStore,
	fetchMcpEndpoint,
	McpToolDefinitionSchema,
	McpTransportError,
	mcpApprovalBindingHash,
	mcpToolsetHash,
	scanModelOutput,
	verifySignedMcpToolManifest,
} from "@singularityrd/aidr-core";
// readMcpSseMessages is not part of the core package export; it resolves to the
// same module instance as the package's own mcp-transport import.
import { readMcpSseMessages } from "../../core/dist/mcp-transport.js";
import {
	authenticateBearer,
	GatewayConfigError,
	resourceUriAllowed,
	validateGatewayConfig,
} from "./config.mjs";
import {
	coverageDescriptor,
	McpGatewayRefusal,
	makeMcpGatewayCoverageEvent,
	refusalPayload,
} from "./coverage.mjs";
import {
	createToolCallDetector,
	createToolMetadataScanner,
	decisionPayload,
	McpToolCallBlocked,
} from "./detection.mjs";
import { inspectToolResult } from "./output-inspection.mjs";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const SESSION = /^[\x21-\x7e]{8,256}$/;
const PROTOCOL_VERSION = /^\d{4}-\d{2}-\d{2}$/;
const MAX_SESSIONS = 10_000;
const MAX_SESSIONS_PER_TENANT = 256;
const SESSION_TTL_MS = 30 * 60 * 1000;
const UPSTREAM_TIMEOUT_MS = 15_000;
const DAY_MS = 24 * 60 * 60 * 1000;
/** A manifest inside its expiry warning window is reported at most this often. */
const EXPIRY_WARNING_INTERVAL_MS = 60 * 60 * 1000;
/** Fields a manifest reload may change; anything else requires a restart. */
const RELOADABLE_SERVER_FIELDS = ["signedManifest", "trustedSigners", "revokedKeyIds"];
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const RESOURCE_METHODS = new Set(["resources/list", "resources/templates/list", "resources/read"]);
const PROMPT_METHODS = new Set(["prompts/list", "prompts/get"]);
// Paginated context lists and the result field each one returns.
const CONTEXT_LISTS = {
	"resources/list": "resources",
	"resources/templates/list": "resourceTemplates",
	"prompts/list": "prompts",
};
// Long-lived resource subscriptions and list-change pushes have no correlated
// request the gateway could hold back for inspection, so they stay refused.
const REFUSED_METHODS = new Set([
	"resources/subscribe",
	"resources/unsubscribe",
	"notifications/resources/updated",
	"notifications/resources/list_changed",
	"notifications/prompts/list_changed",
]);
const MAX_CURSOR_LENGTH = 1024;
const MAX_PROMPT_ARGUMENTS = 256;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

// Gateway-minted JSON-RPC ids and continuation states travel through the same
// payload inspection as untrusted content. A UUID's hex digits periodically form
// a 13-16 digit run the PII scanner rightly reads as a card number (~0.1% of
// UUIDs), which made the gateway block its own toolset re-verification. Encode
// 128 random bits with letters only so the gateway never trips its own scanner.
const NONCE_ALPHABET = "abcdefghjkmnpqrs";

/**
 * Fair-share admission for one shared pool (see GATEWAY_CAPACITY): returns the
 * refusal code, or null when a tenant holding `tenantHeld` of `total` entries may
 * take one more. The last `reserved` slots go only to tenants below their
 * guaranteed floor, so tenants at quota can never starve a quiet tenant.
 */
export function tenantAdmissionRefusal(pool, total, tenantHeld) {
	if (total >= pool.global) return "gateway_busy";
	if (tenantHeld >= pool.perTenant) return "tenant_busy";
	if (total >= pool.global - pool.reserved && tenantHeld >= pool.guaranteed) return "tenant_busy";
	return null;
}

export function gatewayNonce(prefix) {
	let suffix = "";
	for (const byte of randomBytes(16))
		suffix += NONCE_ALPHABET[byte >> 4] + NONCE_ALPHABET[byte & 15];
	return `${prefix}-${suffix}`;
}

function resolvedUpstreamAuth(server) {
	const auth = Object.hasOwn(server, "resolvedUpstreamAuth")
		? server.resolvedUpstreamAuth
		: server.upstreamAuthEnv
			? process.env[server.upstreamAuthEnv]
			: undefined;
	if (server.upstreamAuthEnv && (!auth || /[\r\n]/.test(auth)))
		throw new Error("upstream_auth_unavailable");
	return auth;
}

function upstreamHeaders(server, sessionId) {
	const auth = resolvedUpstreamAuth(server);
	return {
		"content-type": "application/json",
		accept:
			server.transport === "sse"
				? "text/event-stream, application/json"
				: "application/json, text/event-stream",
		...(auth ? { authorization: `Bearer ${auth}` } : {}),
		...(sessionId ? { "mcp-session-id": sessionId } : {}),
		...(server.protocolVersion ? { "mcp-protocol-version": server.protocolVersion } : {}),
		...(server.rpcMethod ? { "mcp-method": server.rpcMethod } : {}),
		...(server.rpcName ? { "mcp-name": server.rpcName } : {}),
	};
}

function error(id, code, message, data) {
	return {
		jsonrpc: "2.0",
		id,
		error: { code, message, ...(data ? { data } : {}) },
	};
}

function rpcResponse(id, result) {
	return { jsonrpc: "2.0", id, result };
}

function jsonObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalBase64(value) {
	return (
		typeof value === "string" &&
		BASE64.test(value) &&
		Buffer.from(value, "base64").toString("base64") === value
	);
}

const JSON_SCHEMA_KEYWORDS = new Set([
	"$anchor",
	"$comment",
	"$defs",
	"$id",
	"$ref",
	"$schema",
	"additionalProperties",
	"allOf",
	"anyOf",
	"const",
	"contains",
	"default",
	"definitions",
	"dependentRequired",
	"deprecated",
	"description",
	"else",
	"enum",
	"examples",
	"exclusiveMaximum",
	"exclusiveMinimum",
	"if",
	"items",
	"maxContains",
	"maximum",
	"maxItems",
	"maxLength",
	"maxProperties",
	"minContains",
	"minimum",
	"minItems",
	"minLength",
	"minProperties",
	"multipleOf",
	"not",
	"oneOf",
	"pattern",
	"patternProperties",
	"prefixItems",
	"properties",
	"propertyNames",
	"readOnly",
	"required",
	"then",
	"title",
	"type",
	"uniqueItems",
	"writeOnly",
]);

const MAX_SCHEMA_REGEX_LENGTH = 256;
const MAX_SCHEMA_REGEX_INPUT_LENGTH = 4096;
const MAX_SCHEMA_REGEX_WORK = 1_000_000;

function compileSafeSchemaRegex(pattern) {
	if (typeof pattern !== "string" || pattern.length > MAX_SCHEMA_REGEX_LENGTH) return null;
	let inCharacterClass = false;
	let hasQuantifier = false;
	for (let index = 0; index < pattern.length; index += 1) {
		const character = pattern[index];
		if (character === "\\") {
			const escaped = pattern[index + 1];
			if (escaped === undefined || /[1-9k]/i.test(escaped)) return null;
			if (!inCharacterClass && ["p", "P", "u"].includes(escaped) && pattern[index + 2] === "{") {
				const close = pattern.indexOf("}", index + 3);
				if (close < 0) return null;
				index = close;
			} else {
				index += 1;
			}
			continue;
		}
		if (inCharacterClass) {
			if (character === "]") inCharacterClass = false;
			continue;
		}
		if (character === "[") {
			inCharacterClass = true;
			continue;
		}
		if (character === "(" || character === ")" || character === "|") return null;
		if (character === "*" || character === "+" || character === "?" || character === "{") {
			if (hasQuantifier) return null;
			hasQuantifier = true;
		}
	}
	if (inCharacterClass) return null;
	try {
		return new RegExp(pattern, "u");
	} catch {
		return null;
	}
}

function testSchemaRegex(pattern, value, context) {
	context.regexWork += pattern.source.length * Math.max(1, value.length);
	if (context.regexWork > MAX_SCHEMA_REGEX_WORK) {
		throw new Error("schema_validation_budget_exhausted");
	}
	return pattern.test(value);
}

function jsonTypeMatches(value, type) {
	if (type === "null") return value === null;
	if (type === "array") return Array.isArray(value);
	if (type === "object") return jsonObject(value);
	if (type === "integer") return Number.isSafeInteger(value);
	if (type === "number") return typeof value === "number" && Number.isFinite(value);
	return typeof value === type && ["boolean", "string"].includes(type);
}

function resolveLocalSchemaRef(root, reference) {
	if (reference === "#") return root;
	if (typeof reference !== "string" || !reference.startsWith("#/")) return null;
	let current = root;
	for (const raw of reference.slice(2).split("/")) {
		const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
		if (!jsonObject(current) && !Array.isArray(current)) return null;
		if (!Object.hasOwn(current, key)) return null;
		current = current[key];
	}
	return current;
}

function supportedJsonSchema(
	schema,
	root = schema,
	context = { nodes: 0, seen: new Set() },
	depth = 0,
) {
	context.nodes += 1;
	if (context.nodes > 10_000 || depth > 64) return false;
	if (typeof schema === "boolean") return true;
	if (!jsonObject(schema) || Object.keys(schema).some((key) => !JSON_SCHEMA_KEYWORDS.has(key))) {
		return false;
	}
	if (context.seen.has(schema)) return true;
	context.seen.add(schema);
	const nested = (child) => supportedJsonSchema(child, root, context, depth + 1);
	if (schema.$ref !== undefined) {
		const target = resolveLocalSchemaRef(root, schema.$ref);
		if (target === null || !nested(target)) return false;
	}
	const types =
		schema.type === undefined ? [] : Array.isArray(schema.type) ? schema.type : [schema.type];
	if (
		types.some(
			(type) =>
				type !== "null" &&
				type !== "array" &&
				type !== "object" &&
				type !== "integer" &&
				type !== "number" &&
				type !== "boolean" &&
				type !== "string",
		) ||
		(schema.type !== undefined && types.length === 0)
	)
		return false;
	for (const keyword of [
		"minLength",
		"maxLength",
		"minItems",
		"maxItems",
		"minContains",
		"maxContains",
		"minProperties",
		"maxProperties",
	]) {
		if (!validNonnegativeInteger(schema[keyword])) return false;
	}
	for (const keyword of ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"]) {
		if (schema[keyword] !== undefined && !Number.isFinite(schema[keyword])) return false;
	}
	if (
		schema.multipleOf !== undefined &&
		(!Number.isFinite(schema.multipleOf) || schema.multipleOf <= 0)
	) {
		return false;
	}
	if (schema.pattern !== undefined && !compileSafeSchemaRegex(schema.pattern)) {
		return false;
	}
	if (schema.uniqueItems !== undefined && typeof schema.uniqueItems !== "boolean") return false;
	if (
		schema.required !== undefined &&
		(!Array.isArray(schema.required) || schema.required.some((key) => typeof key !== "string"))
	) {
		return false;
	}
	if (schema.enum !== undefined && (!Array.isArray(schema.enum) || schema.enum.length === 0))
		return false;
	for (const keyword of ["allOf", "anyOf", "oneOf", "prefixItems"]) {
		if (
			schema[keyword] !== undefined &&
			(!Array.isArray(schema[keyword]) || !schema[keyword].every(nested))
		) {
			return false;
		}
	}
	for (const keyword of [
		"not",
		"if",
		"then",
		"else",
		"contains",
		"propertyNames",
		"additionalProperties",
	]) {
		if (schema[keyword] !== undefined && !nested(schema[keyword])) return false;
	}
	if (schema.items !== undefined) {
		const items = Array.isArray(schema.items) ? schema.items : [schema.items];
		if (!items.every(nested)) return false;
	}
	for (const keyword of ["$defs", "definitions", "properties", "patternProperties"]) {
		if (schema[keyword] === undefined) continue;
		if (!jsonObject(schema[keyword]) || !Object.values(schema[keyword]).every(nested)) return false;
	}
	if (schema.patternProperties !== undefined) {
		for (const pattern of Object.keys(schema.patternProperties)) {
			if (!compileSafeSchemaRegex(pattern)) return false;
		}
	}
	if (schema.dependentRequired !== undefined) {
		if (!jsonObject(schema.dependentRequired)) return false;
		if (
			Object.values(schema.dependentRequired).some(
				(required) => !Array.isArray(required) || required.some((item) => typeof item !== "string"),
			)
		)
			return false;
	}
	return true;
}

function matchesJsonSchema(
	value,
	schema,
	root = schema,
	context = { nodes: 0, regexWork: 0 },
	depth = 0,
) {
	context.nodes += 1;
	if (context.nodes > 10_000 || depth > 64) throw new Error("schema_validation_budget_exhausted");
	if (typeof schema === "boolean") return schema;
	if (!jsonObject(schema) || Object.keys(schema).some((key) => !JSON_SCHEMA_KEYWORDS.has(key))) {
		return false;
	}
	const nested = (candidate, childSchema) =>
		matchesJsonSchema(candidate, childSchema, root, context, depth + 1);
	if (schema.$ref !== undefined) {
		const target = resolveLocalSchemaRef(root, schema.$ref);
		if (target === null || !nested(value, target)) return false;
	}
	if (schema.type !== undefined) {
		const types = Array.isArray(schema.type) ? schema.type : [schema.type];
		if (types.length === 0 || types.some((type) => typeof type !== "string")) return false;
		if (!types.some((type) => jsonTypeMatches(value, type))) return false;
	}
	if (schema.const !== undefined && !isDeepStrictEqual(value, schema.const)) return false;
	if (schema.enum !== undefined) {
		if (
			!Array.isArray(schema.enum) ||
			!schema.enum.some((entry) => isDeepStrictEqual(value, entry))
		) {
			return false;
		}
	}
	for (const [keyword, mode] of [
		["allOf", "all"],
		["anyOf", "any"],
		["oneOf", "one"],
	]) {
		if (schema[keyword] === undefined) continue;
		if (!Array.isArray(schema[keyword]) || schema[keyword].length === 0) return false;
		const count = schema[keyword].filter((candidate) => nested(value, candidate)).length;
		if ((mode === "all" && count !== schema[keyword].length) || (mode === "any" && count === 0)) {
			return false;
		}
		if (mode === "one" && count !== 1) return false;
	}
	if (schema.not !== undefined && nested(value, schema.not)) return false;
	if (schema.if !== undefined) {
		const branch = nested(value, schema.if) ? schema.then : schema.else;
		if (branch !== undefined && !nested(value, branch)) return false;
	}

	if (typeof value === "string") {
		if (schema.pattern !== undefined && value.length > MAX_SCHEMA_REGEX_INPUT_LENGTH) return false;
		if (!validNonnegativeInteger(schema.minLength) || !validNonnegativeInteger(schema.maxLength)) {
			return false;
		}
		if (schema.minLength !== undefined && [...value].length < schema.minLength) return false;
		if (schema.maxLength !== undefined && [...value].length > schema.maxLength) return false;
		if (schema.pattern !== undefined) {
			const pattern = compileSafeSchemaRegex(schema.pattern);
			if (!pattern || !testSchemaRegex(pattern, value, context)) return false;
		}
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) return false;
		for (const keyword of ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"]) {
			if (schema[keyword] !== undefined && !Number.isFinite(schema[keyword])) return false;
		}
		if (schema.minimum !== undefined && value < schema.minimum) return false;
		if (schema.maximum !== undefined && value > schema.maximum) return false;
		if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) return false;
		if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) return false;
		if (schema.multipleOf !== undefined) {
			if (!Number.isFinite(schema.multipleOf) || schema.multipleOf <= 0) return false;
			const quotient = value / schema.multipleOf;
			if (Math.abs(quotient - Math.round(quotient)) > Number.EPSILON * 10) return false;
		}
	}
	if (Array.isArray(value) && !matchesArraySchema(value, schema, nested)) return false;
	if (jsonObject(value) && !matchesObjectSchema(value, schema, nested, context)) return false;
	return true;
}

function validNonnegativeInteger(value) {
	return value === undefined || (Number.isSafeInteger(value) && value >= 0);
}

function matchesArraySchema(value, schema, nested) {
	if (
		!validNonnegativeInteger(schema.minItems) ||
		!validNonnegativeInteger(schema.maxItems) ||
		!validNonnegativeInteger(schema.minContains) ||
		!validNonnegativeInteger(schema.maxContains)
	) {
		return false;
	}
	if (schema.minItems !== undefined && value.length < schema.minItems) return false;
	if (schema.maxItems !== undefined && value.length > schema.maxItems) return false;
	if (schema.uniqueItems !== undefined && typeof schema.uniqueItems !== "boolean") return false;
	if (schema.uniqueItems && value.length > 1024) return false;
	if (
		schema.uniqueItems &&
		value.some((item, index) =>
			value.slice(0, index).some((prior) => isDeepStrictEqual(prior, item)),
		)
	)
		return false;
	const prefix = schema.prefixItems ?? (Array.isArray(schema.items) ? schema.items : []);
	if (
		!Array.isArray(prefix) ||
		prefix.slice(0, value.length).some((item, index) => !nested(value[index], item))
	)
		return false;
	const itemSchema = Array.isArray(schema.items) ? true : (schema.items ?? true);
	for (let index = prefix.length; index < value.length; index += 1) {
		if (!nested(value[index], itemSchema)) return false;
	}
	if (schema.contains !== undefined) {
		const count = value.filter((item) => nested(item, schema.contains)).length;
		if (
			count < (schema.minContains ?? 1) ||
			count > (schema.maxContains ?? Number.POSITIVE_INFINITY)
		) {
			return false;
		}
	}
	return true;
}

function matchesObjectSchema(value, schema, nested, context) {
	if (
		!validNonnegativeInteger(schema.minProperties) ||
		!validNonnegativeInteger(schema.maxProperties)
	) {
		return false;
	}
	const keys = Object.keys(value);
	if (schema.minProperties !== undefined && keys.length < schema.minProperties) return false;
	if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) return false;
	if (schema.required !== undefined) {
		if (!Array.isArray(schema.required) || schema.required.some((key) => typeof key !== "string")) {
			return false;
		}
		if (schema.required.some((key) => !Object.hasOwn(value, key))) return false;
	}
	const properties = schema.properties ?? {};
	const patterns = schema.patternProperties ?? {};
	if (!jsonObject(properties) || !jsonObject(patterns)) return false;
	let compiledPatterns;
	compiledPatterns = Object.entries(patterns).map(([source, child]) => [
		compileSafeSchemaRegex(source),
		child,
	]);
	if (compiledPatterns.some(([pattern]) => !pattern)) return false;
	for (const key of keys) {
		if (compiledPatterns.length > 0 && key.length > MAX_SCHEMA_REGEX_INPUT_LENGTH) return false;
		if (schema.propertyNames !== undefined && !nested(key, schema.propertyNames)) return false;
		let matched = false;
		if (Object.hasOwn(properties, key)) {
			matched = true;
			if (!nested(value[key], properties[key])) return false;
		}
		for (const [pattern, child] of compiledPatterns) {
			if (!testSchemaRegex(pattern, key, context)) continue;
			matched = true;
			if (!nested(value[key], child)) return false;
		}
		if (!matched && !nested(value[key], schema.additionalProperties ?? true)) return false;
	}
	if (schema.dependentRequired !== undefined) {
		if (!jsonObject(schema.dependentRequired)) return false;
		for (const [key, required] of Object.entries(schema.dependentRequired)) {
			if (!Array.isArray(required) || required.some((item) => typeof item !== "string"))
				return false;
			if (Object.hasOwn(value, key) && required.some((item) => !Object.hasOwn(value, item)))
				return false;
		}
	}
	return true;
}

function safeJson(value) {
	const text = JSON.stringify(value);
	if (typeof text !== "string") throw new Error("invalid JSON");
	return text;
}

/**
 * Request bodies must be uncompressed UTF-8 JSON. A compressed body or another
 * charset is refused with its own reason instead of a generic failure.
 */
function assertRequestEncoding(headers) {
	if (!/^application\/json(?:\s*;|$)/i.test(headers["content-type"] ?? ""))
		throw new Error("invalid_content_type");
	const charset = /;\s*charset\s*=\s*"?([^";\s]+)"?/i.exec(headers["content-type"])?.[1];
	if (charset !== undefined && !/^utf-?8$/i.test(charset)) throw new Error("unsupported_charset");
	const encoding = headers["content-encoding"];
	if (encoding !== undefined && encoding.trim().toLowerCase() !== "identity")
		throw new Error("unsupported_content_encoding");
}

async function readBody(request, maxBytes, signal) {
	const announced = request.headers["content-length"];
	if (announced !== undefined && (!/^\d+$/.test(announced) || Number(announced) > maxBytes)) {
		throw new Error("request_too_large");
	}
	const chunks = [];
	let bytes = 0;
	const abort = () => request.destroy(new Error("gateway_unavailable"));
	signal.throwIfAborted();
	signal.addEventListener("abort", abort, { once: true });
	try {
		for await (const chunk of request) {
			bytes += chunk.byteLength;
			if (bytes > maxBytes) throw new Error("request_too_large");
			chunks.push(chunk);
		}
		signal.throwIfAborted();
		const body = Buffer.concat(chunks);
		// JSON never contains a raw NUL byte, so one means UTF-16/32 text.
		if (body.includes(0)) throw new Error("invalid_request_encoding");
		try {
			return textDecoder.decode(body);
		} catch {
			throw new Error("invalid_request_encoding");
		}
	} finally {
		signal.removeEventListener("abort", abort);
	}
}

function parseRequest(text) {
	let rpc;
	try {
		rpc = JSON.parse(text);
	} catch {
		throw new Error("invalid_rpc_request");
	}
	if (
		jsonObject(rpc) &&
		rpc.jsonrpc === "2.0" &&
		REFUSED_METHODS.has(rpc.method) &&
		(!Object.hasOwn(rpc, "id") || typeof rpc.id === "string" || Number.isSafeInteger(rpc.id))
	)
		return rpc;
	if (
		jsonObject(rpc) &&
		rpc.jsonrpc === "2.0" &&
		!Object.hasOwn(rpc, "method") &&
		(typeof rpc.id === "string" || Number.isSafeInteger(rpc.id)) &&
		Object.hasOwn(rpc, "result") !== Object.hasOwn(rpc, "error")
	)
		return rpc;
	const notification = rpc?.method === "notifications/initialized";
	if (
		!jsonObject(rpc) ||
		rpc.jsonrpc !== "2.0" ||
		typeof rpc.method !== "string" ||
		![
			"initialize",
			"server/discover",
			"ping",
			"tools/list",
			"tools/call",
			...RESOURCE_METHODS,
			...PROMPT_METHODS,
			"notifications/initialized",
		].includes(rpc.method) ||
		(notification
			? Object.hasOwn(rpc, "id")
			: typeof rpc.id !== "string" && typeof rpc.id !== "number") ||
		(typeof rpc.id === "number" && !Number.isSafeInteger(rpc.id)) ||
		(rpc.params !== undefined && !jsonObject(rpc.params))
	) {
		throw new Error("invalid_rpc_request");
	}
	return rpc;
}

/**
 * Map a server-initiated method to a fixed category for the operator policy
 * and for redacted audit/coverage events (never the server's method or params).
 */
function serverMethodCategory(method) {
	if (method === "sampling/createMessage") return "sampling";
	if (method === "elicitation/create") return "elicitation";
	if (method === "roots/list") return "roots";
	if (typeof method === "string" && method.startsWith("notifications/")) return "notifications";
	return "other";
}

function serverInitiatedRefusal(category = "other") {
	return new McpGatewayRefusal(
		"server_initiated_method",
		"MCP server method is not permitted by the client capability and gateway policy",
		{ serverMethod: category },
	);
}

function parseUpstreamResponse(text, expectedId) {
	const rpc = JSON.parse(text);
	// A JSON response body is the answer; a server request in its place leaves
	// no result to deliver, whatever the policy says.
	if (jsonObject(rpc) && typeof rpc.method === "string")
		throw serverInitiatedRefusal(serverMethodCategory(rpc.method));
	if (
		!jsonObject(rpc) ||
		rpc.jsonrpc !== "2.0" ||
		rpc.id !== expectedId ||
		"result" in rpc === "error" in rpc
	) {
		throw new Error("invalid_upstream_rpc");
	}
	if ("error" in rpc) throw new Error("upstream_rpc_error");
	return rpc.result;
}

function normalizeToolSet(result) {
	if (
		!jsonObject(result) ||
		!Array.isArray(result.tools) ||
		result.nextCursor !== undefined ||
		result.tools.length > 4096
	)
		throw new Error("invalid_tool_list");
	const tools = result.tools.map((tool) => {
		if (!jsonObject(tool)) throw new Error("invalid_tool_definition");
		return McpToolDefinitionSchema.parse({
			name: tool.name,
			description: tool.description,
			input_schema: tool.inputSchema,
			...(tool.outputSchema !== undefined ? { output_schema: tool.outputSchema } : {}),
			...(tool.annotations !== undefined ? { annotations: tool.annotations } : {}),
		});
	});
	return tools;
}

function collectStrings(value, depth = 0, nodes = { count: 0 }, output = []) {
	nodes.count += 1;
	if (nodes.count > 100_000 || depth > 32) throw new Error("output_uninspectable");
	if (typeof value === "string") output.push(value);
	else if (Array.isArray(value))
		for (const item of value) collectStrings(item, depth + 1, nodes, output);
	else if (jsonObject(value))
		for (const [key, item] of Object.entries(value)) {
			output.push(key);
			collectStrings(item, depth + 1, nodes, output);
		}
	return output;
}

/** The text a model reads from one content block, message or embedded resource. */
function blockText(item) {
	if (!jsonObject(item)) return undefined;
	if (typeof item.text === "string") return item.text;
	if (jsonObject(item.content) && typeof item.content.text === "string") return item.content.text;
	if (jsonObject(item.resource) && typeof item.resource.text === "string")
		return item.resource.text;
	return undefined;
}

/**
 * Every array of content blocks (tool `content`, prompt `messages`, resource
 * `contents`) joined in order, with and without a separator. The model reads
 * consecutive blocks as one text, so an injection or secret split across two
 * blocks must be scanned as one string too.
 */
function joinedBlockViews(value, output = []) {
	if (Array.isArray(value)) {
		const texts = value.map(blockText).filter((text) => text !== undefined);
		if (texts.length > 1) output.push(texts.join(""), texts.join("\n"));
		for (const item of value) joinedBlockViews(item, output);
	} else if (jsonObject(value)) {
		for (const item of Object.values(value)) joinedBlockViews(item, output);
	}
	return output;
}

const BASE64_TOKEN = /[A-Za-z0-9+/_-]{24,}={0,2}/g;
const HEX_TOKEN = /(?:[0-9A-Fa-f]{2}){12,}/g;
const MIN_DECODED_TEXT = 12;
const DECODE_ROUNDS = 2;

/** Decoded bytes that read as text: valid UTF-8, almost entirely printable. */
function decodedText(bytes) {
	if (bytes.length < MIN_DECODED_TEXT) return null;
	const text = bytes.toString("utf8");
	let printable = 0;
	for (const character of text) {
		const code = character.codePointAt(0);
		if (code === 0xfffd) return null;
		if (code >= 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) printable += 1;
	}
	return printable / text.length >= 0.95 ? text : null;
}

/**
 * Bounded base64/base64url and hex decoding pass (two nested rounds). Only
 * runs that decode to readable text are added to the scan input; the decoded
 * total can never exceed the encoded input it came from.
 */
function decodedViews(text) {
	const views = [];
	let input = text;
	for (let round = 0; round < DECODE_ROUNDS && input; round += 1) {
		const decoded = [];
		for (const [token] of input.matchAll(BASE64_TOKEN)) {
			const value = decodedText(Buffer.from(token, "base64"));
			if (value) decoded.push(value);
		}
		for (const [token] of input.matchAll(HEX_TOKEN)) {
			const value = decodedText(Buffer.from(token, "hex"));
			if (value) decoded.push(value);
		}
		input = decoded.join("\n");
		if (input) views.push(input);
	}
	return views;
}

/**
 * Pattern-based output inspection. The scanner reads the serialized JSON, the
 * string values (NFKC, zero-width characters removed), the content blocks
 * joined as the model reads them, and readable base64/hex decodings of those.
 * It does not interpret paraphrased or otherwise obfuscated instructions.
 */
function inspect(value, scanner, maxBytes) {
	const json = safeJson(value);
	if (Buffer.byteLength(json, "utf8") > maxBytes) throw new Error("output_oversize");
	const clean = (input) => input.normalize("NFKC").replace(/[\u200B-\u200D\uFEFF]/g, "");
	const text = clean(collectStrings(value).join(" "));
	const joined = joinedBlockViews(value).map(clean);
	const views = [json, text, ...joined, ...decodedViews([text, ...joined].join("\n"))].join("\n");
	if (Buffer.byteLength(views, "utf8") > maxBytes * 10) throw new Error("output_oversize");
	let findings;
	try {
		findings = scanner(views);
	} catch {
		throw new Error("scanner_unavailable");
	}
	if (!Array.isArray(findings)) throw new Error("scanner_unavailable");
	if (findings.length > 0) throw new Error("output_blocked");
}

const BLOCK_REASONS = new Set([
	"manifest_quarantined",
	"manifest_rejected",
	"request_too_large",
	"invalid_content_type",
	"unsupported_content_encoding",
	"unsupported_charset",
	"invalid_request_encoding",
	"invalid_rpc_request",
	"invalid_protocol_version",
	"invalid_session",
	"session_required",
	"unexpected_session",
	"invalid_upstream_session",
	"unexpected_upstream_session",
	"session_changed",
	"tool_not_allowed",
	"resource_not_allowed",
	"prompt_not_allowed",
	"policy_blocked",
	"invalid_context_list",
	"invalid_context_result",
	"arguments_schema_mismatch",
	"output_schema_mismatch",
	"schema_validation_budget_exhausted",
	"toolset_drift",
	"output_blocked",
	"output_oversize",
	"output_uninspectable",
	"scanner_unavailable",
	"unsupported_tool_output",
	"unsupported_structured_output",
	"unsupported_binary_output",
	"binary_output_oversize",
	"binary_inflation_limit",
	"invalid_binary_encoding",
	"binary_content_mismatch",
	"server_initiated_method",
	"arguments_blocked",
	"input_not_fully_inspected",
	"approval_required",
	"detection_unavailable",
	"invalid_tool_result",
	"invalid_initialize_result",
	"invalid_tool_list",
	"invalid_tool_definition",
	"invalid_upstream_rpc",
	"upstream_rpc_error",
	"invalid_sse_field",
	"unsupported_sse_event",
	"multiple_sse_responses",
	"missing_sse_response",
	"upstream_auth_unavailable",
	"notification_response_body",
	"invalid_notification_ack",
	"tenant_busy",
	"gateway_busy",
]);

/**
 * The observed tool a `tools/call` names, once the call is allowed for this
 * client and its arguments match the tool's input schema; throws otherwise.
 */
function callableTool(rpc, observed, allowed) {
	const tool = observed.find((candidate) => candidate.name === rpc.params?.name);
	if (
		!jsonObject(rpc.params) ||
		typeof rpc.params.name !== "string" ||
		!allowed.has(rpc.params.name) ||
		!tool ||
		(rpc.params.arguments !== undefined && !jsonObject(rpc.params.arguments))
	) {
		throw new Error("tool_not_allowed");
	}
	if (
		!supportedJsonSchema(tool.input_schema) ||
		!matchesJsonSchema(rpc.params.arguments ?? {}, tool.input_schema)
	) {
		throw new Error("arguments_schema_mismatch");
	}
	if (tool.output_schema !== undefined && !supportedJsonSchema(tool.output_schema)) {
		throw new Error("output_schema_mismatch");
	}
	return tool;
}

/** A tool with an output schema must return matching structuredContent (unless it errored). */
function assertOutputMatchesSchema(tool, result) {
	if (tool.output_schema === undefined) return;
	const structured = result.structuredContent;
	if (
		(structured === undefined && result.isError !== true) ||
		(structured !== undefined && !matchesJsonSchema(structured, tool.output_schema))
	) {
		throw new Error("output_schema_mismatch");
	}
}

function blockedAuditFields(blocked) {
	return {
		...(blocked?.category ? { category: blocked.category } : {}),
		...(blocked?.threatId ? { threatId: blocked.threatId } : {}),
	};
}

function refusalStatus(reason, rpcId) {
	if (reason === "tenant_busy" || reason === "gateway_busy") return 429;
	if (reason === "request_too_large") return 413;
	if (reason === "unsupported_content_encoding" || reason === "unsupported_charset") return 415;
	return rpcId === null ? 400 : 200;
}

function refusalData(refusal, blocked) {
	if (refusal) return refusalPayload(refusal);
	return blocked ? decisionPayload(blocked) : undefined;
}

function safeReason(cause) {
	if (cause instanceof McpToolCallBlocked) return cause.code;
	if (cause instanceof McpGatewayRefusal && /^[a-z0-9_]{1,64}$/.test(cause.code)) return cause.code;
	if (cause instanceof McpTransportError && /^[a-z0-9_]{1,64}$/.test(cause.code)) return cause.code;
	if (cause instanceof Error && BLOCK_REASONS.has(cause.message)) return cause.message;
	return "gateway_unavailable";
}

const BINARY_OUTPUT_TYPES = new Set(["image", "audio"]);

function upstreamInitializeRequest(rpc) {
	const params = rpc.params;
	if (
		!jsonObject(params) ||
		typeof params.protocolVersion !== "string" ||
		!PROTOCOL_VERSION.test(params.protocolVersion) ||
		!jsonObject(params.capabilities) ||
		!jsonObject(params.clientInfo) ||
		typeof params.clientInfo.name !== "string" ||
		params.clientInfo.name.length === 0 ||
		params.clientInfo.name.length > 128 ||
		typeof params.clientInfo.version !== "string" ||
		params.clientInfo.version.length === 0 ||
		params.clientInfo.version.length > 128
	)
		throw new Error("invalid_rpc_request");
	return {
		jsonrpc: "2.0",
		id: rpc.id,
		method: "initialize",
		params: {
			protocolVersion: params.protocolVersion,
			capabilities: {},
			clientInfo: { name: params.clientInfo.name, version: params.clientInfo.version },
		},
	};
}

/** Advertise only the context surfaces this client is scoped to and the upstream offers. */
function advertisedCapabilities(server, upstream) {
	const scoped = (field, capability) =>
		server.client[field]?.[server.id] && jsonObject(upstream?.[capability])
			? { [capability]: {} }
			: {};
	return {
		tools: {},
		...scoped("allowedResources", "resources"),
		...scoped("allowedPrompts", "prompts"),
	};
}

function contextRequest(rpc, client, server) {
	const resource = RESOURCE_METHODS.has(rpc.method);
	const scope = (resource ? client.allowedResources : client.allowedPrompts)?.[server.id];
	if (!scope) throw new Error(resource ? "resource_not_allowed" : "prompt_not_allowed");
	const params = rpc.params ?? {};
	const fields =
		rpc.method === "resources/read"
			? ["uri"]
			: rpc.method === "prompts/get"
				? ["name", "arguments"]
				: ["cursor"];
	if (Object.keys(params).some((key) => key !== "_meta" && !fields.includes(key)))
		throw new Error("invalid_rpc_request");
	if (
		params.cursor !== undefined &&
		(typeof params.cursor !== "string" || params.cursor.length > MAX_CURSOR_LENGTH)
	)
		throw new Error("invalid_rpc_request");
	if (rpc.method === "resources/read" && !resourceUriAllowed(params.uri, scope))
		throw new Error("resource_not_allowed");
	if (rpc.method === "prompts/get") {
		if (typeof params.name !== "string" || !scope.includes(params.name))
			throw new Error("prompt_not_allowed");
		if (
			params.arguments !== undefined &&
			(!jsonObject(params.arguments) ||
				Object.keys(params.arguments).length > MAX_PROMPT_ARGUMENTS ||
				Object.values(params.arguments).some((value) => typeof value !== "string"))
		)
			throw new Error("invalid_rpc_request");
	}
	return {
		scope,
		params: Object.fromEntries(
			fields.filter((key) => params[key] !== undefined).map((key) => [key, params[key]]),
		),
	};
}

function templateAllowed(uriTemplate, scope) {
	const literal = uriTemplate.split("{")[0];
	return scope.some((pattern) =>
		pattern.endsWith("*") ? literal.startsWith(pattern.slice(0, -1)) : pattern === uriTemplate,
	);
}

function contextListItemAllowed(method, item, scope) {
	if (!jsonObject(item) || typeof item.name !== "string") throw new Error("invalid_context_list");
	if (method === "prompts/list") return scope.includes(item.name);
	if (method === "resources/templates/list") {
		if (typeof item.uriTemplate !== "string" || item.uriTemplate.length > 2048)
			throw new Error("invalid_context_list");
		return templateAllowed(item.uriTemplate, scope);
	}
	if (typeof item.uri !== "string") throw new Error("invalid_context_list");
	return resourceUriAllowed(item.uri, scope);
}

function unsupportedContextOutput() {
	return new McpGatewayRefusal(
		"unsupported_context_output",
		"MCP resource or prompt content representation is unsupported and was refused",
	);
}

function validateResourceContents(item) {
	if (
		!jsonObject(item) ||
		typeof item.uri !== "string" ||
		(item.mimeType !== undefined && typeof item.mimeType !== "string")
	)
		throw unsupportedContextOutput();
	const text = typeof item.text === "string";
	const blob = Object.hasOwn(item, "blob");
	if (text === blob || (blob && (!canonicalBase64(item.blob) || typeof item.mimeType !== "string")))
		throw unsupportedContextOutput();
}

function validatePromptContent(content) {
	if (!jsonObject(content)) throw unsupportedContextOutput();
	if (content.type === "text" && typeof content.text === "string") return;
	if (
		BINARY_OUTPUT_TYPES.has(content.type) &&
		canonicalBase64(content.data) &&
		typeof content.mimeType === "string"
	)
		return;
	if (content.type === "resource") return validateResourceContents(content.resource);
	if (
		content.type === "resource_link" &&
		typeof content.uri === "string" &&
		typeof content.name === "string"
	)
		return;
	throw unsupportedContextOutput();
}

/** Validate and minimize an upstream context result; list entries outside the client scope are dropped. */
function contextResult(method, result, scope, modern) {
	if (!jsonObject(result) || (modern && result.resultType !== "complete"))
		throw new Error("invalid_context_result");
	const tail = modern ? { resultType: "complete" } : {};
	if (Object.hasOwn(CONTEXT_LISTS, method)) {
		const field = CONTEXT_LISTS[method];
		const items = result[field];
		if (
			!Array.isArray(items) ||
			items.length > 4096 ||
			(result.nextCursor !== undefined &&
				(typeof result.nextCursor !== "string" || result.nextCursor.length > MAX_CURSOR_LENGTH))
		)
			throw new Error("invalid_context_list");
		return {
			[field]: items.filter((item) => contextListItemAllowed(method, item, scope)),
			// Pagination cursors are opaque upstream state and are relayed unchanged.
			...(result.nextCursor !== undefined ? { nextCursor: result.nextCursor } : {}),
			...tail,
		};
	}
	if (method === "resources/read") {
		if (!Array.isArray(result.contents) || result.contents.length > 4096)
			throw new Error("invalid_context_result");
		for (const item of result.contents) {
			validateResourceContents(item);
			if (!resourceUriAllowed(item.uri, scope)) throw new Error("resource_not_allowed");
		}
		return { contents: result.contents, ...tail };
	}
	if (
		!Array.isArray(result.messages) ||
		result.messages.length > 4096 ||
		(result.description !== undefined && typeof result.description !== "string")
	)
		throw new Error("invalid_context_result");
	for (const message of result.messages) {
		if (!jsonObject(message) || !["user", "assistant"].includes(message.role))
			throw new Error("invalid_context_result");
		validatePromptContent(message.content);
	}
	return {
		...(result.description !== undefined ? { description: result.description } : {}),
		messages: result.messages,
		...tail,
	};
}

function clientInitializeResult(result, server) {
	if (
		!jsonObject(result) ||
		typeof result.protocolVersion !== "string" ||
		!PROTOCOL_VERSION.test(result.protocolVersion) ||
		!jsonObject(result.serverInfo) ||
		typeof result.serverInfo.name !== "string" ||
		result.serverInfo.name.length === 0 ||
		result.serverInfo.name.length > 128 ||
		typeof result.serverInfo.version !== "string" ||
		result.serverInfo.version.length === 0 ||
		result.serverInfo.version.length > 128
	) {
		throw new Error("invalid_initialize_result");
	}
	return {
		protocolVersion: result.protocolVersion,
		capabilities: advertisedCapabilities(server, result.capabilities),
		serverInfo: { name: result.serverInfo.name, version: result.serverInfo.version },
	};
}

function send(response, status, body, extraHeaders = {}) {
	if (response.writableEnded || response.destroyed) return;
	if (response.headersSent) {
		response.end(`event: message\ndata: ${safeJson(body)}\n\n`);
		return;
	}
	response.writeHead(status, {
		"content-type": "application/json; charset=utf-8",
		"cache-control": "no-store",
		"x-content-type-options": "nosniff",
		...extraHeaders,
	});
	response.end(safeJson(body));
}

function sendRpcResult(response, result) {
	if (result.notification) {
		response.writeHead(202, {
			"cache-control": "no-store",
			"x-content-type-options": "nosniff",
		});
		response.end();
		return;
	}
	send(
		response,
		200,
		result.body,
		result.sessionHeader ? { "mcp-session-id": result.sessionHeader } : {},
	);
}

export function createMcpGateway(input, dependencies = {}) {
	let config = validateGatewayConfig(input);
	const stores = new Map();
	const sessions = new Map();
	const inflight = new Map();
	const pendingReplies = new Map();
	const continuations = new Map();
	const clientCapabilities = new Map();
	const scanner = dependencies.scanner ?? scanModelOutput;
	const lookup = dependencies.lookup;
	const pinnedFetch = dependencies.pinnedFetch;
	const now = dependencies.now ?? (() => new Date());
	const onEvent = dependencies.onEvent ?? (() => undefined);
	const directUpstreamCheck = dependencies.directUpstreamCheck ?? dependencies.checkDirectUpstream;
	const evaluateArguments = createToolCallDetector(
		config,
		dependencies.evaluateToolCall ? { evaluate: dependencies.evaluateToolCall } : {},
	);
	const scanToolMetadata = dependencies.toolMetadataScanner ?? createToolMetadataScanner(config);
	let startupCheckPromise;
	let ready = false;
	let boundPort;
	let expiryTimer;
	const expiryWarnedAt = new Map();
	let activeRequests = 0;
	// Only standalone hosts install this check; private hosts supply their own full guards.
	const assertInstalledPrivacySupported = async () =>
		await dependencies.assertInstalledPrivacySupported?.();

	async function emitEvent(event) {
		try {
			await onEvent(event);
		} catch {
			/* Coverage and audit sinks cannot weaken a refusal or startup result. */
		}
	}

	function storeFor(tenantId) {
		let store = stores.get(tenantId);
		if (!store) {
			store =
				dependencies.storeFactory?.(tenantId) ??
				new FileMcpAttestationStore(
					join(config.stateDir, createHash("sha256").update(tenantId).digest("hex")),
				);
			stores.set(tenantId, store);
		}
		return store;
	}

	async function audit(tenantId, serverId, clientId, decision, reason, detail = {}) {
		await emitEvent({
			tenantId,
			serverId,
			clientId,
			decision,
			reason,
			...detail,
			at: now().toISOString(),
		});
	}

	/**
	 * A server message outside the client's `allowedServerMethods` follows the
	 * operator `serverInitiated` policy: `deny` (the default, and always for
	 * methods outside the known categories) refuses the request; `ignore` drops
	 * the message without delivering it and audits the drop by category only,
	 * never the server's method or params.
	 */
	async function applyServerInitiatedPolicy(server, message) {
		const category = serverMethodCategory(message.method);
		if ((config.serverInitiated[category] ?? "deny") !== "ignore")
			throw serverInitiatedRefusal(category);
		await emitEvent(
			makeMcpGatewayCoverageEvent({
				channel: "upstream_response",
				surface: "server_initiated_method",
				status: "ignored",
				coverageStatus: "limited",
				reasonCode: "server_initiated_method_ignored",
				decision: "deny",
				enforcement: "dropped",
				at: now().toISOString(),
				tenantId: server.tenantId,
				serverId: server.id,
				clientId: server.requestContext?.clientId,
				requestMethod: server.requestContext?.requestMethod,
				serverMethod: category,
			}),
		);
	}

	async function emitBinaryInspection(server, binaryItems) {
		if (binaryItems === 0) return;
		// Binary payloads pass only after type, size and encoding checks, and only
		// their printable runs are scanned. Pixel/audio semantics are not
		// interpreted, so coverage is reported as limited rather than full.
		await emitEvent(
			makeMcpGatewayCoverageEvent({
				channel: "upstream_response",
				surface: "tool_output",
				status: "inspected",
				coverageStatus: "limited",
				reasonCode: "binary_output_bounded_inspection",
				decision: "allow",
				enforcement: "bounded_inspection",
				at: now().toISOString(),
				tenantId: server.tenantId,
				serverId: server.id,
				clientId: server.requestContext?.clientId,
				requestMethod: server.requestContext?.requestMethod,
				outputType: "binary",
				itemCount: binaryItems,
			}),
		);
	}

	function owner(server, sessionId) {
		return `${server.tenantId}\0${server.client.id}\0${server.id}\0${sessionId ?? ""}`;
	}

	function scopedCapabilities(server, requested = {}) {
		const methods = server.client.allowedServerMethods?.[server.id] ?? [];
		return Object.fromEntries(
			[
				["sampling", "sampling/createMessage"],
				["elicitation", "elicitation/create"],
				["roots", "roots/list"],
			]
				.filter(
					([capability, method]) => methods.includes(method) && jsonObject(requested[capability]),
				)
				.map(([capability]) => [
					capability,
					capability === "elicitation"
						? {
								...(jsonObject(requested.elicitation.form) ||
								(!Object.hasOwn(requested.elicitation, "form") &&
									!Object.hasOwn(requested.elicitation, "url"))
									? { form: {} }
									: {}),
								...(jsonObject(requested.elicitation.url) ? { url: {} } : {}),
							}
						: {},
				]),
		);
	}

	/**
	 * Scan a payload and pass it through the configured guard. `scanView` is a
	 * decoded view the scanner reads instead of raw base64 (the guard still gets
	 * the complete payload). `boundedOpaque` marks opaque content that already
	 * passed the bounded binary checks: with no guard configured it is released
	 * with limited coverage; a configured guard must still attest
	 * `opaqueInspected` for it.
	 */
	async function guardPayload(
		payload,
		server,
		sessionId,
		direction,
		method,
		{ scanView, boundedOpaque = false } = {},
	) {
		inspect(scanView ?? payload, scanner, config.maxBodyBytes);
		let opaque = false;
		const visit = (value, depth = 0) => {
			if (depth > 32) throw new Error("output_uninspectable");
			if (!value || typeof value !== "object") return;
			if (
				["image", "audio", "resource", "resource_link"].includes(value.type) ||
				Object.hasOwn(value, "blob")
			)
				opaque = true;
			for (const child of Object.values(value)) visit(child, depth + 1);
		};
		visit(payload);
		const guard = direction === "to_upstream" ? dependencies.toolGuard : dependencies.outputGuard;
		if (guard) {
			let rejectGuard;
			const aborted = new Promise((_, reject) => {
				rejectGuard = () => reject(server.signal.reason ?? new Error("gateway_unavailable"));
			});
			server.signal.throwIfAborted();
			server.signal.addEventListener("abort", rejectGuard, { once: true });
			let verdict;
			try {
				verdict = await Promise.race([
					guard({
						payload: structuredClone(payload),
						direction,
						method,
						signal: server.signal,
						tenantId: server.tenantId,
						clientId: server.client.id,
						serverId: server.id,
						requestId: server.requestId,
						inputSha256: server.inputSha256,
						payloadSha256: createHash("sha256").update(safeJson(payload), "utf8").digest("hex"),
						runtime: "mcp-gateway",
						sessionId: sessionId ?? null,
						protocolVersion: server.protocolVersion,
						toolsetHash: mcpToolsetHash(server.signedManifest.manifest.tools),
					}),
					aborted,
				]);
			} finally {
				server.signal.removeEventListener("abort", rejectGuard);
			}
			server.signal?.throwIfAborted();
			// A policy `deny` or `ask` blocks release; `ask` waits for out-of-band
			// operator approval and is never resolvable from the agent side.
			if (verdict?.decision !== undefined && verdict.decision !== "allow")
				throw new Error("policy_blocked");
			if (
				verdict?.allowed !== true ||
				verdict?.coverage !== "full" ||
				(opaque && verdict?.opaqueInspected !== true)
			)
				throw new McpGatewayRefusal(
					"output_uninspectable",
					"Configured guard could not inspect the complete MCP payload",
				);
		} else if (opaque && !boundedOpaque)
			throw new McpGatewayRefusal(
				"unsupported_binary_output",
				"Opaque MCP content requires a capable approved content scanner",
			);
	}

	function permittedServerMessage(message, server) {
		const category = serverMethodCategory(message.method);
		const methods = server.client.allowedServerMethods?.[server.id] ?? [];
		if (!methods.includes(message.method)) throw serverInitiatedRefusal(category);
		const capability = {
			"sampling/createMessage": "sampling",
			"elicitation/create": "elicitation",
			"roots/list": "roots",
		}[message.method];
		if (capability && !jsonObject(server.capabilities?.[capability]))
			throw serverInitiatedRefusal(category);
		if (message.params !== undefined && !jsonObject(message.params))
			throw new Error("invalid_upstream_rpc");
		if (
			message.method === "sampling/createMessage" &&
			(!Array.isArray(message.params?.messages) ||
				message.params.messages.length === 0 ||
				!Number.isSafeInteger(message.params.maxTokens) ||
				message.params.maxTokens < 1 ||
				message.params.tools !== undefined)
		)
			throw new Error("invalid_upstream_rpc");
		if (message.method === "elicitation/create") {
			if (typeof message.params?.message !== "string") throw new Error("invalid_upstream_rpc");
			if (message.params.mode === "url") {
				if (!jsonObject(server.capabilities.elicitation.url))
					throw serverInitiatedRefusal(category);
				let url;
				try {
					url = new URL(message.params.url);
				} catch {
					throw new Error("invalid_upstream_rpc");
				}
				if (
					url.protocol !== "https:" ||
					url.username ||
					url.password ||
					(server.protocolVersion !== "2026-07-28" &&
						typeof message.params.elicitationId !== "string")
				)
					throw new Error("invalid_upstream_rpc");
			} else {
				if (!jsonObject(server.capabilities.elicitation.form))
					throw serverInitiatedRefusal(category);
				if (message.params.mode !== undefined && message.params.mode !== "form")
					throw new Error("invalid_upstream_rpc");
				if (!supportedJsonSchema(message.params.requestedSchema))
					throw new Error("invalid_upstream_rpc");
			}
		}
	}

	function validateInputResponse(result, request) {
		if (!jsonObject(result)) throw new Error("invalid_rpc_request");
		if (
			request.method === "roots/list" &&
			(!Array.isArray(result.roots) ||
				result.roots.some(
					(root) =>
						!jsonObject(root) || typeof root.uri !== "string" || !root.uri.startsWith("file://"),
				))
		)
			throw new Error("invalid_rpc_request");
		if (
			request.method === "sampling/createMessage" &&
			(result.role !== "assistant" ||
				typeof result.model !== "string" ||
				(!jsonObject(result.content) && !Array.isArray(result.content)))
		)
			throw new Error("invalid_rpc_request");
		if (
			request.method === "elicitation/create" &&
			(!["accept", "decline", "cancel"].includes(result.action) ||
				(result.action === "accept" &&
					request.params.mode !== "url" &&
					!matchesJsonSchema(result.content, request.params.requestedSchema)))
		)
			throw new Error("invalid_rpc_request");
	}

	async function relayServerMessage(message, server, sessionId, signal) {
		const notification = message.method.startsWith("notifications/");
		if (notification === Object.hasOwn(message, "id")) throw new Error("invalid_upstream_rpc");
		const category = serverMethodCategory(message.method);
		// Methods the client did not opt into follow the operator deny/ignore policy.
		const methods = server.client.allowedServerMethods?.[server.id] ?? [];
		if (!methods.includes(message.method)) return applyServerInitiatedPolicy(server, message);
		if (server.protocolVersion === "2026-07-28" && !notification)
			throw serverInitiatedRefusal(category);
		permittedServerMessage(message, server);
		await guardPayload(message, server, sessionId, "to_client", message.method);
		signal.throwIfAborted();
		const response = server.response;
		if (!response || !/text\/event-stream/i.test(server.request.headers.accept ?? ""))
			throw serverInitiatedRefusal(category);
		let delivered = message;
		if (Object.hasOwn(message, "id")) {
			if (server.replyIds.size >= 16) throw new Error("gateway_unavailable");
			admitTenantEntry(pendingReplies, server.tenantId, config.tenantQuotas.pendingReplies);
			if (
				[...pendingReplies.values()].some(
					(pending) =>
						pending.owner === owner(server, sessionId) && pending.originalId === message.id,
				)
			)
				throw new Error("invalid_upstream_rpc");
			const id = gatewayNonce("aidr-reply");
			pendingReplies.set(id, {
				tenantId: server.tenantId,
				owner: owner(server, sessionId),
				originalId: message.id,
				server,
				sessionId,
				method: message.method,
				message,
				signal,
			});
			server.replyIds.add(id);
			delivered = { ...message, id };
		}
		await assertInstalledPrivacySupported();
		if (!response.headersSent)
			response.writeHead(200, {
				"content-type": "text/event-stream",
				"cache-control": "no-store",
				"x-accel-buffering": "no",
			});
		await new Promise((resolve, reject) =>
			response.write(`event: message\ndata: ${safeJson(delivered)}\n\n`, (cause) =>
				cause ? reject(cause) : resolve(),
			),
		);
	}

	async function acceptReply(rpc, server, sessionId, signal) {
		const pending = pendingReplies.get(rpc.id);
		if (
			!pending ||
			pending.owner !== owner(server, sessionId) ||
			pending.signal.aborted ||
			pending.server.resolvedUpstreamAuth !== server.resolvedUpstreamAuth ||
			(server.protocolVersion !== undefined &&
				server.protocolVersion !== pending.server.protocolVersion)
		)
			throw new Error("invalid_session");
		if (
			Object.hasOwn(rpc, "error") &&
			(!jsonObject(rpc.error) ||
				!Number.isSafeInteger(rpc.error.code) ||
				typeof rpc.error.message !== "string")
		)
			throw new Error("invalid_rpc_request");
		if (Object.hasOwn(rpc, "result")) validateInputResponse(rpc.result, pending.message);
		await guardPayload(rpc, pending.server, sessionId, "to_upstream", pending.method);
		if (pendingReplies.get(rpc.id) !== pending || pending.signal.aborted)
			throw new Error("invalid_session");
		pendingReplies.delete(rpc.id);
		pending.server.replyIds.delete(rpc.id);
		await forward(
			pending.server,
			{ ...rpc, id: pending.originalId },
			sessionId,
			AbortSignal.any([signal, pending.signal]),
		);
		return { notification: true };
	}

	async function mrtrResult(result, rpc, server, sessionId) {
		if (
			!jsonObject(result) ||
			(result.inputRequests === undefined && result.requestState === undefined) ||
			(result.requestState !== undefined && typeof result.requestState !== "string") ||
			(result.inputRequests !== undefined && !jsonObject(result.inputRequests))
		)
			throw new Error("invalid_tool_result");
		const requests = result.inputRequests ?? {};
		if (Object.keys(requests).length > 16) throw new Error("invalid_tool_result");
		for (const request of Object.values(requests)) {
			if (
				!jsonObject(request) ||
				!["sampling/createMessage", "elicitation/create", "roots/list"].includes(request.method)
			)
				throw serverInitiatedRefusal(serverMethodCategory(request?.method));
			permittedServerMessage(request, server);
		}
		await guardPayload(result, server, sessionId, "to_client", "input_required");
		for (const [id, saved] of continuations)
			if (saved.expiresAt <= now().getTime()) continuations.delete(id);
		admitTenantEntry(continuations, server.tenantId, config.tenantQuotas.continuations);
		const state = gatewayNonce("aidr-mrtr");
		continuations.set(state, {
			tenantId: server.tenantId,
			owner: owner(server, sessionId),
			upstreamAuth: server.resolvedUpstreamAuth,
			id: rpc.id,
			name: rpc.params.name,
			arguments: structuredClone(rpc.params.arguments ?? {}),
			requests,
			upstreamState: result.requestState,
			expiresAt: now().getTime() + 5 * 60_000,
		});
		return { ...result, requestState: state };
	}

	async function mrtrRetry(rpc, server, sessionId) {
		if (rpc.params.inputResponses === undefined && rpc.params.requestState === undefined) return {};
		const saved = continuations.get(rpc.params.requestState);
		if (
			!saved ||
			saved.owner !== owner(server, sessionId) ||
			saved.upstreamAuth !== server.resolvedUpstreamAuth ||
			saved.id === rpc.id ||
			saved.expiresAt <= now().getTime() ||
			saved.name !== rpc.params.name ||
			!isDeepStrictEqual(saved.arguments, rpc.params.arguments ?? {})
		)
			throw new Error("invalid_session");
		const responses = rpc.params.inputResponses ?? {};
		if (
			!jsonObject(responses) ||
			!isDeepStrictEqual(Object.keys(responses).sort(), Object.keys(saved.requests).sort())
		)
			throw new Error("invalid_rpc_request");
		for (const [key, result] of Object.entries(responses))
			validateInputResponse(result, saved.requests[key]);
		await guardPayload(responses, server, sessionId, "to_upstream", "inputResponses");
		if (continuations.get(rpc.params.requestState) !== saved) throw new Error("invalid_session");
		continuations.delete(rpc.params.requestState);
		return {
			...(Object.keys(responses).length ? { inputResponses: responses } : {}),
			...(saved.upstreamState !== undefined ? { requestState: saved.upstreamState } : {}),
		};
	}

	async function emitCoverageForRefusal(refusal, context) {
		const descriptor = coverageDescriptor(refusal.code);
		await emitEvent(
			makeMcpGatewayCoverageEvent({
				channel: "upstream_response",
				surface: refusal.surface ?? descriptor.surface,
				status: "refused",
				coverageStatus: refusal.coverageStatus ?? descriptor.coverageStatus,
				reasonCode: refusal.code,
				decision: "deny",
				enforcement: refusal.enforcement ?? descriptor.enforcement,
				at: now().toISOString(),
				tenantId: context.tenantId,
				serverId: context.serverId,
				clientId: context.clientId,
				requestMethod: context.requestMethod,
				outputType: refusal.outputType ?? descriptor.outputType,
				serverMethod: refusal.serverMethod,
				refusal: refusalPayload(refusal),
			}),
		);
	}

	function normalizeDirectUpstreamCheck(result) {
		if (
			result === "bypass" ||
			result?.status === "bypass" ||
			result?.directAccess === true ||
			result?.bypass === true
		)
			return "bypass";
		if (
			result === "routed" ||
			result?.status === "routed" ||
			result === false ||
			result?.bypass === false
		)
			return "routed";
		if (result === "unobservable" || result?.status === "unobservable" || result == null)
			return "unobservable";
		throw new Error("invalid_direct_upstream_check");
	}

	function startupReason(status) {
		return status === "bypass"
			? "direct_upstream_bypass_detected"
			: status === "routed"
				? "direct_upstream_bypass_not_observed"
				: "direct_upstream_bypass_unobservable";
	}

	async function observeDirectUpstream(server, gatewayAddress) {
		if (typeof directUpstreamCheck !== "function")
			return { status: "unobservable", reasonCode: "direct_upstream_bypass_unobservable" };
		try {
			const status = normalizeDirectUpstreamCheck(
				await directUpstreamCheck({
					tenantId: server.tenantId,
					serverId: server.id,
					upstreamUrl: server.url,
					gatewayAddress,
				}),
			);
			return { status, reasonCode: startupReason(status) };
		} catch {
			return { status: "unobservable", reasonCode: "direct_upstream_check_failed" };
		}
	}

	function startupBypassRefusal() {
		return new McpGatewayRefusal(
			"direct_upstream_bypass_detected",
			"Direct upstream access was observed for an MCP server; gateway startup was refused",
			{
				surface: "direct_upstream",
				coverageStatus: "limited",
				enforcement: "startup_refusal",
			},
		);
	}

	async function runStartupSelfCheck(gatewayAddress) {
		await verifyConfiguredManifests(config.servers);
		const results = [];
		for (const server of config.servers) {
			if (config.routingRequired) {
				const upstreamToken = resolvedUpstreamAuth(server);
				if (authenticateBearer(`Bearer ${upstreamToken}`, config.clients))
					throw startupBypassRefusal();
				const tokens = [undefined];
				for (const client of config.clients.filter(
					(candidate) =>
						candidate.tenantId === server.tenantId &&
						Object.hasOwn(candidate.allowedTools, server.id),
				)) {
					const token = process.env[client.probeTokenEnv];
					if (authenticateBearer(`Bearer ${token}`, config.clients) !== client)
						throw new Error("upstream_auth_unavailable");
					tokens.push(token);
				}
				for (const protocolVersion of server.protocolVersions)
					for (const token of tokens) {
						await assertInstalledPrivacySupported();
						await fetchMcpEndpoint(
							server.url,
							{
								method: "POST",
								headers: {
									"content-type": "application/json",
									accept: "application/json, text/event-stream",
									"mcp-protocol-version": protocolVersion,
									"mcp-method": "ping",
									...(token ? { authorization: `Bearer ${token}` } : {}),
								},
								body: safeJson({
									jsonrpc: "2.0",
									id: gatewayNonce("aidr-routing"),
									method: "ping",
									params:
										protocolVersion === "2026-07-28"
											? {
													_meta: {
														"io.modelcontextprotocol/protocolVersion": protocolVersion,
														"io.modelcontextprotocol/clientCapabilities": {},
													},
												}
											: {},
								}),
								signal: AbortSignal.timeout(10_000),
							},
							{
								lookup,
								pinnedFetch,
								allowedAddresses: server.pinnedAddresses,
								maxBodyBytes: config.maxBodyBytes,
								acceptUnauthorizedResponse: true,
							},
						);
					}
			}
			const observation = await observeDirectUpstream(server, gatewayAddress);
			const refusal = observation.status === "bypass" ? startupBypassRefusal() : null;
			await emitEvent(
				makeMcpGatewayCoverageEvent({
					channel: "startup",
					surface: "direct_upstream",
					status: refusal ? "refused" : observation.status,
					coverageStatus: observation.status === "routed" ? "observed" : "limited",
					reasonCode: observation.reasonCode,
					decision: refusal ? "deny" : "unknown",
					enforcement: refusal ? "startup_refusal" : "not_verified",
					at: now().toISOString(),
					tenantId: server.tenantId,
					serverId: server.id,
					refusal: refusal ? refusalPayload(refusal) : undefined,
				}),
			);
			results.push({
				tenantId: server.tenantId,
				serverId: server.id,
				status: observation.status,
				reasonCode: observation.reasonCode,
			});
			if (refusal) throw refusal;
		}
		return results;
	}

	/** The operator-configured connection an approval is bound to. */
	function approvalConnection(server) {
		return [
			"gateway-v1",
			server.tenantId,
			server.id,
			server.url,
			server.transport,
			server.sessionMode,
			server.upstreamAuthEnv ?? null,
			resolvedUpstreamAuth(server) ?? null,
		];
	}

	function manifestVerifier(server) {
		return {
			trustedSigners: server.trustedSigners,
			revokedKeyIds: new Set(server.revokedKeyIds ?? []),
			expectedServerId: server.id,
			maxLifetimeMs: config.manifestPolicy.maxLifetimeDays * DAY_MS,
			now: now(),
		};
	}

	/** A redacted manifest lifecycle event (`rejected`, `expiring`, `reloaded`). */
	function manifestEvent(server, status, reasonCode) {
		const expiresAt = Date.parse(server.signedManifest?.manifest?.expires_at);
		return {
			event: "aidr.mcp_gateway.manifest",
			type: "mcp_gateway_manifest",
			tenantId: server.tenantId,
			serverId: server.id,
			status,
			reasonCode,
			...(Number.isFinite(expiresAt) ? { expiresAt: new Date(expiresAt).toISOString() } : {}),
			at: now().toISOString(),
		};
	}

	/** Report a manifest inside the operator's expiry warning window. */
	async function warnIfExpiring(server, { force = false } = {}) {
		const expiresAt = Date.parse(server.signedManifest?.manifest?.expires_at);
		const current = now().getTime();
		if (
			!Number.isFinite(expiresAt) ||
			expiresAt - current > config.manifestPolicy.expiryWarningDays * DAY_MS
		)
			return;
		const key = `${server.tenantId}\0${server.id}`;
		const last = expiryWarnedAt.get(key);
		if (!force && last !== undefined && current - last < EXPIRY_WARNING_INTERVAL_MS) return;
		expiryWarnedAt.set(key, current);
		await emitEvent(manifestEvent(server, "expiring", "manifest_expiring_soon"));
	}

	/**
	 * Verify every configured signed manifest (schema, signer, revocation,
	 * lifetime, validity window, signature) before the gateway serves traffic
	 * or adopts a reloaded configuration. The first invalid manifest refuses
	 * with its precise reason, for example `manifest_expired`.
	 */
	async function verifyConfiguredManifests(servers) {
		for (const server of servers) {
			const verified = verifySignedMcpToolManifest(server.signedManifest, manifestVerifier(server));
			if (verified.valid) continue;
			const code = `manifest_${verified.reason}`;
			await emitEvent(manifestEvent(server, "rejected", code));
			throw new McpGatewayRefusal(
				code,
				"A configured signed MCP manifest is invalid; the gateway refused to use it",
				{ surface: "signed_manifest", coverageStatus: "limited", enforcement: "startup_refusal" },
			);
		}
		for (const server of servers) await warnIfExpiring(server, { force: true });
	}

	async function attest(server) {
		const ignored = [];
		const result = await attestMcpToolManifest({
			candidate: server.signedManifest,
			connection: approvalConnection(server),
			verifier: manifestVerifier(server),
			store: storeFor(server.tenantId),
			approvalKeys: config.approvalKeys,
			onApprovalIgnored: (reason) => ignored.push(reason),
		});
		// An approval entry the operator keys did not sign (or that expired) is
		// never honoured; report it so a forged or stale entry is visible.
		for (const approvalRejection of ignored) {
			await audit(server.tenantId, server.id, null, "deny", "approval_entry_ignored", {
				approvalRejection,
			});
		}
		if (result.status === "rejected") {
			// The client sees the generic reason; the audit event carries the
			// precise one (expired, lifetime_too_long, invalid_signature, ...).
			throw Object.assign(new Error("manifest_rejected"), { manifestReason: result.reason });
		}
		if (result.status !== "accepted") throw new Error(`manifest_${result.status}`);
		await warnIfExpiring(server);
	}

	async function forward(server, rpc, sessionId, signal) {
		const reply = !Object.hasOwn(rpc, "method");
		await guardPayload(rpc, server, sessionId, "to_upstream", rpc.method ?? "reply");
		const headersServer = {
			...server,
			rpcMethod: rpc.method,
			rpcName: rpc.params?.name ?? rpc.params?.uri,
		};
		await assertInstalledPrivacySupported();
		const response = await fetchMcpEndpoint(
			server.url,
			{
				method: "POST",
				headers: upstreamHeaders(headersServer, sessionId),
				body: safeJson(rpc),
				signal,
			},
			{
				mode: "auto",
				maxBodyBytes: config.maxBodyBytes,
				lookup,
				pinnedFetch,
				allowedAddresses: server.pinnedAddresses,
				acceptNotificationResponse: rpc.method === "notifications/initialized",
				acceptJsonRpcResponse: reply,
			},
		);
		const sessionHeader = response.headers.get("mcp-session-id");
		if (rpc.method !== "initialize" && sessionHeader && sessionHeader !== sessionId) {
			throw new Error("session_changed");
		}
		if (rpc.method === "notifications/initialized" || reply) {
			if (response.status !== 202) throw new Error("invalid_notification_ack");
			return { result: undefined, sessionHeader };
		}
		if (/^text\/event-stream(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")) {
			let result;
			let messages = 0;
			for await (const message of readMcpSseMessages(response, config.maxBodyBytes, signal)) {
				if (++messages > 64) throw new Error("output_oversize");
				if (typeof message.method === "string")
					await relayServerMessage(message, server, sessionId, signal);
				else {
					result = parseUpstreamResponse(safeJson(message), rpc.id);
					break;
				}
			}
			if (result === undefined) throw new Error("missing_sse_response");
			return { result, sessionHeader };
		}
		const text = textDecoder.decode(new Uint8Array(await response.arrayBuffer()));
		return { result: parseUpstreamResponse(text, rpc.id), sessionHeader };
	}

	async function verifiedTools(server, sessionId, signal) {
		const id = gatewayNonce("aidr-list");
		const { result } = await forward(
			server,
			{
				jsonrpc: "2.0",
				id,
				method: "tools/list",
				params: server.meta ? { _meta: server.meta } : {},
			},
			sessionId,
			signal,
		);
		if (server.protocolVersion === "2026-07-28" && result?.resultType !== "complete")
			throw new Error("invalid_tool_list");
		const observed = normalizeToolSet(result);
		const observedHash = mcpToolsetHash(observed);
		if (observedHash !== mcpToolsetHash(server.signedManifest.manifest.tools)) {
			throw new Error("toolset_drift");
		}
		await assertToolMetadataClean(server, observed, observedHash);
		inspect(result, scanner, config.maxBodyBytes);
		return observed;
	}

	/**
	 * Tool poisoning: hidden or injected instructions in tool names, descriptions
	 * or schemas block every request to the server, even when the toolset is
	 * signed and operator-approved (a signature proves the publisher, not the
	 * content). Review-level findings are audited and left to output inspection.
	 */
	async function assertToolMetadataClean(server, observed, toolsetHash) {
		const { blocking, suspicious } = await scanToolMetadata(observed, toolsetHash);
		const clientId = server.requestContext?.clientId;
		if (suspicious.length > 0) {
			await audit(server.tenantId, server.id, clientId, "warn", "tool_metadata_suspicious", {
				threatIds: [...new Set(suspicious.map((finding) => finding.threatId))],
			});
		}
		if (blocking.length === 0) return;
		const first = blocking[0];
		throw new McpToolCallBlocked("tool_metadata_poisoned", {
			decision: "deny",
			category: "mcp_tool_poisoning",
			matchedThreatId: first.threatId,
		});
	}

	function boundSession(header, client, server) {
		if (server.sessionMode === "stateless") {
			if (header !== undefined) throw new Error("unexpected_session");
			return undefined;
		}
		if (typeof header !== "string" || !SESSION.test(header)) throw new Error("session_required");
		const session = sessions.get(header);
		if (session && session.expiresAt <= now().getTime()) sessions.delete(header);
		if (
			!session ||
			session.clientId !== client.id ||
			session.tenantId !== client.tenantId ||
			session.serverId !== server.id ||
			session.expiresAt <= now().getTime()
		)
			throw new Error("invalid_session");
		session.expiresAt = now().getTime() + SESSION_TTL_MS;
		return header;
	}

	function pruneExpiredSessions() {
		const current = now().getTime();
		for (const [id, session] of sessions) {
			if (session.expiresAt <= current) sessions.delete(id);
		}
	}

	/** Fail closed unless a map of entries carrying `tenantId` admits one more for this tenant. */
	function admitTenantEntry(entries, tenantId, pool) {
		let tenantEntries = 0;
		for (const entry of entries.values()) {
			if (entry.tenantId === tenantId) tenantEntries += 1;
		}
		const refusal = tenantAdmissionRefusal(pool, entries.size, tenantEntries);
		if (refusal) throw new Error(refusal);
	}

	function sessionCapacityAvailable(tenantId) {
		let tenantSessions = 0;
		for (const session of sessions.values()) {
			if (session.tenantId === tenantId) tenantSessions += 1;
		}
		return tenantSessions < MAX_SESSIONS_PER_TENANT && sessions.size < MAX_SESSIONS;
	}

	async function terminateUpstreamSession(server, sessionId) {
		try {
			await assertInstalledPrivacySupported();
			await fetchMcpEndpoint(
				server.url,
				{
					method: "DELETE",
					headers: upstreamHeaders(server, sessionId),
					// Cleanup must still get one bounded attempt after the client has
					// disconnected or the original request timed out.
					signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
				},
				{
					mode: server.transport,
					maxBodyBytes: config.maxBodyBytes,
					lookup,
					pinnedFetch,
					allowedAddresses: server.pinnedAddresses,
					acceptSessionTerminationResponse: true,
				},
			);
		} catch {
			/* The original refusal remains authoritative when upstream cleanup is unavailable. */
		}
	}

	async function initializeRpc(rpc, client, server, request, signal) {
		if (server.sessionMode === "stateless" && request.headers["mcp-session-id"] !== undefined)
			throw new Error("unexpected_session");
		if (server.sessionMode === "required") {
			pruneExpiredSessions();
			if (!sessionCapacityAvailable(client.tenantId)) throw new Error("invalid_upstream_session");
		}
		const initialize = upstreamInitializeRequest(rpc);
		initialize.params.capabilities = scopedCapabilities(server, rpc.params.capabilities);
		if (
			!server.protocolVersions.includes(initialize.params.protocolVersion) ||
			initialize.params.protocolVersion === "2026-07-28"
		)
			throw new Error("invalid_protocol_version");
		server.protocolVersion = initialize.params.protocolVersion;
		const { result, sessionHeader } = await forward(server, initialize, undefined, signal);
		const newSession =
			typeof sessionHeader === "string" &&
			SESSION.test(sessionHeader) &&
			!sessions.has(sessionHeader);
		try {
			signal.throwIfAborted();
			inspect(result, scanner, config.maxBodyBytes);
			const clientResult = clientInitializeResult(result, server);
			if (
				!server.protocolVersions.includes(clientResult.protocolVersion) ||
				clientResult.protocolVersion === "2026-07-28"
			)
				throw new Error("invalid_protocol_version");
			server.protocolVersion = clientResult.protocolVersion;
			await guardPayload(
				clientResult,
				server,
				newSession ? sessionHeader : undefined,
				"to_client",
				"initialize",
			);
			if (server.sessionMode === "required") {
				pruneExpiredSessions();
				if (
					!sessionHeader ||
					!SESSION.test(sessionHeader) ||
					sessions.has(sessionHeader) ||
					!sessionCapacityAvailable(client.tenantId)
				)
					throw new Error("invalid_upstream_session");
				sessions.set(sessionHeader, {
					clientId: client.id,
					tenantId: client.tenantId,
					serverId: server.id,
					protocolVersion: clientResult.protocolVersion,
					capabilities: initialize.params.capabilities,
					expiresAt: now().getTime() + SESSION_TTL_MS,
				});
			} else if (sessionHeader) throw new Error("unexpected_upstream_session");
			if (server.sessionMode === "stateless") {
				for (const [key, saved] of clientCapabilities)
					if (saved.expiresAt <= now().getTime()) clientCapabilities.delete(key);
				if (clientCapabilities.size >= 10_000 && !clientCapabilities.has(owner(server)))
					throw new Error("gateway_unavailable");
				clientCapabilities.set(owner(server), {
					capabilities: initialize.params.capabilities,
					expiresAt: now().getTime() + SESSION_TTL_MS,
				});
			}
			return { body: rpcResponse(rpc.id, clientResult), sessionHeader };
		} catch (cause) {
			if (newSession) await terminateUpstreamSession(server, sessionHeader);
			throw cause;
		}
	}

	function listTools(rpc, observed, allowed, modern = false) {
		const tools = observed
			.filter((tool) => allowed.has(tool.name))
			.map((tool) => ({
				name: tool.name,
				description: tool.description,
				inputSchema: tool.input_schema,
				...(tool.output_schema ? { outputSchema: tool.output_schema } : {}),
				...(tool.annotations ? { annotations: tool.annotations } : {}),
			}));
		return { body: rpcResponse(rpc.id, { tools, ...(modern ? { resultType: "complete" } : {}) }) };
	}

	async function callTool(rpc, client, server, observed, allowed, sessionId, signal) {
		const tool = callableTool(rpc, observed, allowed);
		const modern = server.protocolVersion === "2026-07-28";
		if (
			!modern &&
			(rpc.params.inputResponses !== undefined || rpc.params.requestState !== undefined)
		)
			throw new Error("invalid_rpc_request");
		// Threat and DLP evaluation of the exact arguments that will be sent,
		// before any upstream execution. A deny, an ask, or an evaluator failure
		// blocks the call. An MRTR retry carries the identical original arguments
		// and is evaluated again.
		await evaluateArguments({
			server,
			client,
			toolName: rpc.params.name,
			args: structuredClone(rpc.params.arguments ?? {}),
			description: tool.description,
			// The bound session (validated against this tenant, client and server)
			// scopes the session-level detection layers to one MCP conversation.
			mcpSessionId: sessionId,
		});
		signal.throwIfAborted();
		const extra = modern ? await mrtrRetry(rpc, server, sessionId) : {};
		const upstream = await forward(
			server,
			{
				jsonrpc: "2.0",
				id: rpc.id,
				method: "tools/call",
				params: {
					name: rpc.params.name,
					arguments: rpc.params.arguments ?? {},
					...extra,
					...(server.meta ? { _meta: server.meta } : {}),
				},
			},
			sessionId,
			signal,
		);
		if (modern && upstream.result?.resultType === "input_required") {
			return {
				body: rpcResponse(rpc.id, await mrtrResult(upstream.result, rpc, server, sessionId)),
			};
		}
		if (modern && upstream.result?.resultType !== "complete")
			throw new Error("invalid_tool_result");
		// Bounded inspection first: envelope, allowlisted and byte-verified binary,
		// decoded resource text. The scanner reads the decoded view, never raw base64.
		const { view, binaryItems } = inspectToolResult(upstream.result, config.binaryOutput, {
			anyStructuredContent: modern,
		});
		assertOutputMatchesSchema(tool, upstream.result);
		// The scanner and any configured output guard then see the complete
		// client-visible result. A configured guard must attest opaque inspection
		// for binary content; without one, only the bounded-inspected binary above
		// is releasable (with limited coverage reported).
		await guardPayload(upstream.result, server, sessionId, "to_client", "tools/call", {
			scanView: view,
			boundedOpaque: true,
		});
		await emitBinaryInspection(server, binaryItems);
		return { body: rpcResponse(rpc.id, upstream.result) };
	}

	async function contextRpc(rpc, request, server, sessionId, signal, modern) {
		try {
			const { result } = await forward(
				server,
				{
					jsonrpc: "2.0",
					id: rpc.id,
					method: rpc.method,
					params: { ...request.params, ...(server.meta ? { _meta: server.meta } : {}) },
				},
				sessionId,
				signal,
			);
			const visible = contextResult(rpc.method, result, request.scope, modern);
			await guardPayload(visible, server, sessionId, "to_client", rpc.method);
			return { body: rpcResponse(rpc.id, visible) };
		} catch (cause) {
			if (cause instanceof McpGatewayRefusal && cause.surface === "tool_output")
				cause.surface = RESOURCE_METHODS.has(rpc.method) ? "resource_output" : "prompt_output";
			throw cause;
		}
	}

	async function processRpc(rpc, client, server, request, signal) {
		if (rpc.method === "initialize") return initializeRpc(rpc, client, server, request, signal);
		const sessionId = boundSession(request.headers["mcp-session-id"], client, server);
		if (!Object.hasOwn(rpc, "method")) return acceptReply(rpc, server, sessionId, signal);
		const negotiatedVersion = sessions.get(sessionId)?.protocolVersion;
		if (negotiatedVersion && server.protocolVersion && server.protocolVersion !== negotiatedVersion)
			throw new Error("invalid_protocol_version");
		server.protocolVersion = negotiatedVersion ?? server.protocolVersion ?? "2025-03-26";
		if (!server.protocolVersions.includes(server.protocolVersion))
			throw new Error("invalid_protocol_version");
		const modern = server.protocolVersion === "2026-07-28";
		if (modern) {
			const meta = rpc.params?._meta;
			if (
				!jsonObject(meta) ||
				meta["io.modelcontextprotocol/protocolVersion"] !== server.protocolVersion ||
				!jsonObject(meta["io.modelcontextprotocol/clientCapabilities"])
			)
				throw new Error("invalid_protocol_version");
			server.capabilities = scopedCapabilities(
				server,
				meta["io.modelcontextprotocol/clientCapabilities"],
			);
			server.meta = { ...meta, "io.modelcontextprotocol/clientCapabilities": server.capabilities };
		} else {
			const saved = clientCapabilities.get(owner(server, sessionId));
			server.capabilities =
				sessions.get(sessionId)?.capabilities ??
				(saved?.expiresAt > now().getTime() ? saved.capabilities : {});
		}
		if (rpc.method === "server/discover") {
			if (!modern) throw new Error("invalid_rpc_request");
			const { result } = await forward(
				server,
				{ ...rpc, params: { ...rpc.params, _meta: server.meta } },
				sessionId,
				signal,
			);
			await guardPayload(result, server, sessionId, "to_client", rpc.method);
			if (!jsonObject(result) || result.resultType !== "complete")
				throw new Error("invalid_upstream_rpc");
			return {
				body: rpcResponse(rpc.id, {
					...result,
					capabilities: advertisedCapabilities(server, result.capabilities),
				}),
			};
		}
		if (rpc.method === "notifications/initialized") {
			if (modern) throw new Error("invalid_rpc_request");
			await forward(server, rpc, sessionId, signal);
			return { notification: true };
		}
		if (rpc.method === "ping")
			return { body: rpcResponse(rpc.id, modern ? { resultType: "complete" } : {}) };
		// Context scope is checked before any upstream call; the signed toolset
		// is still re-verified so a drifted server cannot serve resources/prompts.
		const context =
			RESOURCE_METHODS.has(rpc.method) || PROMPT_METHODS.has(rpc.method)
				? contextRequest(rpc, client, server)
				: null;
		const observed = await verifiedTools(server, sessionId, signal);
		if (context) return contextRpc(rpc, context, server, sessionId, signal, modern);
		const allowed = new Set(client.allowedTools[server.id]);
		if (rpc.method === "tools/list") {
			const result = listTools(rpc, observed, allowed, modern);
			await guardPayload(result.body.result, server, sessionId, "to_client", "tools/list");
			return result;
		}
		return callTool(rpc, client, server, observed, allowed, sessionId, signal);
	}

	async function refuse(response, { client, serverId, rpcId, rpcMethod }, cause) {
		const reason = safeReason(cause);
		const blocked = cause instanceof McpToolCallBlocked ? cause : null;
		const refusal = cause instanceof McpGatewayRefusal ? cause : null;
		await audit(client.tenantId, serverId, client.id, "deny", reason, {
			...blockedAuditFields(blocked),
			...(typeof cause?.manifestReason === "string" && /^[a-z_]{1,48}$/.test(cause.manifestReason)
				? { manifestReason: cause.manifestReason }
				: {}),
		});
		if (refusal) {
			await emitCoverageForRefusal(refusal, {
				tenantId: client.tenantId,
				serverId,
				clientId: client.id,
				requestMethod: rpcMethod,
			});
		}
		const status = refusalStatus(reason, rpcId);
		send(
			response,
			status,
			error(rpcId, -32001, `AIDR blocked MCP request: ${reason}`, refusalData(refusal, blocked)),
			status === 429 ? { connection: "close" } : {},
		);
	}

	async function handleAuthorized(request, response, client, upstream, serverId) {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
		response.once("close", () => {
			if (!response.writableEnded) controller.abort();
		});
		let rpcId = null;
		let rpcMethod;
		let counted = false;
		let requestUpstream;
		try {
			assertRequestEncoding(request.headers);
			const rpc = parseRequest(await readBody(request, config.maxBodyBytes, controller.signal));
			rpcId = rpc.id ?? null;
			rpcMethod = rpc.method;
			if (REFUSED_METHODS.has(rpc.method))
				throw new McpGatewayRefusal(
					"resource_subscription_refused",
					"MCP resource subscriptions and list-change notifications are outside the gateway scope and were refused",
				);
			if (rpc.method) {
				const current = inflight.get(client.tenantId) ?? 0;
				const refusal = tenantAdmissionRefusal(
					config.tenantQuotas.activeRequests,
					activeRequests,
					current,
				);
				if (refusal) throw new Error(refusal);
				inflight.set(client.tenantId, current + 1);
				activeRequests++;
				counted = true;
			}
			const protocolVersion = request.headers["mcp-protocol-version"];
			if (protocolVersion !== undefined && !PROTOCOL_VERSION.test(protocolVersion))
				throw new Error("invalid_protocol_version");
			// Bind the credential snapshot used for attestation to the credential sent
			// upstream. Reading process.env again after an async attestation creates a
			// rotation race that could execute against an unapproved identity.
			requestUpstream = {
				...upstream,
				resolvedUpstreamAuth: resolvedUpstreamAuth(upstream),
				protocolVersion,
				client,
				request,
				response,
				requestId: rpc.id,
				inputSha256: createHash("sha256")
					.update(
						safeJson(
							rpc.method === "resources/read"
								? { uri: rpc.params?.uri ?? null }
								: (rpc.params?.arguments ?? {}),
						),
						"utf8",
					)
					.digest("hex"),
				signal: controller.signal,
				replyIds: new Set(),
				requestContext: { clientId: client.id, requestMethod: rpc.method },
			};
			await attest(requestUpstream);
			const result = await processRpc(rpc, client, requestUpstream, request, controller.signal);
			await audit(client.tenantId, serverId, client.id, "allow", rpc.method);
			await assertInstalledPrivacySupported();
			sendRpcResult(response, result);
		} catch (cause) {
			await refuse(response, { client, serverId, rpcId, rpcMethod }, cause);
		} finally {
			clearTimeout(timeout);
			for (const id of requestUpstream?.replyIds ?? []) pendingReplies.delete(id);
			if (counted) {
				inflight.set(client.tenantId, (inflight.get(client.tenantId) ?? 1) - 1);
				activeRequests--;
			}
		}
	}

	function resolveRoute(request, response) {
		const client = authenticateBearer(request.headers.authorization, config.clients);
		if (!client) {
			send(response, 401, { error: "unauthorized" });
			return null;
		}
		let serverId;
		try {
			serverId = decodeURIComponent(request.url.slice(5));
		} catch {
			send(response, 404, { error: "not_found" });
			return null;
		}
		if (!ID.test(serverId) || !Object.hasOwn(client.allowedTools, serverId)) {
			send(response, 403, { error: "forbidden" });
			return null;
		}
		const upstream = config.servers.find(
			(item) => item.tenantId === client.tenantId && item.id === serverId,
		);
		if (!upstream) {
			send(response, 403, { error: "forbidden" });
			return null;
		}
		return { client, serverId, upstream };
	}

	/**
	 * DNS-rebinding defence: only the loopback names for the bound port, plus
	 * operator-listed `allowedHosts` (a reverse proxy), may address the gateway.
	 */
	function hostAllowed(host) {
		if (typeof host !== "string" || boundPort === undefined) return false;
		const value = host.toLowerCase();
		return (
			value === `127.0.0.1:${boundPort}` ||
			value === `localhost:${boundPort}` ||
			value === `[::1]:${boundPort}` ||
			config.allowedHosts.includes(value)
		);
	}

	const server = createServer(async (request, response) => {
		if (!hostAllowed(request.headers.host)) {
			send(response, 421, { error: "host_forbidden" });
			return;
		}
		try {
			await assertInstalledPrivacySupported();
		} catch {
			send(response, 503, { error: "gateway_unavailable" });
			return;
		}
		if (!ready) {
			send(response, 503, { error: "gateway_starting" });
			return;
		}
		if (request.method === "GET" && request.url === "/healthz") {
			send(response, 200, { status: "up" });
			return;
		}
		if (request.headers.origin !== undefined) {
			send(response, 403, { error: "origin_forbidden" });
			return;
		}
		if (
			request.method !== "POST" ||
			!request.url?.startsWith("/mcp/") ||
			request.url.includes("?")
		) {
			send(response, 404, { error: "not_found" });
			return;
		}
		const route = resolveRoute(request, response);
		if (!route) return;
		const { client, serverId, upstream } = route;
		await handleAuthorized(request, response, client, upstream, serverId);
	});
	server.maxConnections = 100;
	server.maxRequestsPerSocket = 100;
	server.headersTimeout = 10_000;
	server.requestTimeout = 15_000;
	server.keepAliveTimeout = 5_000;

	return {
		get config() {
			return config;
		},
		storeFor,
		/**
		 * Adopt re-signed manifests, signer keys or revocations from a new
		 * configuration without a restart. Every other field must be unchanged,
		 * and every manifest must verify; otherwise the current configuration
		 * stays in force and the reload is refused with a reason code.
		 */
		async reloadManifests(input) {
			const next = validateGatewayConfig(input);
			const fixed = (value) => ({
				...value,
				servers: value.servers.map((item) =>
					Object.fromEntries(
						Object.entries(item).filter(([key]) => !RELOADABLE_SERVER_FIELDS.includes(key)),
					),
				),
			});
			if (!isDeepStrictEqual(fixed(next), fixed(config)))
				throw new GatewayConfigError("configuration change requires restart");
			await verifyConfiguredManifests(next.servers);
			const changed = next.servers.filter(
				(item, index) =>
					!RELOADABLE_SERVER_FIELDS.every((key) =>
						isDeepStrictEqual(item[key], config.servers[index][key]),
					),
			);
			config = next;
			for (const item of changed)
				await emitEvent(manifestEvent(item, "reloaded", "manifest_reloaded"));
			return { reloaded: changed.length };
		},
		close() {
			ready = false;
			clearInterval(expiryTimer);
			return new Promise((resolve) => server.close(resolve));
		},
		/**
		 * Operator approval. `approvalKey` ({ keyId, privateKey }) is the operator
		 * approval private key; the gateway itself never holds it. The expected
		 * toolset, signer and connection binding are derived from this
		 * configuration, never from the (writable) state file.
		 */
		async approve({
			tenantId,
			serverId,
			toolsetHash,
			bindingSha256,
			approvedBy,
			reason,
			approvalKey,
			lifetimeMs,
		}) {
			const target = config.servers.find(
				(item) => item.tenantId === tenantId && item.id === serverId,
			);
			if (!target) throw new Error("unknown tenant server");
			if (!approvalKey) throw new Error("approval key required");
			await assertPrivateMcpStateDirectory(config.stateDir, { create: true });
			const verified = verifySignedMcpToolManifest(target.signedManifest, manifestVerifier(target));
			if (!verified.valid) throw new Error("approval manifest invalid");
			if (verified.toolsetHash !== toolsetHash)
				return { approved: false, reason: "toolset_mismatch" };
			const expectedBinding = mcpApprovalBindingHash({
				serverId: target.id,
				keyId: verified.signed.key_id,
				signerKeySha256: verified.signerKeySha256,
				connection: approvalConnection(target),
			});
			if (expectedBinding !== bindingSha256) return { approved: false, reason: "binding_mismatch" };
			const approvedAt = now();
			return approveQuarantinedMcpToolset({
				serverId,
				toolsetHash,
				bindingSha256,
				approvedBy,
				reason,
				store: storeFor(tenantId),
				approvalKey,
				approvalKeys: config.approvalKeys,
				expected: { keyId: verified.signed.key_id, signerKeySha256: verified.signerKeySha256 },
				now: approvedAt,
				...(lifetimeMs ? { expiresAt: new Date(approvedAt.getTime() + lifetimeMs) } : {}),
			});
		},
		startupSelfCheck(gatewayAddress = null) {
			if (!startupCheckPromise) startupCheckPromise = runStartupSelfCheck(gatewayAddress);
			return startupCheckPromise;
		},
		async listen(port = config.port) {
			await assertInstalledPrivacySupported();
			// Fail closed at startup on a state directory another user could modify.
			await assertPrivateMcpStateDirectory(config.stateDir, { create: true });
			return new Promise((resolve, reject) => {
				server.once("error", reject);
				server.listen(port, "127.0.0.1", async () => {
					server.off("error", reject);
					const address = server.address();
					boundPort = address.port;
					try {
						if (!startupCheckPromise) startupCheckPromise = runStartupSelfCheck(address);
						await startupCheckPromise;
						await assertInstalledPrivacySupported();
						ready = true;
						// Idle gateways still report manifests entering the warning window.
						expiryTimer = setInterval(() => {
							for (const item of config.servers) void warnIfExpiring(item);
						}, EXPIRY_WARNING_INTERVAL_MS);
						expiryTimer.unref();
						resolve(address);
					} catch (cause) {
						server.close(() => reject(cause));
					}
				});
			});
		},
	};
}
