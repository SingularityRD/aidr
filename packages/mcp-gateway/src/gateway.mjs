import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
	approveQuarantinedMcpToolset,
	attestMcpToolManifest,
	FileMcpAttestationStore,
	fetchMcpEndpoint,
	McpToolDefinitionSchema,
	McpTransportError,
	mcpToolsetHash,
	scanModelOutput,
} from "@singularityrd/aidr-core";
import { authenticateBearer, validateGatewayConfig } from "./config.mjs";
import {
	coverageDescriptor,
	McpGatewayRefusal,
	makeMcpGatewayCoverageEvent,
	refusalPayload,
} from "./coverage.mjs";
import { createToolCallDetector, decisionPayload, McpToolCallBlocked } from "./detection.mjs";
import { inspectToolResult } from "./output-inspection.mjs";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const SESSION = /^[\x21-\x7e]{8,256}$/;
const MAX_ACTIVE_PER_TENANT = 16;
const MAX_SESSIONS = 10_000;
const MAX_SESSIONS_PER_TENANT = 256;
const SESSION_TTL_MS = 30 * 60 * 1000;
const UPSTREAM_TIMEOUT_MS = 15_000;
const textDecoder = new TextDecoder("utf-8", { fatal: true });

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
		accept: server.transport === "sse" ? "text/event-stream" : "application/json",
		...(auth ? { authorization: `Bearer ${auth}` } : {}),
		...(sessionId ? { "mcp-session-id": sessionId } : {}),
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

async function readBody(request, maxBytes) {
	const announced = request.headers["content-length"];
	if (announced !== undefined && (!/^\d+$/.test(announced) || Number(announced) > maxBytes)) {
		throw new Error("request_too_large");
	}
	const chunks = [];
	let bytes = 0;
	for await (const chunk of request) {
		bytes += chunk.byteLength;
		if (bytes > maxBytes) throw new Error("request_too_large");
		chunks.push(chunk);
	}
	return textDecoder.decode(Buffer.concat(chunks));
}

function parseRequest(text) {
	const rpc = JSON.parse(text);
	const notification = rpc?.method === "notifications/initialized";
	if (
		!jsonObject(rpc) ||
		rpc.jsonrpc !== "2.0" ||
		typeof rpc.method !== "string" ||
		!["initialize", "ping", "tools/list", "tools/call", "notifications/initialized"].includes(
			rpc.method,
		) ||
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

function parseSseEvent(event) {
	if (!event.trim()) return null;
	const data = [];
	let eventType = "message";
	for (const line of event.split("\n")) {
		if (!line || line.startsWith(":")) continue;
		if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
		else if (line.startsWith("event:")) eventType = line.slice(6).trim();
		else if (line.startsWith("id:") || line.startsWith("retry:")) continue;
		else throw new Error("invalid_sse_field");
	}
	if (data.length === 0) return null;
	if (eventType !== "message") throw new Error("unsupported_sse_event");
	return JSON.parse(data.join("\n"));
}

/**
 * Map a server-initiated method to a fixed category. The gateway relays only
 * request/response pairs, so it can never answer these; it strips the matching
 * client capabilities upstream and applies the operator policy to any the
 * server sends anyway.
 */
function serverMethodCategory(method) {
	if (method === "sampling/createMessage") return "sampling";
	if (method === "elicitation/create") return "elicitation";
	if (method === "roots/list") return "roots";
	if (method.startsWith("notifications/")) return "notifications";
	return "other";
}

function serverInitiatedRefusal(category) {
	return new McpGatewayRefusal(
		"server_initiated_method",
		"MCP server-initiated methods are outside the gateway response coverage and were refused",
		{ serverMethod: category },
	);
}

const MAX_SERVER_MESSAGES = 256;

function parseSse(text) {
	let response = null;
	const serverMessages = [];
	for (const event of text.replace(/\r\n/g, "\n").split(/\n\n+/)) {
		const parsed = parseSseEvent(event);
		if (parsed === null) continue;
		if (jsonObject(parsed) && typeof parsed.method === "string") {
			if (serverMessages.length >= MAX_SERVER_MESSAGES) throw serverInitiatedRefusal("other");
			serverMessages.push(serverMethodCategory(parsed.method));
			continue;
		}
		if (response !== null) throw new Error("multiple_sse_responses");
		response = parsed;
	}
	if (response === null) {
		// A stream that carries only server-initiated messages ends without an
		// answer; report the first message category instead of a generic error.
		if (serverMessages.length > 0) throw serverInitiatedRefusal(serverMessages[0]);
		throw new Error("missing_sse_response");
	}
	return { rpc: response, serverMessages };
}

function parseUpstreamResponse(text, mode, expectedId) {
	let rpc;
	let serverMessages = [];
	if (mode === "sse") ({ rpc, serverMessages } = parseSse(text));
	else {
		rpc = JSON.parse(text);
		// A JSON response body is the answer; a server request in its place
		// leaves no result to deliver, whatever the policy says.
		if (jsonObject(rpc) && typeof rpc.method === "string")
			throw serverInitiatedRefusal(serverMethodCategory(rpc.method));
	}
	if (
		!jsonObject(rpc) ||
		rpc.jsonrpc !== "2.0" ||
		rpc.id !== expectedId ||
		"result" in rpc === "error" in rpc
	) {
		throw new Error("invalid_upstream_rpc");
	}
	if ("error" in rpc) throw new Error("upstream_rpc_error");
	return { result: rpc.result, serverMessages };
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

function inspect(value, scanner, maxBytes) {
	const json = safeJson(value);
	if (Buffer.byteLength(json, "utf8") > maxBytes) throw new Error("output_oversize");
	const text = collectStrings(value)
		.join(" ")
		.normalize("NFKC")
		.replace(/[\u200B-\u200D\uFEFF]/g, "");
	if (Buffer.byteLength(text, "utf8") > maxBytes * 2) throw new Error("output_oversize");
	let findings;
	try {
		findings = scanner(`${json}\n${text}`);
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
	"invalid_rpc_request",
	"invalid_session",
	"session_required",
	"unexpected_session",
	"invalid_upstream_session",
	"unexpected_upstream_session",
	"session_changed",
	"tool_not_allowed",
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
]);

function safeReason(cause) {
	if (cause instanceof McpToolCallBlocked) return cause.code;
	if (cause instanceof McpGatewayRefusal && /^[a-z0-9_]{1,64}$/.test(cause.code)) return cause.code;
	if (cause instanceof McpTransportError && /^[a-z0-9_]{1,64}$/.test(cause.code)) return cause.code;
	if (cause instanceof Error && BLOCK_REASONS.has(cause.message)) return cause.message;
	return "gateway_unavailable";
}

function clientInitializeResult(result) {
	if (
		!jsonObject(result) ||
		typeof result.protocolVersion !== "string" ||
		result.protocolVersion.length === 0 ||
		result.protocolVersion.length > 64 ||
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
		capabilities: { tools: {} },
		serverInfo: { name: result.serverInfo.name, version: result.serverInfo.version },
	};
}

const SERVER_CAPABILITIES_GATEWAY_CANNOT_RELAY = ["sampling", "elicitation", "roots"];

/**
 * The gateway answers each client request with exactly one inspected response
 * and has no channel to relay a server request back to the client. Advertising
 * sampling, elicitation or roots upstream would invite requests that can only
 * be refused, so those client capabilities are removed before forwarding.
 */
function upstreamInitializeRequest(rpc) {
	const capabilities = rpc.params?.capabilities;
	if (!jsonObject(capabilities)) return rpc;
	const forwarded = { ...capabilities };
	for (const key of SERVER_CAPABILITIES_GATEWAY_CANNOT_RELAY) delete forwarded[key];
	return { ...rpc, params: { ...rpc.params, capabilities: forwarded } };
}

function send(response, status, body, extraHeaders = {}) {
	if (response.writableEnded || response.destroyed) return;
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
	const config = validateGatewayConfig(input);
	const stores = new Map();
	const sessions = new Map();
	const inflight = new Map();
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
	let startupCheckPromise;

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

	async function applyServerInitiatedPolicy(server, serverMessages) {
		let denied = null;
		for (const category of serverMessages) {
			const action = config.serverInitiated[category] ?? "deny";
			if (action === "deny") {
				denied ??= category;
				continue;
			}
			// Ignored messages are never delivered to the client; record that they
			// were dropped (category only, never the server's method or params).
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
		if (denied) throw serverInitiatedRefusal(denied);
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
		const results = [];
		for (const server of config.servers) {
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

	async function attest(server) {
		const result = await attestMcpToolManifest({
			candidate: server.signedManifest,
			connection: [
				"gateway-v1",
				server.tenantId,
				server.id,
				server.url,
				server.transport,
				server.sessionMode,
				server.upstreamAuthEnv ?? null,
				resolvedUpstreamAuth(server) ?? null,
			],
			verifier: {
				trustedSigners: server.trustedSigners,
				revokedKeyIds: new Set(server.revokedKeyIds ?? []),
				expectedServerId: server.id,
				now: now(),
			},
			store: storeFor(server.tenantId),
		});
		if (result.status !== "accepted") throw new Error(`manifest_${result.status}`);
	}

	async function forward(server, rpc, sessionId, signal) {
		const response = await fetchMcpEndpoint(
			server.url,
			{
				method: "POST",
				headers: upstreamHeaders(server, sessionId),
				body: safeJson(rpc),
				signal,
			},
			{
				mode: server.transport,
				maxBodyBytes: config.maxBodyBytes,
				lookup,
				pinnedFetch,
				acceptNotificationResponse: rpc.method === "notifications/initialized",
			},
		);
		const sessionHeader = response.headers.get("mcp-session-id");
		if (rpc.method !== "initialize" && sessionHeader && sessionHeader !== sessionId) {
			throw new Error("session_changed");
		}
		if (rpc.method === "notifications/initialized") {
			if (response.status !== 202) throw new Error("invalid_notification_ack");
			return { result: undefined, sessionHeader };
		}
		const text = textDecoder.decode(new Uint8Array(await response.arrayBuffer()));
		const { result, serverMessages } = parseUpstreamResponse(text, server.transport, rpc.id);
		await applyServerInitiatedPolicy(server, serverMessages);
		return { result, sessionHeader };
	}

	async function verifiedTools(server, sessionId, signal) {
		const id = `aidr-list-${Date.now()}-${Math.random().toString(36).slice(2)}`;
		const { result } = await forward(
			server,
			{ jsonrpc: "2.0", id, method: "tools/list", params: {} },
			sessionId,
			signal,
		);
		const observed = normalizeToolSet(result);
		if (mcpToolsetHash(observed) !== mcpToolsetHash(server.signedManifest.manifest.tools)) {
			throw new Error("toolset_drift");
		}
		inspect(result, scanner, config.maxBodyBytes);
		return observed;
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

	function sessionCapacityAvailable(tenantId) {
		let tenantSessions = 0;
		for (const session of sessions.values()) {
			if (session.tenantId === tenantId) tenantSessions += 1;
		}
		return tenantSessions < MAX_SESSIONS_PER_TENANT && sessions.size < MAX_SESSIONS;
	}

	async function terminateUpstreamSession(server, sessionId) {
		try {
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
		const { result, sessionHeader } = await forward(
			server,
			upstreamInitializeRequest(rpc),
			undefined,
			signal,
		);
		const newSession =
			typeof sessionHeader === "string" &&
			SESSION.test(sessionHeader) &&
			!sessions.has(sessionHeader);
		try {
			signal.throwIfAborted();
			inspect(result, scanner, config.maxBodyBytes);
			const clientResult = clientInitializeResult(result);
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
					expiresAt: now().getTime() + SESSION_TTL_MS,
				});
			} else if (sessionHeader) throw new Error("unexpected_upstream_session");
			return { body: rpcResponse(rpc.id, clientResult), sessionHeader };
		} catch (cause) {
			if (newSession) await terminateUpstreamSession(server, sessionHeader);
			throw cause;
		}
	}

	function listTools(rpc, observed, allowed) {
		const tools = observed
			.filter((tool) => allowed.has(tool.name))
			.map((tool) => ({
				name: tool.name,
				description: tool.description,
				inputSchema: tool.input_schema,
				...(tool.output_schema ? { outputSchema: tool.output_schema } : {}),
				...(tool.annotations ? { annotations: tool.annotations } : {}),
			}));
		return { body: rpcResponse(rpc.id, { tools }) };
	}

	async function callTool(rpc, client, server, observed, allowed, sessionId, signal) {
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
		// Threat and DLP evaluation of the exact arguments that will be sent,
		// before any upstream execution. A deny, an ask, or an evaluator failure
		// blocks the call.
		await evaluateArguments({
			server,
			client,
			toolName: rpc.params.name,
			args: structuredClone(rpc.params.arguments ?? {}),
		});
		signal.throwIfAborted();
		const upstream = await forward(
			server,
			{
				jsonrpc: "2.0",
				id: rpc.id,
				method: "tools/call",
				params: { name: rpc.params.name, arguments: rpc.params.arguments ?? {} },
			},
			sessionId,
			signal,
		);
		const { view, binaryItems } = inspectToolResult(upstream.result, config.binaryOutput);
		if (tool.output_schema !== undefined) {
			const structured = upstream.result.structuredContent;
			if (
				(structured === undefined && upstream.result.isError !== true) ||
				(structured !== undefined && !matchesJsonSchema(structured, tool.output_schema))
			) {
				throw new Error("output_schema_mismatch");
			}
		}
		inspect(view, scanner, config.maxBodyBytes);
		await emitBinaryInspection(server, binaryItems);
		return { body: rpcResponse(rpc.id, upstream.result) };
	}

	async function processRpc(rpc, client, server, request, signal) {
		if (rpc.method === "initialize") return initializeRpc(rpc, client, server, request, signal);
		const sessionId = boundSession(request.headers["mcp-session-id"], client, server);
		if (rpc.method === "notifications/initialized") {
			await forward(server, rpc, sessionId, signal);
			return { notification: true };
		}
		if (rpc.method === "ping") return { body: rpcResponse(rpc.id, {}) };
		const observed = await verifiedTools(server, sessionId, signal);
		const allowed = new Set(client.allowedTools[server.id]);
		return rpc.method === "tools/list"
			? listTools(rpc, observed, allowed)
			: callTool(rpc, client, server, observed, allowed, sessionId, signal);
	}

	async function refuse(response, { client, serverId, rpcId, rpcMethod }, cause) {
		const reason = safeReason(cause);
		const blocked = cause instanceof McpToolCallBlocked ? cause : null;
		const refusal = cause instanceof McpGatewayRefusal ? cause : null;
		await audit(client.tenantId, serverId, client.id, "deny", reason, {
			...(blocked?.category ? { category: blocked.category } : {}),
			...(blocked?.threatId ? { threatId: blocked.threatId } : {}),
		});
		if (refusal) {
			await emitCoverageForRefusal(refusal, {
				tenantId: client.tenantId,
				serverId,
				clientId: client.id,
				requestMethod: rpcMethod,
			});
		}
		const status = reason === "request_too_large" ? 413 : rpcId === null ? 400 : 200;
		const data = refusal ? refusalPayload(refusal) : blocked ? decisionPayload(blocked) : undefined;
		send(response, status, error(rpcId, -32001, `AIDR blocked MCP request: ${reason}`, data));
	}

	async function handleAuthorized(request, response, client, upstream, serverId) {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
		response.once("close", () => {
			if (!response.writableEnded) controller.abort();
		});
		let rpcId = null;
		let rpcMethod;
		try {
			if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] ?? "")) {
				throw new Error("invalid_content_type");
			}
			const rpc = parseRequest(await readBody(request, config.maxBodyBytes));
			rpcId = rpc.id ?? null;
			rpcMethod = rpc.method;
			// Bind the credential snapshot used for attestation to the credential sent
			// upstream. Reading process.env again after an async attestation creates a
			// rotation race that could execute against an unapproved identity.
			const requestUpstream = {
				...upstream,
				resolvedUpstreamAuth: resolvedUpstreamAuth(upstream),
				requestContext: { clientId: client.id, requestMethod: rpc.method },
			};
			await attest(requestUpstream);
			const result = await processRpc(rpc, client, requestUpstream, request, controller.signal);
			await audit(client.tenantId, serverId, client.id, "allow", rpc.method);
			sendRpcResult(response, result);
		} catch (cause) {
			await refuse(response, { client, serverId, rpcId, rpcMethod }, cause);
		} finally {
			clearTimeout(timeout);
			inflight.set(client.tenantId, (inflight.get(client.tenantId) ?? 1) - 1);
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

	const server = createServer(async (request, response) => {
		if (request.method === "GET" && request.url === "/healthz") {
			send(response, 200, { status: "up" });
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
		const current = inflight.get(client.tenantId) ?? 0;
		if (current >= MAX_ACTIVE_PER_TENANT) {
			send(response, 429, { error: "tenant_busy" });
			return;
		}
		inflight.set(client.tenantId, current + 1);
		await handleAuthorized(request, response, client, upstream, serverId);
	});
	server.maxConnections = 100;
	server.maxRequestsPerSocket = 100;
	server.headersTimeout = 10_000;
	server.requestTimeout = 15_000;
	server.keepAliveTimeout = 5_000;

	return {
		config,
		storeFor,
		close() {
			return new Promise((resolve) => server.close(resolve));
		},
		async approve({ tenantId, serverId, toolsetHash, bindingSha256, approvedBy, reason }) {
			const target = config.servers.find(
				(item) => item.tenantId === tenantId && item.id === serverId,
			);
			if (!target) throw new Error("unknown tenant server");
			return approveQuarantinedMcpToolset({
				serverId,
				toolsetHash,
				bindingSha256,
				approvedBy,
				reason,
				store: storeFor(tenantId),
				now: now(),
			});
		},
		startupSelfCheck(gatewayAddress = null) {
			if (!startupCheckPromise) startupCheckPromise = runStartupSelfCheck(gatewayAddress);
			return startupCheckPromise;
		},
		listen(port = config.port) {
			return new Promise((resolve, reject) => {
				server.once("error", reject);
				server.listen(port, "127.0.0.1", async () => {
					server.off("error", reject);
					const address = server.address();
					try {
						if (!startupCheckPromise) startupCheckPromise = runStartupSelfCheck(address);
						await startupCheckPromise;
						resolve(address);
					} catch (cause) {
						server.close(() => reject(cause));
					}
				});
			});
		},
	};
}
