import {
	quarantineAgentWrittenFiles,
	recordToolOutcome,
	recordToolOutputCanaries,
	recordToolOutputFlow,
	scanCachedProvisionedOutput,
	type scanModelOutput,
	scanProvisionedOutput,
} from "@singularityrd/aidr-core";
import { getBundledDataDirs } from "./bundled-dirs.js";

export const MAX_TOOL_OUTPUT_BYTES = 256 * 1024;

const QUARANTINE_TITLE = "Singularity AIDR quarantined tool output";
const MAX_SERIALIZATION_NODES = 8_192;
const MAX_SERIALIZATION_DEPTH = 20;
const BINARY_CONTENT_TYPES = new Set([
	"image",
	"audio",
	"video",
	"file",
	"binary",
	"resource",
	"resource_link",
]);

export type OpenCodeAfterToolInput = {
	tool: string;
	sessionID: string;
	callID: string;
	args: unknown;
};

export type OpenCodeAfterToolOutput = {
	title?: string;
	output?: unknown;
	metadata?: unknown;
	/** OpenCode has passed raw MCP CallToolResult objects to this hook in some versions. */
	content?: unknown;
	isError?: unknown;
	_meta?: unknown;
	structuredContent?: unknown;
};

type InspectionStatus =
	| "inspected_clean"
	| "quarantined_finding"
	| "quarantined_size_limit"
	| "quarantined_unsupported_output"
	| "replacement_unavailable"
	| "quarantined_inspection_error";

type StructuredLogger = {
	debug(data: Record<string, unknown>, message: string): void;
	info(data: Record<string, unknown>, message: string): void;
	warn(data: Record<string, unknown>, message: string): void;
	error(data: Record<string, unknown>, message: string): void;
};

function emitCoverageEvent(
	logger: StructuredLogger,
	level: "debug" | "warn" | "error",
	status: InspectionStatus,
	input: OpenCodeAfterToolInput,
	extra: Record<string, unknown> = {},
): void {
	logger[level](
		{
			event: "aidr.output_inspection.coverage",
			connector: "opencode",
			channel: "tool_output",
			hook: "tool.execute.after",
			status,
			tool: input.tool,
			sessionId: input.sessionID,
			callId: input.callID,
			...extra,
		},
		"Singularity AIDR OpenCode output inspection coverage",
	);
}

function canReplaceProperty(
	key: string,
	descriptor: PropertyDescriptor | undefined,
	extensible: boolean,
): boolean {
	if (!descriptor) return extensible;
	if (descriptor.configurable) return true;
	return key !== "__proto__" && "value" in descriptor && descriptor.writable === true;
}

function replaceProperty(output: OpenCodeAfterToolOutput, key: string, value: unknown): void {
	const descriptor = Object.getOwnPropertyDescriptor(output, key);
	const replacement =
		descriptor?.configurable === false
			? { value }
			: {
					value,
					enumerable: true,
					configurable: true,
					writable: true,
				};
	if (!Reflect.defineProperty(output, key, replacement)) {
		throw new TypeError("OpenCode output property cannot be safely replaced");
	}
}

function quarantine(output: OpenCodeAfterToolOutput, reason: string): void {
	const descriptors = Object.getOwnPropertyDescriptors(output);
	const prototype = Object.getPrototypeOf(output);
	if (prototype !== Object.prototype && prototype !== null) {
		throw new TypeError("Unsupported OpenCode output wrapper");
	}
	const extensible = Object.isExtensible(output);
	// A mixed envelope (wrapper fields plus raw MCP `content`) keeps a `content`
	// carrying the notice, so a host that builds model input from MCP `content`
	// gets the notice too, never the original blocks or a missing result.
	const mixed = descriptors.content !== undefined;
	const kept = mixed
		? ["title", "output", "metadata", "content", "isError"]
		: ["title", "output", "metadata"];
	for (const key of kept) {
		if (!canReplaceProperty(key, descriptors[key], extensible)) {
			throw new TypeError("OpenCode output wrapper cannot be safely replaced");
		}
	}
	for (const [key, descriptor] of Object.entries(descriptors)) {
		if (!kept.includes(key) && !descriptor.configurable) {
			throw new TypeError("OpenCode output wrapper cannot be safely replaced");
		}
	}
	const notice = `[Singularity AIDR] ${reason} The tool already completed. AIDR replaced the hook output object; whether the host honors that mutation has not been verified. Treat the original as potentially visible.`;
	replaceProperty(output, "title", QUARANTINE_TITLE);
	replaceProperty(output, "output", notice);
	replaceProperty(output, "metadata", {});
	if (mixed) {
		replaceProperty(output, "content", [{ type: "text", text: notice }]);
		replaceProperty(output, "isError", true);
	}
	for (const key of Object.keys(descriptors)) {
		if (!kept.includes(key) && !Reflect.deleteProperty(output, key)) {
			throw new TypeError("OpenCode output wrapper cannot be safely replaced");
		}
	}
}

function ownDataValue(output: OpenCodeAfterToolOutput, key: string): unknown {
	try {
		const descriptor = Object.getOwnPropertyDescriptor(output, key);
		return descriptor && "value" in descriptor ? descriptor.value : undefined;
	} catch {
		return undefined;
	}
}

function hasOwnProperty(output: OpenCodeAfterToolOutput, key: string): boolean {
	try {
		return Object.getOwnPropertyDescriptor(output, key) !== undefined;
	} catch {
		return false;
	}
}

/**
 * Every own field of a wrapper result other than `output`: `title`, `metadata`
 * and anything else the host put next to them. A mixed envelope (a wrapper
 * `output` plus raw MCP `content` / `structuredContent` / `_meta`) is possible,
 * and OpenCode may build model input from either side, so every field is
 * inspected, never only the declared wrapper fields.
 */
function wrapperSidecarKeys(output: OpenCodeAfterToolOutput): string[] {
	return Object.getOwnPropertyNames(output).filter((key) => key !== "output");
}

function hasUninspectableSidecar(output: OpenCodeAfterToolOutput): boolean {
	try {
		return wrapperSidecarKeys(output).some((key) => {
			const descriptor = Object.getOwnPropertyDescriptor(output, key);
			return descriptor !== undefined && !("value" in descriptor);
		});
	} catch {
		return true;
	}
}

function isRawMcpResult(output: OpenCodeAfterToolOutput): boolean {
	return ownDataValue(output, "output") === undefined && hasOwnProperty(output, "content");
}

function canReplaceMcpField(key: string, descriptor: PropertyDescriptor): boolean {
	return (
		(key === "content" || key === "isError") &&
		(descriptor.configurable === true || ("value" in descriptor && descriptor.writable === true))
	);
}

function removeMcpSidecars(
	output: OpenCodeAfterToolOutput,
	descriptors: PropertyDescriptorMap,
): boolean {
	return Object.keys(descriptors)
		.filter((key) => key !== "content" && key !== "isError")
		.every((key) => Reflect.deleteProperty(output, key));
}

/**
 * Some OpenCode MCP execution paths pass the raw CallToolResult to
 * `tool.execute.after` instead of the declared `{ title, output, metadata }`
 * wrapper. The model-facing text is then built from `content`, so rewriting
 * only `output.output` would leave the original MCP result intact.
 *
 * Replace the full plain-data envelope so `_meta` and `structuredContent`
 * cannot retain a second copy of the untrusted payload. If the host gives us an
 * immutable, accessor-backed, or otherwise exotic value, report that
 * replacement was unavailable instead of claiming successful quarantine.
 */
function quarantineRawMcpResult(output: OpenCodeAfterToolOutput, reason: string): boolean {
	try {
		const prototype = Object.getPrototypeOf(output);
		if (prototype !== Object.prototype && prototype !== null) return false;
		const descriptors = Object.getOwnPropertyDescriptors(output);
		const extensible = Object.isExtensible(output);
		if (
			!descriptors.content ||
			!canReplaceMcpField("content", descriptors.content) ||
			(descriptors.isError ? !canReplaceMcpField("isError", descriptors.isError) : !extensible) ||
			!Object.entries(descriptors).every(
				([key, descriptor]) =>
					key === "content" || key === "isError" || descriptor.configurable === true,
			)
		) {
			return false;
		}
		replaceProperty(output, "content", [
			{
				type: "text",
				text: `[Singularity AIDR] ${reason} The tool already completed. AIDR replaced the hook output object; whether the host honors that mutation has not been verified. Treat the original as potentially visible.`,
			},
		]);
		replaceProperty(output, "isError", true);
		return removeMcpSidecars(output, descriptors);
	} catch {
		return false;
	}
}

function quarantineInspectedOutput(
	output: OpenCodeAfterToolOutput,
	reason: string,
	input: OpenCodeAfterToolInput,
	logger: StructuredLogger,
	status: InspectionStatus,
	extra: Record<string, unknown> = {},
): void {
	let replacementApplied = false;
	try {
		replacementApplied = isRawMcpResult(output)
			? quarantineRawMcpResult(output, reason)
			: (quarantine(output, reason), true);
	} catch {
		replacementApplied = false;
	}
	if (!replacementApplied) {
		emitCoverageEvent(logger, "error", "replacement_unavailable", input, {
			observedStatus: status,
			replacementApplied: false,
			...extra,
		});
		return;
	}
	emitCoverageEvent(
		logger,
		status === "quarantined_inspection_error" ? "error" : "warn",
		status,
		input,
		{
			replacementApplied: true,
			...extra,
		},
	);
}

function isOpaqueBinaryContent(value: unknown): boolean {
	if (value === null || typeof value !== "object") return false;
	if (
		ArrayBuffer.isView(value) ||
		value instanceof ArrayBuffer ||
		(typeof Blob !== "undefined" && value instanceof Blob)
	) {
		return true;
	}
	const type = Object.getOwnPropertyDescriptor(value, "type");
	return Boolean(
		(type &&
			"value" in type &&
			typeof type.value === "string" &&
			BINARY_CONTENT_TYPES.has(type.value.toLowerCase())) ||
			Object.prototype.hasOwnProperty.call(value, "blob"),
	);
}

type SerializationResult =
	| { status: "ok"; text: string }
	| { status: "oversize" }
	| { status: "unsupported" };

function quotedStringBytes(value: string, limit: number): number | null {
	let bytes = 2;
	for (let index = 0; index < value.length; index += 1) {
		const code = value.charCodeAt(index);
		if (code === 0x22 || code === 0x5c) bytes += 2;
		else if (code <= 0x1f) bytes += [0x08, 0x09, 0x0a, 0x0c, 0x0d].includes(code) ? 2 : 6;
		else if (code >= 0xd800 && code <= 0xdbff) {
			const next = value.charCodeAt(index + 1);
			if (next >= 0xdc00 && next <= 0xdfff) {
				bytes += 4;
				index += 1;
			} else bytes += 6;
		} else if (code >= 0xdc00 && code <= 0xdfff) bytes += 6;
		else if (code <= 0x7f) bytes += 1;
		else if (code <= 0x7ff) bytes += 2;
		else bytes += 3;
		if (bytes > limit) return null;
	}
	return bytes;
}

function preflightJson(value: unknown): "oversize" | "unsupported" | null {
	let bytes = 0;
	let nodes = 0;
	const ancestors = new Set<object>();
	const add = (count: number): "oversize" | null => {
		bytes += count;
		return bytes > MAX_TOOL_OUTPUT_BYTES ? "oversize" : null;
	};
	const addString = (text: string): "oversize" | null => {
		const size = quotedStringBytes(text, MAX_TOOL_OUTPUT_BYTES - bytes);
		return size === null ? "oversize" : add(size);
	};
	const visit = (current: unknown, depth: number): "oversize" | "unsupported" | null => {
		nodes += 1;
		if (nodes > MAX_SERIALIZATION_NODES || depth > MAX_SERIALIZATION_DEPTH) return "unsupported";
		if (current === null) return add(4);
		if (typeof current === "string") return addString(current);
		if (typeof current === "boolean") return add(current ? 4 : 5);
		if (typeof current === "number")
			return add(Buffer.byteLength(JSON.stringify(current) ?? "null", "utf8"));
		if (typeof current !== "object") return "unsupported";
		if (isOpaqueBinaryContent(current)) return "unsupported";
		if (ancestors.has(current)) return "unsupported";
		ancestors.add(current);
		try {
			if (Array.isArray(current)) {
				if (Object.getPrototypeOf(current) !== Array.prototype) return "unsupported";
				const toJson = Object.getOwnPropertyDescriptor(current, "toJSON");
				if (toJson) return "unsupported";
				const opening = add(1);
				if (opening) return opening;
				for (let index = 0; index < current.length; index += 1) {
					if (index > 0) {
						const comma = add(1);
						if (comma) return comma;
					}
					const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
					if (!descriptor || !("value" in descriptor)) return "unsupported";
					const result = visit(descriptor.value, depth + 1);
					if (result) return result;
				}
				return add(1);
			}
			const prototype = Object.getPrototypeOf(current);
			if (prototype !== Object.prototype && prototype !== null) return "unsupported";
			if (Object.getOwnPropertyDescriptor(current, "toJSON")) return "unsupported";
			const opening = add(1);
			if (opening) return opening;
			let count = 0;
			for (const key in current) {
				if (!Object.prototype.hasOwnProperty.call(current, key)) continue;
				if (count > 0) {
					const comma = add(1);
					if (comma) return comma;
				}
				const keyResult = addString(key);
				if (keyResult) return keyResult;
				const colon = add(1);
				if (colon) return colon;
				const descriptor = Object.getOwnPropertyDescriptor(current, key);
				if (!descriptor || !("value" in descriptor)) return "unsupported";
				const result = visit(descriptor.value, depth + 1);
				if (result) return result;
				count += 1;
			}
			return add(1);
		} catch {
			return "unsupported";
		} finally {
			ancestors.delete(current);
		}
	};
	try {
		return visit(value, 0);
	} catch {
		return "unsupported";
	}
}

function serialiseOutput(value: unknown): SerializationResult {
	if (typeof value === "string") {
		return Buffer.byteLength(value, "utf8") > MAX_TOOL_OUTPUT_BYTES
			? { status: "oversize" }
			: { status: "ok", text: value };
	}
	if (value === null) return { status: "ok", text: "null" };
	const preflight = preflightJson(value);
	if (preflight) return { status: preflight };
	try {
		const serialised = JSON.stringify(value, function (key, item) {
			// Buffer.toJSON() runs before the replacer; inspect the original value
			// instead of treating its numeric byte array as scanned text.
			const property = Object.getOwnPropertyDescriptor(this, key);
			if (!property || !("value" in property)) throw new TypeError("Uninspectable output");
			const original = property.value;
			if (isOpaqueBinaryContent(original)) {
				throw new TypeError("Uninspectable binary output");
			}
			return item;
		});
		return typeof serialised === "string"
			? { status: "ok", text: serialised }
			: { status: "unsupported" };
	} catch {
		return { status: "unsupported" };
	}
}

/**
 * Produce additional bounded views that reveal common chunk-boundary and
 * Unicode obfuscation without ever copying output into logs or diagnostics.
 */
function inspectionViews(text: string): string[] {
	const canonical = text.normalize("NFKC").replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
	const structuralJoin = canonical.replace(/:/g, " ").replace(/["'`{},:[\]\\]/g, "");
	return [...new Set([text, canonical, structuralJoin])];
}

interface McpTextCollection {
	text: string;
	unsupported: boolean;
}

function mcpTextBlockText(value: unknown): string | undefined {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
	const type = Object.getOwnPropertyDescriptor(value, "type");
	const text = Object.getOwnPropertyDescriptor(value, "text");
	return type &&
		"value" in type &&
		type.value === "text" &&
		text &&
		"value" in text &&
		typeof text.value === "string"
		? text.value
		: undefined;
}

/** Extract a bounded supplemental view so adjacent MCP text blocks stay contiguous. */
function collectMcpText(serialized: string): McpTextCollection {
	let root: unknown;
	try {
		root = JSON.parse(serialized);
	} catch {
		return { text: "", unsupported: false };
	}
	const runs: string[] = [];
	let length = 0;
	let nodes = 0;
	let unsupported = false;
	const visit = (current: unknown, depth: number): void => {
		if (unsupported) return;
		if (nodes >= 8_192 || depth > 20) {
			unsupported = true;
			return;
		}
		nodes += 1;
		if (current === null || typeof current !== "object") return;
		if (isOpaqueBinaryContent(current)) {
			unsupported = true;
			return;
		}
		if (Array.isArray(current)) {
			let run: string[] = [];
			const flush = () => {
				if (run.length === 0) return;
				const text = run.join("");
				if (length + text.length > MAX_TOOL_OUTPUT_BYTES) unsupported = true;
				else {
					runs.push(text);
					length += text.length;
				}
				run = [];
			};
			for (let index = 0; index < current.length; index += 1) {
				const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
				if (!descriptor || !("value" in descriptor)) {
					unsupported = true;
					return;
				}
				const text = mcpTextBlockText(descriptor.value);
				if (text === undefined) flush();
				else run.push(text);
				visit(descriptor.value, depth + 1);
				if (unsupported) return;
			}
			flush();
			return;
		}
		for (const key in current) {
			if (!Object.prototype.hasOwnProperty.call(current, key)) continue;
			const descriptor = Object.getOwnPropertyDescriptor(current, key);
			if (!descriptor || !("value" in descriptor)) {
				unsupported = true;
				return;
			}
			visit(descriptor.value, depth + 1);
			if (unsupported) return;
		}
	};
	visit(root, 0);
	return { text: runs.join("\n"), unsupported };
}

export function reportOpenCodeOutputCoverage(logger: StructuredLogger): void {
	logger.info(
		{
			event: "aidr.output_inspection.health",
			connector: "opencode",
			channel: "tool_output",
			status: "hook_registered_host_acceptance_required",
			hook: "tool.execute.after",
			maxBytes: MAX_TOOL_OUTPUT_BYTES,
			failureMode: "replace_hook_result_or_report_unavailable",
			hostAcceptanceVerified: false,
		},
		"Singularity AIDR OpenCode output inspection capability",
	);
	logger.warn(
		{
			event: "aidr.output_inspection.health",
			connector: "opencode",
			channel: "provider_stream_and_non_tool_content",
			status: "unsupported_by_host_preconsumption_api",
			reason:
				"OpenCode exposes completed message events only after provider content exists; those events cannot guarantee pre-consumption enforcement",
		},
		"Singularity AIDR OpenCode output inspection coverage gap",
	);
}

/**
 * Record what a flagged tool output carried (secrets, injection payloads) in the
 * session's toxic-flow record, so the session's next calls are judged with it.
 * The output itself is still quarantined; this never throws.
 */
async function feedSessionFlow(
	input: OpenCodeAfterToolInput,
	findings: ReturnType<typeof scanModelOutput>,
	logger: StructuredLogger,
): Promise<void> {
	const args = input.args;
	const result = await recordToolOutputFlow(
		{
			sessionId: input.sessionID,
			toolName: input.tool,
			toolInput:
				args && typeof args === "object" && !Array.isArray(args)
					? (args as Record<string, unknown>)
					: undefined,
			findings,
		},
		{ agentRuntime: "opencode" },
	);
	if (result === "unavailable") {
		logger.warn(
			{ event: "aidr.toxic_flow.feed_unavailable", connector: "opencode", tool: input.tool },
			"Singularity AIDR could not record tool-output taint for session toxic-flow detection",
		);
	}
}

/**
 * Did the host report this tool call as failed? Only the explicit markers OpenCode
 * sends count: the bash tool's `metadata.exit` (the process exit code) other than
 * 0, and a raw MCP result with `isError: true`. A tool that throws never reaches
 * `tool.execute.after`, so it is not seen here. An unknown shape is not a failure,
 * so the runaway guard can only under-count, never invent a loop.
 */
export function openCodeToolFailed(output: OpenCodeAfterToolOutput): boolean {
	if (!output || typeof output !== "object") return false;
	if (isRawMcpResult(output)) return ownDataValue(output, "isError") === true;
	const metadata = ownDataValue(output, "metadata");
	if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return false;
	const exit = ownDataValue(metadata as OpenCodeAfterToolOutput, "exit");
	return typeof exit === "number" && Number.isFinite(exit) && exit !== 0;
}

/** The host result fields, read as own data properties only (no getters run). */
function outputSnapshot(output: OpenCodeAfterToolOutput): Record<string, unknown> {
	const snapshot: Record<string, unknown> = {};
	for (const key of ["title", "output", "metadata", "content", "structuredContent"]) {
		const value = ownDataValue(output, key);
		if (value !== undefined) snapshot[key] = value;
	}
	return snapshot;
}

/**
 * Session-level observations of a completed call, taken before output inspection
 * rewrites a quarantined result: a canary value in the output (audit entry and
 * managed incident) and a reported failure (runaway guard). Never throws.
 */
async function observeCompletedCall(
	input: OpenCodeAfterToolInput,
	output: OpenCodeAfterToolOutput,
	logger: StructuredLogger,
): Promise<void> {
	try {
		const args = input.args;
		const toolInput =
			args && typeof args === "object" && !Array.isArray(args)
				? (args as Record<string, unknown>)
				: {};
		const failed = openCodeToolFailed(output);
		const canaries = await recordToolOutputCanaries({
			sessionId: input.sessionID,
			toolName: input.tool,
			toolOutput: outputSnapshot(output),
			agentRuntime: "opencode",
		});
		if (canaries === "unavailable") {
			logger.warn(
				{ event: "aidr.canary.output_check_unavailable", connector: "opencode", tool: input.tool },
				"Singularity AIDR could not check this tool output for canary credentials",
			);
		}
		if (failed) {
			await recordToolOutcome(
				{ sessionId: input.sessionID, toolName: input.tool, toolInput, failed: true },
				{ agentRuntime: "opencode" },
			);
		}
	} catch {
		// Observation only: a hostile host shape must not break output inspection.
	}
}

/**
 * File quarantine after a completed call (opt-in, `response.quarantine.enabled`):
 * a file the call wrote or downloaded that the content scan classifies as
 * malicious is moved into the quarantine vault, and the model-visible output
 * says so. Runs after output inspection so a quarantined output keeps its own
 * notice. Never throws.
 */
async function quarantineWrittenFiles(
	input: OpenCodeAfterToolInput,
	output: OpenCodeAfterToolOutput,
	logger: StructuredLogger,
): Promise<void> {
	try {
		const args = input.args;
		const result = await quarantineAgentWrittenFiles({
			sessionId: input.sessionID,
			toolName: input.tool,
			toolInput:
				args && typeof args === "object" && !Array.isArray(args)
					? (args as Record<string, unknown>)
					: {},
			agentRuntime: "opencode",
			threatsDir: getBundledDataDirs().threatsDir,
		});
		if (!result.agentNotice) return;
		logger.warn(
			{
				event: "aidr.file_quarantine",
				connector: "opencode",
				tool: input.tool,
				quarantined: result.quarantined.map((item) => item.id),
			},
			"Singularity AIDR quarantined a file this tool call wrote",
		);
		const current = ownDataValue(output, "output");
		if (typeof current === "string") output.output = `${current}\n\n${result.agentNotice}`;
	} catch {
		// Observation only: never break the host's tool result.
	}
}

export function createOutputHandlers(logger: StructuredLogger) {
	const inspectToolOutput = async (
		input: OpenCodeAfterToolInput,
		output: OpenCodeAfterToolOutput,
	): Promise<void> => {
		let rawMcpResult = false;
		try {
			await scanProvisionedOutput([], "opencode");
			rawMcpResult = isRawMcpResult(output);
			if (!rawMcpResult && hasUninspectableSidecar(output)) {
				quarantineInspectedOutput(
					output,
					"The host returned accessor-backed output fields that could not be inspected; output was not classified as clean.",
					input,
					logger,
					"quarantined_unsupported_output",
					{ rawMcpResult: false },
				);
				return;
			}
			if (!rawMcpResult && ownDataValue(output, "output") === undefined) {
				quarantineInspectedOutput(
					output,
					"The host output shape could not be normalized, so inspection coverage is unavailable.",
					input,
					logger,
					"quarantined_unsupported_output",
					{ rawMcpResult: false },
				);
				return;
			}
			if (rawMcpResult && !Array.isArray(ownDataValue(output, "content"))) {
				quarantineInspectedOutput(
					output,
					"The host returned malformed MCP content that could not be inspected; output was not classified as clean.",
					input,
					logger,
					"quarantined_unsupported_output",
					{ rawMcpResult: true },
				);
				return;
			}
			const serialisation = serialiseOutput(rawMcpResult ? output : ownDataValue(output, "output"));
			const sidecarValue = rawMcpResult
				? undefined
				: Object.fromEntries(
						wrapperSidecarKeys(output)
							.map((key) => [key, ownDataValue(output, key)] as const)
							.filter((entry) => entry[1] !== undefined),
					);
			const sidecar = sidecarValue === undefined ? undefined : serialiseOutput(sidecarValue);
			if (serialisation.status === "oversize" || sidecar?.status === "oversize") {
				quarantineInspectedOutput(
					output,
					`Tool output exceeded the ${MAX_TOOL_OUTPUT_BYTES}-byte inspection limit and was not classified as clean.`,
					input,
					logger,
					"quarantined_size_limit",
					{ maxBytes: MAX_TOOL_OUTPUT_BYTES, rawMcpResult },
				);
				return;
			}
			if (serialisation.status === "unsupported" || sidecar?.status === "unsupported") {
				quarantineInspectedOutput(
					output,
					"The host returned an unsupported output representation, so inspection coverage is unavailable.",
					input,
					logger,
					"quarantined_unsupported_output",
					{ rawMcpResult },
				);
				return;
			}
			const text = serialisation.text;
			const sidecarText = sidecar?.text ?? "";

			const bytes = Buffer.byteLength(text, "utf8") + Buffer.byteLength(sidecarText, "utf8");
			if (bytes > MAX_TOOL_OUTPUT_BYTES) {
				quarantineInspectedOutput(
					output,
					`Tool output exceeded the ${MAX_TOOL_OUTPUT_BYTES}-byte inspection limit and was not classified as clean.`,
					input,
					logger,
					"quarantined_size_limit",
					{ outputBytes: bytes, maxBytes: MAX_TOOL_OUTPUT_BYTES, rawMcpResult },
				);
				return;
			}
			const mcpText = collectMcpText(text);
			const sidecarMcpText = sidecarText
				? collectMcpText(sidecarText)
				: { text: "", unsupported: false };
			if (mcpText.unsupported || sidecarMcpText.unsupported) {
				quarantineInspectedOutput(
					output,
					"The host returned unsupported or incomplete content that could not be inspected; output was not classified as clean.",
					input,
					logger,
					"quarantined_unsupported_output",
					{ rawMcpResult },
				);
				return;
			}

			const findings = scanCachedProvisionedOutput(
				[text, mcpText.text, sidecarText, sidecarMcpText.text]
					.filter(Boolean)
					.flatMap(inspectionViews),
				"opencode",
			);
			if (findings.length > 0) {
				const ruleIds = findings.map((finding) => finding.ruleId).sort();
				// Quarantine in the same turn as the inspection, then feed session flow.
				quarantineInspectedOutput(
					output,
					`Tool output matched security rules: ${ruleIds.join(", ")}.`,
					input,
					logger,
					"quarantined_finding",
					{
						outputBytes: bytes,
						findingCount: findings.length,
						findingRuleIds: ruleIds,
						rawMcpResult,
					},
				);
				await feedSessionFlow(input, findings, logger);
				return;
			}

			// The wrapper contract exposes `output`; the raw MCP contract exposes
			// `content[]`. Never manufacture a wrapper field on a raw result because
			// OpenCode builds model input from the MCP `content` array.
			if (!rawMcpResult && typeof ownDataValue(output, "output") !== "string") output.output = text;
			emitCoverageEvent(logger, "debug", "inspected_clean", input, {
				outputBytes: bytes,
				rawMcpResult,
			});
		} catch (error) {
			quarantineInspectedOutput(
				output,
				"Output inspection was unavailable for this response; output was not classified as clean.",
				input,
				logger,
				"quarantined_inspection_error",
				{ errorType: error instanceof Error ? error.name : typeof error, rawMcpResult },
			);
		}
	};

	const afterToolUse = async (
		input: OpenCodeAfterToolInput,
		output: OpenCodeAfterToolOutput,
	): Promise<void> => {
		// Both start synchronously: the observation snapshots the original output
		// before any await, and inspection begins its signed-trust warm-up at once
		// so it decides on the current payload after warm-up. Neither throws.
		const observed = observeCompletedCall(input, output, logger);
		const inspected = inspectToolOutput(input, output);
		await Promise.all([observed, inspected]);
		await quarantineWrittenFiles(input, output, logger);
	};

	return {
		"tool.execute.after": afterToolUse,
	};
}
