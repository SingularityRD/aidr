import { scanModelOutput } from "@singularityrd/aidr-core";

/** Default maximum amount of tool output inspected before delivery (256 KiB). */
export const DEFAULT_TOOL_OUTPUT_MAX_BYTES = 256 * 1024;
/** Hard ceiling prevents a JavaScript caller from configuring an effectively unbounded scan. */
export const MAX_TOOL_OUTPUT_MAX_BYTES = 16 * 1024 * 1024;

export type ToolOutputInspectionStatus = "clean" | "findings" | "oversize" | "unavailable";
export type ToolOutputDelivery = "allow" | "block" | "redact";
export type ToolOutputUnsafeAction = Exclude<ToolOutputDelivery, "allow">;
export type ToolOutputFinding = ReturnType<typeof scanModelOutput>[number];

export interface ToolOutputGuardOptions {
	/** Maximum UTF-8 bytes inspected. Oversized output is never reported as clean. */
	maxBytes?: number;
	/** Delivery action when the scanner reports a finding. Default: `block`. */
	findingAction?: ToolOutputUnsafeAction;
	/** Delivery action when the complete output does not fit in maxBytes. Default: `block`. */
	oversizeAction?: ToolOutputUnsafeAction;
	/** Delivery action when the output cannot be converted to inspectable text. Default: `block`. */
	unavailableAction?: ToolOutputUnsafeAction;
}

export interface ToolOutputInspection {
	status: ToolOutputInspectionStatus;
	findings: ToolOutputFinding[];
	inspectedBytes: number;
	maxBytes: number;
	reason?: string;
}

export interface ToolOutputGuardResult<T> {
	inspection: ToolOutputInspection;
	delivery: ToolOutputDelivery;
	/** Present only when delivery is allowed or replaced with a safe redaction marker. */
	output?: T | string;
}

/**
 * Raised by `enforceToolOutput` when unsafe, oversized, or uninspectable output
 * must not reach the model.
 */
export class AIDRToolOutputError extends Error {
	constructor(public readonly inspection: ToolOutputInspection) {
		super(formatToolOutputBlockReason(inspection));
		this.name = "AIDRToolOutputError";
	}
}

interface SerializationSuccess {
	ok: true;
	text: string;
	mcpText: string;
	bytes: number;
}

interface SerializationFailure {
	ok: false;
	status: "oversize" | "unavailable";
	bytes: number;
	reason: string;
}

type SerializationResult = SerializationSuccess | SerializationFailure;

const MAX_NESTING_DEPTH = 32;
const BINARY_CONTENT_TYPES = new Set([
	"image",
	"audio",
	"video",
	"file",
	"binary",
	"resource",
	"resource_link",
]);

function isOpaqueBinaryContent(value: object): boolean {
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

function validateMaxBytes(value: number | undefined): number {
	const maxBytes = value ?? DEFAULT_TOOL_OUTPUT_MAX_BYTES;
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_TOOL_OUTPUT_MAX_BYTES) {
		throw new RangeError(
			`Tool output maxBytes must be an integer from 1 to ${MAX_TOOL_OUTPUT_MAX_BYTES}`,
		);
	}
	return maxBytes;
}

/** Return the UTF-8 byte length, stopping as soon as the limit is exceeded. */
function boundedUtf8Length(value: string, limit: number): number {
	let bytes = 0;
	for (let index = 0; index < value.length; index += 1) {
		const code = value.charCodeAt(index);
		if (code <= 0x7f) {
			bytes += 1;
		} else if (code <= 0x7ff) {
			bytes += 2;
		} else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
			const next = value.charCodeAt(index + 1);
			if (next >= 0xdc00 && next <= 0xdfff) {
				bytes += 4;
				index += 1;
			} else {
				bytes += 3;
			}
		} else {
			bytes += 3;
		}
		if (bytes > limit) return bytes;
	}
	return bytes;
}

/**
 * Convert common framework outputs to scanner text without constructing an
 * unbounded JSON string. Adjacent array string chunks stay contiguous so split
 * tokens remain detectable.
 */
class BoundedOutputSerializer {
	private readonly chunks: string[] = [];
	private readonly mcpTextRuns: string[] = [];
	private readonly seen = new Set<object>();
	private bytes = 0;
	private mcpTextLength = 0;

	constructor(private readonly maxBytes: number) {}

	serialize(value: unknown): SerializationResult {
		const failure = this.visit(value, 0);
		if (failure) return failure;
		return {
			ok: true,
			text: this.chunks.join(""),
			mcpText: this.mcpTextRuns.join("\n"),
			bytes: this.bytes,
		};
	}

	private appendMcpTextRun(run: string[]): SerializationFailure | undefined {
		if (run.length === 0) return undefined;
		const text = run.join("");
		const separatorLength = this.mcpTextRuns.length > 0 ? 1 : 0;
		if (this.mcpTextLength + separatorLength + text.length > this.maxBytes) {
			return this.failure("unavailable", "MCP text blocks exceed the inspection limit");
		}
		this.mcpTextRuns.push(text);
		this.mcpTextLength += separatorLength + text.length;
		return undefined;
	}

	private failure(status: SerializationFailure["status"], reason: string): SerializationFailure {
		return { ok: false, status, bytes: this.bytes, reason };
	}

	private append(chunk: string): SerializationFailure | undefined {
		const remaining = this.maxBytes - this.bytes;
		const chunkBytes = boundedUtf8Length(chunk, remaining);
		if (chunkBytes > remaining) {
			return this.failure(
				"oversize",
				`Tool output exceeds the ${this.maxBytes}-byte inspection limit`,
			);
		}
		this.chunks.push(chunk);
		this.bytes += chunkBytes;
		return undefined;
	}

	private visit(current: unknown, depth: number): SerializationFailure | undefined {
		if (depth > MAX_NESTING_DEPTH) {
			return this.failure("unavailable", `Tool output nesting exceeds ${MAX_NESTING_DEPTH} levels`);
		}
		if (current === null) return this.append("null");
		if (current === undefined) return this.append("");

		switch (typeof current) {
			case "string":
				return this.append(current);
			case "number":
			case "boolean":
			case "bigint":
				return this.append(String(current));
			case "function":
			case "symbol":
				return this.failure(
					"unavailable",
					`Tool output contains unsupported ${typeof current} data`,
				);
			default:
				return this.visitObject(current as object, depth);
		}
	}

	private visitObject(current: object, depth: number): SerializationFailure | undefined {
		if (current instanceof Date) return this.append(current.toISOString());
		if (isOpaqueBinaryContent(current)) {
			return this.failure(
				"unavailable",
				"Opaque binary tool output requires a host-specific decoder before inspection",
			);
		}
		if (this.seen.has(current)) {
			return this.failure("unavailable", "Tool output contains a circular reference");
		}

		this.seen.add(current);
		try {
			if (Array.isArray(current)) {
				let mcpTextRun: string[] = [];
				const flushMcpTextRun = () => {
					const failure = this.appendMcpTextRun(mcpTextRun);
					mcpTextRun = [];
					return failure;
				};
				for (let index = 0; index < current.length; index += 1) {
					const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
					if (!descriptor || !("value" in descriptor)) {
						return this.failure("unavailable", "Tool output array contains unreadable data");
					}
					const mcpText = mcpTextBlockText(descriptor.value);
					if (mcpText === undefined) {
						const failure = flushMcpTextRun();
						if (failure) return failure;
					} else {
						mcpTextRun.push(mcpText);
					}
					const next = Object.getOwnPropertyDescriptor(current, String(index + 1));
					const joinsNextString =
						typeof descriptor.value === "string" && typeof next?.value === "string";
					const entryFailure = this.visitEntry("", descriptor.value, depth, !joinsNextString);
					if (entryFailure) return entryFailure;
				}
				const failure = flushMcpTextRun();
				if (failure) return failure;
				return undefined;
			}

			const prototype = Object.getPrototypeOf(current);
			let hasEntries = false;
			for (const key in current) {
				if (!Object.prototype.hasOwnProperty.call(current, key)) continue;
				hasEntries = true;
				const descriptor = Object.getOwnPropertyDescriptor(current, key);
				if (!descriptor || !("value" in descriptor)) {
					return this.failure("unavailable", "Tool output contains unreadable data");
				}
				const entryFailure = this.visitEntry(key, descriptor.value, depth);
				if (entryFailure) return entryFailure;
			}
			if (!hasEntries && prototype !== Object.prototype && prototype !== null) {
				return this.failure(
					"unavailable",
					"Tool output type requires a host-specific text decoder before inspection",
				);
			}
			return undefined;
		} catch (error) {
			return this.failure(
				"unavailable",
				`Tool output could not be read for inspection: ${error instanceof Error ? error.message : String(error)}`,
			);
		} finally {
			this.seen.delete(current);
		}
	}

	private visitEntry(
		key: string,
		entry: unknown,
		depth: number,
		appendSeparator = true,
	): SerializationFailure | undefined {
		if (key) {
			const keyFailure = this.append(`${key}=`);
			if (keyFailure) return keyFailure;
		}
		const valueFailure = this.visit(entry, depth + 1);
		if (valueFailure) return valueFailure;
		return appendSeparator ? this.append("\n") : undefined;
	}
}

function serializeBounded(value: unknown, maxBytes: number): SerializationResult {
	return new BoundedOutputSerializer(maxBytes).serialize(value);
}

/** Inspect a complete tool/framework result using the core output scanner. */
export function scanToolOutput(
	output: unknown,
	options: Pick<ToolOutputGuardOptions, "maxBytes"> = {},
): ToolOutputInspection {
	const maxBytes = validateMaxBytes(options.maxBytes);
	let serialized: SerializationResult;
	try {
		serialized = serializeBounded(output, maxBytes);
	} catch (error) {
		return {
			status: "unavailable",
			findings: [],
			inspectedBytes: 0,
			maxBytes,
			reason: `Tool output could not be read for inspection: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	if (!serialized.ok) {
		return {
			status: serialized.status,
			findings: [],
			inspectedBytes: serialized.bytes,
			maxBytes,
			reason: serialized.reason,
		};
	}

	try {
		const byRule = new Map<string, ToolOutputFinding>();
		for (const view of [serialized.text, serialized.mcpText]) {
			for (const finding of scanModelOutput(view)) {
				if (!byRule.has(finding.ruleId)) byRule.set(finding.ruleId, finding);
			}
		}
		const findings = [...byRule.values()];
		return {
			status: findings.length > 0 ? "findings" : "clean",
			findings,
			inspectedBytes: serialized.bytes,
			maxBytes,
			...(findings.length > 0
				? { reason: `Tool output matched ${findings.length} output security rule(s)` }
				: {}),
		};
	} catch (error) {
		return {
			status: "unavailable",
			findings: [],
			inspectedBytes: serialized.bytes,
			maxBytes,
			reason: `Tool output scanner is unavailable: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
}

/**
 * Inspect and choose whether the original result, a safe marker, or no result
 * may be delivered. Unsafe states are fail-closed by default.
 */
export function guardToolOutput<T>(
	output: T,
	options: ToolOutputGuardOptions = {},
): ToolOutputGuardResult<T> {
	const inspection = scanToolOutput(output, options);
	if (inspection.status === "clean") {
		return { inspection, delivery: "allow", output };
	}

	const delivery =
		inspection.status === "findings"
			? (options.findingAction ?? "block")
			: inspection.status === "oversize"
				? (options.oversizeAction ?? "block")
				: (options.unavailableAction ?? "block");

	if (delivery === "redact") {
		return {
			inspection,
			delivery,
			output: `[AIDR REDACTED: ${inspection.status}]`,
		};
	}
	return { inspection, delivery: "block" };
}

/** Inspect and return the deliverable output, or throw before model consumption. */
export function enforceToolOutput<T>(output: T, options: ToolOutputGuardOptions = {}): T | string {
	const result = guardToolOutput(output, options);
	if (result.delivery === "block") throw new AIDRToolOutputError(result.inspection);
	return result.output as T | string;
}

export function formatToolOutputBlockReason(inspection: ToolOutputInspection): string {
	if (inspection.status === "findings") {
		const rules = inspection.findings.map((finding) => finding.ruleId).join(", ");
		return `AIDR blocked tool output before model consumption (${rules})`;
	}
	return `AIDR blocked tool output before model consumption: ${inspection.reason ?? inspection.status}`;
}
