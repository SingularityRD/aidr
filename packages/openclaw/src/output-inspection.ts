import { types } from "node:util";
import { scanCachedProvisionedOutput, scanModelOutput } from "@singularityrd/aidr-core";

/**
 * Keep inspection CPU and memory work bounded even when a tool returns a huge
 * or adversarial object. The value is intentionally aligned with the existing
 * Claude Code output-inspection ceiling.
 */
export const OUTPUT_INSPECTION_MAX_CHARS = 256 * 1024;
const OUTPUT_INSPECTION_MAX_NODES = 8_192;
const OUTPUT_INSPECTION_MAX_DEPTH = 20;
const OPAQUE_CONTENT_TYPES = new Set([
	"image",
	"audio",
	"video",
	"file",
	"binary",
	"resource",
	"resource_link",
]);

export type OutputInspectionSurface = "tool_output" | "model_response";

interface SafeOutputFinding {
	ruleId: string;
	reason: string;
	severity: "high" | "critical";
}

export interface OutputInspection {
	surface: OutputInspectionSurface;
	findings: SafeOutputFinding[];
	incomplete: boolean;
	unsupportedContent: boolean;
	inspectedChars: number;
	limitChars: number;
}

interface TextCollection {
	text: string;
	incomplete: boolean;
	unsupportedContent: boolean;
	mcpText: string;
}

class BoundedTextCollector {
	private readonly chunks: string[] = [];
	private readonly mcpTextRuns: string[] = [];
	private readonly seen = new WeakSet<object>();
	private length = 0;
	private mcpTextLength = 0;
	private nodes = 0;
	private incomplete = false;
	private unsupportedContent = false;

	collect(value: unknown): TextCollection {
		this.visit(value, 0);
		return {
			text: this.chunks.join(""),
			incomplete: this.incomplete,
			unsupportedContent: this.unsupportedContent,
			mcpText: this.mcpTextRuns.join("\n"),
		};
	}

	private append(text: string, separate = true): void {
		if (!text) return;
		const remaining = OUTPUT_INSPECTION_MAX_CHARS - this.length;
		if (remaining <= 0) {
			this.incomplete = true;
			return;
		}

		const separator = separate && this.length > 0 ? "\n" : "";
		if (separator) {
			this.chunks.push(separator);
			this.length += separator.length;
		}

		const afterSeparator = OUTPUT_INSPECTION_MAX_CHARS - this.length;
		if (text.length > afterSeparator) {
			this.chunks.push(text.slice(0, afterSeparator));
			this.length += afterSeparator;
			this.incomplete = true;
			return;
		}
		this.chunks.push(text);
		this.length += text.length;
	}

	private visit(current: unknown, depth: number, separate = true): void {
		if (this.length >= OUTPUT_INSPECTION_MAX_CHARS) {
			this.incomplete = true;
			return;
		}
		if (this.nodes >= OUTPUT_INSPECTION_MAX_NODES) {
			this.incomplete = true;
			return;
		}
		this.nodes += 1;

		if (this.visitPrimitive(current, separate)) return;
		if (current === null || typeof current !== "object") return;
		this.visitObject(current, depth);
	}

	private visitPrimitive(current: unknown, separate: boolean): boolean {
		if (typeof current === "string") {
			this.append(current, separate);
			return true;
		}
		if (
			typeof current === "number" ||
			typeof current === "bigint" ||
			typeof current === "boolean"
		) {
			this.append(String(current));
			return true;
		}
		return current === null || (typeof current !== "object" && typeof current !== "function");
	}

	private visitObject(current: object, depth: number): void {
		if (types.isProxy(current)) {
			// Proxy descriptors can conceal different host-visible/serialized text.
			this.markUnsupportedContent();
			return;
		}
		if (depth >= OUTPUT_INSPECTION_MAX_DEPTH) {
			this.incomplete = true;
			return;
		}
		if (this.seen.has(current)) return;
		this.seen.add(current);
		const prototype = Object.getPrototypeOf(current);
		if (
			(Array.isArray(current)
				? prototype !== Array.prototype
				: prototype !== Object.prototype && prototype !== null) ||
			Object.getOwnPropertyDescriptor(current, "toJSON")
		) {
			this.markUnsupportedContent();
			return;
		}

		const type = Object.getOwnPropertyDescriptor(current, "type");
		if (
			ArrayBuffer.isView(current) ||
			current instanceof ArrayBuffer ||
			(typeof Blob !== "undefined" && current instanceof Blob) ||
			(type &&
				"value" in type &&
				typeof type.value === "string" &&
				OPAQUE_CONTENT_TYPES.has(type.value.toLowerCase())) ||
			Object.hasOwn(current, "blob")
		) {
			this.markUnsupportedContent();
			return;
		}

		if (Array.isArray(current)) {
			this.visitArray(current, depth);
			return;
		}
		this.visitRecord(current, depth);
	}

	private markUnsupportedContent(): void {
		// Opaque bytes and custom-serialized values cannot be inspected as text.
		// Callers take the existing fail-closed path.
		this.incomplete = true;
		this.unsupportedContent = true;
	}

	private exhausted(): boolean {
		return this.nodes >= OUTPUT_INSPECTION_MAX_NODES || this.length >= OUTPUT_INSPECTION_MAX_CHARS;
	}

	private visitArray(current: unknown[], depth: number): void {
		let mcpTextRun: string[] = [];
		const flushMcpTextRun = () => {
			if (mcpTextRun.length === 0) return;
			const text = mcpTextRun.join("");
			if (this.mcpTextLength + text.length > OUTPUT_INSPECTION_MAX_CHARS) {
				this.incomplete = true;
				mcpTextRun = [];
				return;
			}
			this.mcpTextRuns.push(text);
			this.mcpTextLength += text.length;
			mcpTextRun = [];
		};
		let previousWasString = false;
		for (let index = 0; index < current.length; index += 1) {
			if (this.exhausted()) {
				this.incomplete = true;
				break;
			}
			const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
			if (!descriptor || !("value" in descriptor)) {
				this.incomplete = true;
				return;
			}
			const value = descriptor.value;
			const blockText = mcpTextBlockText(value);
			if (blockText === undefined) flushMcpTextRun();
			else mcpTextRun.push(blockText);
			const isString = typeof value === "string";
			this.visit(value, depth + 1, !(previousWasString && isString));
			previousWasString = isString;
		}
		flushMcpTextRun();
	}

	private visitRecord(current: object, depth: number): void {
		// for..in lets us stop before enumerating an adversarially wide object.
		for (const key in current) {
			if (!Object.hasOwn(current, key)) continue;
			if (this.exhausted()) {
				this.incomplete = true;
				break;
			}
			this.append(key);
			const descriptor = Object.getOwnPropertyDescriptor(current, key);
			if (!descriptor || !("value" in descriptor)) {
				// Accessors are intentionally not executed. Their content is uninspected.
				this.incomplete = true;
				continue;
			}
			this.visit(descriptor.value, depth + 1);
		}
	}
}

function mcpTextBlockText(value: unknown): string | undefined {
	if (value === null || typeof value !== "object" || types.isProxy(value) || Array.isArray(value))
		return undefined;
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

/**
 * Collect only primitive text from an unknown hook payload. This deliberately
 * avoids JSON.stringify/toJSON and property getters: hook results are untrusted
 * and neither should be allowed to execute code inside the Gateway process.
 */
function collectBoundedText(value: unknown): TextCollection {
	return new BoundedTextCollector().collect(value);
}

export function inspectBoundedOutput(
	value: unknown,
	surface: OutputInspectionSurface,
	scan: (views: readonly string[]) => ReturnType<typeof scanModelOutput> = (views) =>
		views.flatMap(scanModelOutput),
): OutputInspection {
	const collection = collectBoundedText(value);
	return summarizeInspection(collection, surface, scan([collection.text, collection.mcpText]));
}

/** The host's persistence hook cannot await policy or entitlement reads. */
export function inspectCachedProvisionedBoundedOutput(
	value: unknown,
	surface: OutputInspectionSurface,
): OutputInspection {
	return inspectBoundedOutput(value, surface, (views) =>
		scanCachedProvisionedOutput(views, "openclaw"),
	);
}

function summarizeInspection(
	collection: TextCollection,
	surface: OutputInspectionSurface,
	scanned: ReturnType<typeof scanModelOutput>,
): OutputInspection {
	const findingsByRule = new Map<string, SafeOutputFinding>();
	for (const finding of scanned) {
		if (!findingsByRule.has(finding.ruleId)) {
			findingsByRule.set(finding.ruleId, {
				ruleId: finding.ruleId,
				reason: finding.reason,
				severity: finding.severity,
			});
		}
	}
	const findings = [...findingsByRule.values()];

	return {
		surface,
		findings,
		incomplete: collection.incomplete,
		unsupportedContent: collection.unsupportedContent,
		inspectedChars: collection.text.length,
		limitChars: OUTPUT_INSPECTION_MAX_CHARS,
	};
}

export function requiresOutputProtection(inspection: OutputInspection): boolean {
	return inspection.incomplete || inspection.findings.length > 0;
}

/** Safe metadata only: never repeat excerpts or original output. */
export function outputInspectionSummary(inspection: OutputInspection): string {
	const rules = inspection.findings.map((finding) => finding.ruleId).join(", ");
	const parts = [
		inspection.findings.length > 0 ? `rules ${rules}` : null,
		inspection.unsupportedContent ? "unsupported non-text content was not inspected" : null,
		inspection.incomplete && !inspection.unsupportedContent
			? `inspection limit ${inspection.limitChars} characters reached`
			: null,
	].filter((part): part is string => part !== null);
	return parts.join("; ");
}
