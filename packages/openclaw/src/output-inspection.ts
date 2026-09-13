import { scanModelOutput } from "@singularityrd/aidr-core";

/**
 * Keep inspection CPU and memory work bounded even when a tool returns a huge
 * or adversarial object. The value is intentionally aligned with the existing
 * Claude Code output-inspection ceiling.
 */
export const OUTPUT_INSPECTION_MAX_CHARS = 256 * 1024;
const OUTPUT_INSPECTION_MAX_NODES = 8_192;
const OUTPUT_INSPECTION_MAX_DEPTH = 20;

export type OutputInspectionSurface = "tool_output" | "model_response";

export interface SafeOutputFinding {
	ruleId: string;
	reason: string;
	severity: "high" | "critical";
}

export interface OutputInspection {
	surface: OutputInspectionSurface;
	findings: SafeOutputFinding[];
	incomplete: boolean;
	inspectedChars: number;
	limitChars: number;
}

interface TextCollection {
	text: string;
	incomplete: boolean;
}

class BoundedTextCollector {
	private readonly chunks: string[] = [];
	private readonly seen = new WeakSet<object>();
	private length = 0;
	private nodes = 0;
	private incomplete = false;

	collect(value: unknown): TextCollection {
		this.visit(value, 0);
		return { text: this.chunks.join(""), incomplete: this.incomplete };
	}

	private append(text: string): void {
		if (!text) return;
		const remaining = OUTPUT_INSPECTION_MAX_CHARS - this.length;
		if (remaining <= 0) {
			this.incomplete = true;
			return;
		}

		const separator = this.length > 0 ? "\n" : "";
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

	private visit(current: unknown, depth: number): void {
		if (this.length >= OUTPUT_INSPECTION_MAX_CHARS) {
			this.incomplete = true;
			return;
		}
		if (this.nodes >= OUTPUT_INSPECTION_MAX_NODES) {
			this.incomplete = true;
			return;
		}
		this.nodes += 1;

		if (this.visitPrimitive(current)) return;
		if (current === null || typeof current !== "object") return;
		this.visitObject(current, depth);
	}

	private visitPrimitive(current: unknown): boolean {
		if (typeof current === "string") {
			this.append(current);
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
		if (depth >= OUTPUT_INSPECTION_MAX_DEPTH) {
			this.incomplete = true;
			return;
		}
		if (this.seen.has(current)) return;
		this.seen.add(current);

		if (current instanceof Uint8Array || current instanceof ArrayBuffer) {
			// Binary payloads are not model-visible text. Do not expand every byte.
			return;
		}

		if (Array.isArray(current)) {
			this.visitArray(current, depth);
			return;
		}
		this.visitRecord(current, depth);
	}

	private exhausted(): boolean {
		return this.nodes >= OUTPUT_INSPECTION_MAX_NODES || this.length >= OUTPUT_INSPECTION_MAX_CHARS;
	}

	private visitArray(current: unknown[], depth: number): void {
		for (let index = 0; index < current.length; index += 1) {
			if (this.exhausted()) {
				this.incomplete = true;
				break;
			}
			this.visit(current[index], depth + 1);
		}
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
): OutputInspection {
	const collection = collectBoundedText(value);
	const findings = scanModelOutput(collection.text).map((finding) => ({
		ruleId: finding.ruleId,
		reason: finding.reason,
		severity: finding.severity,
	}));

	return {
		surface,
		findings,
		incomplete: collection.incomplete,
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
		inspection.incomplete ? `inspection limit ${inspection.limitChars} characters reached` : null,
	].filter((part): part is string => part !== null);
	return parts.join("; ");
}
