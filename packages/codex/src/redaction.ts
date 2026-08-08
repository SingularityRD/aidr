import { type RedactedValue, sha256 } from "./types.js";

const MAX_DEPTH = 8;
const MAX_STRING_BYTES = 4096;
const SENSITIVE_KEY =
	/(?:api[_-]?key|authorization|bearer|cookie|credential|password|passwd|private[_-]?key|secret|token)/i;
const SECRET_VALUE =
	/(?:bearer\s+[a-z0-9._~+/=-]{12,}|(?:sk|rk|gh[pousr]|xox[baprs])-[a-z0-9_-]{8,}|-----begin [a-z ]+-----|eyj[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+)/gi;

export function redactString(value: string): string {
	const bounded = value.length > MAX_STRING_BYTES ? `${value.slice(0, MAX_STRING_BYTES)}…` : value;
	return bounded.replace(SECRET_VALUE, (match) => `[REDACTED:${sha256(match).slice(0, 16)}]`);
}
export function redactValue(value: unknown, depth = 0): RedactedValue {
	if (depth > MAX_DEPTH) return "[REDACTED:depth-limit]";
	if (value === null || typeof value === "boolean" || typeof value === "number") return value;
	if (typeof value === "string") return redactString(value);
	if (Array.isArray(value)) return value.slice(0, 128).map((item) => redactValue(item, depth + 1));
	if (typeof value !== "object") return "[REDACTED:unsupported-value]";
	const output: Record<string, RedactedValue> = {};
	for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 128)) {
		output[key] = SENSITIVE_KEY.test(key)
			? `[REDACTED:${sha256(JSON.stringify(child) ?? "null").slice(0, 16)}]`
			: redactValue(child, depth + 1);
	}
	return output;
}
export function redactRecord(value: Record<string, unknown>): Record<string, RedactedValue> {
	return redactValue(value) as Record<string, RedactedValue>;
}
