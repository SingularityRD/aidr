import { readSync } from "node:fs";

export const MAX_POST_TOOL_INPUT_BYTES = 1024 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;

/** Read at most the configured limit plus one byte so oversized hook input is detectable. */
export function readBoundedStdin(fd = 0, maxBytes = MAX_POST_TOOL_INPUT_BYTES): string | null {
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
		throw new RangeError("maxBytes must be a non-negative safe integer");
	}
	const chunks: Buffer[] = [];
	const buffer = Buffer.alloc(READ_CHUNK_BYTES);
	let total = 0;

	while (true) {
		const length = Math.min(buffer.length, maxBytes + 1 - total);
		const read = readSync(fd, buffer, 0, length, null);
		if (read === 0) return Buffer.concat(chunks, total).toString("utf8");
		total += read;
		if (total > maxBytes) return null;
		chunks.push(Buffer.from(buffer.subarray(0, read)));
	}
}

export type BoundedJsonResult<T> =
	| { status: "parsed"; value: T }
	| { status: "oversized" }
	| { status: "invalid" };

/** Do not parse unbounded hook input: the byte ceiling is checked first. */
export function readBoundedJson<T = unknown>(
	fd = 0,
	maxBytes = MAX_POST_TOOL_INPUT_BYTES,
	parse: (text: string) => T = JSON.parse,
): BoundedJsonResult<T> {
	const text = readBoundedStdin(fd, maxBytes);
	if (text === null) return { status: "oversized" };
	try {
		return { status: "parsed", value: parse(text) };
	} catch {
		return { status: "invalid" };
	}
}
