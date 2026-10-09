import { closeSync, mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { readBoundedJson, readBoundedStdin } from "../hook-input.js";

const TEST_DIR = mkdtempSync(join(tmpdir(), "aidr-post-tool-input-"));
const INPUT_PATH = join(TEST_DIR, "stdin.json");

afterAll(() => {
	rmSync(TEST_DIR, { recursive: true, force: true });
});

function readInput(input: string, limit: number): string | null {
	writeFileSync(INPUT_PATH, input);
	const fd = openSync(INPUT_PATH, "r");
	try {
		return readBoundedStdin(fd, limit);
	} finally {
		closeSync(fd);
	}
}

function readJsonInput<T>(input: string, limit: number, parse: (text: string) => T) {
	writeFileSync(INPUT_PATH, input);
	const fd = openSync(INPUT_PATH, "r");
	try {
		return readBoundedJson(fd, limit, parse);
	} finally {
		closeSync(fd);
	}
}

describe("bounded PostToolUse input", () => {
	it("accepts input at the byte limit", () => {
		expect(readInput("safe", 4)).toBe("safe");
	});

	it("stops after detecting one byte beyond the limit", () => {
		expect(readInput("unsafe", 4)).toBeNull();
	});

	it("does not invoke JSON parsing after detecting oversized input", () => {
		const parse = vi.fn((text: string) => JSON.parse(text));
		expect(readJsonInput('{"tool_response":"unsafe"}', 8, parse)).toEqual({ status: "oversized" });
		expect(parse).not.toHaveBeenCalled();
	});
});

describe("strict UTF-8 hook input", () => {
	function readBytes(bytes: Buffer): string | null {
		writeFileSync(INPUT_PATH, bytes);
		const fd = openSync(INPUT_PATH, "r");
		try {
			return readBoundedStdin(fd, 1024);
		} finally {
			closeSync(fd);
		}
	}

	it("accepts a validly encoded U+FFFD", () => {
		expect(readBytes(Buffer.from('{"command":"echo �"}', "utf8"))).toBe('{"command":"echo �"}');
	});

	it("throws on undecodable bytes instead of substituting U+FFFD", () => {
		const invalid = Buffer.concat([
			Buffer.from('{"command":"echo '),
			Buffer.from([0xff, 0xfe]),
			Buffer.from('"}'),
		]);
		expect(() => readBytes(invalid)).toThrow(TypeError);
	});
});
