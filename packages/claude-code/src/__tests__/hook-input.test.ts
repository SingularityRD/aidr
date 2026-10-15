import { closeSync, mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
	MAX_POST_TOOL_INPUT_BYTES,
	readBoundedJson,
	readBoundedStdin,
	readPostToolStdin,
	resolvePostToolInputLimit,
	toolNameFromInputPrefix,
} from "../hook-input.js";

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

describe("PostToolUse stdin reader (CON-9)", () => {
	function stream(chunks: string[], end = true) {
		const readable = new PassThrough();
		for (const chunk of chunks) readable.write(chunk);
		if (end) readable.end();
		return readable;
	}

	it("parses input within the ceiling", async () => {
		const input = stream(['{"tool_name":"Bash",', '"tool_response":{"stdout":"ok"}}']);
		await expect(readPostToolStdin(1024, input)).resolves.toEqual({
			status: "parsed",
			value: { tool_name: "Bash", tool_response: { stdout: "ok" } },
		});
	});

	it("keeps the input prefix so oversized input still names its tool", async () => {
		const progress = { prefix: "" };
		const input = stream([
			'{"session_id":"s","tool_name":"mcp__a__b",',
			`"x":"${"y".repeat(64)}"}`,
		]);
		await expect(readPostToolStdin(32, input, progress)).resolves.toEqual({ status: "oversized" });
		expect(toolNameFromInputPrefix(progress.prefix)).toBe("mcp__a__b");
	});

	it("exposes the prefix while the input is still incomplete", async () => {
		const progress = { prefix: "" };
		const input = stream(['{"tool_name":"Bash","tool_response":{"stdout":"'], false);
		void readPostToolStdin(1024, input, progress);
		await new Promise((done) => setImmediate(done));
		expect(toolNameFromInputPrefix(progress.prefix)).toBe("Bash");
	});

	it("does not take a tool name from an escaped string value", () => {
		expect(toolNameFromInputPrefix('{"cwd":"\\"tool_name\\":\\"Bash\\""')).toBeUndefined();
		expect(toolNameFromInputPrefix('{"tool_name":"Bash\\u0041"}')).toBe("BashA");
	});

	it("bounds the configurable input ceiling", () => {
		expect(resolvePostToolInputLimit({})).toBe(MAX_POST_TOOL_INPUT_BYTES);
		expect(resolvePostToolInputLimit({ AIDR_POST_TOOL_USE_MAX_INPUT_BYTES: "2097152" })).toBe(
			2_097_152,
		);
		// Below the floor, above the cap or not an integer: the default.
		for (const value of ["1024", String(128 * 1024 * 1024), "16MiB"]) {
			expect(resolvePostToolInputLimit({ AIDR_POST_TOOL_USE_MAX_INPUT_BYTES: value })).toBe(
				MAX_POST_TOOL_INPUT_BYTES,
			);
		}
	});
});
