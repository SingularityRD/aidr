import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import {
	createHookResponder,
	EXIT_FLUSH_BACKSTOP_MS,
	HOOK_HOST_TIMEOUT_MS,
	hasMalformedCommandText,
	isValidUtf8,
	isWellFormedToolCall,
	malformedShellCommandReason,
	readBoundedStdinAsync,
	resolveHookDeadlineMs,
	withHookDeadline,
} from "../hook-deadline.js";

const spec = { envVar: "AIDR_TEST_DEADLINE_MS", hostTimeoutMs: 10_000, defaultMs: 8_000 };

describe("resolveHookDeadlineMs", () => {
	it.each([
		[undefined, 8_000],
		["2500", 2_500],
		["100", 100],
		["9000", 9_000],
		["9001", 8_000],
		["99", 8_000],
		["1.5", 8_000],
		["-1", 8_000],
		["abc", 8_000],
	])("resolves %j to %d ms, never past the host timeout minus headroom", (value, expected) => {
		expect(resolveHookDeadlineMs(spec, { AIDR_TEST_DEADLINE_MS: value })).toBe(expected);
	});

	it("caps a default that does not leave headroom", () => {
		expect(resolveHookDeadlineMs({ ...spec, defaultMs: 20_000 })).toBe(9_000);
	});

	it("documents each host budget", () => {
		expect(HOOK_HOST_TIMEOUT_MS).toEqual({
			claudeCode: 15_000,
			codex: 10_000,
			cursor: 30_000,
			vscode: 30_000,
		});
	});
});

function io() {
	const written: string[] = [];
	const exit = vi.fn();
	return {
		written,
		exit,
		io: {
			writeStdout: (text: string, done: () => void) => {
				written.push(text);
				done();
			},
			writeStderr: vi.fn(),
			exit,
		},
	};
}

describe("createHookResponder", () => {
	it("writes the caller's answer once and exits after the flush", async () => {
		const t = io();
		const responder = createHookResponder({
			deadlineMs: 50,
			onDeadline: () => ({ stdout: "deny\n" }),
			io: t.io,
		});
		expect(responder.answer({ stdout: "allow\n" })).toBe(true);
		expect(responder.answer({ stdout: "second\n" })).toBe(false);
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(t.written).toEqual(["allow\n"]);
		expect(t.exit).toHaveBeenCalledOnce();
		expect(t.exit).toHaveBeenCalledWith(0);
	});

	it("writes the deadline block when the caller is late and drops the late answer", async () => {
		const t = io();
		const responder = createHookResponder({
			deadlineMs: 20,
			onDeadline: () => ({ stdout: "deny\n", stderr: "late", exitCode: 2 }),
			io: t.io,
		});
		await new Promise((resolve) => setTimeout(resolve, 60));
		expect(responder.answered).toBe(true);
		expect(responder.answer({ stdout: "allow\n" })).toBe(false);
		expect(t.written).toEqual(["deny\n"]);
		expect(t.io.writeStderr).toHaveBeenCalledWith("late\n");
		expect(t.exit).toHaveBeenCalledWith(2);
	});

	it("exits once via the backstop when the stdout flush never completes", async () => {
		const t = io();
		const responder = createHookResponder({
			deadlineMs: 5_000,
			onDeadline: () => ({ stdout: "deny\n" }),
			io: { ...t.io, writeStdout: () => {} },
		});
		responder.answer({ stdout: "allow\n", exitCode: 0 });
		await new Promise((resolve) => setTimeout(resolve, EXIT_FLUSH_BACKSTOP_MS + 100));
		expect(t.exit).toHaveBeenCalledOnce();
		expect(t.exit).toHaveBeenCalledWith(0);
	});

	it("still exits (fail closed via exit code) when the deadline answer throws", async () => {
		const t = io();
		createHookResponder({
			deadlineMs: 10,
			onDeadline: () => {
				throw new Error("boom");
			},
			io: t.io,
		});
		await new Promise((resolve) => setTimeout(resolve, 40));
		expect(t.exit).toHaveBeenCalledWith(2);
	});
});

describe("withHookDeadline", () => {
	it("returns the work's result when it is in time", async () => {
		await expect(withHookDeadline(Promise.resolve("ok"), 50, () => "late")).resolves.toBe("ok");
	});

	it("returns the timeout result for hung work", async () => {
		await expect(withHookDeadline(new Promise(() => {}), 20, () => "blocked")).resolves.toBe(
			"blocked",
		);
	});

	it("propagates a rejection unchanged", async () => {
		await expect(
			withHookDeadline(Promise.reject(new Error("x")), 50, () => "late"),
		).rejects.toThrow("x");
	});
});

describe("readBoundedStdinAsync", () => {
	it("reads the whole stream", async () => {
		const stream = new PassThrough();
		const read = readBoundedStdinAsync(1024, stream);
		stream.end(Buffer.from('{"a":1}'));
		await expect(read).resolves.toEqual({ status: "read", bytes: Buffer.from('{"a":1}') });
	});

	it("reports oversized input without waiting for the end of the stream", async () => {
		const stream = new PassThrough();
		const read = readBoundedStdinAsync(4, stream);
		stream.write(Buffer.from("12345"));
		await expect(read).resolves.toEqual({ status: "oversized" });
	});

	it("does not block the event loop while stdin stays open", async () => {
		const stream = new PassThrough();
		const read = readBoundedStdinAsync(1024, stream);
		stream.write("{");
		const winner = await Promise.race([
			read.then(() => "read"),
			new Promise((resolve) => setTimeout(() => resolve("timer"), 20)),
		]);
		expect(winner).toBe("timer");
		stream.destroy();
	});
});

describe("input hygiene", () => {
	it.each([
		["rm -rf /\u0000", true],
		["echo \ud800", true],
		["echo \udc00x", true],
		["echo �", true],
		["echo 😀", false],
		["git status", false],
	])("hasMalformedCommandText(%j) is %s", (command, expected) => {
		expect(hasMalformedCommandText(command)).toBe(expected);
	});

	it("validates UTF-8 strictly", () => {
		expect(isValidUtf8(Buffer.from("héllo"))).toBe(true);
		expect(isValidUtf8(Buffer.from([0x7b, 0xff, 0x7d]))).toBe(false);
	});

	it.each([
		["Bash", {}, true],
		["Bash", null, false],
		["Bash", undefined, false],
		["Bash", "ls", false],
		["Bash", ["ls"], false],
		["", {}, false],
		[42, {}, false],
	])("isWellFormedToolCall(%j, %j) is %s", (name, input, expected) => {
		expect(isWellFormedToolCall(name, input)).toBe(expected);
	});

	it("flags malformed shell commands only for shell tools", () => {
		expect(malformedShellCommandReason("Bash", { command: "ls" })).toBeNull();
		expect(malformedShellCommandReason("exec", { command: ["bash", "-lc", "ls"] })).toBeNull();
		expect(malformedShellCommandReason("Bash", { command: 42 })).toMatch(/neither a string/);
		expect(malformedShellCommandReason("shell", { command: ["ls", 1] })).toMatch(/neither/);
		expect(malformedShellCommandReason("Shell", { command: "ls\u0000" })).toMatch(/NUL/);
		expect(malformedShellCommandReason("bash", { cmd: "ls \ud800" })).toMatch(/NUL/);
		expect(malformedShellCommandReason("Read", { command: "\u0000" })).toBeNull();
	});
});
