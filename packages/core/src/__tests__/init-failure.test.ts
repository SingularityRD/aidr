import { describe, expect, it } from "vitest";
import { formatInitFailureMessage, initFailureCode } from "../init-failure.js";
import { ArtifactIntegrityError } from "../integrity/runtime.js";

describe("connector initialisation failure", () => {
	it("derives a code from an integrity failure status", () => {
		expect(initFailureCode(new ArtifactIntegrityError("x/dist", { status: "hash_mismatch" }))).toBe(
			"integrity_hash_mismatch",
		);
	});

	it("prefers an errno-style code, then a specific error name", () => {
		expect(initFailureCode(Object.assign(new Error("boom"), { code: "EACCES" }))).toBe("EACCES");
		expect(initFailureCode(new TypeError("x is not a function"))).toBe("TypeError");
	});

	it("never leaks the raw error message", () => {
		const secret = "/home/alice/.ssh/id_rsa token=abc";
		expect(initFailureCode(new Error(secret))).toBe("init_error");
		expect(initFailureCode(secret)).toBe("init_error");
		expect(initFailureCode(undefined)).toBe("init_error");
		expect(initFailureCode({ code: "bad code; rm -rf /" })).toBe("bad_code_rm_-rf");
	});

	it("formats the block reason shown for every tool call", () => {
		expect(formatInitFailureMessage("ENOENT")).toBe(
			"AIDR failed to initialise: ENOENT; tool calls are blocked until fixed",
		);
		expect(formatInitFailureMessage("")).toBe(
			"AIDR failed to initialise: init_error; tool calls are blocked until fixed",
		);
	});
});
