import { describe, expect, it } from "vitest";
import { generateApiKey, hashToolCall } from "../utils/crypto.js";
import {
	loadBundledThreatCount,
	resolveBundledDataDirs,
	verifyDetection,
} from "../utils/test-protection.js";

/**
 * The CLI previously had zero tests, which is how it shipped reporting a
 * hardcoded rule count ("150 rules active") while loading zero rules, claiming a
 * non-functional hook install had succeeded, and generating credentials from
 * Math.random(). These tests pin the corrected behaviour.
 */

describe("CLI bundled detection data", () => {
	it("ships threat rules with the package", () => {
		const { threatsDir } = resolveBundledDataDirs();
		expect(threatsDir).toContain("resources");
		expect(threatsDir).toContain("threats");
	});

	it("loads a non-zero number of real threat rules", async () => {
		const count = await loadBundledThreatCount();
		// The reported count must be the real loaded count, not a constant.
		expect(count).toBeGreaterThan(0);
	});

	it("reports the loaded rule count consistently across calls", async () => {
		const first = await loadBundledThreatCount();
		const second = await loadBundledThreatCount();
		expect(first).toBe(second);
	});

	it("verifies detection by matching a known-malicious probe", async () => {
		const result = await verifyDetection();
		expect(result.ok).toBe(true);
		expect(result.detail).toMatch(/\d+ rules, probe matched \d+/);
	});

	it("self-test detail contains the real rule count, not a hardcoded value", async () => {
		const count = await loadBundledThreatCount();
		const result = await verifyDetection();
		expect(result.detail).toContain(String(count));
	});
});

describe("CLI credential generation", () => {
	it("produces a prefixed key", () => {
		expect(generateApiKey()).toMatch(/^aidr_[A-Za-z0-9_-]+$/);
	});

	it("produces unique keys", () => {
		const keys = new Set(Array.from({ length: 50 }, () => generateApiKey()));
		expect(keys.size).toBe(50);
	});

	it("uses a cryptographically secure source rather than Math.random", () => {
		// Math.random-derived keys are ~13 base36 chars of entropy; CSPRNG keys
		// from 32 bytes are far longer and high-entropy. Assert the entropy shape
		// so a regression back to Math.random fails here.
		const key = generateApiKey();
		const body = key.slice("aidr_".length);
		expect(body.length).toBeGreaterThanOrEqual(40);

		const distinct = new Set(body.split(""));
		expect(distinct.size).toBeGreaterThan(12);
	});

	it("does not derive the key from Math.random output", () => {
		// Pin Math.random to a constant; a CSPRNG-based key must be unaffected.
		const original = Math.random;
		try {
			Math.random = () => 0.42;
			const a = generateApiKey();
			const b = generateApiKey();
			expect(a).not.toBe(b);
		} finally {
			Math.random = original;
		}
	});

	it("hashes tool calls deterministically to 16 hex characters", () => {
		const first = hashToolCall("Bash", { command: "echo hi" });
		const second = hashToolCall("Bash", { command: "echo hi" });
		expect(first).toBe(second);
		expect(first).toMatch(/^[a-f0-9]{16}$/);
	});
});
