/**
 * CON-7: AIDR_THREATS_DIR / AIDR_ALLOWLISTS_DIR used to put any directory ahead
 * of the bundled rules in every build, silently. A commercial build now ignores
 * the override (and says so); a development build still honours it, but never
 * without a warning.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { assetOverrideNotice, resolveAssetDir } from "../assets.js";

const KEYS = ["AIDR_THREATS_DIR", "AIDR_ALLOWLISTS_DIR", "AIDR_COMMERCIAL"] as const;
const saved: Partial<Record<(typeof KEYS)[number], string | undefined>> = {};
let benignRules: string;

beforeEach(async () => {
	for (const key of KEYS) {
		saved[key] = process.env[key];
		delete process.env[key];
	}
	// The audit reproduction: one harmless rule instead of the shipped set.
	benignRules = await mkdtemp(join(tmpdir(), "aidr-benign-rules-"));
	await writeFile(
		join(benignRules, "only.yaml"),
		'- id: "X-1"\n  category: x\n  severity: low\n  confidence: 0.1\n  action: block\n  pattern: "never-matches-anything"\n  match_on: command\n  title: x\n',
	);
});

afterEach(async () => {
	for (const key of KEYS) {
		if (saved[key] === undefined) delete process.env[key];
		else process.env[key] = saved[key];
	}
	await rm(benignRules, { recursive: true, force: true });
});

describe("Claude Code rule directory overrides", () => {
	it("has nothing to report without an override", () => {
		expect(assetOverrideNotice()).toBeNull();
		expect(resolveAssetDir("threats")).not.toBe(benignRules);
	});

	it("ignores AIDR_THREATS_DIR in a commercial build and reports it", () => {
		process.env.AIDR_COMMERCIAL = "1";
		process.env.AIDR_THREATS_DIR = benignRules;
		expect(resolveAssetDir("threats")).not.toBe(benignRules);
		expect(assetOverrideNotice()).toContain(`ignored AIDR_THREATS_DIR=${benignRules}`);
	});

	it("ignores AIDR_ALLOWLISTS_DIR in a commercial build", () => {
		process.env.AIDR_COMMERCIAL = "1";
		process.env.AIDR_ALLOWLISTS_DIR = benignRules;
		expect(resolveAssetDir("allowlists")).not.toBe(benignRules);
		expect(assetOverrideNotice()).toContain("ignored AIDR_ALLOWLISTS_DIR");
	});

	it("honours the override in a development build, with a warning", () => {
		process.env.AIDR_THREATS_DIR = benignRules;
		expect(resolveAssetDir("threats")).toBe(benignRules);
		expect(assetOverrideNotice()).toContain(
			`using threat rules from AIDR_THREATS_DIR=${benignRules}`,
		);
	});
});
