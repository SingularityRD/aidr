import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { evaluateToolCall } from "../evaluator.js";
import { extractFromBash } from "../extractors.js";
import { PackageChecker } from "../package-checker.js";
import type { PackageCheckResult } from "../types.js";

let root: string;
let configPath: string;
let packsDir: string;
const previousEnv = new Map<string, string | undefined>();
const ENV_KEYS = ["HOME", "USERPROFILE", "AIDR_COMMERCIAL", "AIDR_BUILD", "AIDR_BUILD_FLAVOR"];

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-signed-intel-package-"));
	configPath = join(root, "config.json");
	packsDir = join(root, "packs");
	await mkdir(packsDir, { recursive: true });
	for (const key of ENV_KEYS) {
		previousEnv.set(key, process.env[key]);
		if (key === "HOME" || key === "USERPROFILE") process.env[key] = root;
		else delete process.env[key];
	}
});

afterEach(async () => {
	vi.restoreAllMocks();
	for (const key of ENV_KEYS) {
		const value = previousEnv.get(key);
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
	previousEnv.clear();
	await rm(root, { recursive: true, force: true });
});

function packageRequest() {
	const command = "npm install known-good@1.0.0";
	return {
		sessionId: "signed-intel-package-failclosed",
		toolName: "Bash",
		toolInput: { command },
		artifacts: extractFromBash(command),
	};
}

function cleanResult(): PackageCheckResult[] {
	return [
		{
			packageName: "known-good",
			registry: "npm",
			verdict: "clean",
			confidence: 1,
			details: "verified",
		},
	];
}

async function writeConfig(mode: "local" | "managed", packsEnabled: boolean): Promise<void> {
	await writeFile(
		configPath,
		JSON.stringify({
			mode,
			heuristics_enabled: false,
			package_check: { enabled: true },
			intel_packs: {
				enabled: packsEnabled,
				packs_dir: packsDir,
				trusted_keys_path: join(root, "trusted-keys.json"),
				cache_ttl_seconds: 0,
			},
			file_check: { enabled: false },
			url_check: { enabled: false },
			amsi_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
		}),
		"utf8",
	);
}

async function evaluatePackage() {
	return evaluateToolCall(packageRequest(), {
		configPath,
		threatsDir: root,
		allowlistsDir: root,
	});
}

describe("signed intel-pack availability for package checks", () => {
	it("requires review when enabled packs have no available corpus", async () => {
		await writeConfig("local", true);
		const checker = vi.spyOn(PackageChecker.prototype, "checkPackages");

		const verdict = await evaluatePackage();

		expect(checker).not.toHaveBeenCalled();
		expect(verdict).toMatchObject({
			decision: "ask",
			category: "supply_chain",
			source: "package_check",
		});
		expect(verdict.artifacts).toContain("known-good");
		expect(verdict.reasons.join(" ")).toContain("required signed intel packs are unavailable");
	});

	it("requires review when every configured pack is rejected", async () => {
		const rejectedPack = join(packsDir, "rejected", "1.0.0");
		await mkdir(rejectedPack, { recursive: true });
		await writeFile(join(rejectedPack, "active.json"), JSON.stringify({ version: "1.0.0" }));
		await writeFile(join(rejectedPack, "manifest.json"), "{invalid-json");
		await writeFile(join(rejectedPack, "manifest.sig"), "invalid-signature");
		await writeConfig("local", true);
		const checker = vi.spyOn(PackageChecker.prototype, "checkPackages");

		const verdict = await evaluatePackage();

		expect(checker).not.toHaveBeenCalled();
		expect(verdict.decision).toBe("ask");
		expect(verdict.source).toBe("package_check");
		expect(verdict.reasons.join(" ")).toContain("no complete signed intel pack was available");
	});

	it.each([
		{ mode: "local" as const, packsEnabled: false, name: "disabled" },
		{ mode: "managed" as const, packsEnabled: true, name: "unentitled" },
	])("does not treat $name packs as an outage", async ({ mode, packsEnabled }) => {
		await writeConfig(mode, packsEnabled);
		const checker = vi
			.spyOn(PackageChecker.prototype, "checkPackages")
			.mockResolvedValueOnce(cleanResult());

		const verdict = await evaluatePackage();

		expect(checker).toHaveBeenCalledOnce();
		expect(verdict).toMatchObject({ decision: "allow", source: "none" });
	});
});
