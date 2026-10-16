import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	clearRemoteRuntimePolicyCacheForTests,
	inspectRemoteRuntimePolicyCache,
	syncRemoteRuntimePolicy,
} from "../remote-policy.js";
import { runSessionStart } from "../session-start.js";
import { ConfigSchema } from "../types.js";

const originalFetch = globalThis.fetch;
const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = resolve(__dirname, "..", "..", "..", "..", "allowlists");

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe("critical runtime session and control-plane boundaries", () => {
	it("starts a local session without creating an implicit remote authority", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-critical-session-"));
		const configPath = join(root, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({
				mode: "local",
				auth: { api_key: "local-test-key" },
				control_plane: { enabled: false },
				policy: { enabled: true },
				logging: { enabled: false },
			}),
			"utf8",
		);
		try {
			const result = await runSessionStart({
				plugins: [],
				threatsDir: THREATS_DIR,
				allowlistsDir: ALLOWLISTS_DIR,
				version: "critical-test",
				agentRuntime: "claude-code",
				configPath,
				aidrDirPath: root,
			});
			expect(result.enabled).toBe(true);
			expect(result.disabled_reason).toBeUndefined();
			expect(result.scanResults).toEqual([]);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("does not apply malformed remote policy responses", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-critical-policy-response-"));
		const cachePath = join(root, "remote-policy.json");
		clearRemoteRuntimePolicyCacheForTests();
		try {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					ok: true,
					runtime_policy: { command_default: "not-a-policy" },
					policy_sha256: createHash("sha256")
						.update('{"command_default":"not-a-policy"}')
						.digest("hex"),
				}),
			} as unknown as Response);
			const config = ConfigSchema.parse({
				control_plane: {
					enabled: true,
					endpoint: "https://control.example.test",
					remote_policy_cache_enabled: true,
					remote_policy_cache_path: cachePath,
				},
				policy: { enabled: false },
			});
			const result = await syncRemoteRuntimePolicy(config, "critical-token");
			expect(result.policy.runtime_defaults.command_action).not.toBe("allow");
			expect(result.policy.runtime_defaults.file_action).not.toBe("allow");
			await expect(readFile(cachePath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
		} finally {
			clearRemoteRuntimePolicyCacheForTests();
			await rm(root, { recursive: true, force: true });
		}
	});

	it("marks missing and mismatched persistent policy caches unusable", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-critical-policy-cache-"));
		const cachePath = join(root, "cache.json");
		const config = ConfigSchema.parse({
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
				remote_policy_cache_enabled: true,
				remote_policy_cache_path: cachePath,
			},
		});
		try {
			await writeFile(cachePath, "{}", "utf8");
			const invalid = await inspectRemoteRuntimePolicyCache(config, "token");
			expect(invalid).toMatchObject({ source: "invalid", usable: false, present: true });
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
});
