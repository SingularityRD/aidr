import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { evaluateToolCall } from "../evaluator.js";
import {
	clearRemoteRuntimePolicyCacheForTests,
	inspectRemoteRuntimePolicyCache,
	syncRemoteRuntimePolicy,
} from "../remote-policy.js";
import { ConfigSchema } from "../types.js";

const roots: string[] = [];
const originalFetch = globalThis.fetch;
afterEach(async () => {
	globalThis.fetch = originalFetch;
	clearRemoteRuntimePolicyCacheForTests();
	for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});
async function fixture() {
	const root = await mkdtemp(join(tmpdir(), "aidr-required-policy-"));
	roots.push(root);
	return {
		root,
		config: ConfigSchema.parse({
			mode: "local",
			control_plane: {
				enabled: true,
				endpoint: "https://policy.example.test",
				remote_policy_required: true,
				remote_policy_cache_path: join(root, "policy.json"),
				remote_policy_offline_grace_seconds: 60,
			},
			logging: { enabled: false },
			cache: { enabled: false },
		}),
	};
}
function response(
	status = 200,
	body: unknown = {
		policy_version: "1",
		cache_seconds: 5,
		runtime_policy: { mcp_deny_tools: ["vault.read_secret"], command_default: "deny" },
	},
) {
	return { ok: status >= 200 && status < 300, status, json: async () => body } as Response;
}

describe("required central policy offline boundary", () => {
	it("retains last-known controls only within the fixed grace and never renews it offline", async () => {
		const { config } = await fixture();
		globalThis.fetch = vi.fn().mockResolvedValue(response());
		await syncRemoteRuntimePolicy(config, "required-agent", undefined, 10000);
		const bytes = await readFile(config.control_plane.remote_policy_cache_path, "utf8");
		clearRemoteRuntimePolicyCacheForTests();
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
		const stale = await syncRemoteRuntimePolicy(config, "required-agent", undefined, 20000);
		expect(stale.policy.mcp.deny_tools).toEqual(["vault.read_secret"]);
		expect(stale.policy.runtime_defaults.command_action).toBe("block");
		expect(await inspectRemoteRuntimePolicyCache(config, "required-agent", 20000)).toMatchObject({
			source: "expired",
			usable: true,
		});
		expect(await readFile(config.control_plane.remote_policy_cache_path, "utf8")).toBe(bytes);
		await expect(
			syncRemoteRuntimePolicy(config, "required-agent", undefined, 75000),
		).rejects.toThrow("offline grace");
	});

	it("does not extend the original expiry by loading a disk cache into memory", async () => {
		const { config } = await fixture();
		config.control_plane.remote_policy_offline_grace_seconds = 0;
		globalThis.fetch = vi.fn().mockResolvedValue(response());
		await syncRemoteRuntimePolicy(config, "required-agent", undefined, 10000);
		clearRemoteRuntimePolicyCacheForTests();
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
		await syncRemoteRuntimePolicy(config, "required-agent", undefined, 14999);
		expect(globalThis.fetch).not.toHaveBeenCalled();
		await expect(
			syncRemoteRuntimePolicy(config, "required-agent", undefined, 15000),
		).rejects.toThrow("Required central policy");
	});

	it.each([401, 403, 404])("does not use stale authority after HTTP %i", async (status) => {
		const { config } = await fixture();
		globalThis.fetch = vi.fn().mockResolvedValue(response());
		await syncRemoteRuntimePolicy(config, "required-agent", undefined, 10000);
		globalThis.fetch = vi.fn().mockResolvedValue(response(status, { error: "denied" }));
		await expect(
			syncRemoteRuntimePolicy(config, "required-agent", undefined, 20000),
		).rejects.toThrow("Required central policy");
	});

	it("rejects malformed central policy and refuses a different token's cache", async () => {
		const { config } = await fixture();
		globalThis.fetch = vi
			.fn()
			.mockResolvedValue(
				response(200, { policy_version: "2", runtime_policy: { command_default: ["allow"] } }),
			);
		await expect(syncRemoteRuntimePolicy(config, "required-agent")).rejects.toThrow(
			"Required central policy",
		);
		globalThis.fetch = vi.fn().mockResolvedValue(response());
		await syncRemoteRuntimePolicy(config, "required-agent", undefined, 10000);
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
		await expect(
			syncRemoteRuntimePolicy(config, "different-agent", undefined, 20000),
		).rejects.toThrow("Required central policy");
	});

	it("blocks at the evaluator before artifact and allowlist short circuits", async () => {
		const { config, root } = await fixture();
		config.auth.api_key = "required-agent";
		const configPath = join(root, "config.json");
		await writeFile(configPath, JSON.stringify(config));
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
		const verdict = await evaluateToolCall(
			{ sessionId: "offline", toolName: "mcp__vault__read_secret", toolInput: {}, artifacts: [] },
			{ configPath, threatsDir: root, allowlistsDir: root },
		);
		expect(verdict).toMatchObject({ decision: "deny", source: "remote_policy_unavailable" });
	});

	it("keeps an unenrolled endpoint's local detection independent", async () => {
		const { config } = await fixture();
		globalThis.fetch = vi.fn();
		expect(await syncRemoteRuntimePolicy(config, "")).toBe(config);
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it("does not let an allowlisted URL override an explicit central MCP denial", async () => {
		const { config, root } = await fixture();
		config.auth.api_key = "required-agent";
		config.allowlist.path = join(root, "allowlist.json");
		await writeFile(
			config.allowlist.path,
			JSON.stringify({
				urls: {
					"https://safe.example.test/": {
						added_at: new Date().toISOString(),
						reason: "safe URL",
						original_verdict: "ask",
					},
				},
				commands: {},
			}),
		);
		const configPath = join(root, "config.json");
		await writeFile(configPath, JSON.stringify(config));
		globalThis.fetch = vi.fn().mockResolvedValue(response());
		const verdict = await evaluateToolCall(
			{
				sessionId: "policy-precedence",
				toolName: "mcp__vault__read_secret",
				toolInput: { url: "https://safe.example.test/" },
				artifacts: [{ type: "url", value: "https://safe.example.test/" }],
			},
			{ configPath, threatsDir: root, allowlistsDir: root },
		);
		expect(verdict.decision).toBe("deny");
		expect(verdict.source).not.toBe("allowlisted");
	});

	it("reports a matching loaded revision and keeps enforcement when receipt delivery fails", async () => {
		const { config } = await fixture();
		const policy = { command_default: "deny" };
		const hash = createHash("sha256").update(JSON.stringify(policy)).digest("hex");
		const fetcher = vi
			.fn()
			.mockResolvedValueOnce(
				response(200, {
					policy_version: "1",
					cache_seconds: 5,
					runtime_policy: policy,
					agent_bound: true,
					policy_sha256: hash,
				}),
			)
			.mockRejectedValueOnce(new Error("receipt offline"));
		globalThis.fetch = fetcher;
		const applied = await syncRemoteRuntimePolicy(config, "required-agent", undefined, 10000);
		expect(applied.policy.runtime_defaults.command_action).toBe("block");
		expect(fetcher).toHaveBeenCalledTimes(2);
		expect(String(fetcher.mock.calls[1][0])).toMatch(/policy-ack$/);
		expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({ version: 1, policy_sha256: hash });
	});
});
