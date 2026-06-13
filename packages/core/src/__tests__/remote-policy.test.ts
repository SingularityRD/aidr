import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { evaluateToolCall } from "../evaluator.js";
import {
	applyRemoteRuntimePolicy,
	clearRemoteRuntimePolicyCacheForTests,
	inspectRemoteRuntimePolicyCache,
	syncRemoteRuntimePolicy,
} from "../remote-policy.js";
import { ConfigSchema } from "../types.js";

const originalFetch = globalThis.fetch;

describe("remote runtime policy merge", () => {
	afterEach(() => {
		globalThis.fetch = originalFetch;
		clearRemoteRuntimePolicyCacheForTests();
	});

	it("maps dashboard MCP policy into local enforcement config", () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: false,
				mcp: {
					enabled: false,
					allow_servers: ["local"],
					deny_servers: ["old-deny"],
				},
			},
		});

		const merged = applyRemoteRuntimePolicy(config, {
			runtime_policy: {
				mcp_unknown: "ask",
				mcp_risky: "deny",
				mcp_allow_servers: ["GitHub", "github"],
				mcp_require_approval_servers: ["filesystem"],
				mcp_deny_servers: ["shell wrapper", "shell-wrapper"],
			},
		});

		expect(merged.policy.enabled).toBe(true);
		expect(merged.policy.mcp).toMatchObject({
			enabled: true,
			unknown_server_action: "require_approval",
			risky_server_action: "block",
			allow_servers: ["github"],
			require_approval_servers: ["filesystem"],
			deny_servers: ["shell-wrapper"],
		});
	});

	it("maps dashboard command/file/url/package/output defaults into local policy", () => {
		const config = ConfigSchema.parse({
			policy: { enabled: false },
		});

		const merged = applyRemoteRuntimePolicy(config, {
			runtime_policy: {
				command_default: "ask",
				file_default: "deny",
				url_default: "ask",
				package_default: "deny",
				output_default: "allow",
			},
		});

		expect(merged.policy.runtime_defaults).toMatchObject({
			command_action: "require_approval",
			file_action: "block",
			url_action: "require_approval",
			package_action: "block",
			output_action: "allow",
		});
	});

	it("fails open when the control plane policy fetch fails", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 401,
			json: async () => ({ error: "invalid_agent_token" }),
		} as unknown as Response);

		const config = ConfigSchema.parse({
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
			},
			policy: { enabled: false },
		});

		await expect(syncRemoteRuntimePolicy(config, "agent-token")).resolves.toBe(config);
	});

	it("fetches once and reuses the short-lived policy cache", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({
				ok: true,
				cache_seconds: 60,
				runtime_policy: {
					command_default: "ask",
					mcp_unknown: "deny",
					mcp_risky: "ask",
					mcp_deny_servers: ["unknown-proxy"],
					mcp_require_approval_tools: ["filesystem.read_file"],
				},
			}),
		} as unknown as Response);
		globalThis.fetch = fetchMock;

		const config = ConfigSchema.parse({
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
			},
			policy: { enabled: false },
		});

		const first = await syncRemoteRuntimePolicy(config, "agent-token", undefined, 1000);
		const second = await syncRemoteRuntimePolicy(config, "agent-token", undefined, 2000);

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(first.policy.runtime_defaults.command_action).toBe("require_approval");
		expect(first.policy.mcp.unknown_server_action).toBe("block");
		expect(second.policy.mcp.deny_servers).toEqual(["unknown-proxy"]);
		expect(second.policy.mcp.require_approval_tools).toEqual(["filesystem.read_file"]);
	});

	it("reuses cached remote policy without replacing caller-local config", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({
				ok: true,
				cache_seconds: 60,
				runtime_policy: {
					command_default: "ask",
				},
			}),
		} as unknown as Response);
		globalThis.fetch = fetchMock;

		const firstConfig = ConfigSchema.parse({
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
				remote_policy_cache_enabled: false,
			},
			disabled_threats: [],
			policy: { enabled: false },
		});
		const secondConfig = ConfigSchema.parse({
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
				remote_policy_cache_enabled: false,
			},
			disabled_threats: ["CLT-CMD-001"],
			policy: { enabled: false },
		});

		await syncRemoteRuntimePolicy(firstConfig, "agent-token", undefined, 1000);
		const second = await syncRemoteRuntimePolicy(secondConfig, "agent-token", undefined, 2000);

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(second.policy.runtime_defaults.command_action).toBe("require_approval");
		expect(second.disabled_threats).toEqual(["CLT-CMD-001"]);
	});

	it("persists fetched runtime policy without storing the agent token", async () => {
		const root = join(tmpdir(), `aidr-remote-policy-cache-${Math.random().toString(16).slice(2)}`);
		await mkdir(root, { recursive: true });
		const cachePath = join(root, "runtime-policy-cache.json");
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({
				ok: true,
				policy_version: "pol_123",
				cache_seconds: 120,
				runtime_policy: {
					command_default: "deny",
					mcp_unknown: "ask",
				},
			}),
		} as unknown as Response);
		globalThis.fetch = fetchMock;

		const config = ConfigSchema.parse({
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
				remote_policy_cache_path: cachePath,
			},
			policy: { enabled: false },
		});

		try {
			const first = await syncRemoteRuntimePolicy(config, "agent-token-secret", undefined, 10_000);
			expect(first.policy.runtime_defaults.command_action).toBe("block");
			expect(first.policy.mcp.unknown_server_action).toBe("require_approval");
			expect(fetchMock).toHaveBeenCalledTimes(1);

			const rawCache = await readFile(cachePath, "utf-8");
			expect(rawCache).toContain("pol_123");
			expect(rawCache).not.toContain("agent-token-secret");

			clearRemoteRuntimePolicyCacheForTests();
			globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));

			const restored = await syncRemoteRuntimePolicy(
				config,
				"agent-token-secret",
				undefined,
				20_000,
			);
			expect(restored.policy.runtime_defaults.command_action).toBe("block");
			expect(restored.policy.mcp.unknown_server_action).toBe("require_approval");
			expect(globalThis.fetch).not.toHaveBeenCalled();
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("reports persisted policy cache freshness without exposing the agent token", async () => {
		const root = join(
			tmpdir(),
			`aidr-remote-policy-cache-status-${Math.random().toString(16).slice(2)}`,
		);
		await mkdir(root, { recursive: true });
		const cachePath = join(root, "runtime-policy-cache.json");
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({
				ok: true,
				policy_version: "pol_status",
				cache_seconds: 60,
				runtime_policy: {
					command_default: "ask",
				},
			}),
		} as unknown as Response);

		const config = ConfigSchema.parse({
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
				remote_policy_cache_path: cachePath,
			},
			policy: { enabled: false },
		});

		try {
			await syncRemoteRuntimePolicy(config, "agent-token-secret", undefined, 10_000);

			const fresh = await inspectRemoteRuntimePolicyCache(config, "agent-token-secret", 20_000);
			expect(fresh).toMatchObject({
				enabled: true,
				present: true,
				source: "valid",
				usable: true,
				policyVersion: "pol_status",
				keyMatches: true,
				ageSeconds: 10,
				ttlSeconds: 50,
			});

			const mismatched = await inspectRemoteRuntimePolicyCache(
				config,
				"different-agent-token",
				20_000,
			);
			expect(mismatched).toMatchObject({
				source: "mismatched",
				usable: false,
				keyMatches: false,
				policyVersion: "pol_status",
			});

			const expired = await inspectRemoteRuntimePolicyCache(config, "agent-token-secret", 80_000);
			expect(expired).toMatchObject({
				source: "expired",
				usable: false,
				policyVersion: "pol_status",
				ttlSeconds: 0,
			});

			const rawCache = await readFile(cachePath, "utf-8");
			expect(rawCache).not.toContain("agent-token-secret");
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("enforces fetched MCP policy in the evaluator before artifact short-circuiting", async () => {
		const root = join(tmpdir(), `aidr-remote-policy-${Math.random().toString(16).slice(2)}`);
		await mkdir(root, { recursive: true });
		const configPath = join(root, "config.json");
		const threatsDir = join(root, "threats");
		const allowlistsDir = join(root, "allowlists");
		await mkdir(threatsDir, { recursive: true });
		await mkdir(allowlistsDir, { recursive: true });
		await writeFile(
			configPath,
			`${JSON.stringify(
				{
					mode: "local",
					auth: { api_key: "aidr_agent_token" },
					control_plane: {
						enabled: true,
						endpoint: "https://control.example.test",
						timeout_seconds: 0.5,
					},
					policy: { enabled: false },
					logging: { enabled: false },
					cache: { enabled: false },
				},
				null,
				2,
			)}\n`,
			"utf-8",
		);

		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({
				ok: true,
				runtime_policy: {
					mcp_unknown: "deny",
					mcp_risky: "ask",
					mcp_deny_servers: [],
				},
			}),
		} as unknown as Response);

		try {
			const verdict = await evaluateToolCall(
				{
					sessionId: "sess_remote_policy",
					toolName: "mcp__unknownProxy__query",
					toolInput: {},
					artifacts: [],
				},
				{ configPath, threatsDir, allowlistsDir },
			);

			expect(verdict.decision).toBe("deny");
			expect(verdict.category).toBe("mcp_tool_call");
			expect(verdict.matchedThreatId).toBe("POL-MCP-001");
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
});
