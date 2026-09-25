import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { evaluateToolCall } from "../evaluator.js";
import {
	applyRemoteRuntimePolicy,
	clearRemoteRuntimePolicyCacheForTests,
	syncRemoteRuntimePolicy,
} from "../remote-policy.js";
import { ConfigSchema } from "../types.js";

// The AI governance overlay (docs/ai-governance.md) travels next to the
// published runtime policy and can only add MCP restrictions.

const originalFetch = globalThis.fetch;

function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value && typeof value === "object") {
		return `{${Object.entries(value as Record<string, unknown>)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
			.join(",")}}`;
	}
	return JSON.stringify(value);
}

const sha256 = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");

function response(body: Record<string, unknown>): Response {
	return { ok: true, status: 200, json: async () => body } as unknown as Response;
}

function policyBody(policy: Record<string, unknown>, governance?: Record<string, unknown>, digest?: string) {
	return {
		policy_version: "7",
		cache_seconds: 60,
		runtime_policy: policy,
		policy_sha256: sha256(policy),
		...(governance ? { governance, governance_sha256: digest ?? sha256(governance) } : {}),
	};
}

afterEach(() => {
	globalThis.fetch = originalFetch;
	clearRemoteRuntimePolicyCacheForTests();
});

describe("AI governance overlay on the remote runtime policy", () => {
	it("adds banned and restricted MCP servers on top of the published lists", () => {
		const config = ConfigSchema.parse({ policy: { enabled: false } });
		const governance = {
			mcp_deny_servers: ["shell-runner", "published-deny"],
			mcp_require_approval_servers: ["github"],
		};
		const merged = applyRemoteRuntimePolicy(
			config,
			policyBody(
				{ mcp_default: "allow", mcp_deny_servers: ["published-deny"], mcp_allow_servers: ["github"] },
				governance,
			),
		);
		expect(merged.policy.mcp.deny_servers).toEqual(["published-deny", "shell-runner"]);
		expect(merged.policy.mcp.require_approval_servers).toEqual(["github"]);
		// The published allow list is untouched; deny/require-approval win in evaluation.
		expect(merged.policy.mcp.allow_servers).toEqual(["github"]);
	});

	it("refuses an overlay whose digest, shape or entries do not verify", () => {
		const config = ConfigSchema.parse({ policy: { enabled: false } });
		const policy = { mcp_default: "allow" };
		const governance = { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: [] };
		for (const body of [
			policyBody(policy, governance, "0".repeat(64)),
			policyBody(policy, { ...governance, extra: [] }),
			policyBody(policy, { mcp_deny_servers: ["bad id!"], mcp_require_approval_servers: [] }),
			policyBody(policy, { mcp_deny_servers: "shell-runner", mcp_require_approval_servers: [] }),
			{ ...policyBody(policy), governance_sha256: sha256(governance) },
		]) {
			expect(applyRemoteRuntimePolicy(config, body)).toBe(config);
		}
	});

	it("does not apply or cache a policy response whose overlay fails verification", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-governance-overlay-"));
		const cachePath = join(root, "runtime-policy-cache.json");
		const policy = { mcp_default: "allow" };
		const governance = { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: [] };
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(response(policyBody(policy, governance, "f".repeat(64))))
			.mockResolvedValueOnce(response(policyBody(policy, governance)));
		globalThis.fetch = fetchMock;
		const config = ConfigSchema.parse({
			control_plane: { enabled: true, endpoint: "https://control.example.test", remote_policy_cache_path: cachePath },
			policy: { enabled: false },
		});
		try {
			expect(await syncRemoteRuntimePolicy(config, "agent-token")).toBe(config);
			await expect(readFile(cachePath, "utf-8")).rejects.toThrow();
			const accepted = await syncRemoteRuntimePolicy(config, "agent-token");
			expect(accepted.policy.mcp.deny_servers).toEqual(["shell-runner"]);
			const persisted = JSON.parse(await readFile(cachePath, "utf-8"));
			expect(persisted.body.governance).toEqual(governance);
			expect(persisted.body.governance_sha256).toBe(sha256(governance));
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("keeps the overlay when the policy is served from the persisted cache", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-governance-cache-"));
		const cachePath = join(root, "runtime-policy-cache.json");
		const policy = { mcp_default: "allow" };
		const governance = { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: ["github"] };
		globalThis.fetch = vi.fn().mockResolvedValue(response(policyBody(policy, governance)));
		const config = ConfigSchema.parse({
			control_plane: { enabled: true, endpoint: "https://control.example.test", remote_policy_cache_path: cachePath },
			policy: { enabled: false },
		});
		try {
			await syncRemoteRuntimePolicy(config, "agent-token", undefined, 1_000);
			// Drop the in-memory copy; the next sync must come from disk.
			clearRemoteRuntimePolicyCacheForTests();
			globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
			const cached = await syncRemoteRuntimePolicy(config, "agent-token", undefined, 2_000);
			expect(globalThis.fetch).not.toHaveBeenCalled();
			expect(cached.policy.mcp.deny_servers).toEqual(["shell-runner"]);
			expect(cached.policy.mcp.require_approval_servers).toEqual(["github"]);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("blocks an MCP call to a server banned only by the governance register", async () => {
		const root = join(tmpdir(), `aidr-governance-eval-${Math.random().toString(16).slice(2)}`);
		await mkdir(join(root, "threats"), { recursive: true });
		await mkdir(join(root, "allowlists"), { recursive: true });
		const configPath = join(root, "config.json");
		await writeFile(
			configPath,
			`${JSON.stringify({
				mode: "local",
				auth: { api_key: "aidr_agent_token" },
				control_plane: {
					enabled: true,
					endpoint: "https://control.example.test",
					timeout_seconds: 0.5,
					remote_policy_cache_enabled: false,
				},
				policy: { enabled: false },
				logging: { enabled: false },
				cache: { enabled: false },
			})}\n`,
			"utf-8",
		);
		const policy = { mcp_default: "allow", mcp_allow_servers: ["shell-runner"] };
		const governance = { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: [] };
		globalThis.fetch = vi.fn().mockResolvedValue(response(policyBody(policy, governance)));
		try {
			const verdict = await evaluateToolCall(
				{ sessionId: "sess_governance", toolName: "mcp__shell-runner__exec", toolInput: {}, artifacts: [] },
				{ configPath, threatsDir: join(root, "threats"), allowlistsDir: join(root, "allowlists") },
			);
			expect(verdict.decision).toBe("deny");
			expect(verdict.matchedThreatId).toBe("POL-MCP-006");
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
});
