import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";
import { DEFAULT_CONTROL_PLANE_ENDPOINT } from "../clients/control-plane-url.js";
import { loadConfig } from "../config.js";
import {
	clearRemoteRuntimePolicyCacheForTests,
	syncRemoteRuntimePolicy,
} from "../remote-policy.js";
import { ConfigSchema } from "../types.js";

/**
 * Client-side half of the connector <-> web control plane contract. The server
 * half (real handlers driven by this client) lives in the aidr-landing repo:
 * src/lib/control-plane/__tests__/connector-contract.test.ts.
 */

let home: string;
const originalHome = process.env.HOME;
const originalFetch = globalThis.fetch;

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-landing-contract-"));
	process.env.HOME = home;
});

afterEach(async () => {
	globalThis.fetch = originalFetch;
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	clearRemoteRuntimePolicyCacheForTests();
	vi.restoreAllMocks();
	await rm(home, { recursive: true, force: true });
});

async function configFrom(raw: unknown) {
	const path = join(home, "config.json");
	await writeFile(path, JSON.stringify(raw));
	return loadConfig(path);
}

describe("default control-plane endpoint (AIDR-016)", () => {
	it("is the origin that serves /v1/*, not the never-provisioned aidr-control.svc host", () => {
		expect(DEFAULT_CONTROL_PLANE_ENDPOINT).toBe("https://aidr.singularityrd.com");
		expect(DEFAULT_CONTROL_PLANE_ENDPOINT).not.toContain("aidr-control");
	});

	it("local mode (the default) has no endpoint and never contacts a control plane", async () => {
		expect((await configFrom({})).control_plane.endpoint).toBe("");
		expect((await configFrom({ mode: "local" })).control_plane.endpoint).toBe("");
	});

	it("managed mode falls back to the default endpoint but honors an explicit one", async () => {
		expect((await configFrom({ mode: "managed" })).control_plane.endpoint).toBe(
			DEFAULT_CONTROL_PLANE_ENDPOINT,
		);
		expect(
			(
				await configFrom({
					mode: "managed",
					control_plane: { endpoint: "https://self-hosted.example.test" },
				})
			).control_plane.endpoint,
		).toBe("https://self-hosted.example.test");
	});

	it("enrollment calls resolve to https://aidr.singularityrd.com/v1/<op>", async () => {
		const config = await configFrom({ mode: "managed" });
		const fetcher = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
		globalThis.fetch = fetcher;
		const client = new ControlPlaneClient(config.control_plane, "token");
		await client.deviceStart({ iid: "iid" });
		await client.devicePoll({ device_code: "code" });
		await client.enroll({ iid: "iid" });
		expect(fetcher.mock.calls.map((c) => c[0])).toEqual([
			"https://aidr.singularityrd.com/v1/device-start",
			"https://aidr.singularityrd.com/v1/device-poll",
			"https://aidr.singularityrd.com/v1/enroll",
		]);
	});
});

describe("enrollment bootstrap timeout", () => {
	it("gives device-start, device-poll and enroll a bootstrap budget beyond the 0.5s hook default", async () => {
		const timeouts: number[] = [];
		const realTimeout = AbortSignal.timeout.bind(AbortSignal);
		vi.spyOn(AbortSignal, "timeout").mockImplementation((ms: number) => {
			timeouts.push(ms);
			return realTimeout(ms);
		});
		globalThis.fetch = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
		const config = ConfigSchema.parse({ control_plane: { endpoint: "https://cp.example.test" } });
		expect(config.control_plane.timeout_seconds).toBe(0.5);
		const client = new ControlPlaneClient(config.control_plane, "token");
		await client.deviceStart({ iid: "iid" });
		await client.devicePoll({ device_code: "code" });
		await client.enroll({ iid: "iid" });
		expect(timeouts).toHaveLength(3);
		for (const ms of timeouts) expect(ms).toBeGreaterThanOrEqual(8_000);
		// Three sequential calls still fit the 30s session-start hook budget.
		expect(timeouts.reduce((a, b) => a + b, 0)).toBeLessThan(30_000);
	});

	it("keeps per-tool-call endpoints on the configured short timeout", async () => {
		const timeouts: number[] = [];
		const realTimeout = AbortSignal.timeout.bind(AbortSignal);
		vi.spyOn(AbortSignal, "timeout").mockImplementation((ms: number) => {
			timeouts.push(ms);
			return realTimeout(ms);
		});
		globalThis.fetch = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
		const config = ConfigSchema.parse({ control_plane: { endpoint: "https://cp.example.test" } });
		const client = new ControlPlaneClient(config.control_plane, "token");
		await client.fetchRuntimePolicy();
		await client.fetchRevocations();
		expect(timeouts).toEqual([500, 500]);
	});
});

describe("required central policy accepts the web control plane's opaque version labels", () => {
	const policy = { command_default: "deny", mcp_deny_servers: ["shell-wrapper"] };
	const sha = createHash("sha256")
		.update(
			JSON.stringify(
				Object.fromEntries(Object.entries(policy).sort(([a], [b]) => (a < b ? -1 : 1))),
			),
		)
		.digest("hex");

	const required = () =>
		ConfigSchema.parse({
			control_plane: {
				endpoint: "https://cp.example.test",
				remote_policy_required: true,
				remote_policy_cache_path: join(home, ".singularity-aidr", "policy-cache.json"),
			},
			logging: { enabled: false },
			cache: { enabled: false },
		});

	const respond = (version: unknown) =>
		vi.fn().mockResolvedValue(
			new Response(
				JSON.stringify({
					ok: true,
					policy_version: version,
					policy_sha256: sha,
					cache_seconds: 30,
					runtime_policy: policy,
				}),
				{ status: 200 },
			),
		);

	it.each(["1", "42", "pol_20260506101000", "2026-05-06T10:10:00.000Z", "default"])(
		"accepts version %s",
		async (version) => {
			globalThis.fetch = respond(version);
			const next = await syncRemoteRuntimePolicy(required(), "agent-token");
			expect(next.policy.runtime_defaults.command_action).toBe("block");
			expect(next.policy.mcp.deny_servers).toEqual(["shell-wrapper"]);
		},
	);

	it.each(["", " ", "has spaces", "x".repeat(200), "../etc/passwd"])(
		"still rejects unusable version %j",
		async (version) => {
			globalThis.fetch = respond(version);
			await expect(syncRemoteRuntimePolicy(required(), "agent-token")).rejects.toThrow(
				"Required central policy",
			);
		},
	);

	it("does not acknowledge a non-integer version (only agent-bound integer revisions are acked)", async () => {
		const fetcher = respond("pol_20260506101000");
		globalThis.fetch = fetcher;
		await syncRemoteRuntimePolicy(required(), "agent-token");
		expect(fetcher).toHaveBeenCalledTimes(1);
	});
});
