import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { syncRemoteRuntimePolicy } from "../remote-policy.js";
import { runSessionStart } from "../session-start.js";
import { ConfigSchema } from "../types.js";

const originalFetch = globalThis.fetch;

describe("session start remote policy cache telemetry", () => {
	let root: string;
	let prevHome: string | undefined;

	beforeEach(async () => {
		prevHome = process.env.HOME;
		root = join(tmpdir(), `aidr-session-policy-cache-${Math.random().toString(16).slice(2)}`);
		await mkdir(root, { recursive: true });
		process.env.HOME = root;
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		if (prevHome === undefined) delete process.env.HOME;
		else process.env.HOME = prevHome;
		await rm(root, { recursive: true, force: true });
	});

	it("sends cached policy freshness in the managed heartbeat event", async () => {
		const aidrDir = join(root, ".singularity-aidr");
		const threatsDir = join(root, "threats");
		const allowlistsDir = join(root, "allowlists");
		const cachePath = join(aidrDir, "runtime-policy-cache.json");
		const configPath = join(aidrDir, "config.json");
		await mkdir(aidrDir, { recursive: true });
		await mkdir(threatsDir, { recursive: true });
		await mkdir(allowlistsDir, { recursive: true });

		const config = ConfigSchema.parse({
			mode: "managed",
			auth: { api_key: "aidr_agent_token" },
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
				timeout_seconds: 0.5,
				remote_policy_cache_path: cachePath,
			},
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
		});
		await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf-8");

		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({
				ok: true,
				policy_version: "pol_session",
				cache_seconds: 60,
				runtime_policy: { command_default: "ask" },
			}),
		} as unknown as Response);
		await syncRemoteRuntimePolicy(config, "aidr_agent_token", undefined, Date.now());

		const ingestPayloads: Record<string, unknown>[] = [];
		globalThis.fetch = vi.fn().mockImplementation(async (url: string, init: RequestInit = {}) => {
			if (url.endsWith("/v1/ingest") && typeof init.body === "string") {
				ingestPayloads.push(JSON.parse(init.body) as Record<string, unknown>);
			}
			return {
				ok: true,
				status: 200,
				json: async () => ({ ok: true, version: "0.6.0" }),
			} as unknown as Response;
		});

		await runSessionStart({
			plugins: [],
			threatsDir,
			allowlistsDir,
			version: "0.6.0",
			agentRuntime: "claude-code",
			configPath,
			aidrDirPath: aidrDir,
		});

		const heartbeat = ingestPayloads.find((payload) =>
			((payload.events as Record<string, unknown>[] | undefined) ?? []).some(
				(event) => event.type === "runtime_policy_cache",
			),
		);
		expect(heartbeat).toBeTruthy();
		expect(heartbeat?.events).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					type: "runtime_policy_cache",
					verdict: "allow",
					severity: "info",
					runtime_policy_cache: expect.objectContaining({
						source: "valid",
						usable: true,
						policy_version: "pol_session",
					}),
				}),
			]),
		);
		expect(JSON.stringify(heartbeat)).not.toContain("aidr_agent_token");
		expect(JSON.stringify(heartbeat)).not.toContain(cachePath);
	});
});
