import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";
import { runSessionStart } from "../session-start.js";

const originalFetch = globalThis.fetch;

function buildConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		mode: "managed",
		auth: {},
		control_plane: {
			enabled: true,
			endpoint: "https://control.example.test/functions",
			timeout_seconds: 0.5,
			send_audit_logs: true,
		},
		url_check: { enabled: false },
		file_check: { enabled: false },
		package_check: { enabled: false },
		cache: { enabled: false },
		logging: { enabled: false },
		...overrides,
	};
}

describe("device-code bootstrap", () => {
	let testHome: string;
	let prevHome: string | undefined;
	let prevCommercial: string | undefined;

	beforeEach(async () => {
		prevHome = process.env.HOME;
		prevCommercial = process.env.AIDR_COMMERCIAL;
		process.env.AIDR_COMMERCIAL = "1";

		testHome = join(tmpdir(), `aidr-device-${Math.random().toString(16).slice(2)}`);
		await mkdir(testHome, { recursive: true });
		process.env.HOME = testHome;

		const configPath = join(testHome, ".singularity-aidr", "config.json");
		await mkdir(join(testHome, ".singularity-aidr"), { recursive: true });
		await writeFile(configPath, `${JSON.stringify(buildConfig(), null, 2)}\n`, "utf-8");
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		if (prevHome === undefined) delete process.env.HOME;
		else process.env.HOME = prevHome;
		if (prevCommercial === undefined) delete process.env.AIDR_COMMERCIAL;
		else process.env.AIDR_COMMERCIAL = prevCommercial;
		await rm(testHome, { recursive: true, force: true });
	});

	it("ControlPlaneClient.deviceStart and devicePoll call expected endpoints", async () => {
		const calls: Array<{ url: string; init: RequestInit }> = [];
		globalThis.fetch = vi.fn().mockImplementation(async (url: string, init: RequestInit = {}) => {
			calls.push({ url, init });
			if (url.endsWith("/v1/device-start")) {
				return {
					ok: true,
					status: 200,
					json: async () => ({
						verification_url: "https://dash.example/verify",
						user_code: "ABCD-EFGH",
						device_code: "aidr_device_123",
						expires_at: new Date(Date.now() + 60_000).toISOString(),
					}),
				} as unknown as Response;
			}
			if (url.endsWith("/v1/device-poll")) {
				return {
					ok: false,
					status: 428,
					json: async () => ({ error: "authorization_pending" }),
				} as unknown as Response;
			}
			return {
				ok: false,
				status: 404,
				json: async () => ({ error: "not_found" }),
			} as unknown as Response;
		});

		const client = new ControlPlaneClient(
			{
				enabled: true,
				endpoint: "https://control.example.test/functions",
				timeout_seconds: 0.5,
				send_audit_logs: true,
				send_clean_verdicts: false,
				sync_incidents: false,
				grace_period_hours: 72,
				redact_mode: "hash",
			},
			"",
		);
		const started = await client.deviceStart({});
		expect(started.ok).toBe(true);

		const polled = await client.devicePoll({ device_code: "aidr_device_123" });
		expect(polled.ok).toBe(false);

		expect(calls.some((c) => c.url.endsWith("/v1/device-start"))).toBe(true);
		expect(calls.some((c) => c.url.endsWith("/v1/device-poll"))).toBe(true);
		const pollCall = calls.find((c) => c.url.endsWith("/v1/device-poll"));
		const headers = pollCall?.init?.headers;
		const authorization =
			headers instanceof Headers
				? headers.get("Authorization")
				: headers && typeof headers === "object"
					? String((headers as Record<string, unknown>).Authorization ?? "")
					: "";
		expect(String(authorization)).toContain("aidr_device_123");
	});

	it("runSessionStart returns bootstrap hint when auth is missing", async () => {
		globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
			if (String(url).endsWith("/v1/device-start")) {
				return {
					ok: true,
					status: 200,
					json: async () => ({
						verification_url: "https://dash.example/verify",
						user_code: "ABCD-EFGH",
						device_code: "aidr_device_123",
						expires_at: new Date(Date.now() + 60_000).toISOString(),
					}),
				} as unknown as Response;
			}
			if (String(url).endsWith("/v1/device-poll")) {
				return {
					ok: false,
					status: 428,
					json: async () => ({ error: "authorization_pending" }),
				} as unknown as Response;
			}
			return {
				ok: false,
				status: 404,
				json: async () => ({ error: "not_found" }),
			} as unknown as Response;
		});

		const result = await runSessionStart({
			plugins: [],
			threatsDir: join(testHome, "threats"),
			allowlistsDir: join(testHome, "allowlists"),
			version: "0.0.0-test",
			agentRuntime: "claude-code",
		});

		expect(result.enabled).toBe(false);
		expect(result.disabled_reason).toBe("auth_required");
		expect(result.bootstrap?.verification_url).toBe("https://dash.example/verify");
		expect(result.bootstrap?.user_code).toBe("ABCD-EFGH");
	});
});
