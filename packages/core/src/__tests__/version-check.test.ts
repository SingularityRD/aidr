import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveEndpoint } from "../clients/url-check.js";
import {
	checkForUpdate,
	isNewerVersion,
	type VersionCheckContext,
	versionCheckEndpoint,
} from "../version-check.js";

describe("isNewerVersion", () => {
	it("detects newer major version", () => {
		expect(isNewerVersion("0.4.0", "1.0.0")).toBe(true);
	});

	it("detects newer minor version", () => {
		expect(isNewerVersion("0.4.0", "0.5.0")).toBe(true);
	});

	it("detects newer patch version", () => {
		expect(isNewerVersion("0.4.0", "0.4.1")).toBe(true);
	});

	it("returns false for same version", () => {
		expect(isNewerVersion("0.4.0", "0.4.0")).toBe(false);
	});

	it("returns false for older version", () => {
		expect(isNewerVersion("1.0.0", "0.9.0")).toBe(false);
	});

	it("handles v prefix", () => {
		expect(isNewerVersion("v0.4.0", "v0.5.0")).toBe(true);
	});

	it("handles partial versions", () => {
		expect(isNewerVersion("1.0", "1.1")).toBe(true);
		expect(isNewerVersion("1", "2")).toBe(true);
	});
});

describe("checkForUpdate", () => {
	const originalFetch = globalThis.fetch;
	const originalSkip = process.env.AIDR_SKIP_VERSION_CHECK;

	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
		if (originalSkip === undefined) delete process.env.AIDR_SKIP_VERSION_CHECK;
		else process.env.AIDR_SKIP_VERSION_CHECK = originalSkip;
		vi.useRealTimers();
	});

	it("never fetches when AIDR_SKIP_VERSION_CHECK=1", async () => {
		process.env.AIDR_SKIP_VERSION_CHECK = "1";
		globalThis.fetch = vi.fn();
		expect(await checkForUpdate("0.6.0")).toBeNull();
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it("returns update available when remote version is newer", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "1.0.0" }),
		});

		const result = await checkForUpdate("0.4.0");
		expect(result).toEqual({
			currentVersion: "0.4.0",
			latestVersion: "1.0.0",
			updateAvailable: true,
		});
	});

	it("returns no update when versions match", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "0.4.0" }),
		});

		const result = await checkForUpdate("0.4.0");
		expect(result).toEqual({
			currentVersion: "0.4.0",
			latestVersion: "0.4.0",
			updateAvailable: false,
		});
	});

	it("returns no update when local is newer", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "0.3.0" }),
		});

		const result = await checkForUpdate("0.4.0");
		expect(result).toEqual({
			currentVersion: "0.4.0",
			latestVersion: "0.3.0",
			updateAvailable: false,
		});
	});

	it("returns null for dev builds", async () => {
		const result = await checkForUpdate("dev");
		expect(result).toBeNull();
	});

	it("returns null on HTTP error", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 404,
		});

		const result = await checkForUpdate("0.4.0");
		expect(result).toBeNull();
	});

	it("returns null on network error", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("network error"));

		const result = await checkForUpdate("0.4.0");
		expect(result).toBeNull();
	});

	it("returns null when response has no version field", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ name: "@singularityrd/aidr-core" }),
		});

		const result = await checkForUpdate("0.4.0");
		expect(result).toBeNull();
	});

	it("always sends POST with environment body", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "0.4.0" }),
		});

		await checkForUpdate("0.4.0");

		const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
		expect(fetchCall[0]).toBe(resolveEndpoint("/v1/version-check"));
		const options = fetchCall[1] as RequestInit;
		expect(options.method).toBe("POST");
		const body = JSON.parse(options.body as string);
		expect(body.aidr_version).toBe("0.4.0");
		expect(body.os).toBe(process.platform);
		expect(body.arch).toBe(process.arch);
		expect(typeof body.os_version).toBe("string");
	});

	it("includes agent context when provided", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "1.0.0" }),
		});

		const ctx: VersionCheckContext = {
			agentRuntime: "cursor",
			agentRuntimeVersion: "0.48.7",
			iid: "550e8400-e29b-41d4-a716-446655440000",
		};

		await checkForUpdate("0.4.0", undefined, undefined, ctx);

		const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
		const body = JSON.parse((fetchCall[1] as RequestInit).body as string);
		expect(body.agent_runtime).toBe("cursor");
		expect(body.agent_runtime_version).toBe("0.48.7");
		expect(body.iid).toBe("550e8400-e29b-41d4-a716-446655440000");
	});

	it("sends body without iid when installation id is unavailable", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "0.4.0" }),
		});

		await checkForUpdate("0.4.0", undefined, undefined, {
			agentRuntime: "claude-code",
		});

		const body = JSON.parse(
			((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1] as RequestInit)
				.body as string,
		);
		expect(body.agent_runtime).toBe("claude-code");
		expect(body.iid).toBeUndefined();
	});
});

describe("versionCheckEndpoint", () => {
	it("uses the public gateway route by default and in local mode", () => {
		expect(versionCheckEndpoint()).toBe(resolveEndpoint("/v1/version-check"));
		expect(
			versionCheckEndpoint({ mode: "local", control_plane: { endpoint: "https://cp.example" } }),
		).toBe(versionCheckEndpoint());
	});

	it("routes a managed install to its own control plane's version-check function", () => {
		expect(
			versionCheckEndpoint({
				mode: "managed",
				control_plane: { endpoint: "https://project.supabase.co/functions" },
			}),
		).toBe("https://project.supabase.co/functions/v1/version-check");
		expect(
			versionCheckEndpoint({
				mode: "managed",
				control_plane: { endpoint: "https://gw.example/v1/" },
			}),
		).toBe("https://gw.example/v1/version-check");
	});

	it("POSTs to the endpoint it is given", async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValue({ ok: true, json: async () => ({ version: "1.0.0" }) });
		const originalFetch = globalThis.fetch;
		globalThis.fetch = fetchMock;
		try {
			await checkForUpdate(
				"0.4.0",
				undefined,
				undefined,
				undefined,
				undefined,
				"https://cp.example/v1/version-check",
			);
			expect(fetchMock.mock.calls[0]?.[0]).toBe("https://cp.example/v1/version-check");
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});
