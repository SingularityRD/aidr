/**
 * Regression tests for AIDR-020's remaining false-clean half.
 *
 * ## The defect
 *
 * The plugin scanner constructed the URL and file reputation clients with **no
 * API key**, while the first-party endpoints require a bearer key. The resulting
 * 401 was swallowed by `catch { /* Fail open *\/ }`, and the clients themselves
 * returned `[]` for any non-OK response. So:
 *
 *   - an unauthenticated deployment,
 *   - a mistyped API key,
 *   - an endpoint that is not deployed at all,
 *
 * all produced a scan result byte-for-byte identical to "we checked every URL and
 * hash and found nothing". The scanner reported the plugin clean.
 *
 * That is the same failure class as the silent zero-rule allow fixed earlier in
 * the evaluator: a detection layer that did not run must never be reported as a
 * clean result.
 *
 * ## What is pinned here
 *
 *   1. A non-OK response throws, rather than returning an empty result.
 *   2. The scanner surfaces the unavailable leg in `unavailableChecks`, with a
 *      reason an operator can act on, and warns.
 *   3. A 401 specifically names the authentication problem.
 *   4. The successful path is unchanged - no degradation notice when the leg
 *      genuinely ran (so the new reporting cannot become noise).
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FileCheckClient } from "../clients/file-check.js";
import { UrlCheckClient } from "../clients/url-check.js";
import { DetectionLegUnavailableError } from "../detection-leg.js";
import { scanPlugin } from "../plugin-scanner.js";
import type { Logger, PluginInfo, Threat } from "../types.js";

function recordingLogger(): { logger: Logger; warnings: string[] } {
	const warnings: string[] = [];
	const logger = {
		debug() {},
		info() {},
		warn(message: unknown) {
			warnings.push(String(message));
		},
		error() {},
		child() {
			return logger;
		},
	} as unknown as Logger;
	return { logger, warnings };
}

describe("reputation clients refuse to report an unavailable leg as clean", () => {
	const originalFetch = globalThis.fetch;

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("URL check throws on a 401 instead of returning an empty result", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 401 });

		const client = new UrlCheckClient(undefined, recordingLogger().logger);
		await expect(client.checkUrls(["https://evil.test/x"])).rejects.toBeInstanceOf(
			DetectionLegUnavailableError,
		);
	});

	it("URL check throws on an unreachable endpoint", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("fetch failed: ENOTFOUND"));

		const client = new UrlCheckClient(undefined, recordingLogger().logger);
		await expect(client.checkUrls(["https://evil.test/x"])).rejects.toBeInstanceOf(
			DetectionLegUnavailableError,
		);
	});

	it("file check throws on a 403 instead of returning an empty result", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 403 });

		const client = new FileCheckClient(undefined, recordingLogger().logger);
		await expect(client.checkHashes(["a".repeat(64)])).rejects.toBeInstanceOf(
			DetectionLegUnavailableError,
		);
	});

	it("names the authentication problem for a 401, because that is the likely cause", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 401 });

		const client = new UrlCheckClient(undefined, recordingLogger().logger);
		const error = await client.checkUrls(["https://evil.test/x"]).catch((e: unknown) => e);

		expect(error).toBeInstanceOf(DetectionLegUnavailableError);
		expect((error as DetectionLegUnavailableError).reason).toMatch(/unauthenticated/i);
		expect((error as DetectionLegUnavailableError).reason).toMatch(/API key/i);
		expect((error as DetectionLegUnavailableError).status).toBe(401);
		expect((error as DetectionLegUnavailableError).leg).toBe("url_reputation");
	});
});

describe("scanPlugin reports reputation legs that did not run", () => {
	const originalFetch = globalThis.fetch;
	let tempDir: string;
	let plugin: PluginInfo;
	const emptyThreats: Threat[] = [];

	beforeEach(async () => {
		tempDir = await mkdtemp(join(tmpdir(), "aidr-leg-report-"));
		plugin = {
			key: "test-plugin",
			installPath: tempDir,
			version: "1.0.0",
			lastUpdated: new Date().toISOString(),
		};
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		await rm(tempDir, { recursive: true, force: true });
	});

	it("keeps URL and file reputation opt-in by default", async () => {
		await writeFile(
			join(tempDir, "plugin.js"),
			'const url = "https://private.example/path?token=secret";\n',
			"utf8",
		);
		const mockFetch = vi.fn();
		globalThis.fetch = mockFetch;

		const result = await scanPlugin(plugin, emptyThreats);

		expect(mockFetch).not.toHaveBeenCalled();
		expect(result.unavailableChecks?.map((check) => check.check)).toEqual([
			"url_reputation",
			"file_reputation",
		]);
		expect(result.unavailableChecks?.map((check) => check.reason).join(" ")).not.toContain("secret");
	});

	it("marks the URL leg unavailable instead of reporting the plugin clean", async () => {
		await writeFile(
			join(tempDir, "plugin.js"),
			'const url = "https://evil.test/payload.sh";\n',
			"utf8",
		);
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 401 });

		const { logger, warnings } = recordingLogger();
		const result = await scanPlugin(plugin, emptyThreats, {
			checkUrls: true,
			checkFileHashes: false,
			logger,
		});

		expect(result.unavailableChecks).toBeDefined();
		const leg = result.unavailableChecks?.find((c) => c.check === "url_reputation");
		expect(leg).toBeDefined();
		expect(leg?.reason).toMatch(/unauthenticated/i);
		expect(leg?.uncheckedCount).toBeGreaterThan(0);
		// The operator is told, not just the return value.
		expect(warnings.join(" ")).toMatch(/URL reputation leg did not run/i);
	});

	it("marks the file leg unavailable when its endpoint rejects the request", async () => {
		await writeFile(join(tempDir, "plugin.js"), "const a = 1;\n", "utf8");
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 403 });

		const { logger, warnings } = recordingLogger();
		const result = await scanPlugin(plugin, emptyThreats, {
			checkUrls: false,
			checkFileHashes: true,
			logger,
		});

		const leg = result.unavailableChecks?.find((c) => c.check === "file_reputation");
		expect(leg).toBeDefined();
		expect(leg?.uncheckedCount).toBeGreaterThan(0);
		expect(warnings.join(" ")).toMatch(/file reputation leg did not run/i);
	});

	it("reports nothing unavailable when the leg actually ran and found nothing", async () => {
		await writeFile(
			join(tempDir, "plugin.js"),
			'const url = "https://benign.test/a";\n',
			"utf8",
		);
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
			answers: [
				{
					key: "https://benign.test/a",
					cache_valid_until: new Date(Date.now() + 60_000).toISOString(),
					result: { success: { coverage: "covered", classification: { result: {} }, flags: [] } },
				},
				],
			}),
		});

		const { logger, warnings } = recordingLogger();
		const result = await scanPlugin(plugin, emptyThreats, {
			checkUrls: true,
			checkFileHashes: false,
			logger,
		});

		// A genuinely clean URL check stays distinct from the deliberately disabled
		// file check, so the operator sees exactly which coverage is missing.
		expect(result.unavailableChecks?.map((check) => check.check)).toEqual(["file_reputation"]);
		expect(warnings.join(" ")).not.toMatch(/URL reputation leg did not run/i);
		expect(result.findings).toEqual([]);
	});

	it("passes the configured API key through to the URL client", async () => {
		await writeFile(
			join(tempDir, "plugin.js"),
			'const url = "https://evil.test/a";\n',
			"utf8",
		);
		const seen: Array<Record<string, string>> = [];
		globalThis.fetch = vi.fn().mockImplementation(async (_u: string, init: RequestInit) => {
			seen.push(init.headers as Record<string, string>);
			return { ok: true, json: async () => ({ answers: [] }) };
		});

		await scanPlugin(plugin, emptyThreats, {
			checkUrls: true,
			checkFileHashes: false,
			apiKey: "test-key-123",
			logger: recordingLogger().logger,
		});

		// Without this the endpoint answers 401 and the leg is dead - the original
		// defect was that the key was simply never passed.
		expect(seen.length).toBeGreaterThan(0);
		expect(seen[0]?.Authorization).toBe("Bearer test-key-123");
	});
});
