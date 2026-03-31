import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RealTimeRuleSync, type RuleSyncConfig } from "../rule-sync.js";
import type { Logger } from "../types.js";

const mockLogger: Logger = {
	debug: vi.fn(),
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
};

function makeConfig(overrides: Partial<RuleSyncConfig> = {}): RuleSyncConfig {
	return {
		cdnUrl: "https://cdn.example.com/rules",
		pollIntervalMinutes: 60,
		emergencyPollIntervalSeconds: 30,
		localCachePath: join(tmpdir(), `rule-sync-test-${Date.now()}.json`),
		maxCacheAgeHours: 24,
		...overrides,
	};
}

describe("RealTimeRuleSync", () => {
	let sync: RealTimeRuleSync;

	beforeEach(() => {
		const config = makeConfig();
		sync = new RealTimeRuleSync(config, mockLogger);
	});

	afterEach(() => {
		sync.stop();
	});

	describe("start", () => {
		it("initializes and starts polling", async () => {
			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }));

			await sync.start();

			expect(sync.getLastSync()).toBeInstanceOf(Date);
			expect(mockLogger.info).toHaveBeenCalledWith(
				"Real-time rule sync started",
				expect.any(Object),
			);
			fetchSpy.mockRestore();
		});
	});

	describe("stop", () => {
		it("stops the polling loop", async () => {
			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

			await sync.start();
			sync.stop();

			expect(mockLogger.info).toHaveBeenCalledWith("Real-time rule sync stopped");
			fetchSpy.mockRestore();
		});
	});

	describe("sync", () => {
		it("returns sync stats after successful sync", async () => {
			const remoteRules = [
				{
					id: "rule-1",
					version: "1.0.0",
					pattern: "test-pattern",
					category: "test",
					severity: "medium" as const,
					action: "block" as const,
					createdAt: new Date().toISOString(),
					updatedAt: new Date().toISOString(),
					hash: "abc123",
				},
			];

			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValue(new Response(JSON.stringify(remoteRules), { status: 200 }));

			const stats = await sync.sync();

			expect(stats.added).toBe(1);
			expect(stats.updated).toBe(0);
			expect(stats.removed).toBe(0);
			expect(mockLogger.info).toHaveBeenCalledWith(
				"Rule sync completed",
				expect.objectContaining({
					added: 1,
					updated: 0,
					removed: 0,
					unchanged: 0,
				}),
			);
			fetchSpy.mockRestore();
		});

		it("handles sync failures gracefully", async () => {
			const fetchSpy = vi.spyOn(global, "fetch").mockRejectedValue(new Error("Network error"));

			const stats = await sync.sync();

			expect(stats.added).toBe(0);
			expect(stats.updated).toBe(0);
			expect(stats.removed).toBe(0);
			expect(mockLogger.error).toHaveBeenCalledWith("Rule sync failed", expect.any(Object));
			fetchSpy.mockRestore();
		});
	});

	describe("downloadRule", () => {
		it("fetches single rule by ID successfully", async () => {
			const rule = {
				id: "test-rule-123",
				version: "2.0.0",
				pattern: "malicious-domain.example.com",
				category: "malware",
				severity: "critical" as const,
				action: "block" as const,
				createdAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
				hash: "def456",
			};

			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValue(new Response(JSON.stringify(rule), { status: 200 }));

			const result = await sync.downloadRule("test-rule-123");

			expect(result).toEqual(rule);
			expect(fetchSpy).toHaveBeenCalledWith(
				"https://cdn.example.com/rules/test-rule-123",
				expect.objectContaining({
					headers: { Accept: "application/json" },
				}),
			);
			expect(mockLogger.info).toHaveBeenCalledWith("Rule downloaded successfully", {
				ruleId: "test-rule-123",
			});
			fetchSpy.mockRestore();
		});

		it("returns null for 404 responses", async () => {
			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValue(new Response("Not found", { status: 404, statusText: "Not Found" }));

			const result = await sync.downloadRule("nonexistent-rule");

			expect(result).toBeNull();
			expect(mockLogger.warn).toHaveBeenCalledWith("Rule not found on CDN", {
				ruleId: "nonexistent-rule",
			});
			fetchSpy.mockRestore();
		});

		it("throws on server errors (5xx)", async () => {
			const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
				new Response("Server Error", {
					status: 500,
					statusText: "Internal Server Error",
				}),
			);

			await expect(sync.downloadRule("any-rule")).rejects.toThrow(
				"Failed to fetch rule any-rule: 500 Internal Server Error",
			);
			fetchSpy.mockRestore();
		});

		it("throws on network errors", async () => {
			const fetchSpy = vi.spyOn(global, "fetch").mockRejectedValue(new Error("Network failure"));

			await expect(sync.downloadRule("any-rule")).rejects.toThrow("Network failure");
			expect(mockLogger.error).toHaveBeenCalledWith(
				"Failed to download rule",
				expect.objectContaining({
					ruleId: "any-rule",
					error: "Network failure",
				}),
			);
			fetchSpy.mockRestore();
		});

		it("properly URL-encodes rule IDs with special characters", async () => {
			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValue(
					new Response(JSON.stringify({ id: "rule/with/slashes" }), { status: 200 }),
				);

			await sync.downloadRule("rule/with/slashes");

			expect(fetchSpy).toHaveBeenCalledWith(
				expect.stringContaining("rules%2Fwith%2Fslashes"),
				expect.any(Object),
			);
			fetchSpy.mockRestore();
		});
	});

	describe("emergencyPush", () => {
		it("downloads emergency rules immediately", async () => {
			const rule = {
				id: "emergency-1",
				version: "1.0.0",
				pattern: "emergency-pattern",
				category: "emergency",
				severity: "critical" as const,
				action: "block" as const,
				createdAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
				hash: "emergency-hash",
			};

			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValue(new Response(JSON.stringify(rule), { status: 200 }));

			await sync.emergencyPush(["emergency-1"]);

			expect(sync.isInEmergencyMode()).toBe(true);
			expect(mockLogger.warn).toHaveBeenCalledWith("Emergency push triggered", expect.any(Object));
			fetchSpy.mockRestore();
		});
	});

	describe("getCurrentRules", () => {
		it("returns all cached rules", async () => {
			const rules = [
				{
					id: "rule-1",
					version: "1.0.0",
					pattern: "pattern-1",
					category: "test",
					severity: "medium" as const,
					action: "block" as const,
					createdAt: new Date().toISOString(),
					updatedAt: new Date().toISOString(),
					hash: "hash1",
				},
				{
					id: "rule-2",
					version: "1.0.0",
					pattern: "pattern-2",
					category: "test",
					severity: "high" as const,
					action: "require_approval" as const,
					createdAt: new Date().toISOString(),
					updatedAt: new Date().toISOString(),
					hash: "hash2",
				},
			];

			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValueOnce(new Response(JSON.stringify(rules), { status: 200 }));

			await sync.sync();
			const currentRules = await sync.getCurrentRules();

			expect(currentRules).toHaveLength(2);
			expect(currentRules.map((r) => r.id)).toContain("rule-1");
			expect(currentRules.map((r) => r.id)).toContain("rule-2");
			fetchSpy.mockRestore();
		});
	});

	describe("caching", () => {
		it("persists rules to local cache after sync", async () => {
			const tmpDir = mkdtempSync(join(tmpdir(), "rule-sync-test-"));
			const cachePath = join(tmpDir, `cache-${Date.now()}.json`);
			const config = makeConfig({ localCachePath: cachePath });
			const testSync = new RealTimeRuleSync(config, mockLogger);

			const rules = [
				{
					id: "cached-rule",
					version: "1.0.0",
					pattern: "cached-pattern",
					category: "test",
					severity: "low" as const,
					action: "log" as const,
					createdAt: new Date().toISOString(),
					updatedAt: new Date().toISOString(),
					hash: "cached-hash",
				},
			];

			const fetchSpy = vi
				.spyOn(global, "fetch")
				.mockResolvedValueOnce(new Response(JSON.stringify(rules), { status: 200 }));

			await testSync.sync();

			// Verify cache file was created
			const cacheContent = readFileSync(cachePath, "utf-8");
			const parsed = JSON.parse(cacheContent);
			expect(parsed.rules).toHaveLength(1);
			expect(parsed.rules[0].id).toBe("cached-rule");

			// Cleanup
			rmSync(tmpDir, { recursive: true, force: true });
			fetchSpy.mockRestore();
		});
	});
});
