import { afterEach, describe, expect, it, vi } from "vitest";
import { PackageChecker } from "../package-checker.js";

const originalFetch = globalThis.fetch;
const packageName = "established-package";
const registryResponse = {
	ok: true,
	status: 200,
	json: async () => ({
		"dist-tags": { latest: "1.0.0" },
		versions: {
			"1.0.0": {
				dist: { integrity: `sha256-${Buffer.alloc(32, 0x11).toString("base64")}` },
			},
		},
		time: { created: "2020-01-01T00:00:00.000Z" },
	}),
};

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe("package checker file reputation failures", () => {
	it.each([
		["HTTP error", { ok: false, status: 503 }],
		["empty response", { ok: true, status: 200, json: async () => ({ responses: [] }) }],
		["missing severity", { ok: true, status: 200, json: async () => ({ responses: [{}] }) }],
		[
			"contradictory benign severity",
			{
				ok: true,
				status: 200,
				json: async () => ({
					responses: [{ severity: "SEVERITY_UNKNOWN", malware_name: ["Trojan.Test"] }],
				}),
			},
		],
	])("reports %s as unknown instead of clean", async (_failure, fileResponse) => {
		globalThis.fetch = vi
			.fn()
			.mockResolvedValueOnce(registryResponse)
			.mockResolvedValueOnce(fileResponse);

		const result = await new PackageChecker().checkSinglePackage({
			name: packageName,
			registry: "npm",
		});
		expect(result).toMatchObject({
			packageName,
			verdict: "unknown",
			confidence: 0,
		});
		expect(result.details).toContain("file reputation check is unavailable");
	});

	it("reports a file-check exception as unknown instead of clean", async () => {
		globalThis.fetch = vi
			.fn()
			.mockResolvedValueOnce(registryResponse)
			.mockRejectedValueOnce(new Error("network failure"));

		const result = await new PackageChecker().checkSinglePackage({
			name: packageName,
			registry: "npm",
		});
		expect(result.verdict).toBe("unknown");
		expect(result.details).toContain("file reputation check is unavailable");
	});

	it("keeps a recent-package warning visible alongside a file-check outage", async () => {
		const recentRegistryResponse = {
			...registryResponse,
			json: async () => ({
				...(await registryResponse.json()),
				time: { created: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
			}),
		};
		globalThis.fetch = vi
			.fn()
			.mockResolvedValueOnce(recentRegistryResponse)
			.mockResolvedValueOnce({ ok: false, status: 503 });

		const result = await new PackageChecker().checkSinglePackage({
			name: packageName,
			registry: "npm",
		});
		expect(result.verdict).toBe("suspicious_age");
		expect(result.details).toContain("file reputation check unavailable");
	});

	it("keeps a completed benign file reputation check clean", async () => {
		globalThis.fetch = vi
			.fn()
			.mockResolvedValueOnce(registryResponse)
			.mockResolvedValueOnce({
				ok: true,
				status: 200,
				json: async () => ({ responses: [{ severity: "SEVERITY_UNKNOWN" }] }),
			});

		const result = await new PackageChecker().checkSinglePackage({
			name: packageName,
			registry: "npm",
		});
		expect(result.verdict).toBe("clean");
	});
});
