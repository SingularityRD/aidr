import { afterEach, describe, expect, it, vi } from "vitest";
import { FileCheckClient } from "../clients/file-check.js";
import { RegistryClient } from "../clients/package-registry.js";
import { PackageChecker } from "../package-checker.js";

const originalFetch = globalThis.fetch;
const sha256 = "11".repeat(32);

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe("package provider response contracts", () => {
	it.each([
		["npm" as const, { "dist-tags": { latest: "1.0.0" }, versions: {} }],
		["npm" as const, { "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { dist: {} } } }],
		["pypi" as const, { info: { version: "1.0.0" }, releases: {} }],
		["pypi" as const, { info: { version: "1.0.0" }, releases: { "1.0.0": [{ digests: {} }] } }],
	])("treats malformed %s HTTP 200 metadata as unavailable", async (registry, body) => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => body,
		});

		const client = new RegistryClient();
		await expect(client.getPackageMetadata("example-package", registry)).rejects.toThrow(
			"Malformed",
		);

		const result = await new PackageChecker({ fileCheckEnabled: false }).checkSinglePackage({
			name: "example-package",
			registry,
		});
		expect(result.verdict).toBe("unknown");
		expect(result.details).toContain("registry response was malformed");
	});

	it.each(["npm" as const, "pypi" as const])(
		"preserves genuine %s HTTP 404 as not_found",
		async (registry) => {
			globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 });
			const client = new RegistryClient();
			expect(await client.getPackageMetadata("absent-package", registry)).toBeNull();

			const result = await new PackageChecker({ fileCheckEnabled: false }).checkSinglePackage({
				name: "absent-package",
				registry,
			});
			expect(result.verdict).toBe("not_found");
		},
	);

	it.each([
		{ responses: [{}] },
		{ responses: [{ severity: "SEVERITY_UNSPECIFIED" }] },
		{ responses: [{ severity: "SEVERITY_UNKNOWN", malware_name: {} }] },
		{ responses: [{ severity: "SEVERITY_UNKNOWN", malware_name: ["Trojan.Test"] }] },
		{ responses: [{ key: { sha256: "22".repeat(32) }, severity: "SEVERITY_UNKNOWN" }] },
	])("rejects an incomplete file-check HTTP 200 response: %j", async (body) => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => body,
		});
		const client = new FileCheckClient();
		expect(await client.checkHash(sha256)).toBeNull();
	});

	it("keeps an explicit benign file-check result available", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({
				responses: [{ key: { sha256 }, severity: "SEVERITY_UNKNOWN" }],
			}),
		});
		const client = new FileCheckClient();
		expect(await client.checkHash(sha256)).toMatchObject({
			severity: "SEVERITY_UNKNOWN",
			detectionNames: [],
		});
	});
});
