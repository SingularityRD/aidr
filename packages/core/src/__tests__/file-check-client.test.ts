import { afterEach, describe, expect, it, vi } from "vitest";
import { FileCheckClient } from "../clients/file-check.js";

describe("FileCheckClient", () => {
	const originalFetch = globalThis.fetch;

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("returns SEVERITY_MALWARE with detection names", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				responses: [
					{
						severity: "SEVERITY_MALWARE",
						malware_name: ["Malware.Generic [InfoStl]"],
					},
				],
			}),
		});

		const client = new FileCheckClient();
		const result = await client.checkHash(
			"5da2e940ce5288dfe73deca2723544c19ce4e3dc8fe32880801c6675de12db0a",
		);
		expect(result).not.toBeNull();
		expect(result?.severity).toBe("SEVERITY_MALWARE");
		expect(result?.detectionNames).toContain("Malware.Generic [InfoStl]");
	});

	it("returns SEVERITY_UNKNOWN for clean hash", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				responses: [
					{
						severity: "SEVERITY_UNKNOWN",
					},
				],
			}),
		});

		const client = new FileCheckClient();
		const result = await client.checkHash("abc123");
		expect(result).not.toBeNull();
		expect(result?.severity).toBe("SEVERITY_UNKNOWN");
		expect(result?.detectionNames).toHaveLength(0);
	});

	it("returns SEVERITY_MALWARE with PUP detection name", async () => {
		// PUP is indicated via detection names, not a separate severity
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				responses: [
					{
						severity: "SEVERITY_MALWARE",
						malware_name: ["PUP.Generic [PUP]"],
					},
				],
			}),
		});

		const client = new FileCheckClient();
		const result = await client.checkHash("def456");
		expect(result).not.toBeNull();
		expect(result?.severity).toBe("SEVERITY_MALWARE");
		expect(result?.detectionNames).toContain("PUP.Generic [PUP]");
	});

	it("returns null on API error (fail-open)", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 500,
		});

		const client = new FileCheckClient();
		const result = await client.checkHash("abc123");
		expect(result).toBeNull();
	});

	it("returns null on timeout (fail-open)", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("timeout"));

		const client = new FileCheckClient();
		const result = await client.checkHash("abc123");
		expect(result).toBeNull();
	});

	it("returns null on empty responses array", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ responses: [] }),
		});

		const client = new FileCheckClient();
		const result = await client.checkHash("abc123");
		expect(result).toBeNull();
	});

	describe("checkHashes (batch)", () => {
		it("returns empty for empty input", async () => {
			const client = new FileCheckClient();
			const results = await client.checkHashes([]);
			expect(results).toEqual([]);
		});

		it("returns results with SHA256 correlation", async () => {
			const hash1 = "aaaa".repeat(16);
			const hash2 = "bbbb".repeat(16);

			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => ({
					responses: [
						{
							key: { sha256: hash1 },
							severity: "SEVERITY_MALWARE",
							malware_name: ["Trojan:Win32/Test"],
						},
						{
							key: { sha256: hash2 },
							severity: "SEVERITY_UNKNOWN",
						},
					],
				}),
			});

			const client = new FileCheckClient();
			const results = await client.checkHashes([hash1, hash2]);

			expect(results).toHaveLength(2);
			expect(results[0].sha256).toBe(hash1);
			expect(results[0].severity).toBe("SEVERITY_MALWARE");
			expect(results[0].detectionNames).toContain("Trojan:Win32/Test");
			expect(results[1].sha256).toBe(hash2);
			expect(results[1].severity).toBe("SEVERITY_UNKNOWN");
			expect(results[1].detectionNames).toHaveLength(0);
		});

		it("batches in groups of 50", async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => ({ responses: [] }),
			});
			globalThis.fetch = mockFetch;

			const hashes = Array.from({ length: 120 }, (_, i) => i.toString(16).padStart(64, "0"));
			const client = new FileCheckClient();
			await client.checkHashes(hashes);

			expect(mockFetch).toHaveBeenCalledTimes(3);
		});

		it("returns empty on API error (fail-open)", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 500,
			});

			const client = new FileCheckClient();
			const results = await client.checkHashes(["abc123"]);
			expect(results).toEqual([]);
		});

		it("returns empty on timeout (fail-open)", async () => {
			globalThis.fetch = vi.fn().mockRejectedValue(new Error("timeout"));

			const client = new FileCheckClient();
			const results = await client.checkHashes(["abc123"]);
			expect(results).toEqual([]);
		});

		it("preserves results from successful batches when one batch fails", async () => {
			const hashes = Array.from({ length: 75 }, (_, i) => i.toString(16).padStart(64, "0"));
			const hash0 = hashes[0];

			let callCount = 0;
			globalThis.fetch = vi.fn().mockImplementation(async () => {
				callCount++;
				if (callCount === 2) {
					throw new Error("network error");
				}
				return {
					ok: true,
					json: async () => ({
						responses: [
							{
								key: { sha256: hash0 },
								severity: "SEVERITY_MALWARE",
								malware_name: ["Trojan:Win32/Test"],
							},
						],
					}),
				};
			});

			const client = new FileCheckClient();
			const results = await client.checkHashes(hashes);

			expect(results).toHaveLength(1);
			expect(results[0].sha256).toBe(hash0);
			expect(results[0].severity).toBe("SEVERITY_MALWARE");
		});
	});
});
