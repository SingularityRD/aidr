import { afterEach, describe, expect, it, vi } from "vitest";
import { FileCheckClient } from "../clients/file-check.js";
import { DetectionLegUnavailableError } from "../detection-leg.js";

describe("FileCheckClient", () => {
	const originalFetch = globalThis.fetch;

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("returns SEVERITY_MALWARE with detection names", async () => {
		const hash = "5da2e940ce5288dfe73deca2723544c19ce4e3dc8fe32880801c6675de12db0a";
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				responses: [
					{
						key: { sha256: hash },
						severity: "SEVERITY_MALWARE",
						malware_name: ["Malware.Generic [InfoStl]"],
					},
				],
			}),
		});

		const client = new FileCheckClient();
		const result = await client.checkHash(hash);
		expect(result).not.toBeNull();
		expect(result?.severity).toBe("SEVERITY_MALWARE");
		expect(result?.detectionNames).toContain("Malware.Generic [InfoStl]");
	});

	it("correlates a keyed SHA-256 response case-insensitively", async () => {
		const hash = "AB".repeat(32);
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				responses: [
					{
						key: { sha256: hash.toLowerCase() },
						severity: "SEVERITY_UNKNOWN",
					},
				],
			}),
		});

		await expect(new FileCheckClient().checkHash(hash)).resolves.toMatchObject({
			severity: "SEVERITY_UNKNOWN",
		});
	});

	it("preserves SEVERITY_UNKNOWN without claiming a benign classification", async () => {
		const hash = "ab".repeat(32);
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				responses: [
					{
						key: { sha256: hash },
						severity: "SEVERITY_UNKNOWN",
					},
				],
			}),
		});

		const client = new FileCheckClient();
		const result = await client.checkHash(hash);
		expect(result).not.toBeNull();
		expect(result?.severity).toBe("SEVERITY_UNKNOWN");
		expect(result?.detectionNames).toHaveLength(0);
	});

	it("returns SEVERITY_MALWARE with PUP detection name", async () => {
		const hash = "de".repeat(32);
		// PUP is indicated via detection names, not a separate severity
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				responses: [
					{
						key: { sha256: hash },
						severity: "SEVERITY_MALWARE",
						malware_name: ["PUP.Generic [PUP]"],
					},
				],
			}),
		});

		const client = new FileCheckClient();
		const result = await client.checkHash(hash);
		expect(result).not.toBeNull();
		expect(result?.severity).toBe("SEVERITY_MALWARE");
		expect(result?.detectionNames).toContain("PUP.Generic [PUP]");
	});

	it.each([
		["missing", { severity: "SEVERITY_MALWARE", malware_name: ["Trojan.Test"] }],
		[
			"mismatched",
			{
				key: { sha256: "cd".repeat(32) },
				severity: "SEVERITY_MALWARE",
				malware_name: ["Trojan.Test"],
			},
		],
	])("returns unavailable for a single response with a %s hash", async (_label, response) => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ responses: [response] }),
		});
		globalThis.fetch = mockFetch;

		await expect(new FileCheckClient().checkHash("ab".repeat(32))).resolves.toBeNull();
		expect(mockFetch).toHaveBeenCalledOnce();
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
			const first = results[0];
			const second = results[1];
			if (!first || !second) throw new Error("Expected two file-check results");
			expect(first.sha256).toBe(hash1);
			expect(first.severity).toBe("SEVERITY_MALWARE");
			expect(first.detectionNames).toContain("Trojan:Win32/Test");
			expect(second.sha256).toBe(hash2);
			expect(second.severity).toBe("SEVERITY_UNKNOWN");
			expect(second.detectionNames).toHaveLength(0);
		});

		it("correlates SHA-256 batches case-insensitively without weakening validation", async () => {
			const hash = "CD".repeat(32);
			globalThis.fetch = vi
				.fn()
				.mockResolvedValueOnce({
					ok: true,
					json: async () => ({
						responses: [
							{
								key: { sha256: hash.toLowerCase() },
								severity: "SEVERITY_UNKNOWN",
							},
						],
					}),
				})
				.mockResolvedValueOnce({
					ok: true,
					json: async () => ({
						responses: [
							{
								key: { sha256: hash.slice(0, -1).toLowerCase() },
								severity: "SEVERITY_UNKNOWN",
							},
						],
					}),
				});

			const client = new FileCheckClient();
			await expect(client.checkHashes([hash])).resolves.toEqual([
				{ sha256: hash, severity: "SEVERITY_UNKNOWN", detectionNames: [] },
			]);
			await expect(client.checkHashes([hash])).rejects.toMatchObject({
				leg: "file_reputation",
				reason: "malformed file reputation response",
				uncheckedCount: 1,
			});
		});

		it("deduplicates canonical hashes and restores caller order, spelling, and multiplicity", async () => {
			const lower = "ab".repeat(32);
			const upper = lower.toUpperCase();
			const mockFetch = vi.fn().mockImplementation(async (_url, _init: RequestInit) => {
				return {
					ok: true,
					json: async () => ({
						responses: [
							{
								key: { sha256: lower },
								severity: "SEVERITY_UNKNOWN",
							},
						],
					}),
				};
			});
			globalThis.fetch = mockFetch;

			const results = await new FileCheckClient().checkHashes([upper, lower, upper]);

			expect(results.map((result) => result.sha256)).toEqual([upper, lower, upper]);
			const request = JSON.parse(String(mockFetch.mock.calls[0]?.[1]?.body));
			expect(request.requests).toEqual([{ key: { sha256: upper } }]);
		});

		it("counts every duplicate as unchecked when its canonical request fails", async () => {
			const hash = "ef".repeat(32);
			globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503 });

			await expect(new FileCheckClient().checkHashes([hash, hash])).rejects.toMatchObject({
				leg: "file_reputation",
				uncheckedCount: 2,
			});
			expect(globalThis.fetch).toHaveBeenCalledOnce();
		});

		it("rejects malformed digests before contacting the provider", async () => {
			globalThis.fetch = vi.fn();

			await expect(new FileCheckClient().checkHashes(["abc123"])).rejects.toMatchObject({
				leg: "file_reputation",
				reason: "invalid SHA-256 digest",
				uncheckedCount: 1,
			});
			expect(globalThis.fetch).not.toHaveBeenCalled();
		});

		it("batches in groups of 50", async () => {
			const mockFetch = vi.fn().mockImplementation(async (_url, init: RequestInit) => {
				const payload = JSON.parse(String(init.body));
				return {
					ok: true,
					json: async () => ({
						responses: payload.requests.map((request: { key: { sha256: string } }) => ({
							key: request.key,
							severity: "SEVERITY_UNKNOWN",
						})),
					}),
				};
			});
			globalThis.fetch = mockFetch;

			const hashes = Array.from({ length: 120 }, (_, i) => i.toString(16).padStart(64, "0"));
			const client = new FileCheckClient();
			await client.checkHashes(hashes);

			expect(mockFetch).toHaveBeenCalledTimes(3);
		});

		it("limits concurrent batches and preserves result order", async () => {
			const releases: Array<() => void> = [];
			let active = 0;
			let peak = 0;
			const mockFetch = vi.fn().mockImplementation(async (_url, init: RequestInit) => {
				const payload = JSON.parse(String(init.body));
				active++;
				peak = Math.max(peak, active);
				await new Promise<void>((resolve) => releases.push(resolve));
				active--;
				return {
					ok: true,
					json: async () => ({
						responses: payload.requests.map((request: { key: { sha256: string } }) => ({
							key: request.key,
							severity: "SEVERITY_UNKNOWN",
						})),
					}),
				};
			});
			globalThis.fetch = mockFetch;

			const hashes = Array.from({ length: 201 }, (_, i) => i.toString(16).padStart(64, "0"));
			const pending = new FileCheckClient().checkHashes(hashes);
			await vi.waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(4));
			expect(peak).toBe(4);

			releases[3]?.();
			await vi.waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(5));
			for (const release of releases) release();

			const results = await pending;
			expect(peak).toBe(4);
			expect(results.map((result) => result.sha256)).toEqual(hashes);
		});

		it("rejects an empty or partial successful response", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => ({ responses: [] }),
			});
			const client = new FileCheckClient();
			await expect(client.checkHashes(["a".repeat(64)])).rejects.toMatchObject({
				leg: "file_reputation",
				uncheckedCount: 1,
			});
		});

		it("bounds the response before parsing JSON", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue(
				new Response("{}", {
					headers: { "content-length": String(1024 * 1024 + 1) },
				}),
			);
			const client = new FileCheckClient();
			await expect(client.checkHashes(["a".repeat(64)])).rejects.toBeInstanceOf(
				DetectionLegUnavailableError,
			);
		});

		// These previously asserted `results === []` and were named "fail-open".
		// An empty array is the same value returned when every hash was checked and
		// none was malicious, so a rejecting or unreachable endpoint was reported to
		// the user as "no malicious files found". The caller may still degrade - the
		// plugin scanner now reports the gap explicitly - but the client must not
		// make that choice silently. See detection-leg.ts.
		it("throws on API error instead of reporting nothing found", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 500,
			});

			const client = new FileCheckClient();
			await expect(client.checkHashes(["a".repeat(64)])).rejects.toBeInstanceOf(
				DetectionLegUnavailableError,
			);
		});

		it("throws on timeout instead of reporting nothing found", async () => {
			globalThis.fetch = vi.fn().mockRejectedValue(new Error("timeout"));

			const client = new FileCheckClient();
			await expect(client.checkHashes(["a".repeat(64)])).rejects.toBeInstanceOf(
				DetectionLegUnavailableError,
			);
		});

		it("keeps detections from successful batches AND reports the batches that failed", async () => {
			// Partial coverage is the subtle case: the detections are real evidence
			// and must survive, while the unchecked hashes are a gap that must not be
			// mistaken for a clean result. Both must come out of the same call.
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
							{ key: { sha256: "not-requested" }, severity: "SEVERITY_UNKNOWN" },
						],
					}),
				};
			});

			const client = new FileCheckClient();
			const error = await client.checkHashes(hashes).catch((e: unknown) => e);

			expect(error).toBeInstanceOf(DetectionLegUnavailableError);
			const legError = error as DetectionLegUnavailableError;

			// The real detection survived.
			const partial = legError.partialResults as Array<{ sha256: string; severity: string }>;
			expect(partial).toHaveLength(1);
			expect(partial[0]?.sha256).toBe(hash0);
			expect(partial[0]?.severity).toBe("SEVERITY_MALWARE");

			// And the gap is quantified, not hidden.
			expect(legError.uncheckedCount).toBe(hashes.length - partial.length);
			expect(partial.length + legError.uncheckedCount).toBeLessThanOrEqual(hashes.length);
			expect(legError.reason.length).toBeGreaterThan(0);
			expect(legError.leg).toBe("file_reputation");
		});
	});

	it("requires HTTPS unless loopback HTTP is explicitly enabled", () => {
		expect(() => new FileCheckClient({ endpoint: "http://reputation.example.test" })).toThrow(
			/HTTPS/,
		);
		expect(
			() => new FileCheckClient({ endpoint: "https://user:secret@example.test/file-check" }),
		).toThrow(/credentials/);
		expect(
			() =>
				new FileCheckClient({
					endpoint: "http://127.0.0.1:3000/file-check",
					allow_insecure_loopback: true,
				}),
		).not.toThrow();
	});
});
