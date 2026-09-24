import { afterEach, describe, expect, it, vi } from "vitest";
import {
	MAX_REGISTRY_RESPONSE_BYTES,
	RegistryClient,
} from "../clients/package-registry.js";

describe("RegistryClient", () => {
	const originalFetch = globalThis.fetch;

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("rejects registry metadata that declares a body above the response limit", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			new Response("{}", {
				status: 200,
				headers: { "content-length": String(MAX_REGISTRY_RESPONSE_BYTES + 1) },
			}),
		);

		await expect(new RegistryClient().getPackageMetadata("express", "npm")).rejects.toThrow(
			/response exceeds the size limit/,
		);
	});

	it("bounds streamed registry metadata even when the declared length is small", async () => {
		const oversized = new Uint8Array(MAX_REGISTRY_RESPONSE_BYTES + 1);
		globalThis.fetch = vi.fn().mockResolvedValue(
			new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(oversized);
						controller.close();
					},
				}),
				{ status: 200, headers: { "content-length": "1" } },
			),
		);

		await expect(new RegistryClient().getPackageMetadata("express", "npm")).rejects.toThrow(
			/response exceeds the size limit/,
		);
	});

	describe("npm", () => {
		it("parses existing package metadata", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					"dist-tags": { latest: "4.18.2" },
					versions: {
						"4.18.2": {
							dist: {
								shasum: "abc123sha1",
								integrity: "sha512-somehash",
							},
						},
					},
					time: {
						created: "2010-12-29T19:38:25.450Z",
						"4.18.2": "2022-10-08T15:00:00.000Z",
					},
				}),
			});

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("express", "npm");
			expect(result).not.toBeNull();
			expect(result?.name).toBe("express");
			expect(result?.resolvedVersion).toBe("4.18.2");
			expect(result?.latestHash).toBe("abc123sha1");
			expect(result?.firstReleaseDate).toBeInstanceOf(Date);
		});

		it("encodes scoped package name correctly", async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					"dist-tags": { latest: "1.0.0" },
					versions: { "1.0.0": { dist: { shasum: "abc" } } },
					time: { created: "2020-01-01T00:00:00.000Z" },
				}),
			});
			globalThis.fetch = mockFetch;

			const client = new RegistryClient();
			await client.getPackageMetadata("@scope/pkg", "npm");

			const calledUrl = (mockFetch.mock.calls[0] as [string])[0];
			expect(calledUrl).toContain("@scope%2fpkg");
		});

		it("resolves specific version hash when version exists", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					"dist-tags": { latest: "1.0.0" },
					versions: {
						"0.2.3": { dist: { shasum: "old-version-hash" } },
						"1.0.0": { dist: { shasum: "latest-hash" } },
					},
					time: { created: "2020-01-01T00:00:00.000Z" },
				}),
			});

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("pkg", "npm", "0.2.3");
			expect(result).not.toBeNull();
			expect(result?.resolvedVersion).toBe("0.2.3");
			expect(result?.latestHash).toBe("old-version-hash");
			expect(result?.requestedVersionFound).toBe(true);
		});

		it("resolves dist-tag (e.g. @latest) to actual version", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					"dist-tags": { latest: "1.0.0", next: "2.0.0-beta.1" },
					versions: {
						"1.0.0": { dist: { shasum: "latest-hash" } },
						"2.0.0-beta.1": { dist: { shasum: "next-hash" } },
					},
					time: { created: "2020-01-01T00:00:00.000Z" },
				}),
			});

			const client = new RegistryClient();

			const resultLatest = await client.getPackageMetadata("pkg", "npm", "latest");
			expect(resultLatest).not.toBeNull();
			expect(resultLatest?.resolvedVersion).toBe("1.0.0");
			expect(resultLatest?.latestHash).toBe("latest-hash");
			expect(resultLatest?.requestedVersionFound).toBe(true);

			const resultNext = await client.getPackageMetadata("pkg", "npm", "next");
			expect(resultNext).not.toBeNull();
			expect(resultNext?.resolvedVersion).toBe("2.0.0-beta.1");
			expect(resultNext?.latestHash).toBe("next-hash");
			expect(resultNext?.requestedVersionFound).toBe(true);
		});

		it("falls back to latest when requested version missing", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					"dist-tags": { latest: "1.0.0" },
					versions: {
						"1.0.0": { dist: { shasum: "latest-hash" } },
					},
					time: { created: "2020-01-01T00:00:00.000Z" },
				}),
			});

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("pkg", "npm", "0.2.3");
			expect(result).not.toBeNull();
			expect(result?.resolvedVersion).toBe("1.0.0");
			expect(result?.requestedVersionFound).toBe(false);
		});

		it("requestedVersionFound is true when no version requested", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					"dist-tags": { latest: "1.0.0" },
					versions: { "1.0.0": { dist: { shasum: "abc" } } },
					time: { created: "2020-01-01T00:00:00.000Z" },
				}),
			});

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("pkg", "npm");
			expect(result?.requestedVersionFound).toBe(true);
		});

		it("returns null on 404", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 404,
			});

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("nonexistent-pkg-xyz", "npm");
			expect(result).toBeNull();
		});

		it("throws on timeout", async () => {
			globalThis.fetch = vi.fn().mockRejectedValue(new Error("timeout"));

			const client = new RegistryClient();
			await expect(client.getPackageMetadata("express", "npm")).rejects.toThrow("timeout");
		});

		it("rejects invalid package name (SSRF attempt)", async () => {
			const mockFetch = vi.fn();
			globalThis.fetch = mockFetch;

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("../../etc/passwd", "npm");
			expect(result).toBeNull();
			expect(mockFetch).not.toHaveBeenCalled();
		});
	});

	describe("pypi", () => {
		it("parses existing package metadata", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					info: { version: "2.31.0" },
					releases: {
						"2.31.0": [
							{
								digests: { sha256: "a".repeat(64) },
								upload_time_iso_8601: "2023-05-22T00:00:00.000Z",
							},
						],
						"1.0.0": [
							{
								digests: { sha256: "b".repeat(64) },
								upload_time_iso_8601: "2012-01-01T00:00:00.000Z",
							},
						],
					},
				}),
			});

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("requests", "pypi");
			expect(result).not.toBeNull();
			expect(result?.name).toBe("requests");
			expect(result?.resolvedVersion).toBe("2.31.0");
			expect(result?.latestHash).toBe("a".repeat(64));
			expect(result?.hashAlgorithm).toBe("sha256");
			// First release should be the earliest
			expect(result?.firstReleaseDate?.getUTCFullYear()).toBe(2012);
		});

		it.each(["a".repeat(63), "a".repeat(65), "g".repeat(64)])(
			"rejects malformed SHA-256 digest %s",
			async (sha256) => {
				globalThis.fetch = vi.fn().mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => ({
						info: { version: "2.31.0" },
						releases: {
							"2.31.0": [{ digests: { sha256 } }],
						},
					}),
				});

				await expect(new RegistryClient().getPackageMetadata("requests", "pypi")).rejects.toThrow(
					/Malformed PyPI registry response/,
				);
			},
		);

		it("returns null on 404", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 404,
			});

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("nonexistent-pkg", "pypi");
			expect(result).toBeNull();
		});

		it("throws on 500", async () => {
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 500,
			});

			const client = new RegistryClient();
			await expect(client.getPackageMetadata("requests", "pypi")).rejects.toThrow(
				"PyPI registry HTTP 500",
			);
		});

		it("rejects invalid package name", async () => {
			const mockFetch = vi.fn();
			globalThis.fetch = mockFetch;

			const client = new RegistryClient();
			const result = await client.getPackageMetadata("../../etc/passwd", "pypi");
			expect(result).toBeNull();
			expect(mockFetch).not.toHaveBeenCalled();
		});
	});
});
