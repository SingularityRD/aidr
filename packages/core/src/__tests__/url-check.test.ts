import { afterEach, describe, expect, it, vi } from "vitest";
import { UrlCheckClient } from "../clients/url-check.js";
import { DetectionLegUnavailableError } from "../detection-leg.js";
import type { UrlCheckResult } from "../types.js";

describe("UrlCheckClient", () => {
	const originalFetch = globalThis.fetch;
	const cleanAnswers = (init: RequestInit) => {
		const payload = JSON.parse(String(init.body));
		return {
			answers: payload.queries.map((query: { key: { "url-like": string } }) => ({
				key: query.key["url-like"],
				coverage: "covered",
				cache_valid_until: new Date(Date.now() + 60_000).toISOString(),
				result: {
					success: {
						classification: { result: {} },
						flags: [],
						coverage: "covered",
					},
				},
			})),
		};
	};

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("returns empty for empty URL list", async () => {
		const client = new UrlCheckClient();
		const results = await client.checkUrls([]);
		expect(results).toEqual([]);
	});

	it("parses malicious URL response", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				answers: [
					{
						key: "http://malware.test",
						result: {
							success: {
								classification: {
									result: {
										malicious: {
											findings: [
												{
													"severity-name": "malware",
													"type-name": "trojan",
												},
											],
										},
									},
								},
								flags: [],
							},
						},
					},
				],
			}),
		});

		const client = new UrlCheckClient();
		const results = await client.checkUrls(["http://malware.test"]);
		expect(results).toHaveLength(1);
		expect(results[0]?.isMalicious).toBe(true);
		expect(results[0]?.findings).toHaveLength(1);
		expect(results[0]?.findings[0]?.severityName).toBe("malware");
	});

	it("parses clean URL response", async () => {
		const cacheValidUntil = new Date(Date.now() + 60_000).toISOString();
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				answers: [
					{
						key: "http://safe.test",
						coverage: "covered",
						cache_valid_until: cacheValidUntil,
						result: {
							success: {
								classification: {
									result: {},
								},
								flags: [],
								coverage: "covered",
							},
						},
					},
				],
			}),
		});

		const client = new UrlCheckClient();
		const results = await client.checkUrls(["http://safe.test"]);
		expect(results).toHaveLength(1);
		expect(results[0]?.isMalicious).toBe(false);
		expect(results[0]?.findings).toHaveLength(0);
		expect(results[0]?.cacheValidUntil).toBe(Date.parse(cacheValidUntil));
	});

	it.each([
		["missing", undefined],
		["expired", "2020-01-01T00:00:00.000Z"],
	])("treats a covered clean response with %s source freshness as unavailable", async (_label, deadline) => {
		const url = "https://stale-safe.test";
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				answers: [
					{
						key: url,
						coverage: "covered",
						...(deadline ? { cache_valid_until: deadline } : {}),
						result: {
							success: {
								classification: { result: {} },
								flags: [],
								coverage: "covered",
							},
						},
					},
				],
			}),
		});

		await expect(new UrlCheckClient().checkUrls([url])).rejects.toBeInstanceOf(
			DetectionLegUnavailableError,
		);
	});

	it("treats a clean response expiring in transit as unavailable at the deadline", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		try {
			const now = new Date("2026-09-24T00:00:00.000Z");
			vi.setSystemTime(now);
			const url = "https://expires-now.test";
			globalThis.fetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => ({
					answers: [
						{
							key: url,
							coverage: "covered",
							cache_valid_until: now.toISOString(),
							result: {
								success: {
									classification: { result: {} },
									flags: [],
									coverage: "covered",
								},
							},
						},
					],
				}),
			});

			await expect(new UrlCheckClient().checkUrls([url])).rejects.toBeInstanceOf(
				DetectionLegUnavailableError,
			);
		} finally {
			vi.useRealTimers();
		}
	});

	it("parses flagged URL response", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				answers: [
					{
						key: "http://suspicious.test",
						coverage: "covered",
						result: {
							success: {
								classification: { result: {} },
								flags: ["TYPOSQUATTING"],
								coverage: "covered",
							},
						},
					},
				],
			}),
		});

		const client = new UrlCheckClient();
		const results = await client.checkUrls(["http://suspicious.test"]);
		expect(results).toHaveLength(1);
		expect(results[0]?.flags).toContain("TYPOSQUATTING");
	});

	// These two cases previously asserted `results === []` and were named
	// "fail-open". That expectation encoded a false-clean: an empty array is the
	// same value returned when every URL was checked and none was malicious, so an
	// unreachable or rejecting endpoint was reported to the user as "no malicious
	// URLs found". The caller may still choose to degrade - the evaluator already
	// wraps this call in try/catch - but the client must not make that choice
	// silently on the caller's behalf. See detection-leg.ts.
	it("throws on fetch error instead of reporting nothing found", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("network error"));

		const client = new UrlCheckClient();
		await expect(client.checkUrls(["http://any.test"])).rejects.toBeInstanceOf(
			DetectionLegUnavailableError,
		);
	});

	it("throws on non-ok response instead of reporting nothing found", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 500,
		});

		const client = new UrlCheckClient();
		await expect(client.checkUrls(["http://any.test"])).rejects.toBeInstanceOf(
			DetectionLegUnavailableError,
		);
	});

	it("reports a URL with no feed coverage as unknown instead of clean", async () => {
		// The endpoint answers 200 for a URL the tenant's reputation store holds no
		// row for, and marks it explicitly (`unknown` classification plus a
		// `no_data` coverage indicator). Reading that as an empty classification is
		// the false-clean: "we have no data about this URL" reached the caller as
		// "this URL is clean".
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				coverage: "partial",
				answers: [
					{
						key: "http://unknown.test",
						coverage: "no_data",
						result: {
							success: {
								classification: { result: { unknown: { reason: "no_reputation_row" } } },
								flags: [],
								coverage: "no_data",
							},
						},
					},
					{
						key: "http://malware.test",
						coverage: "covered",
						result: {
							success: {
								classification: {
									result: {
										malicious: {
											findings: [{ "severity-name": "malware", "type-name": "trojan" }],
										},
									},
								},
								flags: [],
								coverage: "covered",
							},
						},
					},
				],
			}),
		});

		const client = new UrlCheckClient();
		const error = await client
			.checkUrls(["http://unknown.test", "http://malware.test"])
			.catch((e: unknown) => e);

		expect(error).toBeInstanceOf(DetectionLegUnavailableError);
		expect((error as DetectionLegUnavailableError).leg).toBe("url_reputation");
		expect((error as DetectionLegUnavailableError).reason).toMatch(/no reputation feed coverage/i);
		expect((error as DetectionLegUnavailableError).uncheckedCount).toBe(1);
		// The URL the feed DID hold a row for keeps its real detection: the gap is
		// reported without throwing away the evidence found alongside it.
		const partial = (error as DetectionLegUnavailableError).partialResults as UrlCheckResult[];
		expect(partial).toHaveLength(1);
		expect(partial[0]?.url).toBe("http://malware.test");
		expect(partial[0]?.isMalicious).toBe(true);
	});

	it("does not treat an empty classification without positive coverage as clean", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				coverage: "complete",
				answers: [
					{
						key: "https://legacy.test",
						result: {
							success: {
								classification: { result: {} },
								flags: [],
							},
						},
					},
				],
			}),
		});

		const error = await new UrlCheckClient()
			.checkUrls(["https://legacy.test"])
			.catch((cause: unknown) => cause);

		expect(error).toBeInstanceOf(DetectionLegUnavailableError);
		expect((error as DetectionLegUnavailableError).uncheckedCount).toBe(1);
		expect((error as DetectionLegUnavailableError).partialResults).toEqual([]);
	});

	it("rejects an empty or partial successful response instead of treating it as complete", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ answers: [] }),
		});
		const client = new UrlCheckClient();
		await expect(client.checkUrls(["https://missing.test"])).rejects.toMatchObject({
			leg: "url_reputation",
			uncheckedCount: 1,
		});
	});

	it("keeps valid results from a malformed batch without double-counting unchecked URLs", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				answers: [
					{
						key: "https://covered.test",
						coverage: "covered",
						cache_valid_until: new Date(Date.now() + 60_000).toISOString(),
						result: {
							success: {
								classification: { result: {} },
								flags: [],
								coverage: "covered",
							},
						},
					},
					{ key: "https://missing.test", result: "invalid" },
				],
			}),
		});
		const requested = ["https://covered.test", "https://missing.test"];
		const error = await new UrlCheckClient().checkUrls(requested).catch((cause: unknown) => cause);

		expect(error).toBeInstanceOf(DetectionLegUnavailableError);
		const legError = error as DetectionLegUnavailableError;
		expect(legError.partialResults).toHaveLength(1);
		expect(legError.uncheckedCount).toBe(1);
		expect(legError.partialResults.length + legError.uncheckedCount).toBeLessThanOrEqual(
			requested.length,
		);
	});

	it("bounds the response before parsing JSON", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			new Response("{}", {
				headers: { "content-length": String(1024 * 1024 + 1) },
			}),
		);
		const client = new UrlCheckClient();
		await expect(client.checkUrls(["https://example.test"])).rejects.toBeInstanceOf(
			DetectionLegUnavailableError,
		);
	});

	it("requires HTTPS unless loopback HTTP is explicitly enabled", () => {
		expect(() => new UrlCheckClient({ endpoint: "http://reputation.example.test" })).toThrow(
			/HTTPS/,
		);
		expect(
			() => new UrlCheckClient({ endpoint: "https://user:secret@example.test/url-check" }),
		).toThrow(/credentials/);
		expect(
			() =>
				new UrlCheckClient({
					endpoint: "http://127.0.0.1:3000/url-check",
					allow_insecure_loopback: true,
				}),
		).not.toThrow();
	});

	it("sends request payload with kebab-case field names", async () => {
		const mockFetch = vi.fn().mockImplementation(async (_url, init) => ({
			ok: true,
			json: async () => cleanAnswers(init),
		}));
		globalThis.fetch = mockFetch;

		const client = new UrlCheckClient();
		await client.checkUrls(["http://example.test"]);

		expect(mockFetch).toHaveBeenCalledTimes(1);
		const requestInit = mockFetch.mock.calls[0]?.[1] as RequestInit | undefined;
		const body = JSON.parse(String(requestInit?.body));

		// Backend uses #[serde(rename_all = "kebab-case")] — snake_case fields are silently ignored.
		expect(body).toHaveProperty("client-info");
		expect(body["client-info"]).toHaveProperty("product-name");
		expect(body["client-info"]).toHaveProperty("product-version");
		expect(body).not.toHaveProperty("client_info");
	});

	it("batches URLs in groups of 50", async () => {
		const mockFetch = vi.fn().mockImplementation(async (_url, init) => ({
			ok: true,
			json: async () => cleanAnswers(init),
		}));
		globalThis.fetch = mockFetch;

		const urls = Array.from({ length: 120 }, (_, i) => `http://url${i}.test`);
		const client = new UrlCheckClient();
		await client.checkUrls(urls);

		// 120 URLs → 3 batches (50, 50, 20)
		expect(mockFetch).toHaveBeenCalledTimes(3);
	});

	it("deduplicates provider work while preserving duplicate result order", async () => {
		const mockFetch = vi.fn().mockImplementation(async (_url, init) => ({
			ok: true,
			json: async () => cleanAnswers(init),
		}));
		globalThis.fetch = mockFetch;
		const urls = ["https://one.test", "https://two.test", "https://one.test"];

		const results = await new UrlCheckClient().checkUrls(urls);

		expect(JSON.parse(String(mockFetch.mock.calls[0]?.[1]?.body)).queries).toHaveLength(2);
		expect(results.map((result) => result.url)).toEqual(urls);
	});

	it("withholds URLs with query, fragment, or user info and reports incomplete coverage", async () => {
		const mockFetch = vi.fn().mockImplementation(async (_url, init) => ({
			ok: true,
			json: async () => cleanAnswers(init),
		}));
		globalThis.fetch = mockFetch;
		const withheld = [
			"https://example.test/path?access_token=private-value",
			"https://example.test/path#private-fragment",
			"https://private-user:private-password@example.test/path",
		];
		const safe = "https://example.test/public";

		const error = await new UrlCheckClient()
			.checkUrls([...withheld, safe])
			.catch((cause: unknown) => cause);

		expect(mockFetch).toHaveBeenCalledTimes(1);
		const requestBody = String(mockFetch.mock.calls[0]?.[1]?.body);
		for (const secret of ["access_token", "private-value", "private-fragment", "private-user", "private-password"]) {
			expect(requestBody).not.toContain(secret);
		}
		expect(requestBody).toContain(safe);
		expect(error).toBeInstanceOf(DetectionLegUnavailableError);
		expect((error as DetectionLegUnavailableError).uncheckedCount).toBe(withheld.length);
		expect((error as DetectionLegUnavailableError).partialResults).toEqual([
			expect.objectContaining({ url: safe, isMalicious: false }),
		]);
	});

	it("sends query parameters only after explicit opt-in and never sends user info or fragments", async () => {
		const mockFetch = vi.fn().mockImplementation(async (_url, init) => ({
			ok: true,
			json: async () => cleanAnswers(init),
		}));
		globalThis.fetch = mockFetch;
		const url = "https://example.test/path?campaign=demo";

		await expect(
			new UrlCheckClient({ include_query_parameters: true }).checkUrls([url]),
		).resolves.toEqual([expect.objectContaining({ url, isMalicious: false })]);
		expect(String(mockFetch.mock.calls[0]?.[1]?.body)).toContain("campaign=demo");

		mockFetch.mockClear();
		const privateUrl = "https://user:password@example.test/path?campaign=demo#fragment-secret";
		const error = await new UrlCheckClient({ include_query_parameters: true })
			.checkUrls([privateUrl])
			.catch((cause: unknown) => cause);
		expect(mockFetch).not.toHaveBeenCalled();
		expect(error).toBeInstanceOf(DetectionLegUnavailableError);
		expect((error as DetectionLegUnavailableError).uncheckedCount).toBe(1);
	});

	it("limits concurrent batches and preserves result order", async () => {
		const releases: Array<() => void> = [];
		let active = 0;
		let peak = 0;
		const mockFetch = vi.fn().mockImplementation(async (_url, init: RequestInit) => {
			active++;
			peak = Math.max(peak, active);
			await new Promise<void>((resolve) => releases.push(resolve));
			active--;
			return { ok: true, json: async () => cleanAnswers(init) };
		});
		globalThis.fetch = mockFetch;

		const urls = Array.from({ length: 201 }, (_, i) => `http://url${i}.test`);
		const pending = new UrlCheckClient().checkUrls(urls);
		await vi.waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(4));
		expect(peak).toBe(4);

		releases[3]?.();
		await vi.waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(5));
		for (const release of releases) release();

		const results = await pending;
		expect(peak).toBe(4);
		expect(results.map((result) => result.url)).toEqual(urls);
	});
});
