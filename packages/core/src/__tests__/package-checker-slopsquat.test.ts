import { afterEach, describe, expect, it, vi } from "vitest";
import { PackageChecker } from "../package-checker.js";

const DAY_MS = 24 * 60 * 60 * 1000;

function daysAgo(days: number): string {
	return new Date(Date.now() - days * DAY_MS).toISOString();
}

function npmPackument(createdDaysAgo: number, versionCount: number) {
	const versions: Record<string, unknown> = {};
	for (let i = 0; i < versionCount; i += 1) {
		versions[`1.0.${i}`] = { dist: { shasum: `sha1-${i}` } };
	}
	return {
		"dist-tags": { latest: `1.0.${versionCount - 1}` },
		versions,
		time: { created: daysAgo(createdDaysAgo) },
	};
}

function pypiDocument(createdDaysAgo: number, releaseCount: number) {
	const releases: Record<string, unknown> = {};
	for (let i = 0; i < releaseCount; i += 1) {
		releases[`0.${i}`] = [
			{ digests: { sha256: "a".repeat(64) }, upload_time_iso_8601: daysAgo(createdDaysAgo - i) },
		];
	}
	return { info: { version: `0.${releaseCount - 1}` }, releases };
}

/** Fake registry + downloads API; `downloads` null makes the downloads API fail. */
function mockRegistry(document: unknown, downloads: number | null) {
	const fetchMock = vi.fn(async (url: string) => {
		if (url.startsWith("https://api.npmjs.org/downloads/")) {
			return downloads === null
				? { ok: false, status: 503, json: async () => ({}) }
				: { ok: true, status: 200, json: async () => ({ downloads, package: "x" }) };
		}
		return { ok: true, status: 200, json: async () => document };
	});
	globalThis.fetch = fetchMock as unknown as typeof fetch;
	return fetchMock;
}

describe("slopsquatting signals", () => {
	const originalFetch = globalThis.fetch;
	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("reports a non-existent (hallucinated) package as not_found", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 });
		const [result] = await new PackageChecker({ fileCheckEnabled: false }).checkPackages([
			{ name: "react-quick-auth-helperz", registry: "npm" },
		]);
		expect(result).toMatchObject({ verdict: "not_found" });
		expect(result?.details).toMatch(/non-existent or misspelled/);
	});

	it("holds a young npm package with few weekly downloads", async () => {
		const fetchMock = mockRegistry(npmPackument(15, 5), 12);
		const [result] = await new PackageChecker({ fileCheckEnabled: false }).checkPackages([
			{ name: "fastapi-auth-utils", registry: "npm" },
		]);
		expect(result).toMatchObject({ verdict: "suspicious_age" });
		expect(result?.details).toMatch(/15 days ago and has low adoption \(12 downloads last week\)/);
		expect(result?.details).toMatch(/slopsquatting/);
		expect(fetchMock.mock.calls.map(([url]) => url)).toContain(
			"https://api.npmjs.org/downloads/point/last-week/fastapi-auth-utils",
		);
	});

	it("does not hold a young npm package that is already widely used", async () => {
		mockRegistry(npmPackument(15, 2), 250_000);
		const [result] = await new PackageChecker({ fileCheckEnabled: false }).checkPackages([
			{ name: "popular-new-lib", registry: "npm" },
		]);
		// Not verified clean either: without a file-reputation leg it stays unknown.
		expect(result?.verdict).toBe("unknown");
	});

	it("falls back to the version count when download counts are unavailable", async () => {
		mockRegistry(npmPackument(20, 2), null);
		const [few] = await new PackageChecker({ fileCheckEnabled: false }).checkPackages([
			{ name: "young-lib", registry: "npm" },
		]);
		expect(few).toMatchObject({ verdict: "suspicious_age" });
		expect(few?.details).toMatch(/2 published versions/);

		mockRegistry(npmPackument(20, 12), null);
		const [many] = await new PackageChecker({ fileCheckEnabled: false }).checkPackages([
			{ name: "young-busy-lib", registry: "npm" },
		]);
		expect(many?.verdict).toBe("unknown");
	});

	it("uses the release count for PyPI and never calls the npm downloads API for it", async () => {
		const fetchMock = mockRegistry(pypiDocument(10, 1), 0);
		const [result] = await new PackageChecker({ fileCheckEnabled: false }).checkPackages([
			{ name: "langchain-helper-toolz", registry: "pypi" },
		]);
		expect(result).toMatchObject({ verdict: "suspicious_age" });
		expect(result?.details).toMatch(/1 published version\)/);
		expect(fetchMock.mock.calls.some(([url]) => String(url).includes("api.npmjs.org"))).toBe(false);
	});

	it("respects the configured window, thresholds and lookup switch", async () => {
		mockRegistry(npmPackument(15, 1), 3);
		const [off] = await new PackageChecker({
			fileCheckEnabled: false,
			newPackageDays: 0,
		}).checkPackages([{ name: "young-lib", registry: "npm" }]);
		expect(off?.verdict).toBe("unknown");

		mockRegistry(npmPackument(45, 1), 3);
		const [outside] = await new PackageChecker({ fileCheckEnabled: false }).checkPackages([
			{ name: "older-lib", registry: "npm" },
		]);
		expect(outside?.verdict).toBe("unknown");
		const [widened] = await new PackageChecker({
			fileCheckEnabled: false,
			newPackageDays: 60,
		}).checkPackages([{ name: "older-lib", registry: "npm" }]);
		expect(widened?.verdict).toBe("suspicious_age");

		const fetchMock = mockRegistry(npmPackument(15, 9), 3);
		const [noLookup] = await new PackageChecker({
			fileCheckEnabled: false,
			adoptionLookup: false,
		}).checkPackages([{ name: "young-lib", registry: "npm" }]);
		expect(noLookup?.verdict).toBe("unknown");
		expect(fetchMock.mock.calls.some(([url]) => String(url).includes("api.npmjs.org"))).toBe(false);
	});

	it("keeps the unconditional hold for packages younger than seven days", async () => {
		mockRegistry(npmPackument(2, 40), 1_000_000);
		const [result] = await new PackageChecker({ fileCheckEnabled: false }).checkPackages([
			{ name: "brand-new", registry: "npm" },
		]);
		expect(result).toMatchObject({ verdict: "suspicious_age" });
		expect(result?.details).toMatch(/suspicious age/);
	});
});
