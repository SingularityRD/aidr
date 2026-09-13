import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { rm } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FileCheckClient } from "../clients/file-check.js";
import { UrlCheckClient } from "../clients/url-check.js";
import { DetectionLegUnavailableError } from "../detection-leg.js";
import { PackageChecker } from "../package-checker.js";
import {
	canonicalReputationFeedManifest,
	canonicalReputationFeedPayload,
	type ReputationFeedLoadOptions,
	type ReputationFeedPayload,
	updateReputationFeed,
} from "../reputation-feed.js";
import { makeTmpDir } from "./test-utils.js";

const NOW = new Date("2026-09-12T12:00:00.000Z");
const SHA256 = "a".repeat(64);

describe("signed reputation feed consumers", () => {
	let storeDir: string;
	let loadOptions: ReputationFeedLoadOptions;
	const originalFetch = globalThis.fetch;

	beforeEach(async () => {
		storeDir = await makeTmpDir();
		const keys = generateKeyPairSync("ed25519");
		loadOptions = {
			storeDir,
			feedId: "enterprise-reputation",
			trustedKeys: { key1: keys.publicKey.export({ format: "pem", type: "spki" }).toString() },
			now: NOW,
		};
		const payload: ReputationFeedPayload = {
			schema_version: 1,
			records: [
			{ id: "bad-domain", kind: "domain", indicator: "malicious.example", verdict: "deny", severity: "critical" },
			{ id: "bad-file", kind: "file_sha256", indicator: SHA256, verdict: "deny" },
			{ id: "bad-package-name", kind: "package_name", indicator: "npm:bad-pkg", verdict: "deny" },
			{ id: "bad-package-hash", kind: "package_sha256", indicator: "b".repeat(64), verdict: "deny" },
		] };
		const payloadJson = canonicalReputationFeedPayload(payload);
		const manifest = {
			schema_version: 1 as const,
			feed_id: "enterprise-reputation",
			version: "1.0.0",
			sequence: 1,
			issued_at: NOW.toISOString(),
			expires_at: new Date(NOW.getTime() + 86_400_000).toISOString(),
			key_id: "key1",
			provenance: { publisher: "Test Lab", dataset: "Test Dataset", upstream_revision: "1" },
			payload: {
				path: "records.json" as const,
				media_type: "application/vnd.aidr.reputation-feed+json" as const,
				sha256: createHash("sha256").update(payloadJson).digest("hex"),
				record_count: payload.records.length,
			},
		};
		const manifestJson = canonicalReputationFeedManifest(manifest);
		await updateReputationFeed({
			...loadOptions,
			source: {
				provenance: { transport: "file", locator: "unit-fixture" },
				async fetch() {
					return {
						manifest: manifestJson,
						payload: payloadJson,
						signature: sign(null, Buffer.from(manifestJson), keys.privateKey).toString("base64"),
					};
				},
			},
		});
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		await rm(storeDir, { recursive: true, force: true });
	});

	it("blocks an exact domain and subdomain while allowing remote check of lookalikes", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ answers: [] }) });
		const client = new UrlCheckClient({ reputationFeed: loadOptions });
		const urls = ["https://malicious.example/x", "https://sub.malicious.example/y", "https://notmalicious.example/z"];
		const results = await client.checkUrls(urls);
		expect(results.filter((result) => result.isMalicious)).toHaveLength(2);
		expect(results[0]?.findings[0]?.typeName).toContain("signed-feed:enterprise-reputation:bad-domain");
		expect(globalThis.fetch).toHaveBeenCalledTimes(1);
		const request = JSON.parse(String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0]?.[1]?.body));
		expect(request.queries).toEqual([{ key: { "url-like": urls[2] } }]);
	});

	it("returns verified file and package hash detections without remote lookup", async () => {
		globalThis.fetch = vi.fn();
		const client = new FileCheckClient({ reputationFeed: loadOptions });
		expect((await client.checkHash(SHA256))?.severity).toBe("SEVERITY_MALWARE");
		const results = await client.checkHashes([SHA256, "b".repeat(64)]);
		expect(results).toHaveLength(2);
		expect(results.every((result) => result.severity === "SEVERITY_MALWARE")).toBe(true);
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it("preserves signed deny evidence when the remote leg fails for another item", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503 });
		const urlError = await new UrlCheckClient({ reputationFeed: loadOptions }).checkUrls([
			"https://malicious.example/x",
			"https://benign.example/x",
		]).catch((error: unknown) => error);
		expect(urlError).toBeInstanceOf(DetectionLegUnavailableError);
		expect((urlError as DetectionLegUnavailableError).partialResults).toEqual([
			expect.objectContaining({ isMalicious: true, flags: ["signed_reputation_feed"] }),
		]);
		expect((urlError as DetectionLegUnavailableError).uncheckedCount).toBe(1);
		const fileError = await new FileCheckClient({ reputationFeed: loadOptions }).checkHashes([
			SHA256,
			"c".repeat(64),
		]).catch((error: unknown) => error);
		expect(fileError).toBeInstanceOf(DetectionLegUnavailableError);
		expect((fileError as DetectionLegUnavailableError).partialResults).toEqual([
			expect.objectContaining({ sha256: SHA256, severity: "SEVERITY_MALWARE" }),
		]);
		expect((fileError as DetectionLegUnavailableError).uncheckedCount).toBe(1);
	});

	it("blocks signed package names and hashes, including direct single-package checks", async () => {
		const checker = new PackageChecker({ reputationFeed: loadOptions, fileCheckEnabled: false });
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				"dist-tags": { latest: "1.0.0" },
				versions: { "1.0.0": { dist: { integrity: `sha256-${Buffer.from("b".repeat(64), "hex").toString("base64")}` } } },
				time: { created: "2020-01-01T00:00:00.000Z" },
			}),
		});
		const name = await checker.checkSinglePackage({ name: "bad-pkg", registry: "npm" });
		expect(name.verdict).toBe("malicious");
		expect(globalThis.fetch).not.toHaveBeenCalled();
		const hash = await checker.checkSinglePackage({ name: "hash-pkg", registry: "npm" });
		expect(hash.verdict).toBe("malicious");
		expect(hash.details).toContain("bad-package-hash");
	});

	it("stale signed feed cannot produce a clean URL, file, or package result", async () => {
		const stale = { ...loadOptions, now: new Date(NOW.getTime() + 2 * 86_400_000) };
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ answers: [], responses: [] }) });
		await expect(new UrlCheckClient({ reputationFeed: stale }).checkUrls(["https://benign.example"])).rejects.toBeInstanceOf(DetectionLegUnavailableError);
		await expect(new FileCheckClient({ reputationFeed: stale }).checkHashes(["c".repeat(64)])).rejects.toBeInstanceOf(DetectionLegUnavailableError);
		const packageResult = await new PackageChecker({ reputationFeed: stale }).checkSinglePackage({ name: "benign-pkg", registry: "npm" });
		expect(packageResult.verdict).toBe("unknown");
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it("missing or untrusted configured feed reports unavailable without contacting the provider", async () => {
		globalThis.fetch = vi.fn();
		const missing = { ...loadOptions, feedId: "not-installed" };
		const untrusted = { ...loadOptions, trustedKeys: { key1: "not-a-public-key" } };
		for (const options of [missing, untrusted]) {
			await expect(new UrlCheckClient({ reputationFeed: options }).checkUrls(["https://benign.example"])).rejects.toBeInstanceOf(DetectionLegUnavailableError);
			await expect(new FileCheckClient({ reputationFeed: options }).checkHash("c".repeat(64))).rejects.toBeInstanceOf(DetectionLegUnavailableError);
			expect((await new PackageChecker({ reputationFeed: options }).checkSinglePackage({ name: "benign-pkg", registry: "npm" })).verdict).toBe("unknown");
		}
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it("a benign package gets clean only after an actual SHA-256 provider verdict", async () => {
		const benignHash = "c".repeat(64);
		globalThis.fetch = vi.fn()
			.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					"dist-tags": { latest: "1.0.0" },
					versions: { "1.0.0": { dist: { integrity: `sha256-${Buffer.from(benignHash, "hex").toString("base64")}` } } },
					time: { created: "2020-01-01T00:00:00.000Z" },
				}),
			})
			.mockResolvedValueOnce({
				ok: true,
				json: async () => ({ responses: [{ severity: "SEVERITY_UNKNOWN" }] }),
			});
		const result = await new PackageChecker({ reputationFeed: loadOptions }).checkSinglePackage({ name: "benign-pkg", registry: "npm" });
		expect(result.verdict).toBe("clean");
		expect(globalThis.fetch).toHaveBeenCalledTimes(2);
	});
});
