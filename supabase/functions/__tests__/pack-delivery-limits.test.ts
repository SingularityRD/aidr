import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	boundedPackCandidates,
	DEFAULT_PACK_URL_TTL_SECONDS,
	MAX_PACKS_PER_MANIFEST,
	MAX_PACK_URL_TTL_SECONDS,
	MIN_PACK_URL_TTL_SECONDS,
	packSigningTtlSeconds,
	packUrlTtlSeconds,
} from "../_shared/pack-delivery.ts";

describe("pack delivery bounds", () => {
	it("keeps download grants and internal storage URLs inside the documented lifetime", () => {
		expect(packUrlTtlSeconds(undefined)).toBe(DEFAULT_PACK_URL_TTL_SECONDS);
		expect(packUrlTtlSeconds("not-a-number")).toBe(DEFAULT_PACK_URL_TTL_SECONDS);
		expect(packUrlTtlSeconds("0")).toBe(MIN_PACK_URL_TTL_SECONDS);
		expect(packUrlTtlSeconds("600.9")).toBe(600);
		expect(packUrlTtlSeconds("999999")).toBe(MAX_PACK_URL_TTL_SECONDS);
		expect(packSigningTtlSeconds(null, 600, 0)).toBe(600);
		expect(packSigningTtlSeconds(new Date(11_000).toISOString(), 600, 0)).toBe(6);
		expect(packSigningTtlSeconds(new Date(5_000).toISOString(), 600, 0)).toBeNull();
		expect(packSigningTtlSeconds("invalid", 600, 0)).toBeNull();
	});

	it("rejects malformed query results and caps manifest signing candidates", () => {
		expect(boundedPackCandidates(null)).toEqual([]);
		expect(boundedPackCandidates({ pack_id: "not-an-array" })).toBeNull();
		expect(boundedPackCandidates(Array.from({ length: 80 }, (_, index) => index))).toEqual(
			Array.from({ length: MAX_PACKS_PER_MANIFEST }, (_, index) => index),
		);
	});

	it("wires scoped grants to both endpoints and the manifest to the hard work cap", () => {
		const functionsDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
		const download = readFileSync(join(functionsDir, "packs-download", "index.ts"), "utf8");
		const manifest = readFileSync(join(functionsDir, "packs-manifest", "index.ts"), "utf8");

		expect(download).toContain("packUrlTtlSeconds(");
		expect(download).toContain("createSignedUrl(pack.storage_path, storageTtl)");
		expect(download).toContain("authenticateTenantApiKeyHash(");
		expect(download).toContain('redirect: "manual"');
		expect(manifest).toContain("packUrlTtlSeconds(");
		expect(manifest).toContain("signPackDownloadGrant(");
		expect(manifest).not.toContain("createSignedUrl(");
		expect(manifest).toContain(".limit(MAX_PACKS_PER_MANIFEST)");
		expect(manifest).toContain("boundedPackCandidates(rows)");
		expect(manifest).toContain("packs.length >= MAX_PACKS_PER_MANIFEST");
	});

	it("filters shared and tenant packs before applying the manifest cap", () => {
		const functionsDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
		const manifest = readFileSync(join(functionsDir, "packs-manifest", "index.ts"), "utf8");
		const tenantFilter = manifest.indexOf(".or(`tenant_id.is.null,tenant_id.eq.${tenantId}`)");
		const order = manifest.indexOf('.order("issued_at", { ascending: false })');
		const limit = manifest.indexOf(".limit(MAX_PACKS_PER_MANIFEST)");
		expect(tenantFilter).toBeGreaterThan(0);
		expect(tenantFilter).toBeLessThan(order);
		expect(order).toBeLessThan(limit);
	});
});
