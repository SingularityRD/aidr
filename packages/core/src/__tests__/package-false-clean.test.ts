/**
 * Regression tests for two positive false-cleans in package checking.
 *
 * Both bugs reported a package as verified *clean* without any check having run,
 * which is the most dangerous failure mode for a security control:
 *
 * 1. Scoped packages (`@scope/name`) were skipped and reported
 *    `verdict: "clean", confidence: 1.0`. A large share of the npm ecosystem is
 *    scoped and an attacker can register a scope as easily as a plain name, so
 *    `npm install @evil/pkg` was reported verified clean.
 *
 * 2. npm integrity strings are `sha512-...`, but the registry client only
 *    recognised a `sha256-` prefix, so `hashAlgorithm` stayed `"sha1"` and every
 *    downstream SHA-256 hash check silently did nothing. The package then fell
 *    through to `clean` at confidence 1.0.
 */

import { describe, expect, it } from "vitest";
import { RegistryClient, resolveDistDigest } from "../clients/package-registry.js";
import { PackageChecker } from "../package-checker.js";
import type { ParsedPackage } from "../package-extractor.js";

/** A real-ish sha512 integrity string (base64 of 64 bytes). */
const SHA512_B64 = Buffer.alloc(64, 7).toString("base64");
const SHA256_B64 = Buffer.alloc(32, 9).toString("base64");

describe("resolveDistDigest", () => {
	it("prefers a sha512 integrity digest over the legacy shasum", () => {
		const { hash, hashAlgorithm } = resolveDistDigest("deadbeefsha1", `sha512-${SHA512_B64}`);
		expect(hashAlgorithm).toBe("sha512");
		expect(hash).toBe(Buffer.alloc(64, 7).toString("hex"));
		expect(hash).toHaveLength(128);
	});

	it("recognises sha256 and sha384 too", () => {
		expect(resolveDistDigest("", `sha256-${SHA256_B64}`).hashAlgorithm).toBe("sha256");
		expect(resolveDistDigest("", `sha256-${SHA256_B64}`).hash).toHaveLength(64);
		expect(resolveDistDigest("", `sha384-${Buffer.alloc(48, 1).toString("base64")}`).hashAlgorithm).toBe(
			"sha384",
		);
	});

	it("falls back to the shasum and reports sha1 when only that is available", () => {
		const { hash, hashAlgorithm } = resolveDistDigest("abc123", "");
		expect(hashAlgorithm).toBe("sha1");
		expect(hash).toBe("abc123");
	});

	it("does not accept a malformed digest as a strong one", () => {
		// Wrong length for the declared algorithm: must not be treated as verified.
		const tooShort = Buffer.alloc(4).toString("base64");
		expect(resolveDistDigest("fallback", `sha512-${tooShort}`).hashAlgorithm).toBe("sha1");
	});

	it("rejects an unknown or absent algorithm prefix", () => {
		expect(resolveDistDigest("fallback", "md5-abc").hashAlgorithm).toBe("sha1");
		expect(resolveDistDigest("fallback", "").hashAlgorithm).toBe("sha1");
	});
});

describe("scoped packages are actually checked", () => {
	function scopedPkg(name: string): ParsedPackage {
		return { name, registry: "npm", version: undefined } as ParsedPackage;
	}

	it("does not report a scoped package as clean without a check", async () => {
		const checker = new PackageChecker();
		const results = await checker.checkPackages([scopedPkg("@evil/pkg-that-does-not-exist-aidr")]);

		expect(results).toHaveLength(1);
		const [result] = results;
		// The old behaviour was exactly this: verdict "clean", confidence 1.0.
		const wasSkippedAsClean =
			result?.verdict === "clean" && /skipped/i.test(String(result?.details ?? ""));
		expect(wasSkippedAsClean).toBe(false);
		// It must have produced some real verdict instead of a fabricated clean.
		expect(result?.verdict).toBeTruthy();
	});
});

describe("npm metadata yields a usable digest (live registry)", () => {
	it("reports sha512 for a package npm publishes with a sha512 integrity", async () => {
		const client = new RegistryClient({ timeout_seconds: 15 });
		const metadata = await client.getPackageMetadata("lodash", "npm", undefined);
		if (!metadata) {
			// Offline environment: registry lookups are supplementary here, and the
			// pure digest tests above still cover the logic.
			return;
		}
		// lodash's own published dist-tags.latest, not some other registry's version.
		expect(metadata.resolvedVersion).toBe("4.18.1");
		// The property that was broken: npm publishes `sha512-`, so the algorithm
		// must not silently degrade to sha1 (which disabled every hash check).
		expect(metadata.hashAlgorithm).toBe("sha512");
		expect(metadata.latestHash).toMatch(/^[0-9a-f]{128}$/);
	});

	it("routes a scoped package to npm and resolves its latest version", async () => {
		const client = new RegistryClient({ timeout_seconds: 15 });
		const metadata = await client.getPackageMetadata("@types/node", "npm", undefined);
		if (!metadata) return;
		expect(metadata.resolvedVersion).toMatch(/^\d+\.\d+\.\d+/);
		expect(metadata.hashAlgorithm).toBe("sha512");
	});

	it("keeps registry routing correct: an npm name is not answered by PyPI", async () => {
		// `lodash` exists on BOTH registries with entirely different versions.
		// Answering the npm name from PyPI yields an unrelated 0.0.1 package, so
		// every downstream verdict would describe the wrong artifact.
		const client = new RegistryClient({ timeout_seconds: 15 });
		const npmMeta = await client.getPackageMetadata("lodash", "npm", undefined);
		const pypiMeta = await client.getPackageMetadata("lodash", "pypi", undefined);
		if (!npmMeta || !pypiMeta) return;
		expect(npmMeta.resolvedVersion).not.toBe(pypiMeta.resolvedVersion);
		expect(npmMeta.hashAlgorithm).toBe("sha512");
		expect(pypiMeta.hashAlgorithm).toBe("sha256");
	});
});
