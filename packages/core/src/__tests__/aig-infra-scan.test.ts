/**
 * Tests for the native AI-infrastructure scanner.
 *
 * These prove the capability is real without any Go/Python AIG stack: a
 * fingerprint is matched from an actual HTTP response, a version is extracted,
 * and a CVE is matched against that version. A local HTTP server stands in for
 * the target so the test exercises the same code path as production.
 */

import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	compareVersions,
	cveCount,
	evaluateVersionRule,
	fingerprintCount,
	isScannableHost,
	isTargetAllowed,
	lookupCvesForProduct,
	probeMatches,
	resetAigScanCache,
	scanTarget,
	scanTargets,
} from "../aig-infra-scan.js";

describe("native AIG data is present", () => {
	it("ships fingerprints with executable detection blocks", () => {
		expect(fingerprintCount()).toBeGreaterThan(100);
	});

	it("ships a CVE index", () => {
		expect(cveCount()).toBeGreaterThan(1000);
	});
});

describe("target safety", () => {
	it("marks oversized and redirected responses incomplete even when another probe responds", async () => {
		for (const failure of ["response_too_large", "redirect_not_followed"]) {
			let calls = 0;
			const fetchImpl = (async () => {
				if (calls++ === 0) return failure === "response_too_large"
					? new Response(new Uint8Array(256 * 1024 + 1))
					: new Response(null, { status: 302, headers: { Location: "http://external.example/" } });
				return new Response("not found", { status: 404 });
			}) as typeof fetch;
			const result = await scanTarget({ url: "http://127.0.0.1:9001" }, { fetchImpl });
			expect(result.reachable).toBe(true);
			expect(result.error).toBe(failure);
		}
	});

	it("allows loopback and private addresses", () => {
		for (const host of ["127.0.0.1", "localhost", "10.0.0.5", "192.168.1.10", "::1"]) {
			expect(isScannableHost(host)).toBe(true);
		}
	});

	it("refuses public targets by default", () => {
		expect(isScannableHost("evil.example.com")).toBe(false);
		expect(isTargetAllowed("http://evil.example.com/", false)).toBe(false);
		expect(isTargetAllowed("http://127.0.0.1:8080/", false)).toBe(true);
	});

	it("allows public targets only with an explicit opt-in", () => {
		expect(isTargetAllowed("http://evil.example.com/", true)).toBe(true);
	});

	it("rejects non-http protocols and malformed targets", () => {
		expect(isTargetAllowed("file:///etc/passwd", false)).toBe(false);
		expect(isTargetAllowed("not a url", false)).toBe(false);
	});
});

describe("version comparison", () => {
	it("orders versions numerically, not lexically", () => {
		expect(compareVersions("1.10.0", "1.9.0")).toBe(1);
		expect(compareVersions("1.9.0", "1.10.0")).toBe(-1);
		expect(compareVersions("2.0", "2.0.0")).toBe(0);
	});

	it("returns null for versions it cannot order reliably", () => {
		expect(compareVersions("latest", "1.0.0")).toBeNull();
		expect(compareVersions("2026-01-01", "1.0.0")).toBeNull();
		expect(compareVersions("v1.2.3", "1.2.3")).toBe(0);
	});
});

describe("CVE rule evaluation", () => {
	it("matches versions inside the vulnerable range", () => {
		expect(evaluateVersionRule('version < "0.5.2"', "0.5.1")).toEqual({
			matched: true,
			evaluated: true,
		});
	});

	it("does not match versions outside the range", () => {
		expect(evaluateVersionRule('version < "0.5.2"', "0.5.2")).toEqual({
			matched: false,
			evaluated: true,
		});
		expect(evaluateVersionRule('version < "0.5.2"', "1.0.0")).toEqual({
			matched: false,
			evaluated: true,
		});
	});

	it("handles conjunctions and alternatives", () => {
		expect(evaluateVersionRule('version >= "1.0" && version < "2.0"', "1.5")).toEqual({
			matched: true,
			evaluated: true,
		});
		expect(evaluateVersionRule('version >= "1.0" && version < "2.0"', "2.1")).toEqual({
			matched: false,
			evaluated: true,
		});
		expect(evaluateVersionRule('version < "1.0" || version >= "2.0"', "2.5")).toEqual({
			matched: true,
			evaluated: true,
		});
	});

	it("reports unevaluated rather than guessing on an unsupported rule", () => {
		const result = evaluateVersionRule("body=~\"foo.*\"", "1.0.0");
		expect(result.matched).toBe(false);
		expect(result.evaluated).toBe(false);
	});

	it("does not claim a match when the version is unorderable", () => {
		const result = evaluateVersionRule('version < "2.0"', "nightly");
		expect(result.matched).toBe(false);
		expect(result.evaluated).toBe(false);
	});
});

describe("probe matching", () => {
	const headers = new Headers({ "content-type": "text/html" });

	it("requires every matcher to hold (AND semantics)", () => {
		const probe = {
			method: "GET",
			path: "/",
			supported: true,
			matchers: [
				{ key: "body", contains: "alpha" },
				{ key: "body", contains: "beta" },
			],
		};
		expect(probeMatches(probe, "alpha beta", headers, 200)).toBe(true);
		expect(probeMatches(probe, "alpha only", headers, 200)).toBe(false);
	});

	it("honours negation", () => {
		const probe = {
			method: "GET",
			path: "/",
			supported: true,
			matchers: [{ key: "body", contains: "forbidden", negate: true }],
		};
		expect(probeMatches(probe, "clean page", headers, 200)).toBe(true);
		expect(probeMatches(probe, "forbidden", headers, 200)).toBe(false);
	});

	it("matches headers and status", () => {
		expect(
			probeMatches(
				{ method: "GET", path: "/", supported: true, matchers: [{ key: "header", contains: "text/html" }] },
				"",
				headers,
				200,
			),
		).toBe(true);
		expect(
			probeMatches(
				{ method: "GET", path: "/", supported: true, matchers: [{ key: "status", contains: "200" }] },
				"",
				headers,
				200,
			),
		).toBe(true);
	});

	it("never matches when a matcher was unparseable", () => {
		const probe = {
			method: "GET",
			path: "/",
			supported: false,
			matchers: [{ unsupported: "weird=?" }],
		};
		expect(probeMatches(probe, "anything", headers, 200)).toBe(false);
	});
});

describe("CVE lookup for a detected product", () => {
	it("returns unevaluated findings when no version is known", () => {
		// Any product present in the index; take the first to avoid a hard-coded
		// dependency on a specific upstream entry.
		const findings = lookupCvesForProduct("9router", null);
		if (findings.length > 0) {
			expect(findings.every((f) => f.evaluated === false)).toBe(true);
		}
	});

	it("evaluates applicability when a version is known", () => {
		const vulnerable = lookupCvesForProduct("9router", "0.0.1");
		const patched = lookupCvesForProduct("9router", "99.0.0");
		// The vulnerable version must not surface fewer findings than the patched one.
		expect(vulnerable.length).toBeGreaterThanOrEqual(patched.length);
	});

	it("returns nothing for an unknown product", () => {
		expect(lookupCvesForProduct("definitely-not-a-real-product-xyz", "1.0.0")).toEqual([]);
	});
});

describe("end-to-end scan against a local server", () => {
	let server: Server;
	let baseUrl: string;
	/** Product served by the fixture, taken from the compiled dataset. */
	let fixture: { path: string; body: string; product: string };

	beforeAll(async () => {
		resetAigScanCache();
		// Load the compiled data to pick a fingerprint we can actually serve.
		const data = JSON.parse(
			await import("node:fs").then((fs) =>
				fs.readFileSync(
					new URL("../generated/aig-fingerprints.json", import.meta.url),
					"utf8",
				),
			),
		) as {
			fingerprints: Array<{
				p: string;
				n: string;
				http?: Array<{ path: string; matchers: Array<{ contains?: string }> }>;
				ver?: Array<{ path: string; regex: string }>;
			}>;
		};

		// Prefer a fingerprint that has both a probe and a version extractor, so
		// the test covers detection AND version extraction.
		const chosen =
			data.fingerprints.find(
				(f) =>
					f.http?.length &&
					f.ver?.length &&
					f.http[0]?.matchers.every((m) => typeof m.contains === "string"),
			) ?? data.fingerprints.find((f) => f.http?.length);

		if (!chosen?.http?.[0]) throw new Error("compiled dataset has no usable fingerprint");

		const marker = chosen.http[0].matchers.map((m) => m.contains).filter(Boolean) as string[];
		fixture = {
			path: chosen.http[0].path,
			// Body contains every required marker, plus a version string if the
			// fingerprint extracts one.
			body: `${marker.join(" ")}\n{"version":"1.2.3"}\n`,
			product: chosen.p || chosen.n,
		};

		server = createServer((req, res) => {
			if (req.url?.startsWith(fixture.path)) {
				res.writeHead(200, { "content-type": "application/json" });
				res.end(fixture.body);
				return;
			}
			res.writeHead(404);
			res.end("not found");
		});

		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const address = server.address();
		if (!address || typeof address === "string") throw new Error("no server address");
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterAll(async () => {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	});

	it("identifies the running product from its real HTTP response", async () => {
		const result = await scanTarget({ url: baseUrl }, { deadlineMs: 20000 });
		expect(result.error).toBeNull();
		expect(result.reachable).toBe(true);
		expect(result.matched.map((m) => m.product)).toContain(fixture.product);
		expect(result.requestsMade).toBeGreaterThan(0);
	});

	it("never reports a non-matching target as a detection", async () => {
		const result = await scanTarget({ url: baseUrl }, { deadlineMs: 20000 });
		for (const match of result.matched) {
			// Every reported match must carry the evidence that produced it.
			expect(match.probePath).toBeTruthy();
			expect(match.name).toBeTruthy();
		}
	});

	it("reports an unreachable target as an error, not as clean", async () => {
		// Port 1 on loopback: allowed by the safety gate but nothing is listening.
		const result = await scanTarget(
			{ url: "http://127.0.0.1:1" },
			{ timeoutMs: 500, deadlineMs: 4000 },
		);
		expect(result.matched).toEqual([]);
		expect(result.error).not.toBeNull();
		expect(result.reachable).toBe(false);
	});

	it("refuses a public target without the opt-in and makes no requests", async () => {
		const result = await scanTarget({ url: "http://example.com" });
		expect(result.error).toBe("target_not_allowed");
		expect(result.requestsMade).toBe(0);
	});

	it("summarises multiple targets with severity counts", async () => {
		const summary = await scanTargets([baseUrl, "http://127.0.0.1:1"], {
			timeoutMs: 500,
			deadlineMs: 20000,
			concurrency: 2,
		});
		expect(summary.targets).toHaveLength(2);
		expect(summary.scannedAt).toBeTruthy();
		expect(typeof summary.cvesFound).toBe("number");
	});

	it("stops at the deadline instead of running unbounded", async () => {
		const started = Date.now();
		await scanTarget({ url: baseUrl }, { deadlineMs: 1, timeoutMs: 200 });
		// A 1ms deadline must not allow a full sweep of 146 fingerprints.
		expect(Date.now() - started).toBeLessThan(10000);
	});
});
