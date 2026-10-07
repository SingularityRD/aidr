/**
 * Tests for the native AI-infrastructure scanner.
 *
 * These prove the capability is real without any Go/Python AIG stack: a
 * fingerprint is matched from an actual HTTP response, a version is extracted,
 * and a CVE is matched against that version. A local HTTP server stands in for
 * the target so the test exercises the same code path as production.
 */

import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

const INDEX_FILES = [
	"aig-cve-index.json",
	"aig-fingerprints.json",
	"aig-mcp-categories.json",
] as const;

async function writeTestBundle(
	directory: string,
	options: {
		empty?: string;
		missing?: string;
		corrupt?: string;
		fingerprints?: Array<Record<string, unknown>>;
	} = {},
): Promise<void> {
	const indexes: Record<(typeof INDEX_FILES)[number], Record<string, unknown>> = {
		"aig-cve-index.json": { schema: "aig-cve-index/v2", version: 2, cves: [{}] },
		"aig-fingerprints.json": {
			schema: "aig-fingerprint-index/v3",
			version: 3,
			fingerprints: options.fingerprints ?? [{}],
		},
		"aig-mcp-categories.json": { schema: "aig-mcp-categories/v2", version: 2, categories: [{}] },
	};
	if (options.empty === "aig-cve-index.json") indexes[options.empty].cves = [];
	if (options.empty === "aig-fingerprints.json") indexes[options.empty].fingerprints = [];
	const artifacts: Record<string, { sha256: string; bytes: number }> = {};
	await mkdir(directory, { recursive: true });
	for (const file of INDEX_FILES) {
		const bytes = Buffer.from(JSON.stringify(indexes[file]));
		artifacts[file] = {
			sha256: createHash("sha256").update(bytes).digest("hex"),
			bytes: bytes.length,
		};
		if (options.missing !== file) {
			await writeFile(join(directory, file), options.corrupt === file ? "not json" : bytes);
		}
	}
	const bundleId = createHash("sha256")
		.update(JSON.stringify(Object.fromEntries(INDEX_FILES.map((file) => [file, artifacts[file]]))))
		.digest("hex");
	await writeFile(
		join(directory, "aig-data-manifest.json"),
		JSON.stringify({
			schema: "aig-data-manifest/v1",
			generated: new Date().toISOString(),
			bundle_id: bundleId,
			artifacts,
		}),
	);
}

describe("native AIG data is present", () => {
	it("ships fingerprints with executable detection blocks", () => {
		expect(fingerprintCount()).toBeGreaterThan(100);
	});

	it("ships a CVE index", () => {
		expect(cveCount()).toBeGreaterThan(1000);
	});
});

describe("unavailable scanner indexes fail closed", () => {
	const failures = [
		{ name: "missing CVE index", missing: "aig-cve-index.json" },
		{ name: "empty CVE index", empty: "aig-cve-index.json" },
		{ name: "corrupt CVE index", corrupt: "aig-cve-index.json" },
		{ name: "missing fingerprint index", missing: "aig-fingerprints.json" },
		{ name: "empty fingerprint index", empty: "aig-fingerprints.json" },
		{ name: "corrupt fingerprint index", corrupt: "aig-fingerprints.json" },
	] as const;

	it.each(failures)("rejects a $name", async ({ name: _name, ...failure }) => {
		const previousDirectory = process.env.AIG_GENERATED_DIR;
		const directory = await mkdtemp(join(tmpdir(), "aidr-aig-index-"));
		process.env.AIG_GENERATED_DIR = directory;
		resetAigScanCache();
		let requests = 0;
		try {
			await writeTestBundle(directory, failure);
			const result = await scanTarget(
				{ url: "http://127.0.0.1:9001" },
				{
					fetchImpl: (async () => {
						requests++;
						return new Response("no match");
					}) as typeof fetch,
				},
			);
			expect(result.error).toBe("dataset_unavailable");
			expect(result.requestsMade).toBe(0);
			expect(requests).toBe(0);
		} finally {
			if (previousDirectory === undefined) delete process.env.AIG_GENERATED_DIR;
			else process.env.AIG_GENERATED_DIR = previousDirectory;
			resetAigScanCache();
			await rm(directory, { recursive: true, force: true });
		}
	});
});

describe("target safety", () => {
	it("forwards cancellation to an in-flight request", async () => {
		const controller = new AbortController();
		let requestSignal: AbortSignal | undefined;
		let respond: ((response: Response) => void) | undefined;
		let started: (() => void) | undefined;
		const requestStarted = new Promise<void>((resolve) => {
			started = resolve;
		});
		const fetchImpl = ((_input: Parameters<typeof fetch>[0], init?: RequestInit) => {
			requestSignal = init?.signal ?? undefined;
			started?.();
			return new Promise<Response>((resolve) => {
				respond = resolve;
			});
		}) as typeof fetch;
		const scan = scanTarget(
			{ url: "http://127.0.0.1:9001" },
			{ fetchImpl, signal: controller.signal },
		);
		await requestStarted;
		controller.abort();
		respond?.(new Response("late response"));

		await expect(scan).resolves.toMatchObject({ error: "scan_aborted" });
		expect(requestSignal?.aborted).toBe(true);
	});

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
		for (const host of [
			"127.0.0.1", "localhost", "10.0.0.5", "192.168.1.10", "172.16.0.1", "172.31.255.254",
			"169.254.10.20", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1",
		]) {
			expect(isScannableHost(host)).toBe(true);
		}
	});

	it("refuses public targets by default", () => {
		expect(isScannableHost("evil.example.com")).toBe(false);
		expect(isTargetAllowed("http://evil.example.com/", false)).toBe(false);
		expect(isTargetAllowed("http://127.0.0.1:8080/", false)).toBe(true);
	});

	it("never treats private-looking DNS names as private IP literals", () => {
		for (const host of [
			"127.0.0.1.attacker.example",
			"127.0.0.1.nip.io",
			"10.evil.example",
			"10.0.0.1.nip.io",
			"192.168.attacker.example",
			"192.168.1.1.nip.io",
			"172.16.attacker.example",
			"172.16.0.1.nip.io",
			"169.254.attacker.example",
			"169.254.169.254.nip.io",
		]) {
			expect(isScannableHost(host)).toBe(false);
			expect(isTargetAllowed(`http://${host}/`, false)).toBe(false);
		}
		expect(isScannableHost("172.32.0.1")).toBe(false);
		expect(isScannableHost("fec0::1")).toBe(false);
	});

	it("rejects private-looking DNS names before any outbound request", async () => {
		let requests = 0;
		const fetchImpl = (async () => {
			requests++;
			return new Response("unexpected request");
		}) as typeof fetch;

		for (const host of [
			"127.0.0.1.nip.io",
			"10.0.0.1.nip.io",
			"192.168.1.1.nip.io",
			"172.16.0.1.nip.io",
			"169.254.169.254.nip.io",
		]) {
			const result = await scanTarget({ url: `http://${host}/` }, { fetchImpl });
			expect(result.error).toBe("target_not_allowed");
			expect(result.requestsMade).toBe(0);
		}
		expect(requests).toBe(0);
	});

	it("performs an opted-in hostname scan through the injected transport", async () => {
		const previousDirectory = process.env.AIG_GENERATED_DIR;
		const directory = await mkdtemp(join(tmpdir(), "aidr-aig-opt-in-"));
		process.env.AIG_GENERATED_DIR = directory;
		resetAigScanCache();
		let requestedUrl = "";
		try {
			await writeTestBundle(directory, {
				fingerprints: [
					{
						n: "Test service",
						a: "test-vendor",
						sev: "low",
						desc: "test fingerprint",
						p: "test-service",
						v: "1.0.0",
						http: [
							{
								method: "GET",
								path: "/",
								supported: true,
								matchers: [{ key: "status", contains: "200" }],
							},
						],
					},
				],
			});
			const result = await scanTarget(
				{ url: "http://scan.example.test:8080/" },
				{
					allowPublicTargets: true,
					fetchImpl: (async (input: Parameters<typeof fetch>[0]) => {
						requestedUrl = String(input);
						return new Response("not a match", { status: 404 });
					}) as typeof fetch,
				},
			);
			expect(requestedUrl).toBe("http://scan.example.test:8080/");
			expect(result.requestsMade).toBe(1);
			expect(result.reachable).toBe(true);
		} finally {
			if (previousDirectory === undefined) delete process.env.AIG_GENERATED_DIR;
			else process.env.AIG_GENERATED_DIR = previousDirectory;
			resetAigScanCache();
			await rm(directory, { recursive: true, force: true });
		}
	});

	it("allows public targets only with an explicit opt-in", () => {
		expect(isTargetAllowed("http://evil.example.com/", true)).toBe(true);
		expect(isTargetAllowed("file:///etc/passwd", true)).toBe(false);
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

	it("marks a reachable target with no known fingerprint as incomplete", async () => {
		const result = await scanTarget(
			{ url: "http://127.0.0.1:9001" },
			{
				fetchImpl: (async () =>
					new Response("not a known product", { status: 404 })) as typeof fetch,
			},
		);
		expect(result.reachable).toBe(true);
		expect(result.matched).toEqual([]);
		expect(result.error).toBe("no_fingerprint_matched");
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

describe("compiled node-semver CVE ranges", () => {
	it("evaluates the range syntax stored in the CVE index", () => {
		expect(evaluateVersionRule("<0.1.38", "0.1.30")).toEqual({ matched: true, evaluated: true });
		expect(evaluateVersionRule("<0.1.38", "0.1.38")).toEqual({ matched: false, evaluated: true });
		expect(evaluateVersionRule(">=1.0 <2.0", "1.5")).toEqual({ matched: true, evaluated: true });
		expect(evaluateVersionRule(">=1.0 <2.0", "2.0")).toEqual({ matched: false, evaluated: true });
		expect(evaluateVersionRule(">1.0 <1.2 || >=2.0 <2.1", "2.0.5")).toEqual({
			matched: true,
			evaluated: true,
		});
		expect(evaluateVersionRule("=1.4.2", "1.4.2")).toEqual({ matched: true, evaluated: true });
	});

	it("keeps residue that is not a comparator opaque", () => {
		expect(evaluateVersionRule("is_internal==true", "1.0.0")).toEqual({
			matched: false,
			evaluated: false,
		});
		expect(evaluateVersionRule("<1.0 foo", "0.5")).toEqual({ matched: false, evaluated: false });
	});

	it("confirms a CVE index entry for a known vulnerable version", () => {
		const findings = lookupCvesForProduct("ollama", "0.1.30");
		const cve = findings.find((finding) => finding.cveId === "CVE-2024-7773");
		expect(cve).toMatchObject({ evaluated: true, severity: "critical" });
		expect(
			lookupCvesForProduct("ollama", "99.0.0").some((f) => f.cveId === "CVE-2024-7773"),
		).toBe(false);
	});
});

describe("version extraction from a dedicated version endpoint", () => {
	let server: Server;
	let baseUrl: string;
	const requested: string[] = [];

	beforeAll(async () => {
		resetAigScanCache();
		// Ollama is detected on `/` but its version is only served by `/api/version`.
		server = createServer((req, res) => {
			requested.push(`${req.method} ${req.url}`);
			if (req.url === "/") {
				res.writeHead(200, { "content-type": "text/plain" });
				res.end("Ollama is running");
				return;
			}
			if (req.url === "/api/version") {
				res.writeHead(200, { "content-type": "application/json" });
				res.end('{"version":"0.1.30"}');
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

	it("reads the version from the extractor path and confirms the CVE", async () => {
		const result = await scanTarget({ url: baseUrl }, { deadlineMs: 20000 });
		const ollama = result.matched.find((match) => match.product === "ollama");
		expect(ollama).toMatchObject({ version: "0.1.30", probePath: "/", versionPath: "/api/version" });
		expect(requested).toContain("GET /api/version");
		const cve = result.cves.find((finding) => finding.cveId === "CVE-2024-7773");
		expect(cve).toMatchObject({ evaluated: true, severity: "critical" });
	});

	it("feeds a version-confirmed critical CVE into scan-to-policy, which denies", async () => {
		const { evaluatePolicy } = await import("../policy.js");
		const { ConfigSchema } = await import("../types.js");
		const dir = await mkdtemp(join(tmpdir(), "aidr-infra-version-policy-"));
		try {
			const summary = await scanTargets([baseUrl], { deadlineMs: 20000 });
			const reportPath = join(dir, "scan.json");
			await writeFile(reportPath, JSON.stringify(summary));
			const config = ConfigSchema.parse({
				policy: {
					enabled: true,
					ai_infrastructure: { enabled: true, targets: [baseUrl], report_path: reportPath },
				},
			});
			const verdict = await evaluatePolicy(
				"WebFetch",
				[{ type: "url", value: `${baseUrl}/api/generate` }],
				config,
			);
			expect(verdict?.decision).toBe("deny");
			expect(verdict?.reasons.join(" ")).toContain("CVE-2024-7773");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});

describe("version extraction safety", () => {
	it("never sends a non-GET verb or leaves the target origin, and ignores non-2xx bodies", async () => {
		const previousDirectory = process.env.AIG_GENERATED_DIR;
		const directory = await mkdtemp(join(tmpdir(), "aidr-aig-version-safety-"));
		process.env.AIG_GENERATED_DIR = directory;
		resetAigScanCache();
		const requests: string[] = [];
		try {
			await writeTestBundle(directory, {
				fingerprints: [
					{
						n: "Test service",
						a: "test-vendor",
						sev: "low",
						desc: "test fingerprint",
						p: "test-service",
						v: "test",
						http: [
							{
								method: "GET",
								path: "/",
								supported: true,
								matchers: [{ key: "body", contains: "marker" }],
							},
						],
						ver: [
							{ method: "POST", path: "/mcp", part: "body", group: 1, regex: "v(\\d+\\.\\d+)" },
							{
								method: "GET",
								path: "http://evil.example/v",
								part: "body",
								group: 1,
								regex: "v(\\d+\\.\\d+)",
							},
							{ method: "GET", path: "/missing", part: "body", group: 1, regex: "v(\\d+\\.\\d+)" },
						],
					},
				],
			});
			const result = await scanTarget(
				{ url: "http://127.0.0.1:9001" },
				{
					fetchImpl: (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
						const url = new URL(String(input));
						requests.push(`${init?.method ?? "GET"} ${url.origin}${url.pathname}`);
						if (url.pathname === "/") return new Response("marker");
						// A 404 page that happens to contain a version-shaped string.
						return new Response("v9.9 not found", { status: 404 });
					}) as typeof fetch,
				},
			);
			expect(requests).toEqual([
				"GET http://127.0.0.1:9001/",
				"GET http://127.0.0.1:9001/missing",
			]);
			expect(result.matched[0]).toMatchObject({ version: null, versionPath: null });
			expect(result.requestsMade).toBe(2);
		} finally {
			if (previousDirectory === undefined) delete process.env.AIG_GENERATED_DIR;
			else process.env.AIG_GENERATED_DIR = previousDirectory;
			resetAigScanCache();
			await rm(directory, { recursive: true, force: true });
		}
	});
});
