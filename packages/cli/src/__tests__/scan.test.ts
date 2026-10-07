import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
	cveCount,
	fingerprintCount,
	isTargetAllowed,
	resetAigScanCache,
	scanTarget,
} from "@singularityrd/aidr-core";
import scanCommand from "../commands/scan.js";

/**
 * Regression tests for `aidr scan` (the native AI-infrastructure scanner).
 *
 * The CLI layer itself is exercised through the core API these tests cover; the
 * important product property is that a scan never reports a result it did not
 * actually obtain, and never contacts a target it was not permitted to contact.
 */

describe("aidr scan - dataset availability", () => {
	it("reports the compiled dataset sizes the CLI prints", () => {
		// The CLI header prints exactly these counts; if the data fails to load
		// they would silently read 0.
		expect(fingerprintCount()).toBeGreaterThan(100);
		expect(cveCount()).toBeGreaterThan(1000);
	});
});

describe("aidr scan - target permission", () => {
	it("permits loopback targets by default", () => {
		expect(isTargetAllowed("http://127.0.0.1:8080", false)).toBe(true);
		expect(isTargetAllowed("http://localhost:3000", false)).toBe(true);
	});

	it("refuses public targets without the explicit opt-in", () => {
		expect(isTargetAllowed("http://example.com", false)).toBe(false);
		expect(isTargetAllowed("https://1.1.1.1", false)).toBe(false);
	});

	it("permits them only when the opt-in is set", () => {
		expect(isTargetAllowed("http://example.com", true)).toBe(true);
	});
});

describe("aidr scan - a scan that did not happen is never reported as clean", () => {
	it("marks a refused target with a distinguishable error", async () => {
		const result = await scanTarget({ url: "http://example.com" });
		// The CLI relies on this exact sentinel to say "not scanned" instead of
		// printing the "no vulnerabilities matched" caveat.
		expect(result.error).toBe("target_not_allowed");
		expect(result.matched).toEqual([]);
		expect(result.cves).toEqual([]);
	});

	it("marks an unreachable target as an error, not an empty clean result", async () => {
		const result = await scanTarget(
			{ url: "http://127.0.0.1:1" },
			{ timeoutMs: 400, deadlineMs: 3000 },
		);
		expect(result.reachable).toBe(false);
		expect(result.error).not.toBeNull();
		expect(result.error).not.toBe("target_not_allowed");
	});

	it("does not make requests to a refused target", async () => {
		const result = await scanTarget({ url: "http://example.com" });
		expect(result.requestsMade).toBe(0);
	});

	it("separates confirmed from unconfirmed findings in the summary and exit status", async () => {
		const { createServer } = await import("node:http");
		// Ollama detected on `/`; `/api/version` is served only when a version is set.
		const startOllama = async (version: string | null) => {
			const server = createServer((req, res) => {
				if (req.url === "/") {
					res.writeHead(200);
					res.end("Ollama is running");
				} else if (req.url === "/api/version" && version) {
					res.writeHead(200, { "content-type": "application/json" });
					res.end(JSON.stringify({ version }));
				} else {
					res.writeHead(404);
					res.end("not found");
				}
			});
			await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
			const address = server.address();
			if (!address || typeof address === "string") throw new Error("no server address");
			return { server, url: `http://127.0.0.1:${address.port}` };
		};
		const previousExitCode = process.exitCode;
		const output = vi.spyOn(console, "log").mockImplementation(() => undefined);
		const unknown = await startOllama(null);
		const vulnerable = await startOllama("0.1.30");
		resetAigScanCache();
		try {
			process.exitCode = 0;
			await scanCommand({ target: [unknown.url] });
			const unknownText = output.mock.calls.map((call) => String(call[0])).join("\n");
			expect(unknownText).toContain("Confirmed findings: 0 critical, 0 high");
			expect(unknownText).toMatch(/Unconfirmed findings: [1-9]\d* critical/);
			expect(unknownText).toContain("applicability unconfirmed");
			// Unconfirmed is incomplete (1): never clean (0), never a confirmed hit (2).
			expect(process.exitCode).toBe(1);

			output.mockClear();
			process.exitCode = 0;
			await scanCommand({ target: [vulnerable.url], json: true });
			const summary = JSON.parse(String(output.mock.calls[0]?.[0])) as Record<string, number>;
			expect(summary.confirmedCritical).toBeGreaterThan(0);
			expect(summary.critical).toBe(summary.confirmedCritical + summary.unconfirmedCritical);
			expect(process.exitCode).toBe(2);
		} finally {
			output.mockRestore();
			process.exitCode = previousExitCode;
			await new Promise<void>((resolve) => unknown.server.close(() => resolve()));
			await new Promise<void>((resolve) => vulnerable.server.close(() => resolve()));
		}
	});

	it("returns a nonzero CLI status when its dataset is missing", async () => {
		const previousDirectory = process.env.AIG_GENERATED_DIR;
		const previousExitCode = process.exitCode;
		const directory = await mkdtemp(join(tmpdir(), "aidr-scan-no-data-"));
		const output = vi.spyOn(console, "log").mockImplementation(() => undefined);
		process.env.AIG_GENERATED_DIR = join(directory, "missing");
		process.exitCode = 0;
		resetAigScanCache();
		try {
			await scanCommand({ target: ["http://127.0.0.1:9001"], json: true });
			expect(process.exitCode).toBe(1);
			expect(String(output.mock.calls[0]?.[0])).toContain('"error": "dataset_unavailable"');
		} finally {
			output.mockRestore();
			if (previousDirectory === undefined) delete process.env.AIG_GENERATED_DIR;
			else process.env.AIG_GENERATED_DIR = previousDirectory;
			process.exitCode = previousExitCode;
			resetAigScanCache();
			await rm(directory, { recursive: true, force: true });
		}
	});
});
