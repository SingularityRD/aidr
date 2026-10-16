import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";

describe("AI infrastructure policy", () => {
	it("blocks confirmed critical CVEs, requests approval on stale evidence, and scopes to configured origins", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-infra-policy-"));
		try {
			const path = join(dir, "scan.json");
			const config = ConfigSchema.parse({
				policy: {
					enabled: true,
					ai_infrastructure: {
						enabled: true,
						targets: ["http://127.0.0.1:9911"],
						report_path: path,
					},
				},
			});
			const artifact = { type: "url" as const, value: "http://127.0.0.1:9911/invoke" };
			const report = {
				scannedAt: new Date().toISOString(),
				targets: [
					{
						url: "http://127.0.0.1:9911",
						reachable: true,
						matched: [{ product: "test-service" }],
						error: null,
						cves: [{ cveId: "CVE-TEST-1", severity: "critical", evaluated: true }],
					},
				],
			};
			await writeFile(path, JSON.stringify(report));
			expect((await evaluatePolicy("WebFetch", [artifact], config))?.decision).toBe("deny");
			expect(
				await evaluatePolicy(
					"WebFetch",
					[{ ...artifact, value: "http://127.0.0.1:9912/invoke" }],
					config,
				),
			).toBeNull();
			report.targets[0].cves[0].evaluated = false;
			await writeFile(path, JSON.stringify(report));
			expect((await evaluatePolicy("WebFetch", [artifact], config))?.decision).toBe("ask");
			report.targets[0].matched = [];
			report.targets[0].cves = [];
			report.targets[0].error = null;
			await writeFile(path, JSON.stringify(report));
			expect((await evaluatePolicy("WebFetch", [artifact], config))?.decision).toBe("ask");
			const blockUnverifiedConfig = ConfigSchema.parse({
				policy: {
					enabled: true,
					ai_infrastructure: {
						enabled: true,
						targets: ["http://127.0.0.1:9911"],
						report_path: path,
						unverified_action: "block",
					},
				},
			});
			expect((await evaluatePolicy("WebFetch", [artifact], blockUnverifiedConfig))?.decision).toBe(
				"deny",
			);
			report.scannedAt = "2000-01-01";
			await writeFile(path, JSON.stringify(report));
			expect((await evaluatePolicy("WebFetch", [artifact], config))?.reasons[0]).toContain(
				"expired",
			);
			await writeFile(path, "invalid");
			expect((await evaluatePolicy("WebFetch", [artifact], config))?.decision).toBe("ask");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
