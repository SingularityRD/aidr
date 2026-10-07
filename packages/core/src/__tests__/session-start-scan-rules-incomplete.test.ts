import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatSessionStartMessage } from "../format.js";
import type { SessionStartResult } from "../session-start.js";
import {
	RULES_INCOMPLETE_MESSAGE,
	runSessionStartScan,
	runSessionStartScanWithReport,
} from "../session-start-scan.js";
import type { PluginInfo } from "../types.js";

/**
 * The evaluator already turns a clean verdict into `ask` when bundled rule files fail to load.
 * The session-start plugin scan used the old loader and silently scanned with whatever loaded;
 * these tests pin that it now surfaces "rules incomplete — protection degraded" instead.
 */
describe("session-start scan with incomplete bundled rules", () => {
	const originalHome = process.env.HOME;
	const originalFetch = globalThis.fetch;
	let root: string;
	let threatsDir: string;
	let plugin: PluginInfo;

	beforeEach(async () => {
		root = await mkdtemp(join(tmpdir(), "aidr-scan-rules-"));
		process.env.HOME = root;
		vi.stubEnv("AIDR_COMMERCIAL", "");
		vi.stubEnv("AIDR_BUILD", "");
		vi.stubEnv("AIDR_BUILD_FLAVOR", "");
		threatsDir = join(root, "threats");
		const pluginDir = join(root, "plugin");
		await Promise.all([
			mkdir(pluginDir, { recursive: true }),
			mkdir(threatsDir, { recursive: true }),
			mkdir(join(root, "allowlists"), { recursive: true }),
		]);
		await writeFile(join(pluginDir, "index.js"), "console.log('safe');\n", "utf8");
		plugin = {
			key: "rules-plugin",
			installPath: pluginDir,
			version: "1.0.0",
			lastUpdated: "2026-10-07T00:00:00.000Z",
		};
		// File reputation answers "unknown" for every hash, so a complete scan is cacheable.
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			const body = JSON.parse(init.body as string) as {
				requests: Array<{ key: { sha256: string } }>;
			};
			return {
				ok: true,
				status: 200,
				json: async () => ({
					responses: body.requests.map(({ key }) => ({
						key,
						severity: "SEVERITY_UNKNOWN",
						malware_name: [],
					})),
				}),
			} as unknown as Response;
		});
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		vi.unstubAllEnvs();
		if (originalHome === undefined) delete process.env.HOME;
		else process.env.HOME = originalHome;
		await rm(root, { recursive: true, force: true });
	});

	async function context(plugins: PluginInfo[] = [plugin]) {
		const configPath = join(root, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({ url_check: { enabled: false }, file_check: { enabled: true } }),
			"utf8",
		);
		return {
			plugins,
			threatsDir,
			allowlistsDir: join(root, "allowlists"),
			aidrVersion: "1.0.0",
			configPath,
			scanCachePath: join(root, "cache.json"),
		};
	}

	const breakRules = () =>
		writeFile(join(threatsDir, "broken.yaml"), "- id: [unterminated\n  : : :\n", "utf8");

	it("reports complete rules as complete", async () => {
		const report = await runSessionStartScanWithReport(await context());
		expect(report.rulesIncomplete).toBeUndefined();
		expect(report.results).toEqual([]);
	});

	it("marks every scanned plugin degraded and never caches it as clean", async () => {
		await breakRules();
		const scanContext = await context();

		const report = await runSessionStartScanWithReport(scanContext);
		expect(report.rulesIncomplete).toMatchObject({
			message: RULES_INCOMPLETE_MESSAGE,
			files: ["broken.yaml"],
		});
		expect(report.results).toHaveLength(1);
		expect(report.results[0]?.unavailableChecks).toEqual([
			expect.objectContaining({
				check: "threat_rules",
				uncheckedCount: 1,
				reason: expect.stringContaining(RULES_INCOMPLETE_MESSAGE),
			}),
		]);
		await expect(readFile(scanContext.scanCachePath, "utf8")).rejects.toMatchObject({
			code: "ENOENT",
		});

		// The list-only API carries the same degradation, so its callers cannot read it as clean.
		const legacy = await runSessionStartScan(scanContext);
		expect(legacy[0]?.unavailableChecks?.[0]?.check).toBe("threat_rules");
	});

	it("does not reuse a clean cached result once the rules become incomplete", async () => {
		const scanContext = await context();
		expect(await runSessionStartScan(scanContext)).toEqual([]);
		await breakRules();
		const degraded = await runSessionStartScan(scanContext);
		expect(degraded[0]?.unavailableChecks?.[0]?.check).toBe("threat_rules");
	});

	it("surfaces the condition even with no plugins installed", async () => {
		await breakRules();
		const report = await runSessionStartScanWithReport(await context([]));
		expect(report.results).toEqual([]);
		expect(report.rulesIncomplete?.files).toEqual(["broken.yaml"]);
	});

	it("reports an unreadable rule directory as incomplete instead of throwing", async () => {
		const scanContext = { ...(await context()), threatsDir: join(root, "missing-threats") };
		const report = await runSessionStartScanWithReport(scanContext);
		expect(report.rulesIncomplete?.files).toEqual([scanContext.threatsDir]);
		expect(report.results[0]?.unavailableChecks?.[0]?.check).toBe("threat_rules");
	});

	it("formats a degraded session start as review required, never as clean", async () => {
		await breakRules();
		const report = await runSessionStartScanWithReport(await context([]));
		const result: SessionStartResult = {
			enabled: true,
			scanResults: report.results,
			rulesIncomplete: report.rulesIncomplete,
			versionCheck: null,
		};
		const message = formatSessionStartMessage("1.2.3", result);
		expect(message).toContain(RULES_INCOMPLETE_MESSAGE);
		expect(message).toContain("Review Required");
		expect(message).not.toContain("No threats found");

		const withPlugin = await runSessionStartScanWithReport(await context());
		const banner = formatSessionStartMessage("1.2.3", {
			enabled: true,
			scanResults: withPlugin.results,
			rulesIncomplete: withPlugin.rulesIncomplete,
			versionCheck: null,
		});
		expect(banner).toContain("Review Required");
		expect(banner).toContain("Threat rules incomplete — protection degraded");
		expect(banner).toContain("rules-plugin");
	});
});
