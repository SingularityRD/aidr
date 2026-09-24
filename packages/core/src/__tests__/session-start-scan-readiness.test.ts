import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatThreatBanner } from "../format.js";
import * as intelLoader from "../intel/loader.js";
import { emptyIntelMerged } from "../intel/types.js";
import * as managedModule from "../managed.js";
import { runSessionStartScan } from "../session-start-scan.js";
import type { PluginInfo } from "../types.js";

describe("session-start plugin scan coverage and intel cache", () => {
	const originalHome = process.env.HOME;
	const originalFetch = globalThis.fetch;
	let root: string;
	let plugin: PluginInfo;
	let loader: ReturnType<typeof vi.spyOn<typeof intelLoader, "loadMergedIntelFromDisk">>;

	beforeEach(async () => {
		root = await mkdtemp(join(tmpdir(), "aidr-scan-readiness-"));
		process.env.HOME = root;
		vi.stubEnv("AIDR_COMMERCIAL", "");
		vi.stubEnv("AIDR_BUILD", "");
		vi.stubEnv("AIDR_BUILD_FLAVOR", "");
		const pluginDir = join(root, "plugin");
		await Promise.all([
			mkdir(pluginDir, { recursive: true }),
			mkdir(join(root, "threats"), { recursive: true }),
			mkdir(join(root, "allowlists"), { recursive: true }),
		]);
		await writeFile(join(pluginDir, "index.js"), "console.log('safe');\n", "utf8");
		plugin = {
			key: "readiness-plugin",
			installPath: pluginDir,
			version: "1.0.0",
			lastUpdated: "2026-09-23T00:00:00.000Z",
		};
		loader = vi.spyOn(intelLoader, "loadMergedIntelFromDisk");
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
		vi.restoreAllMocks();
		vi.unstubAllEnvs();
		globalThis.fetch = originalFetch;
		if (originalHome === undefined) delete process.env.HOME;
		else process.env.HOME = originalHome;
		await rm(root, { recursive: true, force: true });
	});

	function context(config: Record<string, unknown>, scanCachePath = join(root, "cache.json")) {
		const configPath = join(root, "config.json");
		return writeFile(configPath, JSON.stringify(config), "utf8").then(() => ({
			plugins: [plugin],
			threatsDir: join(root, "threats"),
			allowlistsDir: join(root, "allowlists"),
			aidrVersion: "1.0.0",
			configPath,
			scanCachePath,
		}));
	}

	it("does not persist an empty clean result when the plugin path cannot be inspected", async () => {
		await rm(plugin.installPath, { recursive: true });
		const scanContext = await context({
			url_check: { enabled: false },
			file_check: { enabled: false },
		});

		const first = await runSessionStartScan(scanContext);
		const second = await runSessionStartScan(scanContext);

		expect(first[0]?.unavailableChecks).toEqual([
			expect.objectContaining({ check: "plugin_files", uncheckedCount: 1 }),
		]);
		expect(second[0]?.unavailableChecks).toEqual(first[0]?.unavailableChecks);
		await expect(readFile(scanContext.scanCachePath, "utf8")).rejects.toMatchObject({
			code: "ENOENT",
		});
	});

	it("evicts an earlier clean result when the plugin path later becomes inaccessible", async () => {
		const scanContext = await context({
			url_check: { enabled: false },
			file_check: { enabled: true },
		});

		const clean = await runSessionStartScan(scanContext);
		expect(clean).toEqual([]);
		expect(JSON.parse(await readFile(scanContext.scanCachePath, "utf8")).entries).not.toEqual({});

		await rm(plugin.installPath, { recursive: true });
		const unavailable = await runSessionStartScan(scanContext);

		expect(unavailable[0]?.unavailableChecks).toEqual([
			expect.objectContaining({ check: "plugin_files", uncheckedCount: 1 }),
		]);
		expect(JSON.parse(await readFile(scanContext.scanCachePath, "utf8")).entries).toEqual({});
	});

	it("invalidates clean plugin results when the active plugin-signature intel changes", async () => {
		const scanContext = await context({
			intel_packs: { enabled: true },
			url_check: { enabled: false },
			file_check: { enabled: true },
		});
		loader.mockResolvedValueOnce(emptyIntelMerged());

		const clean = await runSessionStartScan(scanContext);

		const bytes = await readFile(join(plugin.installPath, "index.js"));
		const deniedHash = createHash("sha256").update(bytes).digest("hex");
		const updatedIntel = emptyIntelMerged();
		updatedIntel.pluginSignatureDeny.add(deniedHash);
		loader.mockResolvedValueOnce(updatedIntel);

		const updated = await runSessionStartScan(scanContext);

		expect(clean).toEqual([]);
		expect(updated[0]?.findings).toEqual([
			expect.objectContaining({ threatId: "INTEL-PLUGIN-SIGNATURE-001", severity: "critical" }),
		]);
		expect(loader).toHaveBeenCalledTimes(2);
		expect(globalThis.fetch).toHaveBeenCalledTimes(2);
	});

	it("invalidates clean results when the active premium entitlement changes", async () => {
		const scanContext = await context({
			mode: "managed",
			intel_packs: { enabled: true },
			url_check: { enabled: false },
			file_check: { enabled: true },
		});
		const entitlement = (serial: string, signature: string) => ({
			entitlement: {
				schema_version: 2 as const,
				tenant_id: "tenant",
				subscription_tier: "pro" as const,
				included_agents: 1,
				extra_agents: 0,
				allowed_agents: 1,
				premium_modules: ["intel_packs"],
				issued_at: "2026-09-23T00:00:00.000Z",
				expires_at: "2027-09-23T00:00:00.000Z",
				grace_until: "2027-09-30T00:00:00.000Z",
				serial,
				revocation_epoch: 1,
			},
			entitlement_alg: "ed25519" as const,
			entitlement_sig: signature,
		});
		vi.spyOn(managedModule, "loadManagedState")
			.mockResolvedValueOnce(entitlement("serial-1", "signature-1"))
			.mockResolvedValueOnce(entitlement("serial-2", "signature-2"));
		vi.spyOn(managedModule, "isPremiumModuleEnabled").mockReturnValue(true);
		vi.spyOn(managedModule, "loadRevocationsCache").mockResolvedValue(null);
		loader.mockResolvedValue(emptyIntelMerged());

		await runSessionStartScan(scanContext);
		await runSessionStartScan(scanContext);

		expect(loader).toHaveBeenCalledTimes(2);
		expect(globalThis.fetch).toHaveBeenCalledTimes(2);
	});

	it("invalidates clean results when the active revocation snapshot changes", async () => {
		const scanContext = await context({
			intel_packs: { enabled: true },
			licensing: { revocations_enabled: true, public_keys_pem: ["test-key"] },
			url_check: { enabled: false },
			file_check: { enabled: true },
		});
		const revocations = (epoch: number) => ({
			alg: "ed25519" as const,
			sig_b64: `signature-${epoch}`,
			payload: {
				schema_version: 1 as const,
				issued_at: "2026-09-23T00:00:00.000Z",
				expires_at: "2027-09-23T00:00:00.000Z",
				revocation_epoch: epoch,
				revocations: {
					artifact_ids: [],
					pack_ids: [],
					key_ids: [],
					entitlement_serials: [],
				},
			},
		});
		vi.spyOn(managedModule, "loadRevocationsCache")
			.mockResolvedValueOnce(revocations(1))
			.mockResolvedValueOnce(revocations(2));
		loader.mockResolvedValue(emptyIntelMerged());

		await runSessionStartScan(scanContext);
		await runSessionStartScan(scanContext);

		expect(loader).toHaveBeenCalledTimes(2);
		expect(globalThis.fetch).toHaveBeenCalledTimes(2);
	});

	it("does not load premium intel in a commercial build without the entitled module", async () => {
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		const scanContext = await context({
			mode: "managed",
			intel_packs: { enabled: true, packs_dir: join(root, "packs") },
			url_check: { enabled: false },
			file_check: { enabled: false },
		});

		await runSessionStartScan(scanContext);

		expect(loader).not.toHaveBeenCalled();
	});

	it("formats local plugin-file coverage gaps as review-required, not as a threat", () => {
		const banner = formatThreatBanner("1.0.0", [
			{
				plugin,
				findings: [],
				unavailableChecks: [
					{
						check: "plugin_files",
						reason: "Some paths could not be inspected.",
						uncheckedCount: 2,
					},
				],
			},
		]);

		expect(banner).toContain("Review Required");
		expect(banner).toContain("Plugin file inspection was incomplete for 2 path(s).");
	});
});
