import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runSessionStartScan } from "../session-start-scan.js";
import type { PluginInfo } from "../types.js";

describe("session-start plugin reputation privacy defaults", () => {
	const originalFetch = globalThis.fetch;
	let root: string;
	let plugin: PluginInfo;

	beforeEach(async () => {
		root = join(tmpdir(), `aidr-scan-privacy-${Math.random().toString(16).slice(2)}`);
		const pluginDir = join(root, "plugin");
		await Promise.all([
			mkdir(pluginDir, { recursive: true }),
			mkdir(join(root, "threats"), { recursive: true }),
			mkdir(join(root, "allowlists"), { recursive: true }),
		]);
		await writeFile(
			join(pluginDir, "index.js"),
			'const url = "https://private.example/path?token=secret";\n',
			"utf8",
		);
		await writeFile(
			join(root, "config.json"),
			JSON.stringify({ url_check: { enabled: false }, file_check: { enabled: false } }),
			"utf8",
		);
		plugin = {
			key: "private-plugin",
			installPath: pluginDir,
			version: "1.0.0",
			lastUpdated: "2026-09-23T00:00:00.000Z",
		};
		globalThis.fetch = vi.fn();
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		await rm(root, { recursive: true, force: true });
	});

	it("surfaces withheld checks and does not cache an incomplete scan as clean", async () => {
		const context = {
			plugins: [plugin],
			threatsDir: join(root, "threats"),
			allowlistsDir: join(root, "allowlists"),
			aidrVersion: "1.0.0",
			configPath: join(root, "config.json"),
			scanCachePath: join(root, "scan-cache.json"),
		};

		const first = await runSessionStartScan(context);
		const second = await runSessionStartScan(context);

		expect(first).toHaveLength(1);
		expect(first[0]?.unavailableChecks?.map((check) => check.check)).toEqual([
			"url_reputation",
			"file_reputation",
		]);
		expect(second).toHaveLength(1);
		expect(second[0]?.unavailableChecks).toEqual(first[0]?.unavailableChecks);
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});
});
