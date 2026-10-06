import { mkdir, mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Logger } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { discoverOpenCodePlugins } from "../plugin-discovery.js";

describe("OpenCode plugin discovery", () => {
	let root: string;
	let configDir: string;
	let cacheDir: string;
	let projectDir: string;
	let logger: Logger;

	beforeEach(async () => {
		root = await mkdtemp(join(tmpdir(), "aidr-opencode-discovery-"));
		configDir = join(root, "config", "opencode");
		cacheDir = join(root, "cache", "opencode");
		projectDir = join(root, "project");
		vi.stubEnv("XDG_CONFIG_HOME", join(root, "config"));
		vi.stubEnv("XDG_CACHE_HOME", join(root, "cache"));
		logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() } as Logger;
		await mkdir(configDir, { recursive: true });
		await mkdir(projectDir, { recursive: true });
	});

	afterEach(async () => {
		vi.unstubAllEnvs();
		await rm(root, { recursive: true, force: true });
	});

	async function install(name: string, selector?: string, version = "1.2.3") {
		const path = selector
			? join(cacheDir, "packages", selector, "node_modules", name)
			: join(cacheDir, "node_modules", name);
		await mkdir(path, { recursive: true });
		await writeFile(join(path, "package.json"), JSON.stringify({ name, version }));
		return path;
	}

	it("reads JSONC comments and trailing commas in global and project config", async () => {
		await writeFile(
			join(configDir, "opencode.jsonc"),
			'{ // installed globally\n "plugin": ["global-plugin@1.2.3",], }',
		);
		await writeFile(
			join(projectDir, "opencode.jsonc"),
			'{"plugin": ["@org/project-plugin@beta",],}',
		);
		const globalPath = await install("global-plugin");
		const projectPath = await install("@org/project-plugin", "@org/project-plugin@beta");
		const plugins = await discoverOpenCodePlugins(logger, projectDir);
		expect(plugins.map((plugin) => plugin.installPath)).toEqual([globalPath, projectPath]);
		expect(plugins.map((plugin) => plugin.key)).toEqual([
			"global-plugin@1.2.3",
			"@org/project-plugin@1.2.3",
		]);
	});

	it.each(["example-plugin", "@org/example-plugin"])(
		"normalizes unversioned %s to the current host's @latest cache",
		async (name) => {
			await writeFile(join(configDir, "opencode.json"), JSON.stringify({ plugin: [name] }));
			const installPath = await install(name, `${name}@latest`);
			expect(await discoverOpenCodePlugins(logger)).toEqual([
				expect.objectContaining({ installPath, key: `${name}@1.2.3` }),
			]);
		},
	);

	it("accepts configured options tuples and the Windows sanitized range cache", async () => {
		const name = "@org/range-plugin";
		const selector = `${name}@>=1 <2`;
		await writeFile(
			join(configDir, "opencode.json"),
			JSON.stringify({ plugin: [[selector, { enabled: true }]] }),
		);
		const cacheSelector = process.platform === "win32" ? "@org/range-plugin@_=1 _2" : selector;
		const installPath = await install(name, cacheSelector);
		expect(await discoverOpenCodePlugins(logger)).toEqual([
			expect.objectContaining({ installPath, key: `${name}@1.2.3` }),
		]);
	});

	it("uses the current selector cache before a stale legacy package", async () => {
		await writeFile(join(configDir, "opencode.json"), JSON.stringify({ plugin: ["plugin@2.0.0"] }));
		await install("plugin", undefined, "1.0.0");
		const installPath = await install("plugin", "plugin@2.0.0", "2.0.0");
		expect(await discoverOpenCodePlugins(logger)).toEqual([
			expect.objectContaining({ installPath, key: "plugin@2.0.0" }),
		]);
	});

	it("discovers global and project files in plural and legacy singular directories", async () => {
		const expectedPaths: string[] = [];
		for (const base of [configDir, join(projectDir, ".opencode")]) {
			for (const name of ["plugins", "plugin"]) {
				const dir = join(base, name);
				await mkdir(dir, { recursive: true });
				for (const extension of ["js", "ts"]) {
					const path = join(dir, `local.${extension}`);
					await writeFile(path, "export default () => ({});");
					await utimes(path, new Date("2026-01-01"), new Date("2026-01-01"));
					expectedPaths.push(path);
				}
				await writeFile(join(dir, "ignored.mjs"), "export default () => ({});");
			}
		}
		const plugins = await discoverOpenCodePlugins(logger, projectDir);
		expect(plugins.map((plugin) => plugin.installPath).sort()).toEqual(expectedPaths.sort());
		expect(new Set(plugins.map((plugin) => plugin.key)).size).toBe(plugins.length);
	});

	it("reports malformed config and entries without hiding valid sibling declarations", async () => {
		await writeFile(join(configDir, "opencode.jsonc"), '{"plugin": [');
		await writeFile(
			join(configDir, "opencode.json"),
			JSON.stringify({ plugin: [null, {}, [], "valid@1.2.3", "file:///outside/plugin.ts"] }),
		);
		await install("valid");
		expect((await discoverOpenCodePlugins(logger)).map((plugin) => plugin.key)).toEqual([
			"valid@1.2.3",
		]);
		expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining("Invalid OpenCode config:"));
		expect(logger.warn).toHaveBeenCalledWith(
			expect.stringContaining("Invalid OpenCode plugin entry:"),
		);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.stringContaining("Unsupported OpenCode plugin selector"),
		);
	});
});
