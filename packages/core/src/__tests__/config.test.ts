import { writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig, resolvePath } from "../config.js";
import { makeTmpDir } from "./test-utils.js";

describe("resolvePath", () => {
	it("expands ~ prefix", () => {
		const resolved = resolvePath("~/foo/bar");
		expect(resolved).not.toContain("~");
		expect(resolved).toContain(join("foo", "bar"));
	});

	it("prefers HOME env when expanding ~", () => {
		const prevHome = process.env.HOME;
		const fakeHome = join(homedir(), "aidr-home-override-test");
		try {
			process.env.HOME = fakeHome;
			expect(resolvePath("~/foo/bar")).toBe(join(fakeHome, "foo", "bar"));
		} finally {
			if (prevHome === undefined) {
				delete process.env.HOME;
			} else {
				process.env.HOME = prevHome;
			}
		}
	});

	it("leaves absolute paths unchanged", () => {
		expect(resolvePath("/absolute/path")).toBe("/absolute/path");
	});
});

describe("loadConfig", () => {
	it("returns defaults for missing file", async () => {
		const config = await loadConfig("/nonexistent/config.json");
		expect(config.mode).toBe("managed");
		expect(config.sensitivity).toBe("balanced");
		expect(config.heuristics_enabled).toBe(true);
		expect(config.url_check.enabled).toBe(true);
		expect(config.url_check.timeout_seconds).toBe(5.0);
		expect(config.cache.enabled).toBe(true);
		expect(config.cache.ttl_malicious_seconds).toBe(3600);
		expect(config.cache.ttl_clean_seconds).toBe(86400);
		expect(config.control_plane.grace_period_hours).toBe(72);
		expect(config.control_plane.redact_mode).toBe("hash");
	});

	it("loads valid config", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({
				sensitivity: "paranoid",
				heuristics_enabled: false,
				url_check: { timeout_seconds: 10 },
			}),
		);
		const config = await loadConfig(configPath);
		expect(config.sensitivity).toBe("paranoid");
		expect(config.heuristics_enabled).toBe(false);
		expect(config.url_check.timeout_seconds).toBe(10);
		// Defaults preserved for unset fields
		expect(config.url_check.enabled).toBe(true);
		expect(config.cache.enabled).toBe(true);
	});

	it("returns defaults for malformed JSON", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(configPath, "not json");
		const config = await loadConfig(configPath);
		expect(config.sensitivity).toBe("balanced");
	});

	it("returns defaults for non-object JSON", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(configPath, JSON.stringify([1, 2, 3]));
		const config = await loadConfig(configPath);
		expect(config.sensitivity).toBe("balanced");
	});

	it("defaults disabled_threats to empty array when missing", async () => {
		const config = await loadConfig("/nonexistent/config.json");
		expect(config.disabled_threats).toEqual([]);
	});

	it("parses disabled_threats string array", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({ disabled_threats: ["CLT-CMD-001", "CLT-CMD-002"] }),
		);
		const config = await loadConfig(configPath);
		expect(config.disabled_threats).toEqual(["CLT-CMD-001", "CLT-CMD-002"]);
	});

	it("anchors relative state file paths under ~/.singularity-aidr", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({
				cache: { path: "cache-local.json" },
				allowlist: { path: "allowlists/main.json" },
				logging: { path: "logs/audit.jsonl" },
			}),
		);
		const config = await loadConfig(configPath);
		const aidrDir = join(homedir(), ".singularity-aidr");
		expect(config.cache.path).toBe(resolve(aidrDir, "cache-local.json"));
		expect(config.allowlist.path).toBe(resolve(aidrDir, "allowlists/main.json"));
		expect(config.logging.path).toBe(resolve(aidrDir, "logs/audit.jsonl"));
	});

	it("accepts explicit ~/.singularity-aidr paths", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({
				cache: { path: "~/.singularity-aidr/cache-custom.json" },
				allowlist: { path: "~/.singularity-aidr/allowlist-custom.json" },
				logging: { path: "~/.singularity-aidr/audit-custom.jsonl" },
			}),
		);
		const config = await loadConfig(configPath);
		const aidrDir = join(homedir(), ".singularity-aidr");
		expect(config.cache.path).toBe(resolve(aidrDir, "cache-custom.json"));
		expect(config.allowlist.path).toBe(resolve(aidrDir, "allowlist-custom.json"));
		expect(config.logging.path).toBe(resolve(aidrDir, "audit-custom.jsonl"));
	});

	it("accepts in-tree paths whose segment names start with '..'", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({
				cache: { path: "~/.singularity-aidr/..data/cache.json" },
				allowlist: { path: "~/.singularity-aidr/..cfg/allowlist.json" },
				logging: { path: "~/.singularity-aidr/..logs/audit.jsonl" },
			}),
		);
		const config = await loadConfig(configPath);
		const aidrDir = join(homedir(), ".singularity-aidr");
		expect(config.cache.path).toBe(resolve(aidrDir, "..data/cache.json"));
		expect(config.allowlist.path).toBe(resolve(aidrDir, "..cfg/allowlist.json"));
		expect(config.logging.path).toBe(resolve(aidrDir, "..logs/audit.jsonl"));
	});

	it("falls back to defaults when state file paths escape ~/.singularity-aidr", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		const outsideAbsolute = resolve(homedir(), "..", "evil-allowlist.json");
		await writeFile(
			configPath,
			JSON.stringify({
				cache: { path: "~/../../../tmp/evil-cache.json" },
				allowlist: { path: outsideAbsolute },
				logging: { path: "../evil-audit.jsonl" },
			}),
		);
		const config = await loadConfig(configPath);
		const aidrDir = join(homedir(), ".singularity-aidr");
		expect(config.cache.path).toBe(resolve(aidrDir, "cache.json"));
		expect(config.allowlist.path).toBe(resolve(aidrDir, "allowlist.json"));
		expect(config.logging.path).toBe(resolve(aidrDir, "audit.jsonl"));
	});

	it("falls back when state file paths resolve to ~/.singularity-aidr directory", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({
				cache: { path: "." },
				allowlist: { path: "   " },
				logging: { path: "~/.singularity-aidr/" },
			}),
		);
		const config = await loadConfig(configPath);
		const aidrDir = join(homedir(), ".singularity-aidr");
		expect(config.cache.path).toBe(resolve(aidrDir, "cache.json"));
		expect(config.allowlist.path).toBe(resolve(aidrDir, "allowlist.json"));
		expect(config.logging.path).toBe(resolve(aidrDir, "audit.jsonl"));
	});
});
