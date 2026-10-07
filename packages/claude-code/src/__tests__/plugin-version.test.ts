import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolvePluginManifest } from "../assets.js";

const packageDir = resolve(__dirname, "..", "..");
const packageVersion = (
	JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8")) as { version: string }
).version;
const roots: string[] = [];

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function temp(): string {
	const root = mkdtempSync(join(tmpdir(), "aidr-plugin-version-"));
	roots.push(root);
	return root;
}

function writeJson(file: string, value: unknown): void {
	mkdirSync(resolve(file, ".."), { recursive: true });
	writeFileSync(file, JSON.stringify(value));
}

describe("resolvePluginManifest", () => {
	it("prefers the marketplace plugin.json", () => {
		const root = temp();
		writeJson(join(root, ".claude-plugin", "plugin.json"), { name: "aidr", version: "9.8.7" });
		writeJson(join(root, "package.json"), {
			name: "@singularityrd/aidr-claude-code",
			version: "1.0.0",
		});
		expect(resolvePluginManifest(root, root)).toEqual({ name: "aidr", version: "9.8.7" });
	});

	it("falls back to the connector package.json when plugin.json is absent (endpoint install)", () => {
		const root = temp();
		writeJson(join(root, "package.json"), {
			name: "@singularityrd/aidr-claude-code",
			version: "1.2.3",
		});
		expect(resolvePluginManifest(join(root, "elsewhere"), root)).toEqual({
			name: null,
			version: "1.2.3",
		});
	});

	it("falls back when plugin.json has no version", () => {
		const root = temp();
		writeJson(join(root, ".claude-plugin", "plugin.json"), { name: "aidr" });
		writeJson(join(root, "package.json"), {
			name: "@singularityrd/aidr-claude-code",
			version: "2.0.0",
		});
		expect(resolvePluginManifest(root, root)).toEqual({ name: "aidr", version: "2.0.0" });
	});

	it("ignores an unrelated package.json", () => {
		const root = temp();
		writeJson(join(root, "package.json"), { name: "some-project", version: "5.5.5" });
		expect(resolvePluginManifest(root, root).version).toBe("0.0.0");
	});

	it("the built session-start hook reports the package version from an endpoint-style layout", () => {
		const root = temp();
		const install = join(root, "install");
		const home = join(root, "home");
		mkdirSync(home, { recursive: true });
		cpSync(join(packageDir, "dist"), join(install, "dist"), { recursive: true });
		cpSync(join(packageDir, "package.json"), join(install, "package.json"));
		const env: NodeJS.ProcessEnv = {
			...process.env,
			HOME: home,
			USERPROFILE: home,
			SENTRY_ENABLED: "0",
		};
		for (const key of ["CLAUDE_PLUGIN_ROOT", "AIDR_PLUGIN_ROOT", "AIDR_COMMERCIAL"])
			delete env[key];
		const result = spawnSync(process.execPath, [join(install, "dist", "session-start.cjs")], {
			cwd: install,
			env,
			input: "{}",
			encoding: "utf8",
			timeout: 30_000,
		});
		expect(result.stdout).toContain(`v${packageVersion}`);
		expect(result.stdout).not.toContain("v0.0.0");
	});
});
