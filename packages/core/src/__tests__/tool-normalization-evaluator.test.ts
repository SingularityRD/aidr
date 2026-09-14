import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { VerdictCache } from "../cache.js";
import { evaluateToolCall } from "../evaluator.js";
import { extractFromBash } from "../extractors.js";
import { extractPackagesFromCommand } from "../package-extractor.js";
import { ConfigSchema, nullLogger } from "../types.js";
import { VERSION } from "../version.js";
import { makeTmpDir } from "./test-utils.js";

const NEVER_EXPIRES = "9999-12-31T23:59:59.000Z";
const previousHome = process.env.HOME;

afterAll(() => {
	if (previousHome === undefined) delete process.env.HOME;
	else process.env.HOME = previousHome;
});

async function packageConfig(packageName: string, version: string) {
	const dir = await makeTmpDir();
	process.env.HOME = dir;
	const aidrDir = join(dir, ".singularity-aidr");
	await mkdir(aidrDir, { recursive: true });
	const cachePath = join(aidrDir, "cache.json");
	const configPath = join(aidrDir, "config.json");
	await writeFile(
		cachePath,
		JSON.stringify({
			urls: {},
			commands: {},
			packages: {
				[`npm:${packageName}@${version}`]: {
					verdict: "deny",
					severity: "critical",
					reasons: ["Synthetic package intelligence deny"],
					source: "package_check",
					checkedAt: new Date().toISOString(),
					expiresAt: NEVER_EXPIRES,
					aidrVersion: VERSION,
				},
			},
		}),
		"utf8",
	);
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			control_plane: { enabled: false },
			heuristics_enabled: false,
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: true },
			cache: { enabled: true, path: cachePath },
			logging: { enabled: false },
		}),
		"utf8",
	);
	return { cachePath, configPath, dir };
}

describe("normalized requests reach semantic evaluation legs", () => {
	it("runs package intelligence for a lowercase OpenCode bash call", async () => {
		const { cachePath, configPath, dir } = await packageConfig("synthetic-aidr-package", "1.0.0");
		const command = "npm install synthetic-aidr-package@1.0.0";
		expect(extractPackagesFromCommand(command)).toEqual([
			{
				name: "synthetic-aidr-package",
				version: "1.0.0",
				registry: "npm",
				source: "command",
			},
		]);
		const cache = new VerdictCache(
			ConfigSchema.parse({ cache: { enabled: true, path: cachePath } }).cache,
			nullLogger,
			VERSION,
		);
		await cache.load();
		expect(cache.getPackage("npm:synthetic-aidr-package@1.0.0")?.verdict).toBe("deny");
		const verdict = await evaluateToolCall(
			{
				sessionId: "opencode-bash",
				toolName: "bash",
				toolInput: { command },
				artifacts: extractFromBash(command),
			},
			{ threatsDir: join(dir, "unused"), allowlistsDir: join(dir, "unused"), configPath },
		);

		expect(verdict.decision).toBe("deny");
		expect(verdict.source).toBe("package_check");
		expect(verdict.reasons.join(" ")).toContain("Synthetic package intelligence deny");
	});

	it("inspects an Edit manifest when content is empty and artifacts were omitted", async () => {
		const { configPath, dir } = await packageConfig("synthetic-aidr-package", "1.0.0");
		const verdict = await evaluateToolCall(
			{
				sessionId: "edit-manifest",
				toolName: "edit",
				toolInput: {
					filePath: "package.json",
					content: "",
					newString: '{"dependencies":{"synthetic-aidr-package":"1.0.0"}}',
				},
				artifacts: [],
			},
			{ threatsDir: join(dir, "unused"), allowlistsDir: join(dir, "unused"), configPath },
		);

		expect(verdict.decision).toBe("deny");
		expect(verdict.source).toBe("package_check");
	});

	it("runs package intelligence for a Codex apply_patch manifest edit", async () => {
		const { configPath, dir } = await packageConfig("synthetic-aidr-package", "1.0.0");
		// Authentic Codex payload shape (packages/codex/src/extractors.ts): the
		// patch text is sent in `command`, and the connector emits one `content`
		// artifact for the body plus one `file_path` artifact per touched file.
		const patch = [
			"*** Begin Patch",
			"*** Update File: package.json",
			'-{"dependencies":{"left-pad":"1.3.0"}}',
			'+{"dependencies":{"synthetic-aidr-package":"1.0.0"}}',
			"*** End Patch",
		].join("\n");

		const verdict = await evaluateToolCall(
			{
				sessionId: "codex-apply-patch",
				toolName: "apply_patch",
				toolInput: { command: patch },
				artifacts: [
					{ type: "content", value: patch, context: "apply_patch" },
					{ type: "file_path", value: "package.json" },
				],
			},
			{ threatsDir: join(dir, "unused"), allowlistsDir: join(dir, "unused"), configPath },
		);

		expect(verdict.decision).toBe("deny");
		expect(verdict.source).toBe("package_check");
	});

	it("runs package intelligence for an unknown connector alias carrying a manifest", async () => {
		const { configPath, dir } = await packageConfig("synthetic-aidr-package", "1.0.0");
		const verdict = await evaluateToolCall(
			{
				sessionId: "unknown-alias-manifest",
				// Not a canonical tool name: core must not have to know a
				// connector's edit-tool name to inspect the manifest it writes.
				toolName: "manifest_writer_v2",
				toolInput: {
					filePath: "package.json",
					content: '{"dependencies":{"synthetic-aidr-package":"1.0.0"}}',
				},
				artifacts: [],
			},
			{ threatsDir: join(dir, "unused"), allowlistsDir: join(dir, "unused"), configPath },
		);

		expect(verdict.decision).toBe("deny");
		expect(verdict.source).toBe("package_check");
	});

	it("does not mistake reading a manifest for a supply-chain edit", async () => {
		// The package leg is now payload-driven, so the exclusion of observation
		// tools is load-bearing: a Read of a manifest must stay exactly what it
		// was before, never a package verdict.
		const { configPath, dir } = await packageConfig("synthetic-aidr-package", "1.0.0");
		const content = '{"dependencies":{"synthetic-aidr-package":"1.0.0"}}';
		const verdict = await evaluateToolCall(
			{
				sessionId: "read-manifest",
				toolName: "Read",
				toolInput: { file_path: "package.json", content },
				artifacts: [
					{ type: "file_path", value: "package.json", context: "read" },
					{ type: "content", value: content, context: "read" },
				],
			},
			{ threatsDir: join(dir, "unused"), allowlistsDir: join(dir, "unused"), configPath },
		);

		expect(verdict.source).not.toBe("package_check");
		expect(verdict.decision).toBe("allow");
	});
});
