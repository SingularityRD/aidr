import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as esbuild from "esbuild";
import { afterEach, describe, expect, it } from "vitest";
import {
	binaryFileName,
	bundleCli,
	CLI_ENTRY_POINT,
	checkSeaSupport,
	ENTRY_POINTS,
	MANIFEST_NAME,
	relocatedSmoke,
	SEA_SENTINEL_FUSE,
	stageRuntimeFiles,
	verifyDistributionManifest,
	writeDistributionManifest,
} from "../../scripts/build-sea.mjs";

const distDir = resolve(__dirname, "../../dist");
const scratchDirs: string[] = [];
afterEach(() => {
	for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/**
 * Stage a SEA distribution from the built connector, with each "binary" being
 * the bundle itself so the relocated layout is exercised with `node <file>`
 * exactly as the SEA resolves its package root (dirname(dirname(execPath))).
 */
function stageDistribution(withRuntime = true): string {
	const outDir = mkdtempSync(join(tmpdir(), "aidr-sea-dist-"));
	scratchDirs.push(outDir);
	mkdirSync(join(outDir, "bin"), { recursive: true });
	if (withRuntime) expect(stageRuntimeFiles(distDir, outDir)).toEqual([]);
	for (const { binary, main } of ENTRY_POINTS) {
		copyFileSync(join(distDir, main), join(outDir, "bin", binaryFileName(binary)));
	}
	writeDistributionManifest(outDir, { version: "0.0.0-test" });
	return outDir;
}

const viaNode = (file: string): [string, string[]] => [process.execPath, [file]];

const withFuse = (state: string) => Buffer.from(`\0\0prefix${SEA_SENTINEL_FUSE}${state}suffix\0`);

describe("build-sea checkSeaSupport", () => {
	it("accepts a supported official Node binary", () => {
		expect(checkSeaSupport({ version: "v22.12.0", binary: withFuse(":0") })).toEqual({ ok: true });
		expect(checkSeaSupport({ version: "v24.18.1", binary: withFuse(":0") })).toEqual({ ok: true });
	});

	it("rejects Node versions older than 20", () => {
		const result = checkSeaSupport({ version: "v18.20.4", binary: withFuse(":0") });
		expect(result.ok).toBe(false);
		expect(result.ok === false && result.reason).toMatch(/Node >= 20/);
	});

	it("rejects an unparseable version string", () => {
		expect(checkSeaSupport({ version: "garbage" }).ok).toBe(false);
	});

	it("rejects a shared-libnode build", () => {
		const result = checkSeaSupport({
			version: "v22.12.0",
			nodeShared: true,
			binary: withFuse(":0"),
		});
		expect(result.ok === false && result.reason).toMatch(/shared libnode/);
	});

	it("rejects a binary without the SEA sentinel fuse (e.g. Homebrew)", () => {
		const result = checkSeaSupport({ version: "v22.12.0", binary: Buffer.from("no fuse here") });
		expect(result.ok === false && result.reason).toMatch(/sentinel fuse/);
	});

	it("rejects a binary that is already a SEA", () => {
		const result = checkSeaSupport({ version: "v22.12.0", binary: withFuse(":1") });
		expect(result.ok === false && result.reason).toMatch(/already/);
	});

	it("rejects a binary with duplicate sentinels", () => {
		const twice = Buffer.concat([withFuse(":0"), withFuse(":0")]);
		expect(checkSeaSupport({ version: "v22.12.0", binary: twice }).ok).toBe(false);
	});
});

describe("build-sea outputs", () => {
	it("builds every hook and bin entry point, not only PreToolUse/SessionStart (MSC-11)", () => {
		expect(ENTRY_POINTS.map((e) => e.binary)).toEqual([
			"aidr-pre-tool-use",
			"aidr-post-tool-use",
			"aidr-session-start",
			"aidr-user-prompt-submit",
			"aidr-health",
			"aidr-mcp-server",
		]);
		for (const { main } of ENTRY_POINTS) expect(existsSync(join(distDir, main)), main).toBe(true);
	});

	it("appends .exe only on Windows", () => {
		expect(binaryFileName("aidr-pre-tool-use", "win32")).toBe("aidr-pre-tool-use.exe");
		expect(binaryFileName("aidr-pre-tool-use", "linux")).toBe("aidr-pre-tool-use");
		expect(binaryFileName("aidr-pre-tool-use", "darwin")).toBe("aidr-pre-tool-use");
	});
});

describe("build-sea relocatable distribution (MSC-11)", () => {
	it("a relocated binary without its shipped rules cannot deny (the defect the layout fixes)", () => {
		const bare = stageDistribution(false);
		const problems = relocatedSmoke(bare, viaNode);
		expect(problems.join("\n")).toMatch(/not deny/);
		expect(verifyDistributionManifest(bare).join("\n")).toMatch(
			/dist\/resources\/threats is missing/,
		);
	}, 60_000);

	it("the staged distribution denies a destructive command from its shipped rules wherever it is copied", () => {
		const outDir = stageDistribution();
		expect(verifyDistributionManifest(outDir)).toEqual([]);
		expect(relocatedSmoke(outDir, viaNode)).toEqual([]);
	}, 60_000);

	it("the integrity manifest catches a changed, added or removed file", () => {
		const outDir = stageDistribution();
		writeFileSync(
			join(outDir, "dist", "resources", "threats", "injected.yaml"),
			"- id: injected\n",
		);
		writeFileSync(join(outDir, "bin", binaryFileName("aidr-health")), "tampered");
		rmSync(join(outDir, "dist", "response-worker.cjs"));
		const problems = verifyDistributionManifest(outDir).join("\n");
		expect(problems).toMatch(/dist\/resources\/threats\/injected\.yaml is not in the manifest/);
		expect(problems).toMatch(/bin\/aidr-health(\.exe)? does not match its manifest digest/);
		expect(problems).toMatch(/dist\/response-worker\.cjs is missing/);
		rmSync(join(outDir, MANIFEST_NAME));
		expect(verifyDistributionManifest(outDir)).toEqual([`${MANIFEST_NAME} is missing`]);
	});

	it("the bundled aidr CLI loads the rules shipped next to it and is listed as an entry point", async () => {
		const outDir = stageDistribution();
		const cliDist = resolve(__dirname, "../../../cli/dist");
		const bundle = join(outDir, "cli.bundle.cjs");
		await bundleCli({ cliDist, outfile: bundle, version: "0.0.0-test", esbuild });
		copyFileSync(bundle, join(outDir, "bin", binaryFileName(CLI_ENTRY_POINT.binary)));
		rmSync(bundle);
		const manifest = writeDistributionManifest(outDir, { version: "0.0.0-test" });
		expect(manifest.sea.entry_points).toContain(binaryFileName("aidr"));
		expect(verifyDistributionManifest(outDir)).toEqual([]);
		expect(relocatedSmoke(outDir, viaNode)).toEqual([]);
		// Without its rules the relocated CLI must say so, not report a pass.
		rmSync(join(outDir, "dist", "resources", "threats"), { recursive: true });
		expect(relocatedSmoke(outDir, viaNode).join("\n")).toMatch(
			/aidr CLI could not load the shipped rules/,
		);
	}, 120_000);

	it("staging refuses a connector build without rules or with source maps", () => {
		const fakeDist = mkdtempSync(join(tmpdir(), "aidr-sea-fake-dist-"));
		scratchDirs.push(fakeDist);
		const out = mkdtempSync(join(tmpdir(), "aidr-sea-fake-out-"));
		scratchDirs.push(out);
		expect(stageRuntimeFiles(fakeDist, out).join("\n")).toMatch(/resources\/threats is missing/);
		mkdirSync(join(fakeDist, "resources", "threats"), { recursive: true });
		mkdirSync(join(fakeDist, "resources", "allowlists"), { recursive: true });
		writeFileSync(join(fakeDist, "response-worker.cjs"), "");
		writeFileSync(join(fakeDist, "vendor.map"), "{}");
		mkdirSync(join(fakeDist, "vendor"));
		writeFileSync(join(fakeDist, "vendor", "x.js.map"), "{}");
		const problems = stageRuntimeFiles(fakeDist, out).join("\n");
		expect(problems).toMatch(/contains no rule files/);
		expect(problems).toMatch(/source maps would ship: dist\/vendor\/x\.js\.map/);
	});
});
