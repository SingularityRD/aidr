import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it, vi } from "vitest";

const originalCwd = process.cwd();
let isolatedCwd: string | undefined;

afterEach(async () => {
	process.chdir(originalCwd);
	vi.unstubAllGlobals();
	if (isolatedCwd) await rm(isolatedCwd, { recursive: true, force: true });
});

it("finds repository assets when an ESM consumer inherits a relative global __dirname", async () => {
	isolatedCwd = await mkdtemp(join(tmpdir(), "aidr-codex-assets-"));
	process.chdir(isolatedCwd);
	vi.stubGlobal("__dirname", ".");
	vi.resetModules();
	const { resolveAssetDir } = await import("../assets.js");
	const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
	expect(resolveAssetDir("threats")).toBe(join(repositoryRoot, "threats"));
	expect(resolveAssetDir("allowlists")).toBe(join(repositoryRoot, "allowlists"));
});
