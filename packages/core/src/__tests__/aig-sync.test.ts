import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	checkForUpdates,
	getSyncStatus,
	validateAigDataBundle,
} from "../aig-sync.js";

const SOURCE_GENERATED = resolve(process.cwd(), "packages/core/src/generated");
let tempDir: string;
let previousGeneratedDir: string | undefined;

beforeEach(() => {
	tempDir = mkdtempSync(join(tmpdir(), "aig-sync-test-"));
	for (const file of ["aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json", "aig-data-manifest.json"]) {
		cpSync(join(SOURCE_GENERATED, file), join(tempDir, file));
	}
	previousGeneratedDir = process.env.AIG_GENERATED_DIR;
});

afterEach(() => {
	if (previousGeneratedDir === undefined) delete process.env.AIG_GENERATED_DIR;
	else process.env.AIG_GENERATED_DIR = previousGeneratedDir;
	rmSync(tempDir, { recursive: true, force: true });
});

describe("AIG sync bundle contract", () => {
	it("reports a valid generated bundle and does not request a redundant update", async () => {
		const status = await getSyncStatus({ mode: "local", generated_dir: tempDir });
		expect(status.manifestValid).toBe(true);
		expect(status.signaturePresent).toBe(false);
		expect(status.bundleId).toMatch(/^[a-f0-9]{64}$/);
		expect(status.cveCount).toBe(1925);
		expect((await checkForUpdates({ mode: "local", generated_dir: tempDir })).updateAvailable).toBe(false);
	});

	it("fails closed when an index is changed after manifest generation", async () => {
		const path = join(tempDir, "aig-cve-index.json");
		writeFileSync(path, `${readFileSync(path, "utf8")}\n`, "utf8");
		const validation = await validateAigDataBundle(tempDir);
		expect(validation.valid).toBe(false);
		expect(validation.error).toContain("hash/size mismatch");
		const status = await checkForUpdates({ mode: "local", generated_dir: tempDir });
		expect(status.updateAvailable).toBe(true);
		expect(status.manifestValid).toBe(false);
	});

	it("requires a signature when release policy is enabled", async () => {
		const validation = await validateAigDataBundle(tempDir, { require_signed: true, public_key: "" });
		expect(validation.valid).toBe(false);
		expect(validation.error).toContain("signed manifest required");
	});
});
