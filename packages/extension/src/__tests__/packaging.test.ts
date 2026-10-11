/// <reference types="node" />

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
	assertVsixIntegrityEvidence,
	VSIX_INTEGRITY_EVIDENCE_FILES,
	VSIX_PACKAGE_FILES,
} from "../../../../scripts/lib/vsix-package-files.mjs";
import { buildCursorManifest, buildVsCodeManifest } from "../../scripts/package-vscode-vsix.mjs";

const EXTENSION_ROOT = resolve(__dirname, "..", "..");
const REPO_ROOT = resolve(EXTENSION_ROOT, "..", "..");
const REQUIRED_ENTRY_BUNDLES = ["dist/cursor_extension.js", "dist/vscode_extension.js"];

async function baseManifest(): Promise<Record<string, unknown>> {
	return JSON.parse(await readFile(resolve(EXTENSION_ROOT, "package.json"), "utf8"));
}

function packagedFiles(manifest: Record<string, unknown>): string[] {
	return manifest.files as string[];
}

describe("VSIX packaging evidence", () => {
	it("ships signed evidence in the npm package that the release bundle packs", async () => {
		// The release bundle packs this package with `pnpm pack` and requires the
		// manifest, signature and SBOM inside it. A file list that omits them makes
		// the bundle fail; an absent file (unsigned developer build) is simply not
		// packed, so declaring them does not invent evidence.
		const manifest = await baseManifest();
		expect(packagedFiles(manifest)).toEqual(
			expect.arrayContaining([
				...REQUIRED_ENTRY_BUNDLES,
				"dist/aidr-hook.cjs",
				"dist/aidr-hook.bundle.cjs",
				...VSIX_INTEGRITY_EVIDENCE_FILES,
			]),
		);
	});

	it("does not declare signer-only evidence in an unsigned developer VSIX", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-vsix-unsigned-"));
		try {
			await mkdir(resolve(root, "dist"), { recursive: true });
			for (const relativePath of VSIX_INTEGRITY_EVIDENCE_FILES) {
				if (relativePath === "dist/aidr-artifact.manifest.sig") continue;
				await writeFile(resolve(root, relativePath), "fixture\n", "utf8");
			}
			const files = await assertVsixIntegrityEvidence(root, { requireSignature: false });
			expect(files).not.toContain("dist/aidr-artifact.manifest.sig");
			expect(files).toEqual(expect.arrayContaining(["dist/aidr-artifact.manifest.json"]));
			await expect(assertVsixIntegrityEvidence(root)).rejects.toThrow(
				"dist/aidr-artifact.manifest.sig",
			);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("keeps the staged Cursor package file set identical to the canonical packager", async () => {
		const manifest = buildCursorManifest(await baseManifest());
		expect(manifest.main).toBe("./dist/cursor_extension.js");
		expect(packagedFiles(manifest)).toEqual(VSIX_PACKAGE_FILES);
		expect(packagedFiles(manifest)).toEqual(
			expect.arrayContaining([...REQUIRED_ENTRY_BUNDLES, ...VSIX_INTEGRITY_EVIDENCE_FILES]),
		);
	});

	it("keeps the staged VS Code package file set identical to the canonical packager", async () => {
		const manifest = buildVsCodeManifest(await baseManifest());
		expect(manifest.main).toBe("./dist/vscode_extension.js");
		expect(packagedFiles(manifest)).toEqual(VSIX_PACKAGE_FILES);
		expect(packagedFiles(manifest)).toEqual(
			expect.arrayContaining([...REQUIRED_ENTRY_BUNDLES, ...VSIX_INTEGRITY_EVIDENCE_FILES]),
		);
	});

	it("fails before packaging when any integrity evidence file is missing", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-vsix-evidence-"));
		try {
			await mkdir(resolve(root, "dist"), { recursive: true });
			for (const relativePath of VSIX_INTEGRITY_EVIDENCE_FILES.slice(0, -1)) {
				await writeFile(resolve(root, relativePath), "fixture\n", "utf8");
			}
			await expect(assertVsixIntegrityEvidence(root)).rejects.toThrow(
				"dist/aidr-sbom.cdx.json.sha256",
			);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("keeps prepared-dist command names and public documentation in sync", async () => {
		const rootManifest = JSON.parse(await readFile(resolve(REPO_ROOT, "package.json"), "utf8"));
		const extensionManifest = await baseManifest();
		const rootScripts = rootManifest.scripts as Record<string, string>;
		const extensionScripts = extensionManifest.scripts as Record<string, string>;
		const preparedCommands = [
			"package:cursor:vsix:from-signed-dist",
			"package:vscode:vsix:from-signed-dist",
			"package:vsix:from-signed-dist",
		];
		for (const command of preparedCommands) {
			expect(extensionScripts[command]).toBeTypeOf("string");
		}
		expect(rootScripts["package:vsix:from-signed-dist"]).toContain("package:vsix:from-signed-dist");
		for (const obsolete of ["package:cursor:vsix", "package:vscode:vsix", "package:vsix"]) {
			expect(extensionScripts).not.toHaveProperty(obsolete);
			expect(rootScripts).not.toHaveProperty(obsolete);
		}

		const publicDocs = await Promise.all(
			[
				"README.md",
				"docs/getting-started.md",
				"docs/platform-guides/cursor.md",
				"docs/runbooks/deployment.md",
				"packages/extension/README.md",
				"scripts/closed-source-migration.ps1",
			].map((relative) => readFile(resolve(REPO_ROOT, relative), "utf8")),
		);
		const docs = publicDocs.join("\n");
		expect(docs).not.toMatch(/package:(?:cursor:|vscode:)?vsix(?!:from-signed-dist)/);
		const documentedCommands = [
			...docs.matchAll(/package:(?:cursor:|vscode:)?vsix:from-signed-dist/g),
		].map((match) => match[0]);
		for (const command of documentedCommands) {
			expect(extensionScripts[command] ?? rootScripts[command]).toBeTypeOf("string");
		}
		expect(docs).toContain("protected release-candidate pipeline");
	});
});
