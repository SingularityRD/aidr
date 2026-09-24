import { access } from "node:fs/promises";
import { join } from "node:path";

export const VSIX_INTEGRITY_EVIDENCE_FILES = Object.freeze([
	"dist/aidr-artifact.manifest.json",
	"dist/aidr-artifact.manifest.sig",
	"dist/aidr-sbom.cdx.json",
	"dist/aidr-sbom.cdx.json.sha256",
]);

export const VSIX_PACKAGE_FILES = Object.freeze([
	"dist/cursor_extension.js",
	"dist/vscode_extension.js",
	"dist/aidr-hook.cjs",
	...VSIX_INTEGRITY_EVIDENCE_FILES,
	"resources/**",
	"aidr-icon.png",
	"package.json",
	"README.md",
	"LICENSE",
]);

export async function assertVsixIntegrityEvidence(extensionRoot) {
	const missing = [];
	for (const relativePath of VSIX_INTEGRITY_EVIDENCE_FILES) {
		try {
			await access(join(extensionRoot, relativePath));
		} catch {
			missing.push(relativePath);
		}
	}
	if (missing.length > 0) {
		throw new Error(`VSIX integrity evidence is missing: ${missing.join(", ")}`);
	}
}
