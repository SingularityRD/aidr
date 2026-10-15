import { access } from "node:fs/promises";
import { join } from "node:path";

export const VSIX_INTEGRITY_EVIDENCE_FILES = Object.freeze([
	"dist/aidr-artifact.manifest.json",
	"dist/aidr-artifact.manifest.sig",
	"dist/aidr-sbom.cdx.json",
	"dist/aidr-sbom.cdx.json.sha256",
]);

/** Copied next to package.json when a VSIX is staged (see the packaging scripts). */
export const VSIX_LOCALIZATION_FILES = Object.freeze([
	"package.nls.json",
	"package.nls.tr.json",
	"l10n/**",
]);

export const VSIX_PACKAGE_FILES = Object.freeze([
	"dist/cursor_extension.js",
	"dist/vscode_extension.js",
	"dist/aidr-hook.cjs",
	// Real hook runner; aidr-hook.cjs is the compile-cache bootstrap that requires it.
	"dist/aidr-hook.bundle.cjs",
	// Stable hook launcher (copied to the AIDR home) and the vscode:uninstall cleanup.
	"dist/aidr-hook-launcher.cjs",
	"dist/aidr-uninstall.cjs",
	...VSIX_INTEGRITY_EVIDENCE_FILES,
	"dist/resources/**",
	// Native AMSI addon (koffi, MIT) loaded by the hook runner; manifest-covered.
	"dist/vendor/**",
	"aidr-icon.png",
	// Localized manifest strings (package.nls*.json) and runtime l10n bundles.
	...VSIX_LOCALIZATION_FILES,
	"package.json",
	"README.md",
	"LICENSE",
]);

export async function assertVsixIntegrityEvidence(extensionRoot, { requireSignature = true } = {}) {
	const missing = [];
	let signaturePresent = true;
	for (const relativePath of VSIX_INTEGRITY_EVIDENCE_FILES) {
		try {
			await access(join(extensionRoot, relativePath));
		} catch (error) {
			if (!requireSignature && relativePath === "dist/aidr-artifact.manifest.sig" && error.code === "ENOENT") {
				signaturePresent = false;
				continue;
			}
			missing.push(relativePath);
		}
	}
	if (missing.length > 0) {
		throw new Error(`VSIX integrity evidence is missing: ${missing.join(", ")}`);
	}
	return VSIX_PACKAGE_FILES.filter((file) => signaturePresent || file !== "dist/aidr-artifact.manifest.sig");
}
