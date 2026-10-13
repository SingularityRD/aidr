#!/usr/bin/env node
// Validate the Windows MSI inputs and derive the WiX variables, before any
// signing or packaging step runs (called by build-msi.ps1; unit-tested on any
// OS). Prints one JSON object on success; exits non-zero with the reason on a
// bad input.
//
//   node deploy/installers/windows/msi-inputs.mjs --sea-dir <dir> \
//     --trust-key <pem> --trust-key-fingerprint <sha256> --version 0.6.0[-rc.N] \
//     --signing signed|unsigned

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
	checkSeaBundle,
	checkTrustKey,
	checkVersion,
	InstallerInputError,
	PACKAGE_NAME,
	parseFlags,
} from "../lib/common.mjs";

/** Stable across versions: MajorUpgrade replaces any earlier AIDR MSI. */
const UPGRADE_CODE = "6B3E5F0A-4C1D-4E8B-9A57-2D0C7E1F4A93";
/** Active Setup component id (per-user `aidr setup` at each user's next logon). */
const ACTIVE_SETUP_ID = "{0D9B6C2E-7A41-4F35-B8E2-5C3A91D0E6F4}";

export function msiInputs({ seaDir, trustKey, trustKeyFingerprint, version, signing }) {
	checkVersion(version);
	if (signing !== "signed" && signing !== "unsigned") {
		throw new InstallerInputError("--signing must be 'signed' or 'unsigned'");
	}
	const manifest = checkSeaBundle(resolve(seaDir), { platform: "win32" });
	if (manifest.sea?.arch !== "x64" && manifest.sea?.arch !== "arm64") {
		throw new InstallerInputError(`unsupported SEA architecture ${manifest.sea?.arch}`);
	}
	const { fingerprint } = checkTrustKey(trustKey, trustKeyFingerprint);
	const [major, minor, patch] = version.replace(/-.*$/u, "").split(".").map(Number);
	if (major > 255 || minor > 255 || patch > 65535) {
		throw new InstallerInputError(`version ${version} exceeds the MSI ProductVersion range`);
	}
	const arch = manifest.sea.arch;
	return {
		productVersion: `${major}.${minor}.${patch}`,
		activeSetupVersion: `${major},${minor},${patch}`,
		arch,
		trustKeyFingerprint: fingerprint,
		seaManifestVersion: manifest.artifact_version,
		// An unsigned build says so in its file name; it is never published as signed.
		outputName: `${PACKAGE_NAME}-${version}-windows-${arch}${signing === "unsigned" ? "-UNSIGNED" : ""}.msi`,
		upgradeCode: UPGRADE_CODE,
		activeSetupId: ACTIVE_SETUP_ID,
	};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	try {
		const flags = parseFlags(process.argv.slice(2), ["sea-dir", "trust-key", "trust-key-fingerprint", "version", "signing"]);
		for (const required of ["sea-dir", "trust-key", "trust-key-fingerprint", "version", "signing"]) {
			if (!flags[required]) throw new InstallerInputError(`--${required} is required`);
		}
		const inputs = msiInputs({
			seaDir: flags["sea-dir"],
			trustKey: flags["trust-key"],
			trustKeyFingerprint: flags["trust-key-fingerprint"],
			version: flags.version,
			signing: flags.signing,
		});
		console.log(JSON.stringify(inputs));
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
		process.exit(1);
	}
}
