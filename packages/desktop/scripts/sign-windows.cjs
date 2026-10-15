// electron-builder custom signer (win.signtoolOptions.sign).
//
// Without the release pipeline's Authenticode configuration this does nothing,
// so local and PoC builds stay unsigned. With AIDR_DESKTOP_SIGN=1 it signs each
// file through the repository's HSM-capable signer library,
// scripts/windows-authenticode-signer.ps1 (pfx | azure-key-vault | jsign, see
// docs/operations/windows-code-signing.md), which also verifies the signature,
// the pinned certificate thumbprint and the RFC 3161 timestamp.
//
// The AIDR runtime under resources/runtime/ is NOT signed here: its files are
// covered by the bundle manifest the hooks verify, so it must be Authenticode-
// signed before staging and its manifests rewritten with
// `build-sea.mjs --remanifest <dir>` (README.md "Signing").

const { spawnSync } = require("node:child_process");
const { resolve } = require("node:path");

const SIGNER = resolve(__dirname, "..", "..", "..", "scripts", "windows-authenticode-signer.ps1");

exports.default = async function sign(configuration) {
	const file = configuration.path;
	if (process.env.AIDR_DESKTOP_SIGN !== "1") return;
	if (/[\\/]resources[\\/]runtime[\\/]/i.test(file)) return;
	for (const name of ["AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT", "AIDR_WINDOWS_TIMESTAMP_SERVER"]) {
		if (!process.env[name]) throw new Error(`${name} is required to sign ${file}`);
	}
	// The file path travels in an environment variable, never inside the script text.
	const script = [
		"$ErrorActionPreference = 'Stop'",
		`. '${SIGNER.replaceAll("'", "''")}'`,
		"Invoke-AidrAuthenticodeSign -Files @($env:AIDR_SIGN_FILE) -Thumbprint $env:AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT -TimestampServer $env:AIDR_WINDOWS_TIMESTAMP_SERVER -Description 'Singularity AIDR' -SignTool $env:AIDR_SIGNTOOL",
	].join("; ");
	const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
		env: { ...process.env, AIDR_SIGN_FILE: file },
		stdio: "inherit",
		windowsHide: true,
	});
	if (result.status !== 0) throw new Error(`Authenticode signing failed for ${file}`);
};
