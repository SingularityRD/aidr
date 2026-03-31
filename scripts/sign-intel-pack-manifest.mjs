/**
 * Sign an intel pack manifest (manifest.json) with Ed25519 and write base64 signature to manifest.sig.
 *
 * Usage:
 *   node scripts/sign-intel-pack-manifest.mjs --manifest path/to/manifest.json --out path/to/manifest.sig --key-pkcs8-b64 <base64>
 *
 * Notes:
 * - The signature covers the raw UTF-8 bytes of the manifest JSON file.
 * - Keep the private key server-side (pack build pipeline). Clients only need the public key in:
 *   ~/.singularity-aidr/intel/trusted-keys.json  (key_id -> public key PEM)
 */

import { readFile, writeFile } from "node:fs/promises";
import { sign } from "node:crypto";

function parseArgs(argv) {
	const out = {};
	for (let i = 2; i < argv.length; i++) {
		const a = argv[i];
		if (!a?.startsWith("--")) continue;
		const key = a.slice(2);
		const value = argv[i + 1];
		if (value && !value.startsWith("--")) {
			out[key] = value;
			i++;
		} else {
			out[key] = "true";
		}
	}
	return out;
}

const args = parseArgs(process.argv);
const manifestPath = args.manifest;
const outPath = args.out;
const keyPkcs8B64 = args["key-pkcs8-b64"];

if (!manifestPath || !outPath || !keyPkcs8B64) {
	console.error(
		"Missing args. Expected: --manifest <path> --out <path> --key-pkcs8-b64 <base64>",
	);
	process.exit(2);
}

let keyPem;
try {
	keyPem = Buffer.from(keyPkcs8B64, "base64").toString("utf8");
} catch {
	console.error("Invalid --key-pkcs8-b64 (not base64)");
	process.exit(2);
}

const manifestBytes = await readFile(manifestPath);
const sig = sign(null, manifestBytes, keyPem).toString("base64");
await writeFile(outPath, `${sig}\n`, "utf8");

