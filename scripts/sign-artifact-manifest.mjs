/**
 * Sign an AIDR artifact manifest with an Ed25519 private key.
 *
 * Usage:
 *   node scripts/sign-artifact-manifest.mjs --dir <artifactDir> --key <privateKeyPemPath>
 *
 * Reads `aidr-artifact.manifest.json` and writes a base64 signature to
 * `aidr-artifact.manifest.sig` in the same directory.
 */

import { sign, createPrivateKey } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const args = parseArgs(process.argv.slice(2));
const dir = path.resolve(args["--dir"] ?? ".");
const keyPath = args["--key"] ?? process.env.AIDR_SIGNING_PRIVATE_KEY_PEM_PATH;

if (!keyPath) {
	console.error("Missing required arg: --key <privateKeyPemPath> (or env AIDR_SIGNING_PRIVATE_KEY_PEM_PATH)");
	process.exit(2);
}

const MANIFEST_NAME = "aidr-artifact.manifest.json";
const SIG_NAME = "aidr-artifact.manifest.sig";

const manifestPath = path.join(dir, MANIFEST_NAME);
const sigPath = path.join(dir, SIG_NAME);

const manifestRaw = await readFile(manifestPath, "utf8");
const keyPem = await readFile(path.resolve(keyPath), "utf8");

// Best-effort: ensure watermark lineage is present before signing commercial artifacts.
try {
	const parsed = JSON.parse(manifestRaw);
	if (!parsed?.lineage?.watermark_id) {
		console.warn("WARN: manifest has no lineage.watermark_id (watermarking disabled for this artifact).");
	}
} catch {
	// ignore (signature verification will fail later if manifest isn't valid JSON)
}

const key = createPrivateKey(keyPem);
const signature = sign(null, Buffer.from(manifestRaw, "utf8"), key); // Ed25519 => algorithm null
if (signature.length !== 64) {
	console.error(`Unexpected signature length ${signature.length} (expected 64)`);
	process.exit(1);
}

await writeFile(sigPath, `${signature.toString("base64")}\n`, "utf8");
console.log(`Wrote ${sigPath}`);

function parseArgs(argv) {
	const m = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (!a.startsWith("--")) continue;
		const v = argv[i + 1];
		if (v && !v.startsWith("--")) {
			m[a] = v;
			i++;
		} else {
			m[a] = "true";
		}
	}
	return m;
}
