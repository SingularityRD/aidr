/**
 * Encrypt a file into the AES-256-GCM envelope format expected by
 * @singularityrd/aidr-core intel pack loader.
 *
 * Envelope format (binary):
 * - 12 bytes: IV/nonce
 * - N bytes: ciphertext
 * - 16 bytes: auth tag
 *
 * Usage:
 *   node scripts/encrypt-intel-pack-file.mjs --in <plaintext> --out <payload.enc> --key-b64 <base64-32B>
 *
 * Prints a small JSON summary to stdout:
 *   { sha256_plain, sha256_cipher, bytes_plain, bytes_cipher }
 */

import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const args = parseArgs(process.argv.slice(2));
const inPath = args["--in"];
const outPath = args["--out"];
const keyB64 = args["--key-b64"] ?? process.env.AIDR_PACK_KEY_B64;

if (!inPath || !outPath || !keyB64) {
	console.error("Usage: --in <file> --out <file> --key-b64 <base64-32B>");
	process.exit(2);
}

const key = Buffer.from(String(keyB64).trim(), "base64");
if (key.length !== 32) {
	console.error("ERROR: key must be 32 bytes (base64).");
	process.exit(2);
}

const plain = await readFile(path.resolve(inPath));
const iv = randomBytes(12);
const cipher = createCipheriv("aes-256-gcm", key, iv);
const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
const tag = cipher.getAuthTag();

const envelope = Buffer.concat([iv, ciphertext, tag]);
await writeFile(path.resolve(outPath), envelope);

const sha256Plain = createHash("sha256").update(plain).digest("hex");
const sha256Cipher = createHash("sha256").update(envelope).digest("hex");

process.stdout.write(
	`${JSON.stringify(
		{
			sha256_plain: sha256Plain,
			sha256_cipher: sha256Cipher,
			bytes_plain: plain.length,
			bytes_cipher: envelope.length,
		},
		null,
		2,
	)}\n`,
);

function parseArgs(argv) {
	const out = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (!a || !a.startsWith("--")) continue;
		const key = a;
		const val = argv[i + 1];
		if (val && !val.startsWith("--")) {
			out[key] = val;
			i++;
		} else {
			out[key] = true;
		}
	}
	return out;
}

