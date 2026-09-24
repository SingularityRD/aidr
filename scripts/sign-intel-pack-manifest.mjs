#!/usr/bin/env node
/** Sign the exact manifest bytes consumed by the offline intel-pack loader. */
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i += 1) {
		const name = argv[i];
		if (name === "--help" || name === "-h") return { help: true };
		if (!["--manifest", "--private-key", "--out"].includes(name) || !argv[i + 1] || argv[i + 1].startsWith("--")) {
			throw new Error("Usage: node scripts/sign-intel-pack-manifest.mjs --manifest <file> --private-key <restricted-pem-file> [--out <signature-file>]");
		}
		if (values[name]) throw new Error(`Duplicate argument ${name}`);
		values[name] = argv[++i];
	}
	if (!values["--manifest"] || !values["--private-key"]) {
		throw new Error("Usage: node scripts/sign-intel-pack-manifest.mjs --manifest <file> --private-key <restricted-pem-file> [--out <signature-file>]");
	}
	return values;
}

function requireRegularFile(file, label) {
	const stats = lstatSync(file);
	if (stats.isSymbolicLink() || !stats.isFile()) throw new Error(`${label} must be a regular, non-symlink file`);
	return stats;
}

try {
	const args = parseArgs(process.argv.slice(2));
	if (args.help) {
		console.log("Usage: node scripts/sign-intel-pack-manifest.mjs --manifest <file> --private-key <restricted-pem-file> [--out <signature-file>]");
		process.exit(0);
	}
	const manifestPath = resolve(args["--manifest"]);
	const keyPath = resolve(args["--private-key"]);
	const outputPath = resolve(args["--out"] ?? `${dirname(manifestPath)}/manifest.sig`);
	const keyStats = requireRegularFile(keyPath, "Private key");
	if (process.platform !== "win32" && (keyStats.mode & 0o077) !== 0) {
		throw new Error("Private-key file must be owner-only (mode 0600) on POSIX systems");
	}
	requireRegularFile(manifestPath, "Manifest");
	const manifestBytes = readFileSync(manifestPath);
	const manifest = JSON.parse(manifestBytes.toString("utf8"));
	if (
		!manifest || typeof manifest !== "object" || Array.isArray(manifest) ||
		typeof manifest.pack_id !== "string" || !manifest.pack_id ||
		typeof manifest.version !== "string" || !manifest.version ||
		typeof manifest.key_id !== "string" || !manifest.key_id ||
		!Array.isArray(manifest.files)
	) {
		throw new Error("Manifest must include pack_id, version, key_id, and files");
	}

	const privateKey = createPrivateKey(readFileSync(keyPath));
	if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Private key must be Ed25519");
	const signature = sign(null, manifestBytes, privateKey);
	if (!verify(null, manifestBytes, createPublicKey(privateKey), signature)) {
		throw new Error("Generated signature did not verify against the manifest bytes");
	}
	// wx makes publication immutable by default: never replace a prior signature.
	writeFileSync(outputPath, `${signature.toString("base64")}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
	console.log(`Signed intel-pack manifest (${manifest.pack_id}@${manifest.version}, key ${manifest.key_id})`);
} catch (error) {
	console.error(`ERROR: ${error instanceof Error ? error.message : "signing failed"}`);
	process.exitCode = 1;
}
