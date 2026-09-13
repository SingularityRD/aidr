#!/usr/bin/env node

/**
 * Offline Ed25519 signing for an already assembled AIDR release directory.
 *
 * The private key must remain outside the release directory. The output is an
 * exact-byte manifest plus a detached signature; the public trust policy is
 * deliberately created and distributed out of band.
 *
 * Usage:
 *   node scripts/release-sign.mjs --bundle <dir> --private-key <pem> --key-id <id>
 *     --sequence <positive integer> --expires-at <ISO timestamp>
 *     [--issued-at <ISO timestamp>] [--product-id singularity-aidr]
 *     [--channel stable]
 */

import path from "node:path";

import {
	RELEASE_MANIFEST_NAME,
	RELEASE_SIGNATURE_NAME,
	createReleaseManifest,
	loadEd25519PrivateKey,
	loadReleaseBundle,
	signReleaseManifest,
	writeExclusive,
} from "./release-signing-lib.mjs";

try {
	const args = parseArgs(process.argv.slice(2));
	const bundleArgument = args["--bundle"];
	const privateKeyPath = args["--private-key"] ?? process.env.AIDR_RELEASE_SIGNING_PRIVATE_KEY_PATH;
	const keyId = args["--key-id"] ?? process.env.AIDR_RELEASE_SIGNING_KEY_ID;
	const releaseSequence = args["--sequence"];
	const expiresAt = args["--expires-at"];
	if (!bundleArgument || !privateKeyPath || !keyId || !releaseSequence || !expiresAt) {
		usage();
		process.exit(2);
	}
	const issuedAt = args["--issued-at"] ?? new Date().toISOString();
	const productId = args["--product-id"] ?? "singularity-aidr";
	const channel = args["--channel"] ?? "stable";
	const bundle = await loadReleaseBundle(bundleArgument);
	const signingKey = await loadEd25519PrivateKey(privateKeyPath, bundle.bundle);
	const manifest = createReleaseManifest(bundle, {
		productId,
		channel,
		keyId,
		releaseSequence,
		issuedAt,
		expiresAt,
		fingerprint: signingKey.fingerprint,
	});
	const manifestRaw = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
	const signature = signReleaseManifest(manifestRaw, signingKey.privateKey, keyId);
	const manifestPath = path.join(bundle.bundle, RELEASE_MANIFEST_NAME);
	const signaturePath = path.join(bundle.bundle, RELEASE_SIGNATURE_NAME);
	await writeExclusive(manifestPath, manifestRaw);
	try {
		await writeExclusive(signaturePath, `${JSON.stringify(signature, null, 2)}\n`);
	} catch (error) {
		// A manifest without its detached signature is fail-closed. Preserve it so
		// operators can see that the release directory needs to be rebuilt rather
		// than silently overwriting prior signing evidence.
		throw new Error(`release signature could not be written; rebuild the bundle before retrying: ${formatError(error)}`);
	}
	console.log(
		JSON.stringify({
			status: "signed",
			product_id: manifest.product_id,
			channel: manifest.channel,
			release_sequence: manifest.release_sequence,
			release_version: manifest.release_version,
			key_id: manifest.signer.key_id,
			fingerprint_sha256: manifest.signer.fingerprint_sha256,
			artifacts: manifest.artifacts.length,
			expires_at: manifest.expires_at,
		}),
	);
} catch (error) {
	console.error(`Release signing failed: ${formatError(error)}`);
	process.exit(1);
}

function parseArgs(argv) {
	const values = {};
	for (let index = 0; index < argv.length; index += 1) {
		const flag = argv[index];
		if (!flag?.startsWith("--")) throw new Error(`unexpected positional argument: ${flag}`);
		if (values[flag] !== undefined) throw new Error(`duplicate option: ${flag}`);
		const value = argv[index + 1];
		if (!value || value.startsWith("--")) throw new Error(`missing value for ${flag}`);
		values[flag] = value;
		index += 1;
	}
	const known = new Set([
		"--bundle",
		"--private-key",
		"--key-id",
		"--sequence",
		"--expires-at",
		"--issued-at",
		"--product-id",
		"--channel",
	]);
	for (const flag of Object.keys(values)) if (!known.has(flag)) throw new Error(`unknown option: ${flag}`);
	return values;
}

function usage() {
	console.error(
		"Usage: node scripts/release-sign.mjs --bundle <dir> --private-key <pem> --key-id <id> --sequence <n> --expires-at <ISO timestamp>",
	);
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}
