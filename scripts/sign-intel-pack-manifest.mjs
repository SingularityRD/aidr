#!/usr/bin/env node
/**
 * Sign the exact manifest bytes consumed by the offline intel-pack loader.
 *
 * The signature covers every manifest byte, so the optional customer audience
 * (`audience.customer_ids`, enforced by core `acceptPack`) and the signed
 * `issued_at` / `expires_at` are bound by it. `--audience <id,...|none>` makes the
 * signer refuse a manifest whose audience is not exactly that set (`none`: a
 * generic pack with no audience), so a pack built for one customer is never
 * signed as another's, or as a generic pack, by mistake.
 */
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const USAGE =
	"Usage: node scripts/sign-intel-pack-manifest.mjs --manifest <file> --private-key <restricted-pem-file> [--out <signature-file>] [--audience <customer-id,...|none>]";
const CUSTOMER_ID = /^[a-z0-9][a-z0-9-]{1,31}$/;

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i += 1) {
		const name = argv[i];
		if (name === "--help" || name === "-h") return { help: true };
		if (!["--manifest", "--private-key", "--out", "--audience"].includes(name) || !argv[i + 1] || argv[i + 1].startsWith("--")) {
			throw new Error(USAGE);
		}
		if (values[name]) throw new Error(`Duplicate argument ${name}`);
		values[name] = argv[++i];
	}
	if (!values["--manifest"] || !values["--private-key"]) throw new Error(USAGE);
	return values;
}

function requireRegularFile(file, label) {
	const stats = lstatSync(file);
	if (stats.isSymbolicLink() || !stats.isFile()) throw new Error(`${label} must be a regular, non-symlink file`);
	return stats;
}

/** The manifest's signed audience as a sorted id list (null: generic pack); a malformed one is refused. */
export function manifestAudience(manifest) {
	if (manifest.audience === undefined) return null;
	const audience = manifest.audience;
	const ids = audience?.customer_ids;
	if (
		!audience ||
		typeof audience !== "object" ||
		Array.isArray(audience) ||
		Object.keys(audience).some((key) => key !== "customer_ids") ||
		!Array.isArray(ids) ||
		ids.length < 1 ||
		ids.length > 256 ||
		ids.some((id) => typeof id !== "string" || !CUSTOMER_ID.test(id)) ||
		new Set(ids).size !== ids.length
	) {
		throw new Error("Manifest audience must be { customer_ids: [1..256 unique customer ids] }");
	}
	return [...ids].sort();
}

/** Refuse unless the manifest audience is exactly `expected` ("id,id" or "none"); undefined checks shape only. */
export function assertAudience(manifest, expected) {
	const actual = manifestAudience(manifest);
	if (expected === undefined) return;
	const wanted =
		expected === "none"
			? null
			: [
					...new Set(
						String(expected)
							.split(",")
							.map((id) => id.trim())
							.filter(Boolean),
					),
				].sort();
	if (wanted !== null && (wanted.length === 0 || wanted.some((id) => !CUSTOMER_ID.test(id)))) {
		throw new Error("--audience must be customer ids (a-z0-9-) separated by commas, or none");
	}
	if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
		throw new Error(`Manifest audience ${actual ? actual.join(",") : "none"} does not match --audience ${wanted ? wanted.join(",") : "none"}; refusing to sign`);
	}
}

function main() {
	const args = parseArgs(process.argv.slice(2));
	if (args.help) {
		console.log(USAGE);
		return;
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
		!manifest ||
		typeof manifest !== "object" ||
		Array.isArray(manifest) ||
		typeof manifest.pack_id !== "string" ||
		!manifest.pack_id ||
		typeof manifest.version !== "string" ||
		!manifest.version ||
		typeof manifest.key_id !== "string" ||
		!manifest.key_id ||
		!Array.isArray(manifest.files)
	) {
		throw new Error("Manifest must include pack_id, version, key_id, and files");
	}
	if (typeof manifest.issued_at !== "string" || !Number.isFinite(Date.parse(manifest.issued_at))) {
		throw new Error("Manifest must carry a signed issued_at timestamp (license-bound acceptance compares it)");
	}
	assertAudience(manifest, args["--audience"]);

	const privateKey = createPrivateKey(readFileSync(keyPath));
	if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Private key must be Ed25519");
	const signature = sign(null, manifestBytes, privateKey);
	if (!verify(null, manifestBytes, createPublicKey(privateKey), signature)) {
		throw new Error("Generated signature did not verify against the manifest bytes");
	}
	// wx makes publication immutable by default: never replace a prior signature.
	writeFileSync(outputPath, `${signature.toString("base64")}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
	const audience = manifestAudience(manifest);
	console.log(`Signed intel-pack manifest (${manifest.pack_id}@${manifest.version}, key ${manifest.key_id}, audience ${audience ? audience.join(",") : "none"})`);
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	try {
		main();
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "signing failed"}`);
		process.exitCode = 1;
	}
}
