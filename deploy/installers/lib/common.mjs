// Shared inputs and checks for the desktop installer builders.
//
// Every installer packages the relocatable, RELEASE-flavour SEA directory
// produced by `packages/claude-code/scripts/build-sea.mjs --flavor release` and
// signed with `--sign` (release-rc.yml signs it between the bundle build and
// packaging) byte for byte, next to the release public key:
//
//   <prefix>/bundle/                 the SEA directory (bin/aidr multi-call binary,
//                                    dist/resources + runtime manifest, extensions/,
//                                    aidr-artifact.manifest.json + .sig)
//   <prefix>/config/release-public.pem
//
// `aidr setup` provisions that key into the user's config
// (packages/cli/src/utils/release-key.ts): a release hook trusts its files only
// once the key is set up. The builders never rebuild or edit the bundle; they
// refuse a development-flavour bundle, one whose manifests, digests or
// signatures fail against the release key, and one without the CLI binary.

import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	ARTIFACT_ID,
	distributionFlavor,
	MANIFEST_NAME,
	verifyDistributionManifest,
	verifyDistributionSignatures,
} from "../../../packages/claude-code/scripts/build-sea.mjs";

export const PACKAGE_NAME = "singularity-aidr";
/** Override with --maintainer "Name <address>" (the product owner's packaging contact). */
export const MAINTAINER = "Singularity R&D";
export const LINUX_PREFIX = "/opt/singularity-aidr";
/** The multi-call binary: the CLI and every hook `aidr setup` registers (`aidr hook <name>`). */
const REQUIRED_BINARIES = Object.freeze(["aidr"]);

const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;

export class InstallerInputError extends Error {}

/** Parse `--name value` pairs; unknown flags are an error, never ignored. */
export function parseFlags(argv, allowed) {
	const values = {};
	for (let index = 0; index < argv.length; index += 1) {
		const flag = argv[index];
		if (!flag.startsWith("--")) throw new InstallerInputError(`unexpected argument ${flag}`);
		const name = flag.slice(2);
		if (!allowed.includes(name)) throw new InstallerInputError(`unknown option --${name}`);
		const value = argv[index + 1];
		if (value === undefined || value.startsWith("--")) throw new InstallerInputError(`--${name} needs a value`);
		values[name] = value;
		index += 1;
	}
	return values;
}

export function checkVersion(version) {
	if (typeof version !== "string" || !VERSION_PATTERN.test(version)) {
		throw new InstallerInputError(`invalid package version ${JSON.stringify(version)}`);
	}
	return version;
}

/**
 * The release trust key must be an Ed25519 public key whose SPKI sha256
 * matches the independently supplied fingerprint (the same check release-rc
 * applies to AIDR_SIGNING_PUBLIC_KEY_PEM). A private key is refused outright.
 */
export function checkTrustKey(pemPath, expectedFingerprint) {
	const pem = readFileSync(pemPath, "utf8");
	if (/BEGIN [A-Z ]*PRIVATE KEY/u.test(pem)) throw new InstallerInputError("the trust key file contains a private key");
	let key;
	try {
		key = createPublicKey(pem);
	} catch {
		throw new InstallerInputError("the trust key is not a PEM public key");
	}
	if (key.asymmetricKeyType !== "ed25519") throw new InstallerInputError("the trust key must be Ed25519");
	const fingerprint = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
	const expected = String(expectedFingerprint ?? "").toLowerCase().replace(/^sha256:/u, "");
	if (!/^[0-9a-f]{64}$/u.test(expected)) throw new InstallerInputError("a sha256 trust key fingerprint is required");
	if (fingerprint !== expected) throw new InstallerInputError(`trust key fingerprint mismatch: ${fingerprint}`);
	return { pem: key.export({ type: "spki", format: "pem" }).toString(), fingerprint };
}

/**
 * The optional installer catalog key (`aidr update` verifies the signed
 * installer catalog with it, packages/core/src/update/environment.ts): an
 * Ed25519 SPKI public key in PEM form, never a private key.
 */
export function checkCatalogKey(pemPath) {
	const pem = readFileSync(pemPath, "utf8");
	if (/BEGIN [A-Z ]*PRIVATE KEY/u.test(pem)) throw new InstallerInputError("the catalog key file contains a private key");
	if (!/-----BEGIN PUBLIC KEY-----/u.test(pem)) throw new InstallerInputError("the catalog key is not an SPKI PEM public key");
	let key;
	try {
		key = createPublicKey(pem);
	} catch {
		throw new InstallerInputError("the catalog key is not a PEM public key");
	}
	if (key.asymmetricKeyType !== "ed25519") throw new InstallerInputError("the catalog key must be Ed25519");
	const fingerprint = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
	return { pem: key.export({ type: "spki", format: "pem" }).toString(), fingerprint };
}

/** Where the installers place the catalog key, next to the release key. */
export const CATALOG_KEY_FILE = "installer-catalog-public.pem";

/**
 * Verify a SEA directory for packaging: intact manifests, the release flavour,
 * signatures that verify against the release key the installer embeds, the
 * platform it was built for, and the binary the installer's setup step needs.
 * @param {string} seaDir
 * @param {{ platform: string, trustKeyPem: string }} options
 * @returns the parsed manifest
 */
export function checkSeaBundle(seaDir, { platform, trustKeyPem }) {
	const problems = verifyDistributionManifest(seaDir);
	if (problems.length > 0) throw new InstallerInputError(`SEA bundle ${seaDir} failed verification:\n  ${problems.join("\n  ")}`);
	if (distributionFlavor(seaDir) !== "release") {
		throw new InstallerInputError(`SEA bundle ${seaDir} is a ${distributionFlavor(seaDir)}-flavour build; installers ship the release flavour (build-sea.mjs --flavor release)`);
	}
	if (typeof trustKeyPem !== "string") throw new InstallerInputError("the release trust key is required to check the SEA bundle");
	const unsigned = verifyDistributionSignatures(seaDir, trustKeyPem);
	if (unsigned.length > 0) {
		throw new InstallerInputError(`SEA bundle ${seaDir} is not signed by the release key (build-sea.mjs --sign):\n  ${unsigned.join("\n  ")}`);
	}
	const manifest = JSON.parse(readFileSync(join(seaDir, MANIFEST_NAME), "utf8"));
	if (manifest.artifact_id !== ARTIFACT_ID) throw new InstallerInputError(`${seaDir} is not a ${ARTIFACT_ID} bundle`);
	if (manifest.sea?.platform !== platform) {
		throw new InstallerInputError(`SEA bundle was built for ${manifest.sea?.platform}, not ${platform}; build it on a ${platform} runner`);
	}
	const exe = platform === "win32" ? ".exe" : "";
	const listed = new Set(manifest.files.map((file) => file.path));
	for (const binary of REQUIRED_BINARIES) {
		if (!listed.has(`bin/${binary}${exe}`)) throw new InstallerInputError(`SEA bundle lacks bin/${binary}${exe}`);
	}
	return manifest;
}

export function sha256Of(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}
