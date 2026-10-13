// Shared inputs and checks for the desktop installer builders.
//
// Every installer packages the relocatable SEA directory produced by
// `pnpm build:sea` (packages/claude-code/scripts/build-sea.mjs) byte for byte,
// next to the release trust public key:
//
//   <prefix>/bundle/                 the SEA directory (bin/aidr, hook binaries,
//                                    dist/resources, aidr-artifact.manifest.json)
//   <prefix>/config/release-public.pem
//
// `aidr` finds the key at <bundle>/../config/release-public.pem
// (packages/cli/src/utils/standalone.ts). The builders never rebuild or edit
// the bundle; they verify it against its manifest first and refuse a bundle
// whose manifest, digests or relocated deny canary fail.

import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	ARTIFACT_ID,
	MANIFEST_NAME,
	verifyDistributionManifest,
} from "../../../packages/claude-code/scripts/build-sea.mjs";

export const PACKAGE_NAME = "singularity-aidr";
/** Override with --maintainer "Name <address>" (the product owner's packaging contact). */
export const MAINTAINER = "Singularity R&D";
export const LINUX_PREFIX = "/opt/singularity-aidr";
/** Hook binaries `aidr setup` registers; the bundle must carry them and the CLI. */
const REQUIRED_BINARIES = Object.freeze([
	"aidr",
	"aidr-pre-tool-use",
	"aidr-post-tool-use",
	"aidr-session-start",
]);

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
 * Verify a SEA directory for packaging: intact manifest, the platform it was
 * built for, and the binaries the installer's setup step needs.
 * @returns the parsed manifest
 */
export function checkSeaBundle(seaDir, { platform }) {
	const problems = verifyDistributionManifest(seaDir);
	if (problems.length > 0) throw new InstallerInputError(`SEA bundle ${seaDir} failed verification:\n  ${problems.join("\n  ")}`);
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
