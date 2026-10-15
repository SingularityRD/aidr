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

// ── Per-customer installers ──────────────────────────────────────────────
//
// A customer installer is the same signed product plus one vendor-signed
// customer packet (`aidr-customer-packet-v1`, docs/operations/customer-builds.md).
// `aidr setup` discovers it at <prefix>/config/customer-packet.json, then at the
// machine copy (%ProgramData%\Singularity AIDR\customer-packet.json on Windows,
// /etc/singularity-aidr/customer-packet.json on Linux), and verifies its
// signature against the license public-key registry before using it. The
// builders check its shape and customer id only: the signature check is
// scripts/customer-packet-verify.mjs, which the customer-installer workflow runs
// before any builder, and `aidr setup` repeats it on every endpoint.

const CUSTOMER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,31}$/u;
const PACKET_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const CUSTOMER_PACKET_FORMAT = "aidr-customer-packet-v1";
export const CUSTOMER_PACKET_MAX_BYTES = 64 * 1024;
export const CUSTOMER_PACKET_FILE = "customer-packet.json";
/** The Linux machine copy: a dpkg conffile / RPM %config(noreplace). */
export const LINUX_CUSTOMER_PACKET = "/etc/singularity-aidr/customer-packet.json";
const PACKET_PAYLOAD_KEYS = new Set(["customer_id", "packet_id", "issued_at", "license", "control_plane_url", "sensitivity", "display_name", "licensing_public_keys_pem"]);

function checkCustomerId(customerId) {
	if (typeof customerId !== "string" || !CUSTOMER_ID_PATTERN.test(customerId)) {
		throw new InstallerInputError(`invalid customer id ${JSON.stringify(customerId)} (lower-case letters, digits and '-', 2 to 32 characters)`);
	}
	return customerId;
}

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * Read a customer packet for embedding: at most 64 KiB of UTF-8 JSON in the
 * packet format, only contract payload keys, a well-formed customer id and
 * packet id, and an embedded license for the same customer. With
 * `expectedCustomerId` the packet must be for exactly that customer.
 * @returns {{ bytes: Buffer, customerId: string, packetId: string, sha256: string }}
 */
export function checkCustomerPacket(path, { expectedCustomerId } = {}) {
	const bytes = readFileSync(path);
	if (bytes.length === 0 || bytes.length > CUSTOMER_PACKET_MAX_BYTES) {
		throw new InstallerInputError(`the customer packet must be 1 to ${CUSTOMER_PACKET_MAX_BYTES} bytes, not ${bytes.length}`);
	}
	let document;
	try {
		document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
	} catch {
		throw new InstallerInputError("the customer packet is not UTF-8 JSON");
	}
	if (!isObject(document) || document.format !== CUSTOMER_PACKET_FORMAT) {
		throw new InstallerInputError(`the customer packet is not an ${CUSTOMER_PACKET_FORMAT} document`);
	}
	if (typeof document.key_id !== "string" || document.key_id === "" || typeof document.sig !== "string" || document.sig === "") {
		throw new InstallerInputError("the customer packet has no key_id or signature");
	}
	const { payload } = document;
	if (!isObject(payload)) throw new InstallerInputError("the customer packet has no payload");
	const unknown = Object.keys(payload).filter((key) => !PACKET_PAYLOAD_KEYS.has(key));
	if (unknown.length > 0) throw new InstallerInputError(`the customer packet payload has unknown keys: ${unknown.join(", ")}`);
	const customerId = checkCustomerId(payload.customer_id);
	if (typeof payload.packet_id !== "string" || !PACKET_ID_PATTERN.test(payload.packet_id)) {
		throw new InstallerInputError("the customer packet has an invalid packet_id");
	}
	if (!isObject(payload.license) || payload.license.format !== "aidr-license-v1" || payload.license.payload?.customer_id !== customerId) {
		throw new InstallerInputError(`the customer packet does not embed an aidr-license-v1 license for ${customerId}`);
	}
	if (expectedCustomerId !== undefined && customerId !== checkCustomerId(expectedCustomerId)) {
		throw new InstallerInputError(`the customer packet is for ${customerId}, not ${expectedCustomerId}`);
	}
	return {
		bytes,
		customerId,
		packetId: payload.packet_id,
		sha256: createHash("sha256").update(bytes).digest("hex"),
		// What the install wizard shows; `aidr setup` re-checks all of it against the signature.
		displayName: typeof payload.display_name === "string" ? payload.display_name : null,
		controlPlaneUrl: typeof payload.control_plane_url === "string" ? payload.control_plane_url : null,
		updatesUntil: licenseUpdatesUntil(payload.license.payload),
	};
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** expires_at + grace_days as YYYY-MM-DD (UTC), or null when the license does not say. */
function licenseUpdatesUntil(license) {
	const expiresAt = Date.parse(license.expires_at);
	if (!Number.isFinite(expiresAt) || !Number.isInteger(license.grace_days) || license.grace_days < 0) return null;
	return new Date(expiresAt + license.grace_days * DAY_MS).toISOString().slice(0, 10);
}

/** The customer id as product and file names carry it (BILGEM, HAVELSAN-ANKARA). */
export const customerLabel = (customerId) => checkCustomerId(customerId).toUpperCase();

/**
 * `SingularityAIDR-<CUSTOMER>-<version>-<arch>.<ext>`: the name every per-customer
 * installer ships under (`suffix`, e.g. -UNSIGNED, goes before the extension).
 */
export function customerArtifactName({ customerId, version, arch, ext, suffix = "" }) {
	if (arch !== "x64" && arch !== "arm64") throw new InstallerInputError(`unsupported architecture ${arch}`);
	return `SingularityAIDR-${customerLabel(customerId)}-${checkVersion(version)}-${arch}${suffix}.${ext}`;
}
