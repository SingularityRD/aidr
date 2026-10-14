#!/usr/bin/env node
// Validate the Windows MSI inputs and derive the WiX variables, before any
// signing or packaging step runs (called by build-msi.ps1; unit-tested on any
// OS). Prints one JSON object on success; exits non-zero with the reason on a
// bad input.
//
//   node deploy/installers/windows/msi-inputs.mjs --sea-dir <dir> \
//     --trust-key <pem> --trust-key-fingerprint <sha256> --version 0.6.0[-rc.N] \
//     --signing signed|unsigned [--catalog-key <pem>]
//     [--customer-packet <customer-packet.json> [--customer-id <id>]]
//
// A per-customer build carries the vendor-signed customer packet
// (docs/operations/customer-builds.md): the product is named
// "Singularity AIDR (<CUSTOMER>)" and the files
// SingularityAIDR-<CUSTOMER>-<version>-<arch>.msi / .exe. The UpgradeCode is
// the same as the generic MSI's, so customer and generic installs upgrade
// each other.

import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
	checkCatalogKey,
	checkSeaBundle,
	checkCustomerPacket,
	checkTrustKey,
	checkVersion,
	customerArtifactName,
	customerLabel,
	InstallerInputError,
	PACKAGE_NAME,
	parseFlags,
} from "../lib/common.mjs";

/** Stable across versions: MajorUpgrade replaces any earlier AIDR MSI. */
const UPGRADE_CODE = "6B3E5F0A-4C1D-4E8B-9A57-2D0C7E1F4A93";
/** Stable across versions: the optional Burn bootstrapper EXE (build-msi.ps1 -Bundle). */
const BUNDLE_UPGRADE_CODE = "3A8D1F6C-5B2E-4C7A-9E14-0F6B2D8C3A57";
const PRODUCT_NAME = "Singularity AIDR";
/** Active Setup component id (per-user `aidr setup` at each user's next logon). */
const ACTIVE_SETUP_ID = "{0D9B6C2E-7A41-4F35-B8E2-5C3A91D0E6F4}";
/**
 * Wizard cultures, all in one MSI: the first is the package itself, each other
 * one an embedded language transform named by its LCID (build-msi.ps1).
 */
export const MSI_CULTURES = Object.freeze([
	Object.freeze({ culture: "en-US", lcid: 1033, codepage: 1252 }),
	Object.freeze({ culture: "tr-TR", lcid: 1055, codepage: 1254 }),
]);

/**
 * The company addresses the installer's enrollment handoff accepts
 * (ca/EnrollmentActions.cs UrlPattern; installers.test.mjs keeps them equal).
 */
export const WIZARD_URL_PATTERN = /^https:\/\/[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?(?:\/[A-Za-z0-9._~%/-]*)?$/u;
const WIZARD_URL_MAX_LENGTH = 512;

const codepageChars = new Map();
/** The characters a Windows code page can hold (its MSI string tables are in it). */
function charsOf(codepage) {
	if (!codepageChars.has(codepage)) {
		const decoded = new TextDecoder(`windows-${codepage}`).decode(Uint8Array.from({ length: 256 }, (_, i) => i));
		codepageChars.set(codepage, new Set(decoded));
	}
	return codepageChars.get(codepage);
}

const TURKISH_TO_ASCII = { İ: "I", ı: "i", Ş: "S", ş: "s", Ğ: "G", ğ: "g", Ç: "C", ç: "c", Ö: "O", ö: "o", Ü: "U", ü: "u" };

/**
 * The customer's name as one wizard culture shows it: the packet's display_name
 * when the culture's code page holds it, else with Turkish letters spelled in
 * ASCII, else the customer label (BILGEM). Never text the WiX preprocessor or
 * binder would expand.
 */
export function wizardCustomerName(displayName, label, codepage) {
	const fits = (text) =>
		!/[$!]\(/u.test(text) && !/[\u0000-\u001f\u007f]/u.test(text) && [...text].every((ch) => charsOf(codepage).has(ch));
	if (displayName && fits(displayName)) return displayName;
	const ascii = displayName?.replace(/[İıŞşĞğÇçÖöÜü]/gu, (ch) => TURKISH_TO_ASCII[ch]);
	if (ascii && fits(ascii)) return ascii;
	return label;
}

/** The packet's company address as the wizard hands it on, or null when the packet has none. */
function wizardServer(controlPlaneUrl) {
	if (controlPlaneUrl === null) return null;
	if (controlPlaneUrl.length > WIZARD_URL_MAX_LENGTH || !WIZARD_URL_PATTERN.test(controlPlaneUrl)) {
		throw new InstallerInputError(
			`the customer packet's control_plane_url ${JSON.stringify(controlPlaneUrl)} is not an address the installer accepts (https://host[:port][/path])`,
		);
	}
	return controlPlaneUrl;
}

export function msiInputs({ seaDir, trustKey, trustKeyFingerprint, version, signing, catalogKey, customerPacket, customerId }) {
	checkVersion(version);
	if (signing !== "signed" && signing !== "unsigned") {
		throw new InstallerInputError("--signing must be 'signed' or 'unsigned'");
	}
	const { fingerprint, pem } = checkTrustKey(trustKey, trustKeyFingerprint);
	const manifest = checkSeaBundle(resolve(seaDir), { platform: "win32", trustKeyPem: pem });
	if (manifest.sea?.arch !== "x64" && manifest.sea?.arch !== "arm64") {
		throw new InstallerInputError(`unsupported SEA architecture ${manifest.sea?.arch}`);
	}
	const [major, minor, patch] = version.replace(/-.*$/u, "").split(".").map(Number);
	if (major > 255 || minor > 255 || patch > 65535) {
		throw new InstallerInputError(`version ${version} exceeds the MSI ProductVersion range`);
	}
	const arch = manifest.sea.arch;
	// Optional `aidr update` catalog key, installed as config\installer-catalog-public.pem.
	const catalogKeyFingerprint = catalogKey ? checkCatalogKey(catalogKey).fingerprint : null;
	if (customerId !== undefined && !customerPacket) throw new InstallerInputError("--customer-id needs --customer-packet");
	// Optional customer packet, installed as config\customer-packet.json and (per-machine) the ProgramData copy.
	const packet = customerPacket ? checkCustomerPacket(customerPacket, { expectedCustomerId: customerId }) : null;
	// An unsigned build says so in its file name; it is never published as signed.
	const unsignedMark = signing === "unsigned" ? "-UNSIGNED" : "";
	const fileStem = (ext) =>
		packet
			? customerArtifactName({ customerId: packet.customerId, version, arch, ext, suffix: unsignedMark })
			: `${PACKAGE_NAME}-${version}-windows-${arch}${unsignedMark}.${ext}`;
	return {
		productVersion: `${major}.${minor}.${patch}`,
		activeSetupVersion: `${major},${minor},${patch}`,
		arch,
		trustKeyFingerprint: fingerprint,
		hasCatalogKey: catalogKeyFingerprint ? "1" : "0",
		catalogKeyFingerprint,
		seaManifestVersion: manifest.artifact_version,
		outputName: fileStem("msi"),
		bundleOutputName: fileStem("exe"),
		productName: packet ? `${PRODUCT_NAME} (${customerLabel(packet.customerId)})` : PRODUCT_NAME,
		hasCustomerPacket: packet ? "1" : "0",
		customerId: packet?.customerId ?? null,
		customerPacketSha256: packet?.sha256 ?? null,
		upgradeCode: UPGRADE_CODE,
		bundleUpgradeCode: BUNDLE_UPGRADE_CODE,
		activeSetupId: ACTIVE_SETUP_ID,
		// New for every build, as WiX's default was; shared by the culture builds
		// so the Turkish one is a language transform of the English one.
		productCode: randomUUID().toUpperCase(),
		// Install wizard (ui/AidrUI.wxs): the customer's name per culture, its company
		// address (replaces the company page's choices) and the last update date.
		customerServer: packet ? wizardServer(packet.controlPlaneUrl) : null,
		customerUpdatesUntil: packet?.updatesUntil ?? null,
		cultures: MSI_CULTURES.map((culture) => ({
			...culture,
			customerName: packet ? wizardCustomerName(packet.displayName, customerLabel(packet.customerId), culture.codepage) : null,
		})),
	};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	try {
		const flags = parseFlags(process.argv.slice(2), [
			"sea-dir",
			"trust-key",
			"trust-key-fingerprint",
			"version",
			"signing",
			"catalog-key",
			"customer-packet",
			"customer-id",
		]);
		for (const required of ["sea-dir", "trust-key", "trust-key-fingerprint", "version", "signing"]) {
			if (!flags[required]) throw new InstallerInputError(`--${required} is required`);
		}
		const inputs = msiInputs({
			seaDir: flags["sea-dir"],
			trustKey: flags["trust-key"],
			trustKeyFingerprint: flags["trust-key-fingerprint"],
			version: flags.version,
			signing: flags.signing,
			catalogKey: flags["catalog-key"],
			customerPacket: flags["customer-packet"],
			customerId: flags["customer-id"],
		});
		console.log(JSON.stringify(inputs));
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
		process.exit(1);
	}
}
