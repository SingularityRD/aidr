/**
 * Where an endpoint finds its customer packet and keeps the license it applied.
 *
 * Discovery order (first existing file wins):
 *   1. `<install prefix>/config/customer-packet.json` (shipped by the installer)
 *   2. the machine copy that survives generic upgrades:
 *      `%ProgramData%\Singularity AIDR\customer-packet.json` (Windows) or
 *      `/etc/singularity-aidr/customer-packet.json` (Linux)
 *
 * After setup applies a verified packet, `~/.singularity-aidr/license.json` holds
 * the verified license document (owner-only on POSIX) and
 * `~/.singularity-aidr/customer.json` holds `{ customer_id, packet_id, display_name? }`.
 * Neither file contains a secret; the license is still re-verified on every read.
 */
import { lstatSync } from "node:fs";
import { join, win32 } from "node:path";

import { resolvePath } from "../config.js";
import { atomicWriteJson, getFileContentSync } from "../file-utils.js";
import type { VerifiedCustomerPacket } from "./packet.js";
import {
	isPlainObject,
	LICENSE_MAX_DOCUMENT_BYTES,
	LicenseVerificationError,
	type LicenseVerifyOptions,
	type VerifiedLicense,
	verifyLicense,
} from "./verify.js";

export const CUSTOMER_PACKET_FILE_NAME = "customer-packet.json";
const INSTALLED_LICENSE_PATH = "~/.singularity-aidr/license.json";
const CUSTOMER_RECORD_PATH = "~/.singularity-aidr/customer.json";

export interface CustomerPacketSearchOptions {
	/** The product's install prefix (the directory holding `config/`). */
	installPrefix?: string;
	platform?: NodeJS.Platform;
	env?: NodeJS.ProcessEnv;
}

/** Candidate packet locations, in discovery order. */
export function customerPacketSearchPaths(options: CustomerPacketSearchOptions = {}): string[] {
	const platform = options.platform ?? process.platform;
	const env = options.env ?? process.env;
	const paths: string[] = [];
	if (options.installPrefix) {
		const join_ = platform === "win32" ? win32.join : join;
		paths.push(join_(options.installPrefix, "config", CUSTOMER_PACKET_FILE_NAME));
	}
	if (platform === "win32") {
		const programData = env.ProgramData?.trim() || env.PROGRAMDATA?.trim() || "C:\\ProgramData";
		paths.push(win32.join(programData, "Singularity AIDR", CUSTOMER_PACKET_FILE_NAME));
	} else {
		paths.push(`/etc/singularity-aidr/${CUSTOMER_PACKET_FILE_NAME}`);
	}
	return paths;
}

/**
 * Read a JSON document from a regular, non-symlink file of at most 64 KiB.
 * Throws `LicenseVerificationError` (`unreadable` / `invalid_document`).
 */
export function readSignedDocumentFile(path: string, label: string): unknown {
	let stats: ReturnType<typeof lstatSync>;
	try {
		stats = lstatSync(path);
	} catch {
		throw new LicenseVerificationError(
			"unreadable",
			`${label} ${path} does not exist or is not accessible`,
		);
	}
	if (stats.isSymbolicLink() || !stats.isFile())
		throw new LicenseVerificationError(
			"unreadable",
			`${label} must be a regular, non-symlink file`,
		);
	if (stats.size > LICENSE_MAX_DOCUMENT_BYTES)
		throw new LicenseVerificationError(
			"unreadable",
			`${label} is larger than ${LICENSE_MAX_DOCUMENT_BYTES} bytes`,
		);
	let raw: string;
	try {
		raw = getFileContentSync(path, "utf8");
	} catch {
		throw new LicenseVerificationError("unreadable", `${label} ${path} is not readable`);
	}
	try {
		return JSON.parse(raw) as unknown;
	} catch {
		throw new LicenseVerificationError("invalid_document", `${label} ${path} is not JSON`);
	}
}

function exists(path: string): boolean {
	try {
		lstatSync(path);
		return true;
	} catch {
		return false;
	}
}

/**
 * The first customer packet present in discovery order, unverified, or null when
 * there is none. A present but unreadable file throws: it is not silently skipped
 * in favour of a lower-priority copy.
 */
export function discoverCustomerPacket(
	options: CustomerPacketSearchOptions = {},
): { path: string; document: unknown } | null {
	for (const path of customerPacketSearchPaths(options)) {
		if (!exists(path)) continue;
		return { path, document: readSignedDocumentFile(path, "customer packet") };
	}
	return null;
}

export function installedLicensePath(): string {
	return resolvePath(INSTALLED_LICENSE_PATH);
}

export function customerRecordPath(): string {
	return resolvePath(CUSTOMER_RECORD_PATH);
}

export interface CustomerRecord {
	customer_id: string;
	packet_id: string;
	display_name?: string;
}

/**
 * Persist a verified packet: the license document to license.json and the
 * customer identity to customer.json, both written atomically with mode 0600.
 */
export async function saveCustomerPacket(
	packet: VerifiedCustomerPacket,
	paths: { licensePath?: string; customerPath?: string } = {},
): Promise<void> {
	await atomicWriteJson(paths.licensePath ?? installedLicensePath(), packet.license.document, {
		mode: 0o600,
	});
	const record: CustomerRecord = {
		customer_id: packet.customerId,
		packet_id: packet.packetId,
		...(packet.displayName === undefined ? {} : { display_name: packet.displayName }),
	};
	await atomicWriteJson(paths.customerPath ?? customerRecordPath(), record, { mode: 0o600 });
}

/**
 * Read and re-verify the installed license. Returns null when none is installed;
 * throws `LicenseVerificationError` when one is present but not authentic.
 */
export function readInstalledLicense(
	options: LicenseVerifyOptions & { path?: string } = {},
): VerifiedLicense | null {
	const path = options.path ?? installedLicensePath();
	if (!exists(path)) return null;
	return verifyLicense(readSignedDocumentFile(path, "installed license"), options);
}

/** The applied customer identity, or null when absent or malformed (display only). */
export function readCustomerRecord(path: string = customerRecordPath()): CustomerRecord | null {
	let document: unknown;
	try {
		document = readSignedDocumentFile(path, "customer record");
	} catch {
		return null;
	}
	if (
		!isPlainObject(document) ||
		typeof document.customer_id !== "string" ||
		typeof document.packet_id !== "string" ||
		(document.display_name !== undefined && typeof document.display_name !== "string")
	)
		return null;
	return {
		customer_id: document.customer_id,
		packet_id: document.packet_id,
		...(typeof document.display_name === "string" ? { display_name: document.display_name } : {}),
	};
}
