/**
 * The vendor-signed customer packet (`aidr-customer-packet-v1`) a per-customer
 * installer places on the computer: customer id, license, company address and
 * optional preset. `aidr setup` finds it, verifies it, applies it and records
 * the verified license in the user's AIDR directory; `aidr status` and
 * `aidr doctor` show who the license belongs to and until when updates arrive.
 *
 * Discovery order (the contract): `<install prefix>/config/customer-packet.json`
 * next to the standalone bundle, then the machine copy that survives upgrades
 * (`%ProgramData%\Singularity AIDR\customer-packet.json` on Windows,
 * `/etc/singularity-aidr/customer-packet.json` on Linux). The first file that
 * exists is the one used; a file that does not verify is refused and reported,
 * never skipped in favour of another one.
 *
 * Nothing here can stop local detection: a refused packet or an expired
 * license only changes what the user is told and whether new update packs are
 * accepted (core's pack acceptance reads the license written here).
 */
import { lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { preparePrivateLocalDirectory } from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import {
	type LicenseDocument,
	type LicenseLifecycle,
	licenseState,
	type VerifiedCustomerPacket,
	verifyCustomerPacket,
} from "./customer-packet-core-shim.js";

export type { LicenseLifecycle, VerifiedCustomerPacket };

const CUSTOMER_PACKET_FILE = "customer-packet.json";
const MAX_PACKET_BYTES = 64 * 1024;

export interface CustomerPacketOptions {
	/** Files to look at, in order (tests); default: {@link customerPacketPaths}. */
	paths?: string[];
	/** License public-key registry document (tests); default: core's embedded one. */
	registry?: unknown;
	now?: Date;
}

interface LicenseStatus {
	state: LicenseLifecycle;
	/** expires_at + grace_days: the last day new update packs are accepted. */
	updatesUntil: Date;
}

export type CustomerPacketDiscovery =
	| { state: "none" }
	| { state: "refused"; path: string; reason: string }
	| {
			state: "verified";
			path: string;
			packet: VerifiedCustomerPacket;
			license: LicenseStatus;
	  };

/** Where a customer packet may be, in the contract's order. */
export function customerPacketPaths(
	standaloneRoot: string | null,
	platform: NodeJS.Platform = process.platform,
	env: NodeJS.ProcessEnv = process.env,
): string[] {
	const paths: string[] = [];
	// The bundle is <prefix>/bundle; the installer's config sits next to it.
	if (standaloneRoot) paths.push(join(dirname(standaloneRoot), "config", CUSTOMER_PACKET_FILE));
	if (platform === "win32") {
		const programData = env.ProgramData || env.PROGRAMDATA || "C:\\ProgramData";
		paths.push(`${programData.replace(/[\\/]+$/u, "")}\\Singularity AIDR\\${CUSTOMER_PACKET_FILE}`);
	} else {
		paths.push(`/etc/singularity-aidr/${CUSTOMER_PACKET_FILE}`);
	}
	return paths;
}

const reasonOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

/** The parsed packet file, null when absent; throws when it exists but is unusable. */
function readPacketFile(path: string): unknown | null {
	let info: ReturnType<typeof lstatSync>;
	try {
		info = lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw new Error("the file cannot be read");
	}
	if (info.isSymbolicLink() || !info.isFile()) throw new Error("not a regular file");
	if (info.size > MAX_PACKET_BYTES) throw new Error("larger than 64 KiB");
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		throw new Error("not valid JSON");
	}
}

/** Lifecycle of a verified license at `now`. */
function licenseStatus(license: LicenseDocument, now = new Date()): LicenseStatus {
	return licenseState(license, now);
}

/** Find, read and verify the customer packet. Never throws. */
export function discoverCustomerPacket(
	standaloneRoot: string | null,
	options: CustomerPacketOptions = {},
): CustomerPacketDiscovery {
	const now = options.now ?? new Date();
	for (const path of options.paths ?? customerPacketPaths(standaloneRoot)) {
		let document: unknown;
		try {
			document = readPacketFile(path);
		} catch (error) {
			return { state: "refused", path, reason: reasonOf(error) };
		}
		if (document === null) continue;
		try {
			const packet = verifyCustomerPacket(document, {
				...(options.registry === undefined ? {} : { registry: options.registry }),
				now,
			});
			return { state: "verified", path, packet, license: licenseStatus(packet.license, now) };
		} catch (error) {
			return { state: "refused", path, reason: reasonOf(error) };
		}
	}
	return { state: "none" };
}

/** The verified packet, or null when there is none or it was refused. */
export function verifiedCustomerPacket(
	standaloneRoot: string | null,
	options: CustomerPacketOptions = {},
): VerifiedCustomerPacket | null {
	const discovery = discoverCustomerPacket(standaloneRoot, options);
	return discovery.state === "verified" ? discovery.packet : null;
}

export const licenseFilePath = (home: string) => join(home, ".singularity-aidr", "license.json");
export const customerFilePath = (home: string) => join(home, ".singularity-aidr", "customer.json");

/** Write one owner-only file atomically (temp file in the same private directory, then rename). */
function writePrivateJson(path: string, value: unknown): void {
	const temporary = `${path}.${process.pid}.tmp`;
	try {
		writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 });
		renameSync(temporary, path);
	} catch (error) {
		try {
			unlinkSync(temporary);
		} catch {
			// Nothing was left behind.
		}
		throw error;
	}
}

/**
 * Record the verified packet for this user: `license.json` (the license
 * document, which core's pack acceptance re-reads) and `customer.json`.
 * The directory is made private first (owner-only on POSIX, a protected ACL on
 * Windows), so both files are too.
 */
export function recordCustomerPacket(home: string, packet: VerifiedCustomerPacket): void {
	const directory = join(home, ".singularity-aidr");
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	preparePrivateLocalDirectory(directory);
	writePrivateJson(licenseFilePath(home), packet.license);
	writePrivateJson(customerFilePath(home), {
		customer_id: packet.customerId,
		packet_id: packet.packetId,
		...(packet.displayName ? { display_name: packet.displayName } : {}),
	});
}

/** The name to show for the customer: the display name, else the customer id. */
export const customerLabel = (packet: VerifiedCustomerPacket) =>
	packet.displayName ?? packet.customerId;

/** `YYYY-MM-DD` (UTC): the date only, the same in every locale and time zone. */
export const dateOnly = (date: Date) => date.toISOString().slice(0, 10);

const LICENSE_STATE_KEY = {
	active: "customer.state.active",
	grace: "customer.state.grace",
	expired: "customer.state.expired",
	not_yet_valid: "customer.state.not_yet_valid",
} as const;

/** The license state in the current locale's plain words. */
export const licenseStateLabel = (state: LicenseLifecycle) => ct(LICENSE_STATE_KEY[state]);

/**
 * One line for `aidr status` / `aidr doctor`, or null when no packet was found.
 * A refused packet or a license that is not active is a warning, never a
 * failure: local detection does not depend on either.
 */
export function describeCustomer(
	discovery: CustomerPacketDiscovery,
): { severity: "ok" | "warn"; line: string } | null {
	if (discovery.state === "none") return null;
	if (discovery.state === "refused") {
		return { severity: "warn", line: ct("customer.statusRefused", { reason: discovery.reason }) };
	}
	const { packet, license } = discovery;
	const params = {
		customer: customerLabel(packet),
		id: packet.customerId,
		state: licenseStateLabel(license.state),
		date: dateOnly(license.updatesUntil),
	};
	if (license.state === "expired") {
		return { severity: "warn", line: ct("customer.statusExpired", params) };
	}
	return {
		severity: license.state === "active" ? "ok" : "warn",
		line: ct("customer.status", params),
	};
}

/** The `--json` shape of a discovery (stable English values). */
export function customerReport(discovery: CustomerPacketDiscovery): Record<string, unknown> {
	if (discovery.state === "none") return { state: "none" };
	if (discovery.state === "refused") {
		return { state: "refused", path: discovery.path, reason: discovery.reason };
	}
	const { packet, license } = discovery;
	return {
		state: "verified",
		path: discovery.path,
		customer_id: packet.customerId,
		packet_id: packet.packetId,
		...(packet.displayName ? { display_name: packet.displayName } : {}),
		license_id: packet.license.payload.license_id,
		license_state: license.state,
		updates_until: license.updatesUntil.toISOString(),
		local_detection: "enforced",
	};
}
