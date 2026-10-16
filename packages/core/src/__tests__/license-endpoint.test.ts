import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { verifyCustomerPacket } from "../customer-license/packet.js";
import {
	customerPacketSearchPaths,
	discoverCustomerPacket,
	readCustomerRecord,
	readInstalledLicense,
	saveCustomerPacket,
} from "../customer-license/store.js";
import {
	defaultLicenseKeyRegistry,
	LicenseVerificationError,
	licenseState,
	verifyLicense,
} from "../customer-license/verify.js";
import { acceptPack } from "../intel/acceptance.js";
import { IntelPackManifestSchema } from "../intel/schema.js";
import {
	devKey,
	licensePayload,
	packetPayload,
	registry,
	registryEntry,
	signLicense,
	signPacket,
} from "./license-fixtures.js";
import { makeTmpDir } from "./test-utils.js";

const key = devKey("aidr-license-dev-1");
const trusted = registry([registryEntry(key)]);
const inTerm = Date.parse("2027-03-01T00:00:00Z");
const license = signLicense(licensePayload(), key);
const packet = signPacket(packetPayload(license), key);

describe("embedded license registry", () => {
	it("is the shipped empty registry, so nothing verifies by default (fail closed)", () => {
		expect(defaultLicenseKeyRegistry().keys.size).toBe(0);
		for (const run of [
			() => verifyLicense(license, { now: inTerm }),
			() => verifyCustomerPacket(packet, { now: inTerm }),
		]) {
			expect(run).toThrow(LicenseVerificationError);
			try {
				run();
			} catch (error) {
				expect((error as LicenseVerificationError).code).toBe("no_trusted_keys");
			}
		}
	});

	it("matches deploy/onprem/license-public-keys.json", () => {
		const script = fileURLToPath(new URL("../../scripts/embed-license-keys.mjs", import.meta.url));
		const result = spawnSync(process.execPath, [script, "--check"], { encoding: "utf8" });
		expect(result.status, result.stderr).toBe(0);
	});

	it("refuses a malformed injected registry", () => {
		expect(() => verifyLicense(license, { registry: { keys: [] }, now: inTerm })).toThrow(
			/registry must declare format/,
		);
	});
});

describe("licenseState", () => {
	it("follows expires_at and grace_days on the signed terms", () => {
		const payload = licensePayload();
		expect(licenseState(payload, Date.parse("2026-08-01T00:00:00Z"))).toBe("not_yet_valid");
		expect(licenseState(payload, inTerm)).toBe("active");
		expect(licenseState(license, Date.parse("2027-09-14T23:59:59Z"))).toBe("grace");
		expect(licenseState(license, Date.parse("2027-09-15T00:00:00Z"))).toBe("expired");
		const verified = verifyLicense(license, { registry: trusted, now: inTerm });
		expect(verified.state).toBe("active");
		expect(verified.updatesUntil).toBe("2027-09-15T00:00:00.000Z");
		expect(licenseState(verified, new Date("2030-01-01T00:00:00Z"))).toBe("expired");
	});
});

describe("customer packet", () => {
	it("verifies and exposes setup values without secrets", () => {
		const result = verifyCustomerPacket(packet, { registry: trusted, now: inTerm });
		expect(result).toMatchObject({
			customerId: "example-co",
			packetId: "PKT-example-co-1",
			controlPlaneUrl: "https://aidr.example-co.test/console",
			sensitivity: "balanced",
			displayName: "Example Customer",
			licenseState: "active",
		});
		expect(result.license.payload.license_id).toBe("LIC-2026-0001");
	});

	it("refuses an oversized document before anything else", () => {
		expect(() =>
			verifyCustomerPacket(
				{ ...packet, sig: packet.sig, payload: { pad: "x".repeat(70_000) } },
				{
					registry: trusted,
					now: inTerm,
				},
			),
		).toThrow(/larger than 65536 bytes/);
	});
});

describe("customer packet discovery and the applied license", () => {
	let dir: string;
	let prevHome: string | undefined;
	beforeEach(async () => {
		dir = await makeTmpDir();
		prevHome = process.env.HOME;
		process.env.HOME = dir;
	});
	afterEach(() => {
		if (prevHome === undefined) delete process.env.HOME;
		else process.env.HOME = prevHome;
	});

	it("searches the install prefix first, then the machine copy", () => {
		expect(customerPacketSearchPaths({ installPrefix: "/opt/aidr", platform: "linux" })).toEqual([
			"/opt/aidr/config/customer-packet.json",
			"/etc/singularity-aidr/customer-packet.json",
		]);
		expect(
			customerPacketSearchPaths({
				installPrefix: "C:\\Program Files\\Singularity AIDR",
				platform: "win32",
				env: { ProgramData: "D:\\ProgramData" },
			}),
		).toEqual([
			"C:\\Program Files\\Singularity AIDR\\config\\customer-packet.json",
			"D:\\ProgramData\\Singularity AIDR\\customer-packet.json",
		]);
		expect(customerPacketSearchPaths({ platform: "win32", env: {} })).toEqual([
			"C:\\ProgramData\\Singularity AIDR\\customer-packet.json",
		]);
	});

	it("reads the first packet present and refuses a symlinked one", () => {
		const prefix = join(dir, "prefix");
		mkdirSync(join(prefix, "config"), { recursive: true });
		expect(
			discoverCustomerPacket({ installPrefix: prefix, platform: "linux" })?.path ?? null,
		).not.toBe(join(prefix, "config", "customer-packet.json"));
		writeFileSync(join(prefix, "config", "customer-packet.json"), JSON.stringify(packet));
		const found = discoverCustomerPacket({ installPrefix: prefix, platform: "linux" });
		expect(found?.path).toBe(join(prefix, "config", "customer-packet.json"));
		expect(found?.document).toEqual(packet);

		if (process.platform !== "win32") {
			const linked = join(dir, "linked");
			mkdirSync(join(linked, "config"), { recursive: true });
			symlinkSync(
				join(prefix, "config", "customer-packet.json"),
				join(linked, "config", "customer-packet.json"),
			);
			expect(() => discoverCustomerPacket({ installPrefix: linked, platform: "linux" })).toThrow(
				/regular, non-symlink/,
			);
		}
	});

	it("saves license.json (owner-only) and customer.json, and re-verifies on read", async () => {
		expect(readInstalledLicense({ registry: trusted, now: inTerm })).toBeNull();
		const verified = verifyCustomerPacket(packet, { registry: trusted, now: inTerm });
		await saveCustomerPacket(verified);
		const licensePath = join(dir, ".singularity-aidr", "license.json");
		expect(JSON.parse(readFileSync(licensePath, "utf8"))).toEqual(license);
		if (process.platform !== "win32") expect(statSync(licensePath).mode & 0o777).toBe(0o600);
		expect(readCustomerRecord()).toEqual({
			customer_id: "example-co",
			packet_id: "PKT-example-co-1",
			display_name: "Example Customer",
		});
		expect(readInstalledLicense({ registry: trusted, now: inTerm })?.payload.customer_id).toBe(
			"example-co",
		);

		writeFileSync(
			licensePath,
			JSON.stringify({ ...license, payload: { ...license.payload, seats: 1 } }),
		);
		expect(() => readInstalledLicense({ registry: trusted, now: inTerm })).toThrow(
			/does not verify/,
		);
	});
});

describe("acceptPack", () => {
	const manifest = (overrides: Record<string, unknown> = {}) =>
		IntelPackManifestSchema.parse({
			pack_id: "aidr-intel",
			version: "2.0.0",
			issued_at: "2027-09-14T00:00:00Z",
			key_id: "k1",
			...overrides,
		});
	const verified = verifyLicense(license, { registry: trusted, now: inTerm });

	it("accepts packs issued within expires_at + grace_days, comparing signed times only", () => {
		expect(acceptPack(manifest(), verified)).toEqual({ accepted: true });
		expect(acceptPack(manifest({ issued_at: "2027-09-15T00:00:00Z" }), license)).toEqual({
			accepted: true,
		});
		const late = acceptPack(manifest({ issued_at: "2027-09-15T00:00:01Z" }), verified.payload);
		expect(late).toMatchObject({ accepted: false, code: "license_term_ended" });
		// A garbled time cannot be shown to fall inside the term.
		expect(acceptPack(manifest({ issued_at: "soon" }), verified)).toMatchObject({
			accepted: false,
			code: "license_term_ended",
		});
	});

	it("enforces the audience", () => {
		const forUs = manifest({ audience: { customer_ids: ["other-co", "example-co"] } });
		const forOthers = manifest({ audience: { customer_ids: ["other-co"] } });
		expect(acceptPack(forUs, verified)).toEqual({ accepted: true });
		expect(acceptPack(forOthers, verified)).toMatchObject({
			accepted: false,
			code: "pack_audience_mismatch",
		});
		const { customer_id: _drop, ...anonymous } = licensePayload();
		expect(acceptPack(forUs, anonymous as never)).toMatchObject({
			accepted: false,
			code: "pack_audience_mismatch",
		});
		expect(acceptPack(forUs, null)).toMatchObject({
			accepted: false,
			code: "pack_audience_requires_license",
		});
	});

	it("keeps unlicensed behaviour for packs without an audience", () => {
		expect(acceptPack(manifest({ issued_at: "2099-01-01T00:00:00Z" }), null)).toEqual({
			accepted: true,
		});
	});

	it("validates the signed audience shape", () => {
		expect(
			IntelPackManifestSchema.safeParse({ ...manifest(), audience: { customer_ids: [] } }).success,
		).toBe(false);
		expect(
			IntelPackManifestSchema.safeParse({ ...manifest(), audience: { customer_ids: ["Bad_Id"] } })
				.success,
		).toBe(false);
		expect(
			IntelPackManifestSchema.safeParse({
				...manifest(),
				audience: { customer_ids: Array.from({ length: 257 }, (_, i) => `c-${i}`) },
			}).success,
		).toBe(false);
		expect(
			IntelPackManifestSchema.safeParse({ ...manifest(), audience: { customer_ids: ["ab"], x: 1 } })
				.success,
		).toBe(false);
	});
});
