/**
 * The customer packet: verification (fail closed, domain-separated from the
 * license signature), discovery order, the owner-only license record and the
 * plain EN/TR lines `aidr status` / `aidr doctor` print.
 */
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	customerFilePath,
	customerPacketPaths,
	describeCustomer,
	discoverCustomerPacket,
	licenseFilePath,
	recordCustomerPacket,
} from "../utils/customer-packet.js";
import { licenseState, verifyCustomerPacket } from "../utils/customer-packet-core-shim.js";
import {
	licensePayload,
	registryOf,
	signDocument,
	signedPacket,
	signingKey,
} from "./customer-packet-fixtures.js";

const NOW = Date.parse("2026-10-13T12:00:00Z");
const DAY_MS = 24 * 60 * 60 * 1000;
const key = signingKey();
const registry = registryOf(key);
const verifyAt = (doc: unknown, at = NOW, reg: unknown = registry) =>
	verifyCustomerPacket(doc, { registry: reg, now: new Date(at) });

let dir: string;
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-customer-packet-"));
	vi.stubEnv("AIDR_LOCALE", "en");
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
	vi.unstubAllEnvs();
});

describe("verifyCustomerPacket", () => {
	it("returns the customer, the packet values and the embedded license", () => {
		const packet = signedPacket(key, NOW);
		const verified = verifyAt(packet);
		expect(verified).toMatchObject({
			customerId: "bilgem",
			packetId: "PKT-BILGEM-1",
			displayName: "TÜBİTAK BİLGEM",
			controlPlaneUrl: "https://aidr.bilgem.example.tr",
			sensitivity: "paranoid",
		});
		expect(verified.license).toEqual(packet.payload.license);
	});

	it("still verifies a packet whose license has ended (detection must install)", () => {
		const verified = verifyAt(signedPacket(key, NOW, -120));
		expect(licenseState(verified.license, new Date(NOW)).state).toBe("expired");
	});

	it("fails closed without trusted keys, with an unknown or revoked key", () => {
		const packet = signedPacket(key, NOW);
		expect(() => verifyCustomerPacket(packet, { now: new Date(NOW) })).toThrow(
			/no license public keys/,
		);
		expect(() => verifyAt(packet, NOW, registryOf())).toThrow(/no license public keys/);
		expect(() => verifyAt(packet, NOW, registryOf(signingKey("other-key")))).toThrow(
			/untrusted key/,
		);
		const revoked = { ...key, registryEntry: { ...key.registryEntry, status: "revoked" } };
		expect(() => verifyAt(packet, NOW, registryOf(revoked))).toThrow(/revoked/);
	});

	it("honours key retirement and refuses a malformed registry", () => {
		const packet = signedPacket(key, NOW);
		const retired = {
			...key,
			registryEntry: {
				...key.registryEntry,
				status: "retired",
				retired_at: "2025-01-01T00:00:00Z",
			},
		};
		expect(() => verifyAt(packet, NOW, registryOf(retired))).toThrow(/after retirement/);
		expect(() => verifyAt(packet, NOW, { format: "other", keys: [] })).toThrow(/malformed/);
	});

	it("refuses any change to a signed field", () => {
		const packet = signedPacket(key, NOW);
		const tampered = structuredClone(packet);
		tampered.payload.control_plane_url = "https://attacker.example";
		expect(() => verifyAt(tampered)).toThrow(/signature does not verify/);
		const license = structuredClone(packet);
		(license.payload.license as { payload: { expires_at: string } }).payload.expires_at =
			"2099-01-01T00:00:00Z";
		expect(() => verifyAt(license)).toThrow(/signature does not verify/);
	});

	it("keeps license and packet signatures apart (domain separation)", () => {
		const license = signDocument("aidr-license-v1", licensePayload(NOW, 365), key);
		const payload = (signedPacket(key, NOW) as { payload: unknown }).payload;
		// A packet payload signed as a license, relabelled as a packet: refused.
		const asLicense = signDocument("aidr-license-v1", payload, key);
		expect(() => verifyAt({ ...asLicense, format: "aidr-customer-packet-v1" })).toThrow(
			/signature does not verify/,
		);
		// A license document relabelled as a packet: refused.
		expect(() => verifyAt({ ...license, format: "aidr-customer-packet-v1" })).toThrow(
			/signature does not verify/,
		);
	});

	it("refuses unknown fields, a customer mismatch and a license without customer_id", () => {
		const extra = signDocument(
			"aidr-customer-packet-v1",
			{ ...signedPacket(key, NOW).payload, enrollment_code: "x" },
			key,
		);
		expect(() => verifyAt(extra)).toThrow(/unknown or missing fields/);
		expect(() => verifyAt(signedPacket(key, NOW, 365, { customer_id: "havelsan" }))).toThrow(
			/different customer/,
		);
		expect(() => verifyAt(signedPacket(key, NOW, 365, {}, { customer_id: undefined }))).toThrow(
			/different customer/,
		);
	});

	it("refuses an insecure company address and a bad display name or preset", () => {
		const scheme = ["http", "://aidr.example.tr"].join("");
		expect(() => verifyAt(signedPacket(key, NOW, 365, { control_plane_url: scheme }))).toThrow(
			/https/,
		);
		expect(() =>
			verifyAt(signedPacket(key, NOW, 365, { control_plane_url: "https://u:p@aidr.example.tr" })),
		).toThrow(/https/);
		expect(() => verifyAt(signedPacket(key, NOW, 365, { display_name: " padded" }))).toThrow(
			/display_name/,
		);
		expect(() => verifyAt(signedPacket(key, NOW, 365, { sensitivity: "off" }))).toThrow(
			/sensitivity/,
		);
	});
});

describe("licenseState", () => {
	it("moves from active through grace to expired; updates run until expiry + grace", () => {
		const license = verifyAt(signedPacket(key, NOW, 10)).license;
		const until = Date.parse(license.payload.expires_at) + 30 * DAY_MS;
		expect(licenseState(license, new Date(NOW))).toEqual({
			state: "active",
			updatesUntil: new Date(until),
		});
		expect(licenseState(license, new Date(NOW + 20 * DAY_MS)).state).toBe("grace");
		expect(licenseState(license, new Date(until)).state).toBe("expired");
		expect(licenseState(license, new Date(Date.parse(license.payload.not_before) - 1)).state).toBe(
			"not_yet_valid",
		);
	});
});

describe("discovery", () => {
	const write = (path: string, value: unknown) => {
		mkdirSync(join(path, ".."), { recursive: true });
		writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
	};
	const options = (paths: string[]) => ({ paths, registry, now: new Date(NOW) });

	it("looks next to the bundle first, then at the machine copy", () => {
		expect(customerPacketPaths("/opt/aidr/bundle", "linux")).toEqual([
			"/opt/aidr/config/customer-packet.json",
			"/etc/singularity-aidr/customer-packet.json",
		]);
		expect(customerPacketPaths(null, "win32", { ProgramData: "D:\\Data" })).toEqual([
			"D:\\Data\\Singularity AIDR\\customer-packet.json",
		]);
	});

	it("uses the first file that exists and never falls through a refused one", () => {
		const first = join(dir, "prefix", "customer-packet.json");
		const machine = join(dir, "etc", "customer-packet.json");
		write(machine, signedPacket(key, NOW));
		expect(discoverCustomerPacket(null, options([first, machine]))).toMatchObject({
			state: "verified",
			path: machine,
		});
		const tampered = signedPacket(key, NOW);
		tampered.payload.packet_id = "PKT-OTHER";
		write(first, tampered);
		expect(discoverCustomerPacket(null, options([first, machine]))).toMatchObject({
			state: "refused",
			path: first,
		});
		expect(discoverCustomerPacket(null, options([join(dir, "missing.json")]))).toEqual({
			state: "none",
		});
	});

	it("refuses a link, an oversized or a non-JSON file", () => {
		const target = join(dir, "real.json");
		write(target, signedPacket(key, NOW));
		const link = join(dir, "link.json");
		symlinkSync(target, link);
		expect(discoverCustomerPacket(null, options([link]))).toMatchObject({
			state: "refused",
			reason: "not a regular file",
		});
		const big = join(dir, "big.json");
		write(big, "x".repeat(64 * 1024 + 1));
		expect(discoverCustomerPacket(null, options([big]))).toMatchObject({ state: "refused" });
		const text = join(dir, "text.json");
		write(text, "{not json");
		expect(discoverCustomerPacket(null, options([text]))).toMatchObject({
			state: "refused",
			reason: "not valid JSON",
		});
	});
});

describe("license record", () => {
	it("writes the verified license and the customer identity owner-only", () => {
		const packet = verifyAt(signedPacket(key, NOW));
		recordCustomerPacket(dir, packet);
		expect(JSON.parse(readFileSync(licenseFilePath(dir), "utf8"))).toEqual(packet.license);
		expect(JSON.parse(readFileSync(customerFilePath(dir), "utf8"))).toEqual({
			customer_id: "bilgem",
			packet_id: "PKT-BILGEM-1",
			display_name: "TÜBİTAK BİLGEM",
		});
		if (process.platform !== "win32") {
			expect(statSync(licenseFilePath(dir)).mode & 0o777).toBe(0o600);
			expect(statSync(customerFilePath(dir)).mode & 0o777).toBe(0o600);
			expect(statSync(join(dir, ".singularity-aidr")).mode & 0o777).toBe(0o700);
		}
	});
});

describe("status line", () => {
	const discover = (days: number) => {
		const path = join(dir, "customer-packet.json");
		writeFileSync(path, JSON.stringify(signedPacket(key, NOW, days)));
		return discoverCustomerPacket(null, { paths: [path], registry, now: new Date(NOW) });
	};

	it("names the customer, the license state and the last update date", () => {
		const line = describeCustomer(discover(10));
		expect(line?.severity).toBe("ok");
		expect(line?.line).toBe(
			"Customer: TÜBİTAK BİLGEM (bilgem); license active. Updates until 2026-11-22.",
		);
		vi.stubEnv("AIDR_LOCALE", "tr");
		expect(describeCustomer(discover(10))?.line).toBe(
			"Müşteri: TÜBİTAK BİLGEM (bilgem); lisans etkin. Güncellemeler şu tarihe kadar: 2026-11-22.",
		);
	});

	it("says updates stopped and detection continues for an ended license", () => {
		const line = describeCustomer(discover(-120));
		expect(line?.severity).toBe("warn");
		expect(line?.line).toContain("Updates stopped on");
		expect(line?.line).toContain("detection continues");
	});

	it("reports a refused packet plainly and nothing when there is none", () => {
		expect(describeCustomer({ state: "none" })).toBeNull();
		expect(describeCustomer({ state: "refused", path: "/x", reason: "bad" })?.line).toContain(
			"refused (bad); not used. Local detection is not affected.",
		);
	});
});
