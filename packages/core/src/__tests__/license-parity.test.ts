/**
 * Parity: the endpoint verifiers (src/license) and the vendor/operator .mjs
 * verifiers (scripts/license-verify.mjs, scripts/customer-packet-verify.mjs)
 * must accept and refuse exactly the same documents with the same codes and
 * license states. Fixtures are signed in-test with throwaway keys.
 *
 * The .mjs verifiers are loaded from the repository. When a script in this tree
 * predates a contract feature (customer_id in the license verifier, or the packet
 * verifier itself), only the comparable part runs and the rest is skipped.
 */
import { describe, expect, it } from "vitest";

import { verifyCustomerPacket } from "../license/packet.js";
import { LicenseVerificationError, verifyLicense } from "../license/verify.js";
import {
	DAY,
	devKey,
	licensePayload,
	packetPayload,
	registry,
	registryEntry,
	signDocument,
	signLicense,
	signPacket,
} from "./license-fixtures.js";

const scripts = new URL("../../../../scripts/", import.meta.url);
const licenseScript = new URL("license-verify.mjs", scripts);
const packetScript = new URL("customer-packet-verify.mjs", scripts);
type Mjs = Record<string, (...args: unknown[]) => unknown>;
const licenseMjs = (await import(licenseScript.href)) as Mjs;
const packetMjs = (await import(packetScript.href)) as Mjs;

const active = devKey("aidr-license-dev-1");
const retired = devKey("aidr-license-dev-0");
const revoked = devKey("aidr-license-dev-revoked");
const stranger = devKey("aidr-license-dev-1");
const trusted = registry([
	registryEntry(active),
	registryEntry(retired, {
		not_before: "2025-01-01T00:00:00Z",
		not_after: "2026-06-01T00:00:00Z",
		status: "retired",
		retired_at: "2026-06-01T00:00:00Z",
	}),
	registryEntry(revoked, { status: "revoked" }),
]);
const inTerm = Date.parse("2027-03-01T00:00:00Z");
const MJS_STATE: Record<string, string> = { valid: "active" };

type Outcome = { ok: true; state: string } | { ok: false; code: string };

function outcome(run: () => { state: string }): Outcome {
	try {
		return { ok: true, state: run().state };
	} catch (error) {
		const code = (error as { code?: unknown }).code;
		if (typeof code !== "string") throw error;
		return { ok: false, code };
	}
}

function mjsLicense(document: unknown, reg: unknown, now: number): Outcome {
	return outcome(() => {
		const publicKeys = licenseMjs.parsePublicKeyRegistry(reg);
		const result = licenseMjs.verifyLicense(document, { publicKeys, now }) as { status: string };
		return { state: MJS_STATE[result.status] ?? result.status };
	});
}

function tsLicense(document: unknown, reg: unknown, now: number): Outcome {
	return outcome(() => verifyLicense(document, { registry: reg, now }));
}

function mjsPacket(document: unknown, reg: unknown, now: number): Outcome {
	return outcome(() => {
		const publicKeys = licenseMjs.parsePublicKeyRegistry(reg);
		const result = packetMjs.verifyCustomerPacket(document, { publicKeys, now }) as {
			license_state: string;
		};
		return { state: result.license_state };
	});
}

function tsPacket(document: unknown, reg: unknown, now: number): Outcome {
	return outcome(() => {
		const result = verifyCustomerPacket(document, { registry: reg, now });
		return { state: result.licenseState };
	});
}

function licenseCases(withCustomerId: boolean) {
	const base = (overrides: Record<string, unknown> = {}) => {
		const payload: Record<string, unknown> = licensePayload(overrides);
		if (!withCustomerId) delete payload.customer_id;
		return payload;
	};
	const good = signLicense(base(), active);
	return [
		["valid", good, trusted, inTerm],
		["grace", good, trusted, Date.parse("2027-09-10T00:00:00Z")],
		["expired", good, trusted, Date.parse("2027-10-01T00:00:00Z")],
		["not yet valid", good, trusted, Date.parse("2026-08-01T00:00:00Z")],
		["empty registry", good, registry([]), inTerm],
		["tampered seats", { ...good, payload: { ...good.payload, seats: 9999 } }, trusted, inTerm],
		["other key same id", signLicense(base(), stranger), trusted, inTerm],
		["revoked key", signLicense(base(), revoked), trusted, inTerm],
		["unknown key", signLicense(base(), devKey("aidr-license-dev-9")), trusted, inTerm],
		[
			"retired key in window",
			signLicense(
				base({ issued_at: "2026-05-01T00:00:00Z", not_before: "2026-05-01T00:00:00Z" }),
				retired,
			),
			trusted,
			inTerm,
		],
		["retired key after retirement", signLicense(base(), retired), trusted, inTerm],
		[
			"retired key too late",
			signLicense(
				base({ issued_at: "2026-05-01T00:00:00Z", not_before: "2026-05-01T00:00:00Z" }),
				retired,
			),
			trusted,
			Date.parse("2026-06-01T00:00:00Z") + 1921 * DAY,
		],
		["unknown payload field", signLicense({ ...base(), extra: true }, active), trusted, inTerm],
		["bad grace", signLicense(base({ grace_days: 91 }), active), trusted, inTerm],
		[
			"airgap on team",
			signLicense(base({ deployment: "airgap", plan_id: "team" }), active),
			trusted,
			inTerm,
		],
		[
			"term too long",
			signLicense(base({ expires_at: "2031-09-10T00:00:00Z" }), active),
			trusted,
			inTerm,
		],
		["extra envelope field", { ...good, note: "x" }, trusted, inTerm],
		["short sig", { ...good, sig: "AAAA" }, trusted, inTerm],
		[
			"packet-signed license",
			signDocument("aidr-customer-packet-v1", base(), active, active.keyId),
			trusted,
			inTerm,
		],
		[
			"license format packet",
			{ ...signDocument("aidr-customer-packet-v1", base(), active), format: "aidr-license-v1" },
			trusted,
			inTerm,
		],
		["bad customer_id", signLicense({ ...base(), customer_id: "Bad_Id" }, active), trusted, inTerm],
	] as const;
}

describe("license verifier parity (src/license vs scripts/license-verify.mjs)", () => {
	it.each(licenseCases(false))("without customer_id: %s", (_name, document, reg, now) => {
		expect(tsLicense(document, reg, now)).toEqual(mjsLicense(document, reg, now));
	});

	it.each(licenseCases(true))("with customer_id: %s", (_name, document, reg, now) => {
		expect(tsLicense(document, reg, now)).toEqual(mjsLicense(document, reg, now));
	});

	it("TS outcomes match the contract for customer_id licenses", () => {
		const cases = licenseCases(true);
		const byName = Object.fromEntries(
			cases.map(([name, doc, reg, now]) => [name, tsLicense(doc, reg, now)]),
		);
		expect(byName.valid).toEqual({ ok: true, state: "active" });
		expect(byName.grace).toEqual({ ok: true, state: "grace" });
		expect(byName.expired).toEqual({ ok: true, state: "expired" });
		expect(byName["not yet valid"]).toEqual({ ok: true, state: "not_yet_valid" });
		expect(byName["empty registry"]).toEqual({ ok: false, code: "no_trusted_keys" });
		expect(byName["tampered seats"]).toEqual({ ok: false, code: "bad_signature" });
		expect(byName["revoked key"]).toEqual({ ok: false, code: "revoked_key" });
		expect(byName["unknown key"]).toEqual({ ok: false, code: "unknown_key" });
		expect(byName["retired key after retirement"]).toEqual({ ok: false, code: "key_window" });
		expect(byName["retired key too late"]).toEqual({ ok: false, code: "retired_key_expired" });
		expect(byName["packet-signed license"]).toEqual({ ok: false, code: "invalid_document" });
		expect(byName["license format packet"]).toEqual({ ok: false, code: "bad_signature" });
		expect(byName["bad customer_id"]).toEqual({ ok: false, code: "invalid_payload" });
		expect(() => verifyLicense(cases[0][1], { registry: trusted, now: inTerm })).not.toThrow(
			LicenseVerificationError,
		);
	});
});

function packetCases() {
	const license = signLicense(licensePayload(), active);
	const noCustomer = (() => {
		const payload: Record<string, unknown> = licensePayload();
		delete payload.customer_id;
		return signLicense(payload, active);
	})();
	const good = signPacket(packetPayload(license), active);
	const minimal = (() => {
		const payload: Record<string, unknown> = packetPayload(license);
		delete payload.control_plane_url;
		delete payload.sensitivity;
		delete payload.display_name;
		return signPacket(payload, active);
	})();
	return [
		["valid", good, inTerm],
		["minimal", minimal, inTerm],
		["expired license still verifies", good, Date.parse("2028-01-01T00:00:00Z")],
		[
			"tampered url",
			{ ...good, payload: { ...good.payload, control_plane_url: "https://evil.test" } },
			inTerm,
		],
		["license signature as packet", { ...license, format: "aidr-customer-packet-v1" }, inTerm],
		["revoked packet key", signPacket(packetPayload(license), revoked), inTerm],
		[
			"unknown packet key",
			signPacket(packetPayload(license), devKey("aidr-license-dev-9")),
			inTerm,
		],
		[
			"customer mismatch",
			signPacket(packetPayload(license, { customer_id: "other-co" }), active),
			inTerm,
		],
		["license without customer_id", signPacket(packetPayload(noCustomer), active), inTerm],
		[
			"tampered embedded license",
			signPacket(packetPayload({ ...license, payload: { ...license.payload, seats: 1 } }), active),
			inTerm,
		],
		[
			"unknown field",
			signPacket({ ...packetPayload(license), enrollment_code: "x" }, active),
			inTerm,
		],
		[
			"http url",
			signPacket(
				packetPayload(license, { control_plane_url: "http://aidr.example-co.test" }),
				active,
			),
			inTerm,
		],
		[
			"url credentials",
			signPacket(
				packetPayload(license, { control_plane_url: "https://u:p@aidr.example-co.test" }),
				active,
			),
			inTerm,
		],
		[
			"url fragment",
			signPacket(
				packetPayload(license, { control_plane_url: "https://aidr.example-co.test/#x" }),
				active,
			),
			inTerm,
		],
		["bad sensitivity", signPacket(packetPayload(license, { sensitivity: "lax" }), active), inTerm],
		[
			"display name spaces",
			signPacket(packetPayload(license, { display_name: " Example" }), active),
			inTerm,
		],
		[
			"display name too long",
			signPacket(packetPayload(license, { display_name: "x".repeat(61) }), active),
			inTerm,
		],
		[
			"display name turkish",
			signPacket(packetPayload(license, { display_name: "TÜBİTAK BİLGEM" }), active),
			inTerm,
		],
		["bad packet_id", signPacket(packetPayload(license, { packet_id: "-x" }), active), inTerm],
		[
			"issued before key",
			signPacket(packetPayload(license, { issued_at: "2025-06-01T00:00:00Z" }), active),
			inTerm,
		],
		[
			"oversized",
			signPacket(packetPayload(license, { display_name: "x".repeat(70000) }), active),
			inTerm,
		],
	] as const;
}

describe("customer packet verifier parity (src/license vs scripts/customer-packet-verify.mjs)", () => {
	it.each(packetCases())("%s", (_name, document, now) => {
		expect(tsPacket(document, trusted, now)).toEqual(mjsPacket(document, trusted, now));
	});

	it("TS outcomes match the contract", () => {
		const byName = Object.fromEntries(
			packetCases().map(([name, doc, now]) => [name, tsPacket(doc, trusted, now)]),
		);
		expect(byName.valid).toEqual({ ok: true, state: "active" });
		expect(byName.minimal).toEqual({ ok: true, state: "active" });
		expect(byName["expired license still verifies"]).toEqual({ ok: true, state: "expired" });
		expect(byName["tampered url"]).toEqual({ ok: false, code: "bad_signature" });
		expect(byName["license signature as packet"]).toEqual({ ok: false, code: "bad_signature" });
		expect(byName["revoked packet key"]).toEqual({ ok: false, code: "revoked_key" });
		expect(byName["unknown packet key"]).toEqual({ ok: false, code: "unknown_key" });
		expect(byName["customer mismatch"]).toEqual({ ok: false, code: "customer_mismatch" });
		expect(byName["license without customer_id"]).toEqual({ ok: false, code: "customer_mismatch" });
		expect(byName["tampered embedded license"]).toEqual({ ok: false, code: "invalid_license" });
		for (const name of [
			"unknown field",
			"http url",
			"url credentials",
			"url fragment",
			"bad sensitivity",
			"display name spaces",
			"display name too long",
			"bad packet_id",
		]) {
			expect(byName[name], name).toEqual({ ok: false, code: "invalid_payload" });
		}
		expect(byName["display name turkish"]).toEqual({ ok: true, state: "active" });
		expect(byName["issued before key"]).toEqual({ ok: false, code: "key_window" });
		expect(tsPacket(packetCases()[0][1], registry([]), inTerm)).toEqual({
			ok: false,
			code: "no_trusted_keys",
		});
	});
});
