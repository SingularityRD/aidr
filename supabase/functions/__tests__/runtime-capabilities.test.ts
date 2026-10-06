import { describe, expect, it } from "vitest";
import { buildPremiumModules, tenantRuntimeCapabilities } from "../_shared/runtime-capabilities.ts";

const TENANT = "tenant-1";
const NOW = Date.parse("2026-10-06T12:00:00.000Z");
const CAPS = ["runtime_detectors", "behavioral_learning_v1"];
const ADMISSION = {
	mode: "cloud", status: "active", access_kind: "licensed", allowed_agents: 1,
	expires_at: "2026-10-07T12:00:00.000Z",
};
const CONFIG = JSON.stringify({ [TENANT]: CAPS });

describe("operator runtime capability grants", () => {
	it.each(["cloud", "onprem"])("grants explicitly enabled capabilities to an active licensed %s tenant", (mode) => {
		expect(tenantRuntimeCapabilities(TENANT, CONFIG, { ...ADMISSION, mode }, NOW)).toEqual(CAPS);
		expect(tenantRuntimeCapabilities(TENANT, JSON.stringify({ [TENANT]: [CAPS[0]] }), { ...ADMISSION, mode }, NOW)).toEqual([CAPS[0]]);
	});

	it.each([
		["absent", undefined],
		["empty", ""],
		["disabled", JSON.stringify({ [TENANT]: [] })],
		["foreign tenant", JSON.stringify({ other: CAPS })],
		["malformed JSON", "{"],
		["null", "null"],
		["array", "[]"],
		["scalar", "true"],
		["wildcard tenant", JSON.stringify({ "*": CAPS })],
		["unknown capability", JSON.stringify({ [TENANT]: ["premium_intel"] })],
		["wildcard capability", JSON.stringify({ [TENANT]: ["*"] })],
		["learning without detector", JSON.stringify({ [TENANT]: [CAPS[1]] })],
		["duplicate capability", JSON.stringify({ [TENANT]: [CAPS[0], CAPS[0]] })],
		["non-array grant", JSON.stringify({ [TENANT]: true })],
		["non-string grant", JSON.stringify({ [TENANT]: [null] })],
		["oversized capability list", JSON.stringify({ [TENANT]: [...CAPS, CAPS[0]] })],
		["invalid unrelated entry", JSON.stringify({ [TENANT]: CAPS, other: ["unknown"] })],
		["invalid tenant prefix", JSON.stringify({ [TENANT]: CAPS, "_other": [] })],
		["invalid tenant character", JSON.stringify({ [TENANT]: CAPS, "other/tenant": [] })],
		["oversized tenant ID", JSON.stringify({ [TENANT]: CAPS, ["a".repeat(129)]: [] })],
		["oversized map", JSON.stringify(Object.fromEntries(Array.from({ length: 257 }, (_, i) => [i === 0 ? TENANT : `tenant-${i + 1}`, CAPS])))],
		["oversized JSON", `${CONFIG}${" ".repeat(65_537)}`],
	] as const)("fails closed for %s deployment configuration", (_name, config) => {
		expect(tenantRuntimeCapabilities(TENANT, config, ADMISSION, NOW)).toEqual([]);
	});

	it.each([
		["free", { ...ADMISSION, access_kind: "free" }],
		["trial", { ...ADMISSION, access_kind: "trial" }],
		["pilot", { ...ADMISSION, mode: "pilot", access_kind: "pilot", expires_at: null }],
		["revoked", { ...ADMISSION, status: "revoked" }],
		["expired", { ...ADMISSION, expires_at: new Date(NOW - 1).toISOString() }],
		["exact expiry", { ...ADMISSION, expires_at: new Date(NOW).toISOString() }],
		["missing expiry", { ...ADMISSION, expires_at: null }],
		["invalid expiry", { ...ADMISSION, expires_at: "Infinity" }],
		["numeric expiry", { ...ADMISSION, expires_at: NOW + 86_400_000 }],
		["zero capacity", { ...ADMISSION, allowed_agents: 0 }],
		["no admission", null],
	] as const)("does not mint a capability for %s admission", (_name, admission) => {
		expect(tenantRuntimeCapabilities(TENANT, CONFIG, admission, NOW)).toEqual([]);
	});

	it("accepts the documented limits and returns a fresh grant array", () => {
		const map = Object.fromEntries(Array.from({ length: 256 }, (_, i) => [i === 0 ? TENANT : `tenant-${i + 1}`, CAPS]));
		map["a".repeat(128)] = map[TENANT];
		delete map["tenant-256"];
		const json = JSON.stringify(map);
		const config = `${json}${" ".repeat(65_536 - json.length)}`;
		const grants = tenantRuntimeCapabilities(TENANT, config, ADMISSION, NOW);
		expect(grants).toEqual(CAPS);
		grants.length = 0;
		expect(tenantRuntimeCapabilities(TENANT, config, ADMISSION, NOW)).toEqual(CAPS);
	});

	it("preserves premium flags without converting premium intelligence or tier labels to runtime grants", () => {
		expect(buildPremiumModules(null)).toEqual([]);
		expect(buildPremiumModules({ premium_intel: true, subscription_tier: "enterprise" })).toEqual(["premium_intel"]);
		expect(buildPremiumModules({ premium_intel: true, premium_correlation: true, premium_pkg_plugin: true }, CAPS)).toEqual([
			"premium_intel", "premium_correlation", "premium_pkg_plugin", ...CAPS,
		]);
		expect(buildPremiumModules({ premium_intel: "true", premium_correlation: 1, premium_pkg_plugin: "*" })).toEqual([]);
	});
});
