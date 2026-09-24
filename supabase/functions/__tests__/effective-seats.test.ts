import { describe, expect, it } from "vitest";
import { capEntitlementTimes, parseActiveAdmission, parseEffectiveSeats } from "../_shared/effective-seats.ts";

describe("effective provider seats", () => {
	it("rejects missing, ambiguous and malformed database results", () => {
		for (const value of [null, [], [{ extra_agents: 1, provider_valid_until: null }, {}],
			[{ extra_agents: -1, provider_valid_until: null }],
			[{ extra_agents: 1, provider_valid_until: "not-a-date" }],
			[{ extra_agents: 0, provider_valid_until: "2026-12-01T00:00:00Z" }]]) {
			expect(parseEffectiveSeats(value)).toBeNull();
		}
	});

	it("accepts invoice/manual seats without term and provider seats with a term", () => {
		expect(parseEffectiveSeats([{ extra_agents: 3, provider_valid_until: null }]))
			.toEqual({ extraAgents: 3, providerValidUntilMs: null });
		expect(parseEffectiveSeats([{ extra_agents: 2, provider_valid_until: "2026-12-01T00:00:00Z" }]))
			.toEqual({ extraAgents: 2, providerValidUntilMs: Date.parse("2026-12-01T00:00:00Z") });
	});

	it("clamps both expiry and grace; refuses the boundary and later", () => {
		const expires = "2026-01-08T00:00:00.000Z";
		const grace = "2026-01-11T00:00:00.000Z";
		const term = Date.parse("2026-01-03T00:00:00.000Z");
		expect(capEntitlementTimes(expires, grace, term, Date.parse("2026-01-01T00:00:00Z")))
			.toEqual({ expiresAt: "2026-01-03T00:00:00.000Z", graceUntil: "2026-01-03T00:00:00.000Z" });
		expect(capEntitlementTimes(expires, grace, term, term)).toBeNull();
		expect(capEntitlementTimes(expires, grace, term, term + 1)).toBeNull();
	});
});

describe("tenant admission snapshot boundary", () => {
	const now = Date.parse("2026-09-23T00:00:00Z");
	it("accepts only an active matching mode and kind", () => {
		expect(parseActiveAdmission({ mode: "cloud", status: "active", access_kind: "trial",
			allowed_agents: 1, expires_at: "2026-10-07T00:00:00Z" }, now))
			.toEqual({ allowedAgents: 1, validUntilMs: Date.parse("2026-10-07T00:00:00Z") });
		expect(parseActiveAdmission({ mode: "cloud", status: "active", access_kind: "licensed",
			allowed_agents: 50, expires_at: "2027-09-23T00:00:00Z" }, now))
			.toEqual({ allowedAgents: 50, validUntilMs: Date.parse("2027-09-23T00:00:00Z") });
		expect(parseActiveAdmission({ mode: "pilot", status: "active", access_kind: "pilot",
			allowed_agents: 1, expires_at: null }, now))
			.toEqual({ allowedAgents: 1, validUntilMs: null });
	});
	it("fails closed for expired, revoked, missing term, or trial-kind laundering", () => {
		for (const admission of [
			{ mode: "cloud", status: "expired", access_kind: "trial", allowed_agents: 1, expires_at: "2026-10-07T00:00:00Z" },
			{ mode: "cloud", status: "revoked", access_kind: "licensed", allowed_agents: 5, expires_at: "2027-09-23T00:00:00Z" },
			{ mode: "cloud", status: "active", access_kind: "trial", allowed_agents: 1, expires_at: "2026-09-23T00:00:00Z" },
			{ mode: "cloud", status: "active", access_kind: "licensed", allowed_agents: 5, expires_at: null },
			{ mode: "onprem", status: "active", access_kind: "trial", allowed_agents: 1, expires_at: "2026-10-07T00:00:00Z" },
		]) expect(parseActiveAdmission(admission, now)).toBeNull();
	});
});
