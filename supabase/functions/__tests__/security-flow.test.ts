import { describe, expect, it } from "vitest";
import { getBearerToken } from "../_shared/auth.ts";
import { evaluateDevicePollState, evaluateDeviceVerifyState } from "../_shared/device-auth.ts";
import { parseAllowedOrigins, resolveAllowedOrigin } from "../_shared/origin.ts";

describe("waitlist origin policy", () => {
	it("allows configured origin", () => {
		const allowed = parseAllowedOrigins("https://app.singularityrd.com,https://aidr.dev");
		expect(resolveAllowedOrigin("https://aidr.dev", allowed)).toBe("https://aidr.dev");
	});

	it("blocks disallowed origin", () => {
		const allowed = parseAllowedOrigins("https://app.singularityrd.com");
		expect(resolveAllowedOrigin("https://evil.example", allowed)).toBeNull();
	});
});

describe("device poll states", () => {
	const nowMs = Date.parse("2026-03-28T10:00:00.000Z");

	it("returns pending before verification", () => {
		const state = evaluateDevicePollState({
			nowMs,
			expiresAtIso: "2026-03-28T11:00:00.000Z",
			authorizedAt: null,
			userId: null,
			pilotApproved: true,
			exchangedAt: null,
		});
		expect(state.status).toBe("pending");
	});

	it("returns pilot_not_approved after verify if user not approved", () => {
		const state = evaluateDevicePollState({
			nowMs,
			expiresAtIso: "2026-03-28T11:00:00.000Z",
			authorizedAt: "2026-03-28T09:59:59.000Z",
			userId: "u1",
			pilotApproved: false,
			exchangedAt: null,
		});
		expect(state.status).toBe("forbidden");
	});

	it("returns expired for stale code", () => {
		const state = evaluateDevicePollState({
			nowMs,
			expiresAtIso: "2026-03-28T09:00:00.000Z",
			authorizedAt: null,
			userId: null,
			pilotApproved: true,
			exchangedAt: null,
		});
		expect(state.status).toBe("expired");
	});
});

describe("device verify states", () => {
	const nowMs = Date.parse("2026-03-28T10:00:00.000Z");

	it("returns pilot_not_approved when pending user verifies", () => {
		const state = evaluateDeviceVerifyState({
			nowMs,
			expiresAtIso: "2026-03-28T11:00:00.000Z",
			authorizedAt: null,
			pilotApproved: false,
		});
		expect(state.status).toBe("forbidden");
	});

	it("returns device_code_expired on expired code", () => {
		const state = evaluateDeviceVerifyState({
			nowMs,
			expiresAtIso: "2026-03-28T09:59:59.000Z",
			authorizedAt: null,
			pilotApproved: true,
		});
		expect(state.status).toBe("expired");
	});
});

describe("auth helpers", () => {
	it("extracts bearer token", () => {
		expect(getBearerToken("Bearer aidr_live_test")).toBe("aidr_live_test");
	});

	it("rejects malformed auth header", () => {
		expect(getBearerToken("Basic abc")).toBeNull();
	});
});
