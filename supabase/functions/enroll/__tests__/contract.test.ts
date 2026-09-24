import { describe, expect, it } from "vitest";
import { entitlementWindow, validateEnrollmentBody } from "../contract.ts";

describe("enrollment contract", () => {
	it("accepts only bounded installation metadata and ignores caller entitlement fields", () => {
		expect(validateEnrollmentBody({
			iid: "  agent-1  ",
			agent_runtime: "claude-code",
			allowed_agents: 5000,
			entitlement: { subscription_tier: "enterprise", premium_modules: ["*"] },
		})).toEqual({
			iid: "agent-1",
			agent_runtime: "claude-code",
			agent_runtime_version: null,
		});
	});

	it.each([
		null,
		[],
		{},
		{ iid: "" },
		{ iid: "agent\n1" },
		{ iid: "a".repeat(129) },
		{ iid: "agent-1", agent_runtime_version: 42 },
	])("rejects malformed enrollment metadata: %j", (body) => {
		expect(validateEnrollmentBody(body)).toBeNull();
	});

	it("bounds online validity and offline grace before issuing a signed grant", () => {
		const issued = new Date("2026-01-01T00:00:00.000Z");
		expect(entitlementWindow(issued, "168", "72")).toEqual({
			issuedAt: issued.toISOString(),
			expiresAt: "2026-01-08T00:00:00.000Z",
			graceUntil: "2026-01-11T00:00:00.000Z",
		});
		for (const [ttl, grace] of [
			["0", "72"], ["721", "72"], ["168", "169"], ["1.5", "1"], ["01", "1"],
		]) {
			expect(entitlementWindow(issued, ttl, grace)).toBeNull();
		}
		expect(entitlementWindow(new Date(Number.NaN), "168", "72")).toBeNull();
	});
});
