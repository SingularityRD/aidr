import { describe, expect, it } from "vitest";
import { dashboardAgentFreshness } from "../ui/dashboard-freshness";

describe("dashboard agent freshness", () => {
	const now = 1_000_000;

	it("keeps the configured window boundary fresh and marks older evidence stale", () => {
		expect(dashboardAgentFreshness(new Date(now - 600_000).toISOString(), now)).toBe("fresh");
		expect(dashboardAgentFreshness(new Date(now - 600_001).toISOString(), now)).toBe("stale");
	});

	it("does not treat future or malformed timestamps as connected", () => {
		expect(dashboardAgentFreshness(new Date(now + 1).toISOString(), now)).toBe("stale");
		expect(dashboardAgentFreshness("not-a-timestamp", now)).toBe("unknown");
		expect(dashboardAgentFreshness(null, now)).toBe("unknown");
		expect(dashboardAgentFreshness(undefined, now)).toBe("unknown");
		expect(dashboardAgentFreshness("", now)).toBe("unknown");
	});

	it("uses the supplied clock snapshot and rejects invalid clocks or windows", () => {
		const seen = new Date(now).toISOString();
		expect(dashboardAgentFreshness(seen, now, 0)).toBe("fresh");
		expect(dashboardAgentFreshness(seen, now + 1, 0)).toBe("stale");
		for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
			expect(dashboardAgentFreshness(seen, invalid)).toBe("unknown");
			expect(dashboardAgentFreshness(seen, now, invalid)).toBe("unknown");
		}
		expect(dashboardAgentFreshness(seen, now, -1)).toBe("unknown");
	});
});
