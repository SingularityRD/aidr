import { describe, expect, it } from "vitest";
import { isProtectionTightening } from "../utils/protection-change.js";

describe("isProtectionTightening for opt-in protections", () => {
	it("treats turning on quarantine or the signed response chain as tightening", () => {
		expect(isProtectionTightening("response.quarantine.enabled", false, true)).toBe(true);
		expect(isProtectionTightening("response.audit.signed_chain", false, true)).toBe(true);
	});

	it("still treats turning them off as weakening", () => {
		expect(isProtectionTightening("response.quarantine.enabled", true, false)).toBe(false);
		expect(isProtectionTightening("response.audit.signed_chain", true, false)).toBe(false);
	});
});
