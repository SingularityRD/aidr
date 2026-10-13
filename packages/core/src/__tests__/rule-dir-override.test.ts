import { describe, expect, it } from "vitest";
import { ruleDirOverride, ruleDirOverrideNotice, ruleDirOverrides } from "../rule-dir-override.js";

describe("AIDR_THREATS_DIR / AIDR_ALLOWLISTS_DIR overrides (CON-7)", () => {
	it("reports nothing when neither variable is set or both are blank", () => {
		expect(ruleDirOverride("threats", { env: {} })).toBeNull();
		expect(ruleDirOverrides({ env: { AIDR_THREATS_DIR: "  ", AIDR_ALLOWLISTS_DIR: "" } })).toEqual(
			[],
		);
		expect(ruleDirOverrideNotice([])).toBeNull();
	});

	it("never honours an override in a commercial build", () => {
		const override = ruleDirOverride("threats", {
			env: { AIDR_THREATS_DIR: "/tmp/benign-rules" },
			commercial: true,
		});
		expect(override).toEqual({
			kind: "threats",
			envName: "AIDR_THREATS_DIR",
			path: "/tmp/benign-rules",
			accepted: false,
		});
		const notice = ruleDirOverrideNotice(override ? [override] : []);
		expect(notice).toContain("ignored AIDR_THREATS_DIR=/tmp/benign-rules");
		expect(notice).toContain("bundled, integrity-checked threat rules");
	});

	it("honours an override in a development build, loudly", () => {
		const overrides = ruleDirOverrides({
			env: { AIDR_THREATS_DIR: "/tmp/rules", AIDR_ALLOWLISTS_DIR: "/tmp/allow" },
			commercial: false,
		});
		expect(overrides.map((override) => [override.kind, override.accepted])).toEqual([
			["threats", true],
			["allowlists", true],
		]);
		const notice = ruleDirOverrideNotice(overrides) ?? "";
		expect(notice.split("\n")).toHaveLength(2);
		expect(notice).toContain("using threat rules from AIDR_THREATS_DIR=/tmp/rules");
		expect(notice).toContain("using allowlists from AIDR_ALLOWLISTS_DIR=/tmp/allow");
	});

	it("escapes terminal control characters in the reported path", () => {
		const notice = ruleDirOverrideNotice(
			ruleDirOverrides({ env: { AIDR_THREATS_DIR: "/tmp/x\u001b[2Jy" }, commercial: true }),
		);
		expect(notice).not.toContain("\u001b");
	});
});
