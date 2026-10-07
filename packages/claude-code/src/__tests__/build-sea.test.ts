import { describe, expect, it } from "vitest";
import {
	binaryFileName,
	checkSeaSupport,
	ENTRY_POINTS,
	SEA_SENTINEL_FUSE,
} from "../../scripts/build-sea.mjs";

const withFuse = (state: string) => Buffer.from(`\0\0prefix${SEA_SENTINEL_FUSE}${state}suffix\0`);

describe("build-sea checkSeaSupport", () => {
	it("accepts a supported official Node binary", () => {
		expect(checkSeaSupport({ version: "v22.12.0", binary: withFuse(":0") })).toEqual({ ok: true });
		expect(checkSeaSupport({ version: "v24.18.1", binary: withFuse(":0") })).toEqual({ ok: true });
	});

	it("rejects Node versions older than 20", () => {
		const result = checkSeaSupport({ version: "v18.20.4", binary: withFuse(":0") });
		expect(result.ok).toBe(false);
		expect(result.ok === false && result.reason).toMatch(/Node >= 20/);
	});

	it("rejects an unparseable version string", () => {
		expect(checkSeaSupport({ version: "garbage" }).ok).toBe(false);
	});

	it("rejects a shared-libnode build", () => {
		const result = checkSeaSupport({
			version: "v22.12.0",
			nodeShared: true,
			binary: withFuse(":0"),
		});
		expect(result.ok === false && result.reason).toMatch(/shared libnode/);
	});

	it("rejects a binary without the SEA sentinel fuse (e.g. Homebrew)", () => {
		const result = checkSeaSupport({ version: "v22.12.0", binary: Buffer.from("no fuse here") });
		expect(result.ok === false && result.reason).toMatch(/sentinel fuse/);
	});

	it("rejects a binary that is already a SEA", () => {
		const result = checkSeaSupport({ version: "v22.12.0", binary: withFuse(":1") });
		expect(result.ok === false && result.reason).toMatch(/already/);
	});

	it("rejects a binary with duplicate sentinels", () => {
		const twice = Buffer.concat([withFuse(":0"), withFuse(":0")]);
		expect(checkSeaSupport({ version: "v22.12.0", binary: twice }).ok).toBe(false);
	});
});

describe("build-sea outputs", () => {
	it("keeps the historical binary names", () => {
		expect(ENTRY_POINTS.map((e) => e.binary)).toEqual(["aidr-pre-tool-use", "aidr-session-start"]);
	});

	it("appends .exe only on Windows", () => {
		expect(binaryFileName("aidr-pre-tool-use", "win32")).toBe("aidr-pre-tool-use.exe");
		expect(binaryFileName("aidr-pre-tool-use", "linux")).toBe("aidr-pre-tool-use");
		expect(binaryFileName("aidr-pre-tool-use", "darwin")).toBe("aidr-pre-tool-use");
	});
});
