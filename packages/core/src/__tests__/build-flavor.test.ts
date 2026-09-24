import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// The build helper is plain ESM so release packaging can run before package install.
// @ts-expect-error The build-only module intentionally has no declaration file.
import { embedBuildFlavor } from "../../scripts/embed-build-flavor.mjs";

describe("embedded build flavor", () => {
	it("wires development and commercial markers into their respective package builds", () => {
		const packageJson = JSON.parse(
			readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
		) as { scripts: Record<string, string> };
		expect(packageJson.scripts.build).toContain("embed-build-flavor.mjs development");
		expect(packageJson.scripts["build:release"]).toContain("embed-build-flavor.mjs commercial");
	});

	it("replaces the unique marker with an immutable commercial flavor", () => {
		const source = 'const EMBEDDED_BUILD_FLAVOR = "__AIDR_EMBEDDED_BUILD_FLAVOR__";';
		const result = embedBuildFlavor(source, "commercial");
		expect(result).toBe('const EMBEDDED_BUILD_FLAVOR = "commercial";');
		expect(result).not.toContain("__AIDR_EMBEDDED_BUILD_FLAVOR__");
	});

	it("rejects missing or duplicate markers instead of producing an ambiguous release", () => {
		expect(() => embedBuildFlavor("const flavor = 'development';", "commercial")).toThrow(
			"Expected one build flavor marker, found 0",
		);
		const marker = '"__AIDR_EMBEDDED_BUILD_FLAVOR__"';
		expect(() => embedBuildFlavor(`${marker}${marker}`, "commercial")).toThrow(
			"Expected one build flavor marker, found 2",
		);
	});
});
