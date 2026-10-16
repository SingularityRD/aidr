import { existsSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Tests clear ~/.claude, ~/.config and ~/.singularity-aidr under HOME. Every Vitest config
// (the root one and each package's own, used by `pnpm --filter <pkg> test`) must therefore load
// the per-file temporary HOME, or a package-level run deletes the developer's real profile.
const repoRoot = join(__dirname, "..", "..", "..", "..");
const packagesRoot = join(repoRoot, "packages");

const configs = [
	join(repoRoot, "vitest.config.ts"),
	...readdirSync(packagesRoot, { withFileTypes: true })
		.filter((entry) => entry.isDirectory())
		.flatMap((entry) =>
			["vitest.config.ts", "vitest.config.mts", "vitest.config.js", "vitest.config.mjs"].map(
				(name) => join(packagesRoot, entry.name, name),
			),
		)
		.filter((file) => existsSync(file)),
];

describe("vitest configs isolate HOME", () => {
	for (const config of configs) {
		it(`${config.slice(repoRoot.length + 1)} loads vitest-isolated-home and pins English`, () => {
			const source = readFileSync(config, "utf8");
			expect(source).toContain("vitest-isolated-home.mjs");
			expect(source).toMatch(/AIDR_LOCALE:\s*"en"/);
		});
	}

	it("this run's HOME is a temporary directory", () => {
		const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
		expect(resolve(home).startsWith(resolve(tmpdir()))).toBe(true);
	});
});
