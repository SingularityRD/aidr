/**
 * Tests for `aidr setup` honesty (AIDR-007).
 *
 * ## The defects these pin
 *
 * 1. **A rerun was indistinguishable from a first install.** `createConfig`
 *    correctly returned `{outcome: "reused"}`, but setup discarded the outcome
 *    and printed the same `✅ Setup complete!` either way, so a user rerunning
 *    setup could not tell that nothing had changed. (An earlier version was
 *    worse: it printed a fresh success message while doing nothing at all.)
 *
 * 2. **Setup printed an unqualified all-clear on a screen that said protection
 *    was not active.** The next-steps list contained
 *    "Start using your AI agent normally", three lines above
 *    "Protection is NOT yet active for your agent". A security product must not
 *    tell the user to proceed normally while nothing is inspecting their tool
 *    calls.
 *
 * 3. **`installVSCodeHooks` rewrote the whole editor `settings.json`** through a
 *    JSON round-trip, risking loss of the user's own settings. That module is
 *    gone; a test here pins that it does not come back.
 */

import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it, vi } from "vitest";

/**
 * `config-manager` captures `homedir()` at import time, so redirecting
 * `process.env.HOME` in a `beforeEach` is too late — the module has already
 * resolved the developer's real home and would write there. Stubbing the module
 * before importing it is the only way to test this safely.
 */
const testHome = mkdtempSync(join(tmpdir(), "aidr-setup-honesty-"));
const originalHome = process.env.HOME;
process.env.HOME = testHome;

vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome };
});

/**
 * `createConfig` now resolves a secret store before writing anything, and the
 * ACL-hardened file is only used when it is selected explicitly. These cases
 * pin the file layout (`apiKey` in `config.json`) and its reuse/rotation
 * behaviour, so they select that fallback on purpose. The OS-vault path is
 * covered by `secret-store.test.ts`; nothing asserted here is weakened.
 */
process.env.AIDR_SECRET_STORE = "file-acl";

const { createConfig, getConfig, updateConfig } = await import("../utils/config-manager.js");
type Environment = import("../utils/config-manager.js").Environment;

const cliSrc = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const env: Environment = {
	agent: "claude",
	hasNode: true,
	nodeVersion: "v24.0.0",
	projectRoot: process.cwd(),
};

afterAll(() => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(testHome, { recursive: true, force: true });
});

describe("setup reports what it actually did", () => {
	it("reports 'created' on a first run and 'reused' on a rerun", async () => {
		const first = await createConfig(env, false);
		expect(first.outcome).toBe("created");

		// The distinction must be observable, because setup's output is derived
		// from it. A rerun that reported "created" would tell the user something
		// happened when nothing did.
		const second = await createConfig(env, false);
		expect(second.outcome).toBe("reused");
		expect(second.path).toBe(first.path);
	});

	it("writes the config with owner-only permissions", async () => {
		const result = await createConfig(env, false);
		if (process.platform !== "win32") {
			const mode = statSync(result.path).mode & 0o777;
			expect(mode & 0o077).toBe(0);
		}
	});

	it("needs no credential and no vault in local mode (PRD-4, MSC-13)", async () => {
		rmSync(join(testHome, ".singularity-aidr"), { recursive: true, force: true });
		const previous = process.env.AIDR_SECRET_STORE;
		delete process.env.AIDR_SECRET_STORE;
		// Any attempt to probe or use a vault would fail: there is none.
		const noVault = () => ({ status: 127, stdout: "", stderr: "secret-tool: command not found" });
		try {
			const result = await createConfig({ ...env, projectRoot: "/some/repo" }, false, {
				secretStoreRunner: noVault,
			});
			expect(result.outcome).toBe("created");
			expect(result.credential).toBe("none");
			const parsed = JSON.parse(readFileSync(result.path, "utf-8"));
			expect(parsed.apiKey).toBeUndefined();
			expect(parsed.secret_ref).toBeUndefined();
			expect(parsed.secret_store).toBeUndefined();
			// The global config no longer records the directory setup ran in.
			expect(parsed.environment.projectRoot).toBeUndefined();
			expect(readFileSync(result.path, "utf-8")).not.toMatch(/aidr_[A-Za-z0-9]/);
		} finally {
			if (previous === undefined) delete process.env.AIDR_SECRET_STORE;
			else process.env.AIDR_SECRET_STORE = previous;
		}
	});

	it("seals a needed (managed) credential in the encrypted file store when no vault exists", async () => {
		rmSync(join(testHome, ".singularity-aidr"), { recursive: true, force: true });
		await createConfig(env, false);
		updateConfig({ mode: "managed" } as unknown as Partial<
			import("../utils/config-manager.js").Config
		>);
		const previous = process.env.AIDR_SECRET_STORE;
		delete process.env.AIDR_SECRET_STORE;
		const noVault = () => ({ status: 127, stdout: "", stderr: "secret-tool: command not found" });
		try {
			const result = await createConfig(env, false, { secretStoreRunner: noVault });
			expect(result.credential).toBe("encrypted-file");
			const raw = readFileSync(result.path, "utf-8");
			const parsed = JSON.parse(raw);
			// Never plaintext: config.json holds only a reference.
			expect(parsed.apiKey).toBeUndefined();
			expect(parsed.secret_ref.store).toBe("encrypted-file");
			const key = getConfig({ secretStoreRunner: noVault })?.apiKey ?? "";
			expect(key).toMatch(/^aidr_/);
			const sealed = readFileSync(
				join(testHome, ".singularity-aidr", "sealed", `${parsed.secret_ref.id}.sealed.json`),
				"utf-8",
			);
			expect(sealed).not.toContain(key);
			expect(raw).not.toContain(key);
		} finally {
			if (previous === undefined) delete process.env.AIDR_SECRET_STORE;
			else process.env.AIDR_SECRET_STORE = previous;
			rmSync(join(testHome, ".singularity-aidr"), { recursive: true, force: true });
		}
	});

	it("does not rotate the credential on a rerun", async () => {
		await createConfig(env, false);
		updateConfig({ mode: "managed" } as unknown as Partial<
			import("../utils/config-manager.js").Config
		>);
		const first = await createConfig(env, false);
		const originalKey = getConfig()?.apiKey;
		expect(originalKey).toBeTruthy();

		await createConfig(env, false);

		// Reusing the config must not silently mint a new key: a user who had
		// already registered the old one would be broken.
		expect(getConfig()?.apiKey).toBe(originalKey);
		expect(JSON.parse(readFileSync(first.path, "utf-8")).apiKey).toBe(originalKey);
	});

	it("rotates the credential only when --force is passed", async () => {
		await createConfig(env, false);
		const originalKey = getConfig()?.apiKey;

		const forced = await createConfig(env, true);
		expect(forced.outcome).toBe("created");
		expect(getConfig()?.apiKey).not.toBe(originalKey);
	});

	it("preserves runtime policy and auth fields when setup force-replaces its credential", async () => {
		await createConfig(env, false);
		updateConfig({
			mode: "managed",
			auth: { api_key: "runtime-auth-key" },
			policy: { shell: { enabled: true, deny_patterns: ["dangerous-command"] } },
		} as unknown as Partial<import("../utils/config-manager.js").Config>);

		await createConfig(env, true);

		expect(getConfig()).toMatchObject({
			mode: "managed",
			auth: { api_key: "runtime-auth-key" },
			policy: { shell: { enabled: true, deny_patterns: ["dangerous-command"] } },
		});
	});
});

/**
 * Strip comments before asserting that a phrase is ABSENT.
 *
 * These modules document the behaviour they replaced, so the literal phrases
 * legitimately appear inside explanatory comments. A naive `not.toMatch` over
 * the whole file fails on the very documentation that explains the fix.
 *
 * String literals are deliberately NOT stripped: the phrases under test are
 * exactly the user-facing strings the product prints, so they must remain
 * visible to the matcher.
 */
function codeOnly(source: string): string {
	return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
}

describe("setup output does not contradict itself", () => {
	it("never tells the user to proceed normally while protection is inactive", () => {
		const code = codeOnly(readFileSync(join(cliSrc, "commands", "setup.ts"), "utf-8"));

		expect(code).not.toMatch(/Start using your AI agent normally/i);
		// And it must actively warn instead.
		expect(code).toMatch(/NOT inspected|Protection is NOT yet active/i);
	});

	it("does not print an unconditional success line for a rerun", () => {
		const code = codeOnly(readFileSync(join(cliSrc, "commands", "setup.ts"), "utf-8"));
		// The success message must be branched on the outcome.
		expect(code).toMatch(/config\.outcome === "reused"|config\.outcome === 'reused'/);
		expect(code).toMatch(/no changes were needed/i);
	});
});

describe("no module rewrites the user's editor settings", () => {
	it("does not contain an installVSCodeHooks implementation", () => {
		// A previous version rewrote settings.json wholesale. Installing a
		// security tool must never risk the user's own editor configuration.
		const code = codeOnly(readFileSync(join(cliSrc, "utils", "install-hooks.ts"), "utf-8"));
		expect(code).not.toMatch(/installVSCodeHooks/);
		expect(code).not.toMatch(/settings\.json/);
	});

	it("tells the user protection is NOT active rather than implying it is", () => {
		const code = codeOnly(readFileSync(join(cliSrc, "utils", "install-hooks.ts"), "utf-8"));
		expect(code).toMatch(/Protection is NOT yet active/);
		// It previously wrote config files and keys that no shipped connector
		// reads, then reported success.
		expect(code).not.toMatch(/claude-hooks/);
		expect(code).not.toMatch(/hooksPath/);
	});

	it("uses approved release artifacts and exact package-version guidance", () => {
		const code = codeOnly(readFileSync(join(cliSrc, "utils", "install-hooks.ts"), "utf-8"));
		expect(code).toMatch(/verified release bundle/i);
		// The guidance pins the CLI's own release version, never a literal
		// `VERSION` placeholder the user has to substitute.
		expect(code).toMatch(
			/openclaw plugins install npm:@singularityrd\/aidr-openclaw@\$\{VERSION\}/,
		);
		expect(code).not.toMatch(/@singularityrd\/aidr-[a-z]+@VERSION\b/);
		expect(code).not.toMatch(/"VERSION"/);
		expect(code).toMatch(/confirm it against the approved release record/i);
		expect(code).not.toMatch(/build and install the VSIX/i);
		expect(code).not.toMatch(/plugins install @singularityrd\/aidr-openclaw(?:["'\s]|$)/);
	});
});
