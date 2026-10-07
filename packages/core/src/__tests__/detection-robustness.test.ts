/**
 * Regression tests for detection robustness findings:
 *
 *  1. A corrupt, emptied or missing bundled rule file degrades verdicts instead
 *     of silently disabling its rules.
 *  2. User rules may add IDs but never replace a bundled rule.
 *  3. A misconfigured URL-check endpoint is an unavailable leg, never clean.
 *  4. Per-leg timeouts and the total detection budget are bounded.
 *  6. Under enforced integrity, unlisted resource files are refused.
 *  7. A failed managed/licensing gate keeps local detection enforcing; an
 *     integrity failure still fails closed.
 */

import { generateKeyPairSync } from "node:crypto";
import { copyFile, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UrlCheckClient } from "../clients/url-check.js";
import { loadConfig } from "../config.js";
import { evaluateToolCall } from "../evaluator.js";
import { extractFromBash } from "../extractors.js";
import { BUNDLED_THREAT_FILES } from "../generated/threat-parse-cache.js";
import {
	enterDegradedSafeMode,
	resetDegradedSafeModeForTests,
} from "../integrity/degraded-safe-mode.js";
import { clearVerifiedManifest, registerVerifiedManifest } from "../integrity/resource-gate.js";
import { loadThreatSet } from "../threat-loader.js";
import { loadTrustedDomains } from "../trusted-domains.js";
import { MAX_DETECTION_LEG_TIMEOUT_SECONDS } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const REPO_THREATS = resolve(__dirname, "..", "..", "..", "..", "threats");
const REPO_ALLOWLISTS = resolve(__dirname, "..", "..", "..", "..", "allowlists");

const DESTRUCTIVE = "rm -rf /";
const BENIGN = "ls -la";

let home: string;
let previousHome: string | undefined;
let previousUserProfile: string | undefined;

async function copyBundledThreats(target: string, skip: string[] = []): Promise<void> {
	await mkdir(target, { recursive: true });
	for (const name of await readdir(REPO_THREATS)) {
		if (!name.endsWith(".yaml") || skip.includes(name)) continue;
		await copyFile(join(REPO_THREATS, name), join(target, name));
	}
}

async function writeConfig(body: unknown): Promise<string> {
	const dir = join(home, ".singularity-aidr");
	await mkdir(dir, { recursive: true });
	const path = join(dir, "config.json");
	await writeFile(path, JSON.stringify(body), "utf8");
	return path;
}

function bash(command: string) {
	return {
		sessionId: "robustness",
		toolName: "Bash",
		toolInput: { command },
		artifacts: extractFromBash(command),
	};
}

const LOCAL_ONLY = {
	url_check: { enabled: false },
	package_check: { enabled: false },
	file_check: { enabled: false },
	amsi_check: { enabled: false },
	logging: { enabled: false },
};

beforeEach(async () => {
	home = await makeTmpDir();
	previousHome = process.env.HOME;
	previousUserProfile = process.env.USERPROFILE;
	process.env.HOME = home;
	process.env.USERPROFILE = home;
});

afterEach(async () => {
	clearVerifiedManifest();
	resetDegradedSafeModeForTests();
	vi.unstubAllGlobals();
	if (previousHome === undefined) delete process.env.HOME;
	else process.env.HOME = previousHome;
	if (previousUserProfile === undefined) delete process.env.USERPROFILE;
	else process.env.USERPROFILE = previousUserProfile;
	await removeTmpDir(home);
});

describe("incomplete bundled rule set (finding 1)", () => {
	it("loads the shipped rules with no bundled errors", async () => {
		const loaded = await loadThreatSet([REPO_THREATS]);
		expect(loaded.bundledErrors).toEqual([]);
		expect(loaded.threats.length).toBeGreaterThan(0);
	});

	it("reports a corrupt bundled file instead of silently skipping it", async () => {
		const dir = join(home, "threats");
		await copyBundledThreats(dir);
		await writeFile(join(dir, "commands.yaml"), "- id: [unterminated\n  : : :", "utf8");
		const loaded = await loadThreatSet([dir]);
		expect(loaded.bundledErrors.some((e) => e.includes("commands.yaml"))).toBe(true);
	});

	it("reports an emptied bundled file", async () => {
		const dir = join(home, "threats");
		await copyBundledThreats(dir);
		await writeFile(join(dir, "commands.yaml"), "[]\n", "utf8");
		const loaded = await loadThreatSet([dir]);
		expect(loaded.bundledErrors).toContain("Rule file commands.yaml contains no rules");
	});

	it("reports a bundled file that is missing from the bundle", async () => {
		const dir = join(home, "threats");
		await copyBundledThreats(dir, ["credentials.yaml"]);
		const loaded = await loadThreatSet([dir]);
		expect(BUNDLED_THREAT_FILES).toContain("credentials.yaml");
		expect(loaded.bundledErrors.some((e) => e.includes("credentials.yaml is missing"))).toBe(true);
	});

	it("does not hold a directory of custom rules to the shipped file set", async () => {
		const dir = join(home, "custom-threats");
		await mkdir(dir, { recursive: true });
		await writeFile(
			join(dir, "mine.yaml"),
			[
				"- id: CUSTOM-001",
				"  category: test",
				"  severity: high",
				"  confidence: 0.9",
				"  action: block",
				'  pattern: "custom-marker"',
				"  match_on: command",
				"  title: Custom",
			].join("\n"),
			"utf8",
		);
		const loaded = await loadThreatSet([dir]);
		expect(loaded.bundledErrors).toEqual([]);
		expect(loaded.threats.map((t) => t.id)).toEqual(["CUSTOM-001"]);
	});

	it("holds a benign call for review and names the incomplete rules", async () => {
		const dir = join(home, "threats");
		await copyBundledThreats(dir);
		await writeFile(join(dir, "credentials.yaml"), "not: a list\n", "utf8");
		const configPath = await writeConfig(LOCAL_ONLY);
		const verdict = await evaluateToolCall(bash(BENIGN), {
			configPath,
			threatsDir: dir,
			allowlistsDir: REPO_ALLOWLISTS,
		});
		expect(verdict.decision).toBe("ask");
		expect(verdict.category).toBe("rules_incomplete");
		expect(verdict.reasons.join(" ")).toContain("Rules incomplete");
	});

	it("still denies on the rules that did load", async () => {
		const dir = join(home, "threats");
		await copyBundledThreats(dir, ["credentials.yaml"]);
		const configPath = await writeConfig(LOCAL_ONLY);
		const verdict = await evaluateToolCall(bash(DESTRUCTIVE), {
			configPath,
			threatsDir: dir,
			allowlistsDir: REPO_ALLOWLISTS,
		});
		expect(verdict.decision).toBe("deny");
	});

	it("allows a benign call when the bundled rule set is complete", async () => {
		const configPath = await writeConfig(LOCAL_ONLY);
		const verdict = await evaluateToolCall(bash(BENIGN), {
			configPath,
			threatsDir: REPO_THREATS,
			allowlistsDir: REPO_ALLOWLISTS,
		});
		expect(verdict.decision).toBe("allow");
	});
});

describe("user rules cannot replace bundled rules (finding 2)", () => {
	async function writeUserRule(dir: string, id: string, pattern: string) {
		await mkdir(dir, { recursive: true });
		await writeFile(
			join(dir, "user.yaml"),
			[
				`- id: ${id}`,
				"  category: test",
				"  severity: low",
				"  confidence: 0.1",
				"  action: log",
				`  pattern: "${pattern}"`,
				"  match_on: command",
				"  title: User rule",
			].join("\n"),
			"utf8",
		);
	}

	it("ignores a user rule whose ID clashes with a bundled rule and keeps new IDs", async () => {
		const bundled = await loadThreatSet([REPO_THREATS]);
		const victim = bundled.threats[0];
		if (!victim) throw new Error("no bundled rules");
		const userDir = join(home, "user-threats");
		await writeUserRule(userDir, victim.id, "never-matches-anything-xyz");
		await writeFile(
			join(userDir, "extra.yaml"),
			[
				"- id: USER-NEW-001",
				"  category: test",
				"  severity: high",
				"  confidence: 0.9",
				"  action: block",
				'  pattern: "user-only-marker"',
				"  match_on: command",
				"  title: New user rule",
			].join("\n"),
			"utf8",
		);
		const warnings: string[] = [];
		const logger = {
			debug() {},
			info() {},
			warn: (message: string) => {
				warnings.push(message);
			},
			error() {},
		};
		const merged = await loadThreatSet([REPO_THREATS, userDir], logger);
		const kept = merged.threats.find((t) => t.id === victim.id);
		expect(kept?.pattern).toBe(victim.pattern);
		expect(merged.ignoredOverrides).toEqual([victim.id]);
		expect(merged.threats.some((t) => t.id === "USER-NEW-001")).toBe(true);
		expect(warnings.some((w) => w.includes(victim.id))).toBe(true);
	});

	it("does not report rules as clashing when the user directory is the primary one", async () => {
		const merged = await loadThreatSet([REPO_THREATS, REPO_THREATS]);
		expect(merged.ignoredOverrides).toEqual([]);
		expect(merged.threats.length).toBe((await loadThreatSet([REPO_THREATS])).threats.length);
	});

	it("a clashing user rule cannot disarm the bundled destructive-command rule", async () => {
		const configPath = await writeConfig(LOCAL_ONLY);
		const baseline = await evaluateToolCall(bash(DESTRUCTIVE), {
			configPath,
			threatsDir: REPO_THREATS,
			allowlistsDir: REPO_ALLOWLISTS,
		});
		expect(baseline.decision).toBe("deny");
		const victimId = baseline.matchedThreatId;
		expect(victimId).toBeTruthy();
		const userDir = join(home, "user-threats");
		await writeUserRule(userDir, String(victimId), "never-matches-anything-xyz");
		const verdict = await evaluateToolCall(bash(DESTRUCTIVE), {
			configPath,
			threatsDir: REPO_THREATS,
			allowlistsDir: REPO_ALLOWLISTS,
			userThreatsDir: userDir,
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.matchedThreatId).toBe(victimId);
	});
});

describe("URL leg configuration errors (finding 3)", () => {
	const urlRequest = {
		sessionId: "robustness",
		toolName: "WebFetch",
		toolInput: { url: "https://unknown.example/" },
		artifacts: [{ type: "url" as const, value: "https://unknown.example/" }],
	};

	it.each([
		["an unparsable endpoint", "not a url"],
		["a plain-HTTP endpoint", "http://reputation.example/check"],
		["an endpoint with credentials", "https://user:pass@reputation.example/check"],
	])("treats %s as an unavailable leg, never clean", async (_label, endpoint) => {
		const configPath = await writeConfig({
			...LOCAL_ONLY,
			url_check: { enabled: true, endpoint },
		});
		const verdict = await evaluateToolCall(urlRequest, {
			configPath,
			threatsDir: REPO_THREATS,
			allowlistsDir: REPO_ALLOWLISTS,
		});
		expect(verdict.decision).toBe("ask");
		expect(verdict.category).toBe("url_reputation_unavailable");
	});
});

describe("detection time budget (finding 4)", () => {
	it("clamps configured per-leg timeouts", async () => {
		const configPath = await writeConfig({
			url_check: { timeout_seconds: 120 },
			file_check: { timeout_seconds: 0 },
			package_check: { timeout_seconds: 9 },
		});
		const config = await loadConfig(configPath);
		expect(config.url_check.timeout_seconds).toBe(MAX_DETECTION_LEG_TIMEOUT_SECONDS);
		expect(config.file_check.timeout_seconds).toBe(MAX_DETECTION_LEG_TIMEOUT_SECONDS);
		expect(config.package_check.timeout_seconds).toBe(MAX_DETECTION_LEG_TIMEOUT_SECONDS);
		expect(
			(await loadConfig(await writeConfig({ url_check: { timeout_seconds: 1.5 } }))).url_check
				.timeout_seconds,
		).toBe(1.5);
	});

	it("bounds a directly constructed URL client as well", async () => {
		let seenSignal: AbortSignal | undefined;
		vi.stubGlobal(
			"fetch",
			vi.fn((_url: string, init: RequestInit) => {
				seenSignal = init.signal ?? undefined;
				return new Promise((_resolve, reject) => {
					init.signal?.addEventListener("abort", () => reject(init.signal?.reason));
				});
			}),
		);
		const client = new UrlCheckClient({
			endpoint: "https://reputation.example/check",
			timeout_seconds: 600,
		});
		const started = performance.now();
		await expect(client.checkUrls(["https://slow.example/"])).rejects.toThrow();
		const elapsed = performance.now() - started;
		expect(seenSignal?.aborted).toBe(true);
		expect(elapsed).toBeLessThan(MAX_DETECTION_LEG_TIMEOUT_SECONDS * 1000 + 1500);
	}, 15_000);

	it("reports a URL leg that runs out of time as unavailable", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				(_url: string, init: RequestInit) =>
					new Promise((_resolve, reject) => {
						init.signal?.addEventListener("abort", () => reject(init.signal?.reason));
					}),
			),
		);
		const configPath = await writeConfig({
			...LOCAL_ONLY,
			url_check: {
				enabled: true,
				endpoint: "https://reputation.example/check",
				timeout_seconds: 600,
			},
		});
		const started = performance.now();
		const verdict = await evaluateToolCall(
			{
				sessionId: "robustness",
				toolName: "WebFetch",
				toolInput: { url: "https://slow.example/" },
				artifacts: [{ type: "url", value: "https://slow.example/" }],
			},
			{ configPath, threatsDir: REPO_THREATS, allowlistsDir: REPO_ALLOWLISTS },
		);
		expect(performance.now() - started).toBeLessThan(
			MAX_DETECTION_LEG_TIMEOUT_SECONDS * 1000 + 3000,
		);
		expect(verdict).toMatchObject({ decision: "ask", category: "url_reputation_unavailable" });
	}, 20_000);
});

describe("integrity resource gate (finding 6)", () => {
	async function bundle(): Promise<{ root: string; threats: string; allowlists: string }> {
		const root = join(home, "dist");
		const threats = join(root, "resources", "threats");
		const allowlists = join(root, "resources", "allowlists");
		await copyBundledThreats(threats);
		await mkdir(allowlists, { recursive: true });
		for (const name of await readdir(REPO_ALLOWLISTS)) {
			if (name.endsWith(".yaml"))
				await copyFile(join(REPO_ALLOWLISTS, name), join(allowlists, name));
		}
		return { root, threats, allowlists };
	}

	async function listed(root: string, dirs: string[]): Promise<string[]> {
		const files: string[] = [];
		for (const dir of dirs) {
			for (const name of await readdir(join(root, dir))) {
				if (name.endsWith(".yaml")) files.push(`${dir}/${name}`);
			}
		}
		return files;
	}

	it("refuses an extra trusted-domain file the verified manifest does not list", async () => {
		const { root, allowlists } = await bundle();
		registerVerifiedManifest(root, await listed(root, ["resources/allowlists"]));
		await writeFile(
			join(allowlists, "zz-injected.yaml"),
			'- domain: "attacker.example"\n  reason: "injected"\n',
			"utf8",
		);
		const domains = await loadTrustedDomains(allowlists);
		expect(domains.some((d) => d.domain === "attacker.example")).toBe(false);
		expect(domains.length).toBeGreaterThan(0);
	});

	it("refuses an extra rule file and reports the rule set as incomplete", async () => {
		const { root, threats } = await bundle();
		registerVerifiedManifest(root, await listed(root, ["resources/threats"]));
		await writeFile(
			join(threats, "zz-extra.yaml"),
			await readFile(join(REPO_THREATS, "urls.yaml")),
		);
		const loaded = await loadThreatSet([threats]);
		expect(loaded.bundledErrors.some((e) => e.includes("zz-extra.yaml"))).toBe(true);
	});

	it("loads every listed file with no errors", async () => {
		const { root, threats, allowlists } = await bundle();
		registerVerifiedManifest(
			root,
			await listed(root, ["resources/threats", "resources/allowlists"]),
		);
		expect((await loadThreatSet([threats])).bundledErrors).toEqual([]);
		expect((await loadTrustedDomains(allowlists)).length).toBeGreaterThan(0);
	});

	it("is inert when no manifest was verified", async () => {
		const { allowlists } = await bundle();
		await writeFile(
			join(allowlists, "zz-local.yaml"),
			'- domain: "dev.example"\n  reason: "dev"\n',
		);
		const domains = await loadTrustedDomains(allowlists);
		expect(domains.some((d) => d.domain === "dev.example")).toBe(true);
	});
});

describe("managed gate failure keeps local detection (finding 7)", () => {
	const PUBLIC_KEY_PEM = generateKeyPairSync("ed25519")
		.publicKey.export({ type: "spki", format: "pem" })
		.toString();

	async function brokenEnrolledInstall(): Promise<string> {
		const configPath = await writeConfig({
			...LOCAL_ONLY,
			mode: "managed",
			auth: { api_key: "held-api-credential" },
			control_plane: { enabled: true },
			licensing: {
				require_signed_entitlements: true,
				public_keys_pem: [PUBLIC_KEY_PEM],
				revocations_enabled: false,
			},
		});
		await writeFile(
			join(home, ".singularity-aidr", "managed.json"),
			JSON.stringify({ last_sync_attempt_at: new Date().toISOString() }),
		);
		return configPath;
	}

	it("denies a destructive command with the local verdict and a notice", async () => {
		const configPath = await brokenEnrolledInstall();
		const verdict = await evaluateToolCall(bash(DESTRUCTIVE), {
			configPath,
			threatsDir: REPO_THREATS,
			allowlistsDir: REPO_ALLOWLISTS,
		});
		expect(verdict).toMatchObject({ decision: "deny", source: "heuristic" });
		expect(verdict.reasons.join(" ")).toContain("managed features are unavailable");
	});

	it("returns the local allow for a benign command, labelled as managed-disabled", async () => {
		const configPath = await brokenEnrolledInstall();
		const verdict = await evaluateToolCall(bash(BENIGN), {
			configPath,
			threatsDir: REPO_THREATS,
			allowlistsDir: REPO_ALLOWLISTS,
		});
		expect(verdict).toMatchObject({
			decision: "allow",
			category: "managed_disabled",
			source: "managed_disabled",
		});
		expect(verdict.reasons.join(" ")).toContain("missing or invalid server-signed entitlement");
	});

	it("enforces locally in a commercial build whose managed state cannot be loaded", async () => {
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		try {
			const configPath = await writeConfig({ ...LOCAL_ONLY, mode: "managed" });
			// A credential reference that names no vault entry: the provisioning leg fails.
			await writeFile(
				join(home, ".singularity-aidr", "managed.json"),
				JSON.stringify({
					api_key: "plaintext-copy",
					api_key_ref: {
						store: "windows-dpapi",
						id: "missing-ref",
						created_at: new Date().toISOString(),
					},
				}),
			);
			const destructive = await evaluateToolCall(bash(DESTRUCTIVE), {
				configPath,
				threatsDir: REPO_THREATS,
				allowlistsDir: REPO_ALLOWLISTS,
			});
			expect(destructive).toMatchObject({ decision: "deny", source: "heuristic" });
			const benign = await evaluateToolCall(bash(BENIGN), {
				configPath,
				threatsDir: REPO_THREATS,
				allowlistsDir: REPO_ALLOWLISTS,
			});
			expect(benign.decision).toBe("allow");
			expect(benign.reasons.join(" ")).toContain("managed state could not be loaded");
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("still fails closed for every call when artifact integrity failed", async () => {
		const configPath = await writeConfig(LOCAL_ONLY);
		enterDegradedSafeMode("claude-code/dist:hash_mismatch");
		const verdict = await evaluateToolCall(bash(BENIGN), {
			configPath,
			threatsDir: REPO_THREATS,
			allowlistsDir: REPO_ALLOWLISTS,
		});
		expect(verdict).toMatchObject({ decision: "deny", category: "integrity_unverified" });
	});
});
