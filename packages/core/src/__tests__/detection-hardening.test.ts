/**
 * Detection-core hardening: rule-load integrity, additive user rules, URL leg
 * misconfiguration, leg time budget, authenticated verdict cache, closed
 * resource sets, commercial un-enrolled local enforcement, and the advisory
 * escalation / rule labelling in the decision engine.
 */

import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CACHE_KEY_FILE, VerdictCache } from "../cache.js";
import { DecisionEngine } from "../engine.js";
import { evaluateToolCall } from "../evaluator.js";
import { extractFromBash } from "../extractors.js";
import { formatAskMessage, formatDenyMessage } from "../guard.js";
import { verifyArtifactIntegrityAndLog } from "../integrity/runtime.js";
import { verifyArtifactIntegrity } from "../integrity/verify.js";
import { loadThreatsFromDirsWithReport, loadThreatsWithReport } from "../threat-loader.js";
import { loadTrustedDomains } from "../trusted-domains.js";
import type { CacheConfig, HeuristicMatch, Threat } from "../types.js";
import { ConfigSchema, LEG_TOTAL_BUDGET_SECONDS, MAX_LEG_TIMEOUT_SECONDS } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const BLOCK_RULES = `- id: "TST-BLOCK-001"
  category: tool
  severity: critical
  confidence: 0.99
  action: block
  pattern: "destroy-everything"
  match_on: command
  title: "Test destructive command"
`;

const ASK_RULES = `- id: "TST-ASK-001"
  category: credential_access
  severity: high
  confidence: 0.95
  action: require_approval
  pattern: "read-secret-store"
  match_on: command
  title: "Test credential access"
`;

let dirs: string[] = [];
async function tmp(): Promise<string> {
	const dir = await makeTmpDir();
	dirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const dir of dirs) await removeTmpDir(dir);
	dirs = [];
});

function sha256(content: string | Buffer): string {
	return createHash("sha256").update(content).digest("hex");
}

async function writeRules(dir: string, files: Record<string, string>): Promise<void> {
	await mkdir(dir, { recursive: true });
	for (const [name, content] of Object.entries(files)) await writeFile(join(dir, name), content);
}

/** A minimal local-mode config with every remote leg off. */
async function writeLocalConfig(dir: string, extra: Record<string, unknown> = {}): Promise<string> {
	const configPath = join(dir, "config.json");
	await writeFile(
		configPath,
		JSON.stringify({
			url_check: { enabled: false },
			package_check: { enabled: false },
			file_check: { enabled: false },
			amsi_check: { enabled: false },
			logging: { enabled: false },
			cache: { enabled: false },
			...extra,
		}),
	);
	return configPath;
}

function bash(command: string) {
	return {
		sessionId: "hardening",
		toolName: "Bash",
		toolInput: { command },
		artifacts: extractFromBash(command),
	};
}

describe("bundled rule load failures degrade instead of disappearing", () => {
	it.each([
		["empty", ""],
		["unparseable", "- id: [unterminated\n  : : :"],
		["not a list", "id: TST\n"],
		["empty list", "[]\n"],
	])("reports a %s bundled rule file as a load error", async (_label, content) => {
		const threats = await tmp();
		await writeRules(threats, { "a-block.yaml": BLOCK_RULES, "b-broken.yaml": content });
		const report = await loadThreatsWithReport(threats);
		expect(report.threats.map((t) => t.id)).toEqual(["TST-BLOCK-001"]);
		expect(report.errors.map((e) => e.file)).toEqual(["b-broken.yaml"]);
	});

	it("asks instead of allowing when a bundled rule file failed to load", async () => {
		const root = await tmp();
		const threats = join(root, "threats");
		// The file that would have blocked `destroy-everything` is corrupt.
		await writeRules(threats, { "ask.yaml": ASK_RULES, "commands.yaml": "{{{ not yaml" });
		const configPath = await writeLocalConfig(root);

		const verdict = await evaluateToolCall(bash("destroy-everything"), {
			configPath,
			threatsDir: threats,
			allowlistsDir: join(root, "allowlists"),
			userThreatsDir: join(root, "no-user-rules"),
		});
		expect(verdict.decision).toBe("ask");
		expect(verdict.category).toBe("detection_degraded");
		expect(verdict.reasons.join(" ")).toContain("commands.yaml");
		expect(verdict.reasons.join(" ")).toContain("NOT fully inspected");
	});

	it("keeps a deny a deny and surfaces the degradation", async () => {
		const root = await tmp();
		const threats = join(root, "threats");
		await writeRules(threats, { "block.yaml": BLOCK_RULES, "broken.yaml": "" });
		const configPath = await writeLocalConfig(root);

		const verdict = await evaluateToolCall(bash("destroy-everything"), {
			configPath,
			threatsDir: threats,
			allowlistsDir: join(root, "allowlists"),
			userThreatsDir: join(root, "no-user-rules"),
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.matchedThreatId).toBe("TST-BLOCK-001");
		expect(verdict.reasons.join(" ")).toContain("broken.yaml");
	});

	it("loads the shipped rule set without a single error", async () => {
		const shipped = join(__dirname, "..", "..", "..", "..", "threats");
		const report = await loadThreatsFromDirsWithReport([shipped]);
		expect(report.bundledErrors).toEqual([]);
		expect(report.ignoredOverrides).toEqual([]);
		expect(report.bundledCount).toBeGreaterThan(100);
	});
});

describe("the no-rules safeguard is based on bundled rules", () => {
	it("does not let user rules mask an empty bundled rule set", async () => {
		const root = await tmp();
		const bundled = join(root, "bundled");
		const user = join(root, "user");
		await mkdir(bundled, { recursive: true });
		await writeRules(user, { "mine.yaml": ASK_RULES });
		const configPath = await writeLocalConfig(root);

		const verdict = await evaluateToolCall(bash("ls -la"), {
			configPath,
			threatsDir: bundled,
			allowlistsDir: join(root, "allowlists"),
			userThreatsDir: user,
		});
		expect(verdict.decision).toBe("ask");
		expect(verdict.category).toBe("detection_unavailable");
	});
});

describe("user rules are additive only", () => {
	it("keeps the bundled rule when a user rule reuses its id", async () => {
		const root = await tmp();
		const bundled = join(root, "bundled");
		const user = join(root, "user");
		await writeRules(bundled, { "block.yaml": BLOCK_RULES });
		// Same id, never-matching pattern: an attempt to switch the rule off.
		await writeRules(user, {
			"override.yaml": BLOCK_RULES.replace('"destroy-everything"', '"(?!)never"').replace(
				"action: block",
				"action: log",
			),
			"extra.yaml": ASK_RULES,
		});

		const report = await loadThreatsFromDirsWithReport([bundled, user]);
		const rule = report.threats.find((t) => t.id === "TST-BLOCK-001");
		expect(rule?.action).toBe("block");
		expect(rule?.pattern).toBe("destroy-everything");
		expect(report.ignoredOverrides).toEqual(["TST-BLOCK-001"]);
		expect(report.threats.map((t) => t.id).sort()).toEqual(["TST-ASK-001", "TST-BLOCK-001"]);

		const configPath = await writeLocalConfig(root);
		const verdict = await evaluateToolCall(bash("destroy-everything"), {
			configPath,
			threatsDir: bundled,
			allowlistsDir: join(root, "allowlists"),
			userThreatsDir: user,
		});
		expect(verdict.decision).toBe("deny");
	});
});

describe("URL reputation leg misconfiguration is never clean", () => {
	it.each([
		["plain HTTP endpoint", "http://reputation.example.test/url-check"],
		["credentials in the endpoint", "https://user:pass@reputation.example.test/url-check"],
		["unparseable endpoint", "not a url"],
	])("reports the leg unavailable for a %s", async (_label, endpoint) => {
		const root = await tmp();
		const threats = join(root, "threats");
		await writeRules(threats, { "block.yaml": BLOCK_RULES });
		const configPath = await writeLocalConfig(root, { url_check: { enabled: true, endpoint } });

		const verdict = await evaluateToolCall(bash("curl https://unknown-host.example.test/x"), {
			configPath,
			threatsDir: threats,
			allowlistsDir: join(root, "allowlists"),
			userThreatsDir: join(root, "none"),
		});
		expect(verdict.decision).toBe("ask");
		expect(verdict.category).toBe("url_reputation_unavailable");
		expect(verdict.reasons.join(" ")).toContain("NOT verified clean");
	});
});

describe("remote leg timeouts are bounded by the hook budget", () => {
	it("caps every leg timeout and keeps the total under the Codex 10s hook", () => {
		const config = ConfigSchema.parse({
			url_check: { timeout_seconds: 30 },
			file_check: { timeout_seconds: 1e9 },
			package_check: { timeout_seconds: -1 },
			control_plane: { timeout_seconds: 60 },
		});
		expect(config.url_check.timeout_seconds).toBe(MAX_LEG_TIMEOUT_SECONDS);
		expect(config.file_check.timeout_seconds).toBe(MAX_LEG_TIMEOUT_SECONDS);
		expect(config.package_check.timeout_seconds).toBeGreaterThan(0);
		expect(config.package_check.timeout_seconds).toBeLessThanOrEqual(MAX_LEG_TIMEOUT_SECONDS);
		expect(config.control_plane.timeout_seconds).toBe(MAX_LEG_TIMEOUT_SECONDS);
		expect(LEG_TOTAL_BUDGET_SECONDS).toBeLessThan(10);
		expect(MAX_LEG_TIMEOUT_SECONDS).toBeLessThanOrEqual(LEG_TOTAL_BUDGET_SECONDS);
	});

	it("keeps small configured timeouts as they are", () => {
		const config = ConfigSchema.parse({ url_check: { timeout_seconds: 0.25 } });
		expect(config.url_check.timeout_seconds).toBe(0.25);
	});
});

describe("verdict cache authentication", () => {
	function cacheConfig(path: string): CacheConfig {
		return {
			enabled: true,
			ttl_malicious_seconds: 3600,
			ttl_clean_seconds: 86400,
			path,
			encryption: { enabled: false },
		};
	}
	const future = () => new Date(Date.now() + 3_600_000).toISOString();

	it("ignores a forged entry and accepts the entries it wrote itself", async () => {
		const dir = await tmp();
		const path = join(dir, "cache.json");
		const writer = new VerdictCache(cacheConfig(path), undefined, "dev");
		await writer.load();
		writer.putPackage(
			"npm:real",
			{ verdict: "deny", severity: "critical", reasons: ["r"], source: "s" },
			30,
		);
		await writer.save();

		const persisted = JSON.parse(await readFile(path, "utf8"));
		expect(persisted.packages["npm:real"].mac).toMatch(/^[0-9a-f]{64}$/);
		persisted.packages["npm:forged"] = {
			verdict: "allow",
			severity: "info",
			reasons: [],
			source: "forged",
			checkedAt: new Date().toISOString(),
			expiresAt: future(),
			aidrVersion: "dev",
		};
		// A valid MAC copied onto another key must not verify either.
		persisted.packages["npm:moved"] = { ...persisted.packages["npm:real"], verdict: "allow" };
		await writeFile(path, JSON.stringify(persisted));

		const reader = new VerdictCache(cacheConfig(path), undefined, "dev");
		await reader.load();
		expect(reader.getPackage("npm:real")?.verdict).toBe("deny");
		expect(reader.getPackage("npm:forged")).toBeNull();
		expect(reader.getPackage("npm:moved")).toBeNull();
	});

	it("stores the key owner-only on POSIX", async () => {
		const dir = await tmp();
		const cache = new VerdictCache(cacheConfig(join(dir, "cache.json")), undefined, "dev");
		await cache.load();
		const info = await stat(join(dir, CACHE_KEY_FILE));
		expect(info.size).toBe(32);
		if (process.platform !== "win32") expect(info.mode & 0o077).toBe(0);
	});

	it("never lets a cached allow downgrade a rule-match deny", async () => {
		const root = await tmp();
		const threats = join(root, "threats");
		await writeRules(threats, {
			"block.yaml": `- id: "TST-URL-001"
  category: network_egress
  severity: critical
  confidence: 0.99
  action: block
  pattern: "evil\\\\.example\\\\.test"
  match_on: url
  title: "Test malicious host"
`,
		});
		const aidr = join(root, ".singularity-aidr");
		await mkdir(aidr, { recursive: true });
		const previousHome = process.env.HOME;
		const previousProfile = process.env.USERPROFILE;
		process.env.HOME = root;
		process.env.USERPROFILE = root;
		try {
			// A legitimately authenticated allow for the URL (the worst case).
			const cache = new VerdictCache(cacheConfig(join(aidr, "cache.json")), undefined, "dev");
			await cache.load();
			cache.putUrl(
				"https://evil.example.test/payload",
				{ verdict: "allow", severity: "info", reasons: [], source: "url_check" },
				false,
				Date.now() + 3_600_000,
			);
			await cache.save();
			const configPath = join(aidr, "config.json");
			await writeFile(
				configPath,
				JSON.stringify({
					url_check: { enabled: false },
					package_check: { enabled: false },
					amsi_check: { enabled: false },
					logging: { enabled: false },
				}),
			);
			const verdict = await evaluateToolCall(bash("curl https://evil.example.test/payload"), {
				configPath,
				threatsDir: threats,
				allowlistsDir: join(root, "allowlists"),
				userThreatsDir: join(root, "none"),
			});
			expect(verdict.decision).toBe("deny");
			expect(verdict.matchedThreatId).toBe("TST-URL-001");
		} finally {
			if (previousHome === undefined) delete process.env.HOME;
			else process.env.HOME = previousHome;
			if (previousProfile === undefined) delete process.env.USERPROFILE;
			else process.env.USERPROFILE = previousProfile;
		}
	});
});

describe("resource directories are closed sets", () => {
	async function writeManifest(
		root: string,
		files: Record<string, string>,
		artifactId = "core/dist",
	): Promise<string> {
		const raw = JSON.stringify({
			schema_version: 1,
			artifact_id: artifactId,
			artifact_version: "0.0.0",
			created_at: new Date().toISOString(),
			files: Object.entries(files).map(([path, content]) => ({ path, sha256: sha256(content) })),
		});
		await writeFile(join(root, "aidr-artifact.manifest.json"), raw);
		return raw;
	}

	it("fails integrity verification for an unlisted file in a resource directory", async () => {
		const root = await tmp();
		await writeRules(join(root, "resources", "threats"), { "block.yaml": BLOCK_RULES });
		await writeRules(join(root, "resources", "allowlists"), { "domains.yaml": "[]\n" });
		await writeManifest(root, {
			"resources/threats/block.yaml": BLOCK_RULES,
			"resources/allowlists/domains.yaml": "[]\n",
		});
		const params = { artifactDir: root, publicKeysPem: [], verifySignatures: false };
		expect((await verifyArtifactIntegrity(params)).status).toBe("ok");

		await writeFile(
			join(root, "resources", "allowlists", "extra.yaml"),
			'- domain: "evil.example.test"\n  reason: "planted"\n',
		);
		const result = await verifyArtifactIntegrity(params);
		expect(result.status).toBe("unlisted_file");
		expect(result.mismatches?.map((m) => m.path)).toEqual(["resources/allowlists/extra.yaml"]);
	});

	it("ignores unlisted or modified rule files at load time and reports them", async () => {
		const root = await tmp();
		const threats = join(root, "resources", "threats");
		await writeRules(threats, { "block.yaml": BLOCK_RULES, "ask.yaml": ASK_RULES });
		await writeManifest(root, {
			"resources/threats/block.yaml": BLOCK_RULES,
			"resources/threats/ask.yaml": ASK_RULES,
		});
		const clean = await loadThreatsWithReport(threats, undefined, { manifest: {} });
		expect(clean.errors).toEqual([]);

		await writeFile(join(threats, "planted.yaml"), ASK_RULES.replace("TST-ASK-001", "TST-PLANTED"));
		await writeFile(
			join(threats, "block.yaml"),
			BLOCK_RULES.replace("action: block", "action: log"),
		);
		const tampered = await loadThreatsWithReport(threats, undefined, { manifest: {} });
		expect(tampered.threats.map((t) => t.id)).toEqual(["TST-ASK-001"]);
		expect(tampered.errors.map((e) => [e.file, e.kind]).sort()).toEqual([
			["block.yaml", "integrity"],
			["planted.yaml", "unlisted"],
		]);
	});

	it("requires a valid manifest signature when keys are configured", async () => {
		const root = await tmp();
		const threats = join(root, "resources", "threats");
		await writeRules(threats, { "block.yaml": BLOCK_RULES });
		const raw = await writeManifest(root, { "resources/threats/block.yaml": BLOCK_RULES });
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const publicKeysPem = [publicKey.export({ type: "spki", format: "pem" }).toString()];

		const unsigned = await loadThreatsWithReport(threats, undefined, {
			manifest: { publicKeysPem },
		});
		expect(unsigned.threats).toEqual([]);
		expect(unsigned.errors[0]?.kind).toBe("integrity");

		await writeFile(
			join(root, "aidr-artifact.manifest.sig"),
			sign(null, Buffer.from(raw, "utf8"), privateKey).toString("base64"),
		);
		const signed = await loadThreatsWithReport(threats, undefined, { manifest: { publicKeysPem } });
		expect(signed.errors).toEqual([]);
		expect(signed.threats.map((t) => t.id)).toEqual(["TST-BLOCK-001"]);
	});

	it("does not trust an unlisted allowlist file", async () => {
		const root = await tmp();
		const allowlists = join(root, "resources", "allowlists");
		const shipped = '- domain: "good.example.test"\n  reason: "shipped"\n';
		await writeRules(allowlists, { "domains.yaml": shipped });
		await writeManifest(root, { "resources/allowlists/domains.yaml": shipped });
		await writeFile(
			join(allowlists, "planted.yaml"),
			'- domain: "evil.example.test"\n  reason: "planted"\n',
		);
		const domains = await loadTrustedDomains(allowlists);
		expect(domains.map((d) => d.domain)).toEqual(["good.example.test"]);
	});
});

describe("commercial build, un-enrolled", () => {
	let previousCommercial: string | undefined;
	let previousHome: string | undefined;
	let previousProfile: string | undefined;
	let home: string;
	const SHIPPED_THREATS = join(__dirname, "..", "..", "..", "..", "threats");
	const SHIPPED_ALLOWLISTS = join(__dirname, "..", "..", "..", "..", "allowlists");

	beforeEach(async () => {
		previousCommercial = process.env.AIDR_COMMERCIAL;
		previousHome = process.env.HOME;
		previousProfile = process.env.USERPROFILE;
		home = await tmp();
		process.env.AIDR_COMMERCIAL = "1";
		process.env.HOME = home;
		process.env.USERPROFILE = home;
	});

	afterEach(() => {
		if (previousCommercial === undefined) delete process.env.AIDR_COMMERCIAL;
		else process.env.AIDR_COMMERCIAL = previousCommercial;
		if (previousHome === undefined) delete process.env.HOME;
		else process.env.HOME = previousHome;
		if (previousProfile === undefined) delete process.env.USERPROFILE;
		else process.env.USERPROFILE = previousProfile;
	});

	it("enforces locally: benign calls pass, destructive calls are denied", async () => {
		const context = {
			configPath: join(home, ".singularity-aidr", "config.json"),
			threatsDir: SHIPPED_THREATS,
			allowlistsDir: SHIPPED_ALLOWLISTS,
		};
		const benign = await evaluateToolCall(bash("ls -la"), context);
		expect(benign.decision).not.toBe("deny");
		expect(benign.category).not.toBe("managed_disabled");

		const destructive = await evaluateToolCall(bash("rm -rf /"), context);
		expect(destructive.decision).toBe("deny");
		expect(destructive.source).toBe("heuristic");
	});

	it("fails closed on an unsigned artifact, starts a signed one without integrity keys on verified digests, and fails closed on tampering", async () => {
		const artifact = join(home, "dist");
		await writeRules(join(artifact, "resources", "threats"), { "block.yaml": BLOCK_RULES });
		await writeFile(join(artifact, "hook.cjs"), "module.exports = 1;\n");
		await writeFile(
			join(artifact, "aidr-artifact.manifest.json"),
			JSON.stringify({
				schema_version: 1,
				artifact_id: "codex/dist",
				artifact_version: "0.0.0",
				created_at: new Date().toISOString(),
				files: [
					{ path: "hook.cjs", sha256: sha256("module.exports = 1;\n") },
					{ path: "resources/threats/block.yaml", sha256: sha256(BLOCK_RULES) },
				],
			}),
		);
		const configPath = join(home, "no-config.json");

		// An artifact that was never signed (a development or unsigned release
		// build) has no release provenance: it fails closed and is recorded.
		await expect(
			verifyArtifactIntegrityAndLog({
				artifactDir: artifact,
				artifactId: "codex/dist",
				configPath,
			}),
		).rejects.toThrow("codex/dist: no_public_keys");
		const audit = await readFile(join(home, ".singularity-aidr", "audit.jsonl"), "utf8");
		expect(audit).toContain('"matched_threat_id":"INTEGRITY-001"');
		expect(audit).toContain("artifact_unsigned");

		// A signed release on an install with no trust keys starts on verified digests.
		const { privateKey } = generateKeyPairSync("ed25519");
		const manifestRaw = await readFile(join(artifact, "aidr-artifact.manifest.json"), "utf8");
		await writeFile(
			join(artifact, "aidr-artifact.manifest.sig"),
			sign(null, Buffer.from(manifestRaw, "utf8"), privateKey).toString("base64"),
		);
		const result = await verifyArtifactIntegrityAndLog({
			artifactDir: artifact,
			artifactId: "codex/dist",
			configPath,
		});
		expect(result.status).toBe("no_public_keys");
		expect(result.reason).toBe("signature_unverified_digests_ok");

		await writeFile(join(artifact, "resources", "threats", "planted.yaml"), ASK_RULES);
		await expect(
			verifyArtifactIntegrityAndLog({
				artifactDir: artifact,
				artifactId: "codex/dist",
				configPath,
			}),
		).rejects.toThrow("unlisted_file");
	});
});

describe("decision engine escalation and rule labelling", () => {
	function match(overrides: Partial<Threat>): HeuristicMatch {
		return {
			threat: {
				id: "TST-1",
				category: "tool",
				severity: "high",
				confidence: 0.9,
				action: "block",
				pattern: "x",
				compiledPattern: /x/,
				matchOn: new Set(["command"]),
				title: "Test rule",
				expiresAt: null,
				revoked: false,
				...overrides,
			},
			artifact: "x",
		} as HeuristicMatch;
	}

	it("does not hold an advisory sub-threshold finding for review", async () => {
		const verdict = await new DecisionEngine("relaxed").decide({
			heuristicMatches: [
				match({ action: "log", category: "secure_code_sql_injection", confidence: 0.85 }),
			],
			urlCheckResults: [],
		});
		expect(verdict.decision).toBe("allow");
	});

	it("still escalates a sub-threshold finding in a security-relevant category", async () => {
		for (const category of ["credential_access", "some_future_category"]) {
			const verdict = await new DecisionEngine("balanced").decide({
				heuristicMatches: [match({ action: "log", category, confidence: 0.6 })],
				urlCheckResults: [],
			});
			expect(verdict.decision).toBe("ask");
		}
	});

	it("reports the most severe rule with its own severity label", async () => {
		const verdict = await new DecisionEngine().decide({
			heuristicMatches: [
				match({ id: "TST-MED", severity: "medium", confidence: 0.99 }),
				match({ id: "TST-HIGH", severity: "high", confidence: 0.95 }),
			],
			urlCheckResults: [],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.matchedThreatId).toBe("TST-HIGH");
		expect(verdict.ruleSeverity).toBe("high");
		expect(verdict.severity).toBe("warning");

		const deny = formatDenyMessage(verdict);
		expect(deny).toContain("Severity: high");
		expect(deny).toContain("Rule: TST-HIGH");
		const ask = formatAskMessage("act-1", { ...verdict, decision: "ask" }, []);
		expect(ask).toContain("Severity: high");
		expect(ask).toContain("Rule: TST-HIGH");
	});
});
