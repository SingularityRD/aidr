/**
 * Bundled rules that do not load (a corrupt or emptied rule file) must degrade every SDK result,
 * never leave a clean `allow`: the same allow -> ask downgrade the evaluator applies.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AIDRClient, DEGRADED_METADATA_KEY } from "../client.js";
import type { SDKConfig } from "../config.js";
import { DEGRADED_METADATA_KEY as EXPORTED_KEY } from "../index.js";

const ENV_KEYS = ["AIDR_THREATS_DIR", "AIDR_ALLOWLISTS_DIR"] as const;

const config: SDKConfig = {
	apiKey: "test-key",
	timeout: 5000,
	retries: 0,
	cache: false,
	cacheTtl: 300000,
	environment: "production",
	urlReputationEnabled: false,
	includeUrlQueryParameters: false,
};

const PROBE_RULE = [
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
].join("\n");

describe("SDK client with incomplete bundled rules", () => {
	let tmpDir: string;
	const savedEnv: Record<string, string | undefined> = {};

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "aidr-sdk-rules-"));
		for (const key of ENV_KEYS) savedEnv[key] = process.env[key];
		const threatsDir = join(tmpDir, "threats");
		const allowlistsDir = join(tmpDir, "allowlists");
		mkdirSync(threatsDir, { recursive: true });
		mkdirSync(allowlistsDir, { recursive: true });
		writeFileSync(join(threatsDir, "probe.yaml"), PROBE_RULE);
		writeFileSync(
			join(allowlistsDir, "probe.yaml"),
			['- domain: "example.invalid"', '  reason: "test fixture"', ""].join("\n"),
		);
		process.env.AIDR_THREATS_DIR = threatsDir;
		process.env.AIDR_ALLOWLISTS_DIR = allowlistsDir;
	});

	afterEach(() => {
		for (const key of ENV_KEYS) {
			if (savedEnv[key] === undefined) delete process.env[key];
			else process.env[key] = savedEnv[key];
		}
		rmSync(tmpDir, { recursive: true, force: true });
	});

	const breakRules = () =>
		writeFileSync(join(tmpDir, "threats", "broken.yaml"), "- id: [unterminated\n  : : :\n");

	it("exports the degraded metadata key", () => {
		expect(EXPORTED_KEY).toBe(DEGRADED_METADATA_KEY);
	});

	it("keeps a complete rule set clean", async () => {
		const client = new AIDRClient(config);
		await client.init();
		expect(client.isDegraded()).toBe(false);
		const result = await client.check({ action: "execute", resource: "ls -la /tmp" });
		expect(result.decision).toBe("allow");
		expect(result.metadata?.[DEGRADED_METADATA_KEY]).toBeUndefined();
		client.dispose();
	});

	it("never returns a clean allow when a rule file failed to load", async () => {
		breakRules();
		const client = new AIDRClient(config);
		await client.init();
		expect(client.isDegraded()).toBe(true);
		expect(client.getRuleLoadErrors().map((error) => error.file)).toContain("broken.yaml");

		const result = await client.check({ action: "execute", resource: "ls -la /tmp" });
		expect(result.allowed).toBe(false);
		expect(result.decision).toBe("ask");
		expect(result.metadata).toMatchObject({
			[DEGRADED_METADATA_KEY]: true,
			rulesIncomplete: ["broken.yaml"],
		});
		expect(result.reason).toContain("rules incomplete — protection degraded");
		expect(result.reason).toContain("not a clean result");
		client.dispose();
	});

	it("keeps a deny from the rules that did load, flagged as degraded", async () => {
		breakRules();
		const client = new AIDRClient(config);
		await client.init();
		const result = await client.check({ action: "execute", resource: "echo AIDR_TEST_PROBE" });
		expect(result.decision).toBe("deny");
		expect(result.allowed).toBe(false);
		expect(result.metadata?.[DEGRADED_METADATA_KEY]).toBe(true);
		expect(result.reason).toContain("rules incomplete — protection degraded");
		client.dispose();
	});
});
