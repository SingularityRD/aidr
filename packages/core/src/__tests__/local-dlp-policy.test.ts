import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadProvisionedDetectorContext } from "../detector-provisioning.js";
import { evaluateToolCall } from "../evaluator.js";
import { getExtendedHealthStatus } from "../health.js";
import {
	inspectLocalDlpPolicy,
	LOCAL_DLP_POLICY_ENV,
	localDlpPolicyPath,
} from "../local-dlp-policy.js";
import type { Logger } from "../types.js";

const MARKER = "LOCAL-PROJECT-CODENAME-7";

let home: string;
let aidrDir: string;

function localPolicy(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		version: 1,
		tenantId: "local",
		supportedFormats: ["application/json"],
		labels: [{ id: "internal", tenantId: "local", name: "Internal", sensitivity: "restricted" }],
		rules: [
			{
				id: "codename",
				tenantId: "local",
				labelId: "internal",
				name: "Project codename",
				action: "block",
				directions: ["input"],
				matchers: [{ type: "keyword", values: [MARKER], wholeWord: false }],
			},
		],
		...overrides,
	};
}

function recordingLogger(): Logger & { warnings: Array<{ message: string; data?: unknown }> } {
	const warnings: Array<{ message: string; data?: unknown }> = [];
	return {
		warnings,
		debug() {},
		info() {},
		warn(message, data) {
			warnings.push({ message, data });
		},
		error() {},
	};
}

async function writeConfig(mode: "local" | "managed") {
	await writeFile(
		join(aidrDir, "config.json"),
		JSON.stringify({
			mode,
			control_plane: { enabled: false },
			heuristics_enabled: false,
			url_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
		}),
	);
}

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-local-dlp-"));
	aidrDir = join(home, ".singularity-aidr");
	await mkdir(aidrDir, { recursive: true });
	vi.stubEnv("HOME", home);
	vi.stubEnv(LOCAL_DLP_POLICY_ENV, "");
	// The extended health run also probes the URL endpoint; keep it offline.
	vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ status: 204 }));
	await writeConfig("local");
});

afterEach(async () => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	await rm(home, { recursive: true, force: true });
});

describe("local-mode DLP policy file", () => {
	it("defaults to ~/.singularity-aidr/dlp-policy.json and honours the override", () => {
		expect(localDlpPolicyPath()).toBe(join(aidrDir, "dlp-policy.json"));
		vi.stubEnv(LOCAL_DLP_POLICY_ENV, join(home, "custom", "policy.json"));
		expect(localDlpPolicyPath()).toBe(join(home, "custom", "policy.json"));
	});

	it("is off when the file is missing", async () => {
		await expect(inspectLocalDlpPolicy()).resolves.toMatchObject({ status: "absent" });
		const logger = recordingLogger();
		await expect(loadProvisionedDetectorContext("claude-code", { logger })).resolves.toEqual({});
		expect(logger.warnings).toEqual([]);
	});

	it("enforces a valid local policy through the evaluator", async () => {
		await writeFile(join(aidrDir, "dlp-policy.json"), JSON.stringify(localPolicy()));
		const context = await loadProvisionedDetectorContext("claude-code");
		expect(context.runtimeDetectors).toMatchObject({ tenantId: "local", dlp: { enabled: true } });

		const verdict = await evaluateToolCall(
			{
				sessionId: "s1",
				toolName: "CustomTool",
				toolInput: { body: `ship ${MARKER} today` },
				artifacts: [],
			},
			{
				threatsDir: join(home, "empty-threats"),
				allowlistsDir: join(home, "empty-allowlists"),
				...context,
			},
		);
		expect(verdict).toMatchObject({ decision: "deny", source: "dlp", matchedThreatId: "codename" });
		expect(JSON.stringify(verdict)).not.toContain(MARKER);
	});

	it("reads the policy from AIDR_DLP_POLICY_PATH", async () => {
		const custom = join(home, "custom-policy.json");
		await writeFile(custom, JSON.stringify(localPolicy()));
		vi.stubEnv(LOCAL_DLP_POLICY_ENV, custom);
		const context = await loadProvisionedDetectorContext("opencode");
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.id).toBe("codename");
	});

	it("skips an invalid JSON file, logs once, and reports degraded health", async () => {
		await writeFile(join(aidrDir, "dlp-policy.json"), `{"rules": [${MARKER}`);
		const logger = recordingLogger();
		await expect(loadProvisionedDetectorContext("codex", { logger })).resolves.toEqual({});
		await expect(loadProvisionedDetectorContext("codex", { logger })).resolves.toEqual({});
		expect(logger.warnings).toHaveLength(1);
		expect(logger.warnings[0]?.message).toContain("NOT enforced");
		expect(JSON.stringify(logger.warnings)).not.toContain(MARKER);

		const health = await getExtendedHealthStatus();
		const check = health.checks.find((entry) => entry.name === "local_dlp_policy");
		expect(check).toMatchObject({
			status: "degraded",
			details: { configured: true, enforced: false },
		});
		expect(check?.message).toContain("not valid JSON");
		expect(health.status).not.toBe("healthy");
	});

	it("skips a schema-invalid policy without echoing its values", async () => {
		const invalid = localPolicy({
			rules: [
				{
					id: "codename",
					tenantId: "local",
					labelId: "internal",
					name: "Project codename",
					action: MARKER,
					matchers: [{ type: "keyword", values: [MARKER] }],
				},
			],
		});
		await writeFile(join(aidrDir, "dlp-policy.json"), JSON.stringify(invalid));
		const state = await inspectLocalDlpPolicy();
		expect(state.status).toBe("invalid");
		expect(state.status === "invalid" ? state.reason : "").toContain("rules.0.action");
		expect(JSON.stringify(state)).not.toContain(MARKER);

		const logger = recordingLogger();
		await expect(loadProvisionedDetectorContext("cursor", { logger })).resolves.toEqual({});
		expect(logger.warnings).toHaveLength(1);
		expect(JSON.stringify(logger.warnings)).not.toContain(MARKER);
	});

	it("reports a loaded local policy as healthy and enforced", async () => {
		await writeFile(join(aidrDir, "dlp-policy.json"), JSON.stringify(localPolicy()));
		const health = await getExtendedHealthStatus();
		expect(health.checks.find((entry) => entry.name === "local_dlp_policy")).toMatchObject({
			status: "healthy",
			details: { enforced: true, rules: 1 },
		});
	});

	it("ignores the unsigned file in managed mode", async () => {
		await writeConfig("managed");
		await writeFile(join(aidrDir, "dlp-policy.json"), JSON.stringify(localPolicy()));
		const logger = recordingLogger();
		await expect(loadProvisionedDetectorContext("claude-code", { logger })).resolves.toEqual({});
		const health = await getExtendedHealthStatus();
		expect(health.checks.find((entry) => entry.name === "local_dlp_policy")).toMatchObject({
			status: "healthy",
			details: { mode: "managed", applies: false },
		});
	});
});
