import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UrlCheckClient } from "../clients/url-check.js";
import { evaluateToolCall, type ToolEvaluationContext } from "../evaluator.js";
import { extractFromBash, extractFromWebFetch } from "../extractors.js";
import { runSessionStart } from "../session-start.js";
import { ConfigSchema } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

let root: string;
let configPath: string;
const threatsDir = resolve(__dirname, "../../../../threats");
const allowlistsDir = resolve(__dirname, "../../../../allowlists");

async function configure(required: boolean, extra: Record<string, unknown> = {}) {
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			privacy: { required },
			control_plane: { enabled: false },
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: true },
			...extra,
		}),
	);
}

function context(): ToolEvaluationContext {
	return { threatsDir, allowlistsDir, configPath, agentRuntime: "claude-code" };
}

function bash(command: string) {
	return {
		sessionId: "privacy-test-session",
		toolName: "Bash",
		toolInput: { command },
		artifacts: extractFromBash(command),
	};
}

beforeEach(async () => {
	root = await makeTmpDir();
	vi.stubEnv("HOME", root);
	await mkdir(join(root, ".singularity-aidr"), { recursive: true });
	configPath = join(root, "config.json");
	await configure(true);
});

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
	vi.unstubAllEnvs();
});

describe("explicit mandatory privacy profile", () => {
	it("remains opt-in and rejects ambiguous privacy settings", () => {
		expect(ConfigSchema.parse({}).privacy).toBeUndefined();
		expect(ConfigSchema.parse({ privacy: {} }).privacy).toEqual({ required: false });
		expect(ConfigSchema.safeParse({ privacy: { required: "true" } }).success).toBe(false);
		expect(ConfigSchema.safeParse({ privacy: { required: true, trust: "caller" } }).success).toBe(
			false,
		);
	});

	it("refuses benign ordinary tools while preserving the default local benign twin", async () => {
		const blocked = await evaluateToolCall(bash("echo hello"), context());
		expect(blocked.decision).toBe("deny");
		expect(blocked.category).toBe("privacy_required_unsupported");
		await configure(false);
		const allowed = await evaluateToolCall(bash("echo hello"), context());
		expect(allowed.decision).toBe("allow");
	});

	it("retains actual local threat classification without releasing raw artifacts", async () => {
		const blocked = await evaluateToolCall(bash("rm -rf /"), context());
		expect(blocked.decision).toBe("deny");
		expect(blocked.matchedThreatId).toBe("CLT-CMD-006");
		expect(blocked.source).toBe("heuristic");
		expect(blocked.artifacts).toEqual([]);
		expect(blocked.reasons.some((reason) => reason.includes("Mandatory privacy"))).toBe(true);
	});

	it("refuses direct provider input before reputation, enrollment or telemetry and omits audit content", async () => {
		const fetch = vi.fn(() => Promise.reject(new Error("unexpected outbound request")));
		vi.stubGlobal("fetch", fetch);
		const reputation = vi.spyOn(UrlCheckClient.prototype, "checkUrls");
		await configure(true, {
			mode: "managed",
			control_plane: { enabled: true },
			url_check: { enabled: true },
		});
		const url = "https://api.openai.com/v1/responses/PRIVATE-BUSINESS-CONTENT";
		const blocked = await evaluateToolCall(
			{
				sessionId: "privacy-test-session",
				toolName: "WebFetch",
				toolInput: { url, prompt: "PRIVATE-BUSINESS-CONTENT" },
				artifacts: extractFromWebFetch({ url, prompt: "PRIVATE-BUSINESS-CONTENT" }),
			},
			context(),
		);
		expect(blocked.decision).toBe("deny");
		expect(blocked.category).toBe("privacy_required_unsupported");
		expect(fetch).not.toHaveBeenCalled();
		expect(reputation).not.toHaveBeenCalled();
		const audit = await readFile(join(root, ".singularity-aidr", "audit.jsonl"), "utf8");
		expect(audit).toContain("Mandatory privacy");
		expect(audit).not.toContain("PRIVATE-BUSINESS-CONTENT");
		expect(audit).not.toContain("api.openai.com");
	});

	it("does not let missing local rules authorize an unsupported mandatory route", async () => {
		const unavailable = await evaluateToolCall(bash("echo hello"), {
			...context(),
			threatsDir: join(root, "absent-threats"),
			allowlistsDir: join(root, "absent-allowlists"),
		});
		expect(unavailable.decision).toBe("deny");
		expect(unavailable.category).toBe("privacy_required_unsupported");
	});

	it("withholds raw input and uploads when the mandatory configuration cannot be verified", async () => {
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);
		await configure(true, { privacy: { required: "true" } });
		const blocked = await evaluateToolCall(bash("echo PRIVATE-BUSINESS-CONTENT"), context());
		expect(blocked.decision).toBe("deny");
		expect(blocked.category).toBe("config_invalid");
		expect(fetch).not.toHaveBeenCalled();
		const audit = await readFile(join(root, ".singularity-aidr", "audit.jsonl"), "utf8");
		expect(audit).not.toContain("PRIVATE-BUSINESS-CONTENT");
	});

	it("does not downgrade a malformed mandatory startup configuration to ordinary defaults", async () => {
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);
		await configure(true, { privacy: { required: true, unsupportedTrust: "caller" } });
		const result = await runSessionStart({
			plugins: [],
			threatsDir,
			allowlistsDir,
			configPath,
			version: "0.6.0",
			agentRuntime: "claude-code",
		});
		expect(result.enabled).toBe(false);
		expect(result.disabled_reason).toBe("configuration_invalid");
		expect(fetch).not.toHaveBeenCalled();
	});

	it("refuses unsupported hook startup before any discovery or provider request", async () => {
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);
		const result = await runSessionStart({
			plugins: [],
			threatsDir,
			allowlistsDir,
			configPath,
			version: "0.6.0",
			agentRuntime: "claude-code",
		});
		expect(result).toMatchObject({
			enabled: false,
			disabled_reason: "mandatory_privacy_requires_owned_gateway",
			scanResults: [],
			versionCheck: null,
		});
		expect(fetch).not.toHaveBeenCalled();
	});
});
