import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BehavioralDetectionOrchestrator } from "../behavioral-orchestrator.js";
import { VerdictCache } from "../cache.js";
import * as amsi from "../clients/amsi.js";
import { UrlCheckClient } from "../clients/url-check.js";
import { loadProvisionedDetectorContext } from "../detector-provisioning.js";
import { type DlpPolicy, DlpPolicySchema } from "../dlp/policy.js";
import { evaluateToolCall, type ToolEvaluationContext } from "../evaluator.js";
import { PackageChecker } from "../package-checker.js";
import { VERSION } from "../version.js";
import {
	detectorPolicyPayload,
	provisionTenantDetectorPolicy,
	syntheticDlpPolicy,
	TEST_DLP_MARKER,
} from "./detector-provisioning-fixtures.js";
import { makeTmpDir, writeSignedCacheFixture } from "./test-utils.js";

let homeDir: string;
let context: ToolEvaluationContext;
let provider: ReturnType<typeof vi.spyOn>;
let packageProvider: ReturnType<typeof vi.spyOn>;

beforeEach(async () => {
	homeDir = await makeTmpDir();
	vi.stubEnv("HOME", homeDir);
	await mkdir(join(homeDir, ".singularity-aidr"), { recursive: true });
	await configureContext();
	provider = vi
		.spyOn(UrlCheckClient.prototype, "checkUrls")
		.mockImplementation(async (urls) =>
			urls.map((url) => ({ url, isMalicious: false, findings: [], flags: [] })),
		);
	packageProvider = vi.spyOn(PackageChecker.prototype, "checkPackages").mockResolvedValue([]);
});

async function configureContext(
	action: "block" | "ask" = "block",
	exceptions: DlpPolicy["exceptions"] = [],
) {
	const policy = DlpPolicySchema.parse({ ...syntheticDlpPolicy(), exceptions });
	for (const rule of policy.rules) rule.action = action;
	const installed = await provisionTenantDetectorPolicy({
		homeDir,
		agentRuntime: "codex",
		payload: detectorPolicyPayload("tenant-a", { dlp: { enabled: true, policy } }),
	});
	const config = JSON.parse(await readFile(installed.configPath, "utf8"));
	config.url_check = { enabled: true, endpoint: "https://reputation.example/check" };
	config.package_check = { enabled: true };
	config.amsi_check = { enabled: false };
	await writeFile(installed.configPath, JSON.stringify(config));
	context = {
		threatsDir: join(homeDir, "empty-threats"),
		allowlistsDir: join(homeDir, "empty-allowlists"),
		configPath: installed.configPath,
		...(await loadProvisionedDetectorContext("codex")),
	};
}

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
});

function request(toolInput: Record<string, unknown>) {
	return { sessionId: "dlp-preflight", toolName: "CustomTool", toolInput, artifacts: [] };
}

describe("signed tenant DLP before reputation lookup", () => {
	it("inspects retained caller artifacts before sending them to a provider", async () => {
		const verdict = await evaluateToolCall(
			{
				...request({ body: "Public documentation" }),
				artifacts: [{ type: "url", value: `https://public.example/${TEST_DLP_MARKER}` }],
			},
			context,
		);
		expect(verdict).toMatchObject({ decision: "deny", source: "dlp" });
		expect(provider).not.toHaveBeenCalled();
	});

	it("retains the preflight refusal if a signed exception activates during local inspection", async () => {
		const now = Date.now();
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(now);
		await configureContext("ask", [
			{
				id: "future-exception",
				tenantId: "tenant-a",
				ruleId: "tenant-restricted-rule",
				ownerId: "operator-a",
				justification: "Scheduled test-only exception",
				scope: "rule",
				createdAt: new Date(now + 1_000).toISOString(),
				expiresAt: new Date(now + 60_000).toISOString(),
			},
		]);
		vi.spyOn(VerdictCache.prototype, "load").mockImplementation(async () => {
			vi.setSystemTime(now + 2_000);
		});
		const verdict = await evaluateToolCall(
			request({ url: `https://public.example/${TEST_DLP_MARKER}` }),
			context,
		);
		expect(verdict).toMatchObject({ decision: "ask", source: "dlp" });
		expect(provider).not.toHaveBeenCalled();
	});

	it.each([
		{
			label: "custom secret in URL",
			input: { url: `https://public.example/${TEST_DLP_MARKER}` },
			matchedThreatId: "tenant-restricted-rule",
		},
		{
			label: "custom secret in path beside URL",
			input: { url: "https://public.example/", file_path: `/work/${TEST_DLP_MARKER}.txt` },
			matchedThreatId: "tenant-restricted-rule",
		},
		{
			label: "PII with JSON-escaped whitespace",
			input: JSON.parse('{"url":"https://public.example/","body":"SSN: 123\\t45\\t6789"}'),
			matchedThreatId: "pii-ssn",
		},
	])("blocks $label before contacting the provider", async ({ input, matchedThreatId }) => {
		const verdict = await evaluateToolCall(request(input), context);
		expect(verdict).toMatchObject({ decision: "deny", source: "dlp", matchedThreatId });
		expect(provider).not.toHaveBeenCalled();
		expect(JSON.stringify(verdict)).not.toContain(TEST_DLP_MARKER);
		expect(JSON.stringify(verdict)).not.toContain("123");
	});

	it("checks the signed tenant binding before contacting the provider", async () => {
		const verdict = await evaluateToolCall(request({ url: "https://public.example/" }), {
			...context,
			runtimeDetectors: { ...context.runtimeDetectors, tenantId: "tenant-b" },
		});
		expect(verdict).toMatchObject({ decision: "deny", category: "tenant_isolation" });
		expect(provider).not.toHaveBeenCalled();
	});

	it("rejects an invalid delegated credential before contacting the provider", async () => {
		const verdict = await evaluateToolCall(request({ url: "https://public.example/" }), {
			...context,
			delegation: {
				token: "invalid",
				publicKeysById: {},
				issuer: "https://issuer.example/",
				audience: "aidr-runtime",
				tenantId: "tenant-a",
				subjectUserId: "user-a",
				agentId: "agent-a",
				tool: { serverId: "test-host", name: "CustomTool" },
				resource: { type: "repository", id: "test-repository" },
				requiredScopes: ["contents:read"],
			},
		});
		expect(verdict).toMatchObject({ decision: "deny", category: "delegation_denied" });
		expect(provider).not.toHaveBeenCalled();
	});

	it.each(["block", "ask"] as const)(
		"does not send a secret package manifest to providers when tenant DLP requires %s",
		async (action) => {
			await configureContext(action);
			const verdict = await evaluateToolCall(
				request({
					url: "https://public.example/",
					file_path: "/work/package.json",
					content: JSON.stringify({ dependencies: { [TEST_DLP_MARKER]: "1.0.0" } }),
				}),
				context,
			);
			expect(verdict).toMatchObject({
				decision: action === "block" ? "deny" : "ask",
				source: "dlp",
			});
			expect(provider).not.toHaveBeenCalled();
			expect(packageProvider).not.toHaveBeenCalled();
		},
	);

	it("retains a cached package deny while DLP ask suppresses provider inspection", async () => {
		await configureContext("ask");
		const cachePath = join(homeDir, ".singularity-aidr", "cache.json");
		const config = JSON.parse(await readFile(context.configPath as string, "utf8"));
		config.cache = { enabled: true, path: cachePath };
		await writeFile(context.configPath as string, JSON.stringify(config));
		await writeSignedCacheFixture(cachePath, {
			packages: {
				"npm:known-bad@1.0.0": {
					verdict: "deny",
					severity: "critical",
					reasons: ["Known malicious package"],
					source: "package_check",
					checkedAt: new Date().toISOString(),
					expiresAt: new Date(Date.now() + 600_000).toISOString(),
					aidrVersion: VERSION,
				},
			},
		});
		const verdict = await evaluateToolCall(
			request({
				file_path: "/work/package.json",
				content: JSON.stringify({
					description: TEST_DLP_MARKER,
					dependencies: { "known-bad": "1.0.0" },
				}),
			}),
			context,
		);
		expect(verdict).toMatchObject({ decision: "deny", source: "package_check" });
		expect(packageProvider).not.toHaveBeenCalled();
		expect(provider).not.toHaveBeenCalled();
		expect(JSON.stringify(verdict)).not.toContain(TEST_DLP_MARKER);
	});

	it("does not initialize or send content to AMSI while tenant DLP requires approval", async () => {
		await configureContext("ask");
		const config = JSON.parse(await readFile(context.configPath as string, "utf8"));
		config.amsi_check = { enabled: true };
		await writeFile(context.configPath as string, JSON.stringify(config));
		vi.spyOn(amsi, "isAmsiSupported").mockReturnValue(true);
		const initialize = vi.spyOn(amsi.AmsiClient.prototype, "init").mockResolvedValue();
		const scan = vi.spyOn(amsi.AmsiClient.prototype, "scanString");
		const writeRequest = (content: string) => ({
			...request({ file_path: "/work/document.txt", content }),
			toolName: "Write",
		});
		await evaluateToolCall(writeRequest("Public documentation"), context);
		expect(initialize).toHaveBeenCalledTimes(1);
		initialize.mockClear();
		const verdict = await evaluateToolCall(writeRequest(TEST_DLP_MARKER), context);
		expect(verdict).toMatchObject({ decision: "ask", source: "dlp" });
		expect(initialize).not.toHaveBeenCalled();
		expect(scan).not.toHaveBeenCalled();
	});

	it("preserves the normal provider result and evaluates behavior only once", async () => {
		const orchestrator = new BehavioralDetectionOrchestrator();
		const behavioral = vi.spyOn(orchestrator, "evaluate");
		const verdict = await evaluateToolCall(
			request({ url: "https://public.example/", body: "Public documentation" }),
			{
				...context,
				runtimeDetectors: {
					...context.runtimeDetectors,
					tenantId: "tenant-a",
					behavioral: { enabled: true, orchestrator, unavailableAction: "skip" },
				},
			},
		);
		expect(verdict.decision).toBe("allow");
		expect(provider).toHaveBeenCalledExactlyOnceWith(["https://public.example/"]);
		expect(behavioral).toHaveBeenCalledTimes(1);
		expect(behavioral.mock.calls[0]?.[0].learningAllowed).toBe(false);
	});
});
