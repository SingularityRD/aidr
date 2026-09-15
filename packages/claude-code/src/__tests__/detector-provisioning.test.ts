import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { evaluateToolCall } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	behavioralPolicyPayload,
	entitlementSnapshot,
	provisionTenantDetectorPolicy,
	syntheticBehavioralInput,
	syntheticThreatCorpus,
	TEST_SYNTHETIC_THREAT_ID,
	TEST_SYNTHETIC_THREAT_TEXT,
	TEST_TENANT_ID,
} from "../../../core/src/__tests__/detector-provisioning-fixtures.js";
import {
	BehavioralDetectionOrchestrator,
	type BehavioralOrchestratorDependencies,
} from "../../../core/src/behavioral-orchestrator.js";
import { LocalEmbeddingModel } from "../../../core/src/ml-model.js";

const mocked = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	loadManagedState: vi.fn(),
	isEntitlementActive: vi.fn(),
	resolvePath: vi.fn(),
	createBehavioralDetectionOrchestrator: vi.fn(),
}));

// The provisioning implementation lives in core, and Claude Code consumes it
// through the package entry point. These mocks stand in for the core
// submodules that implementation reads, so the real control flow (schema,
// signature, tenant binding, expiry) runs in-process rather than being stubbed.
vi.mock("../../../core/src/config.js", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return { ...actual, loadConfig: mocked.loadConfig, resolvePath: mocked.resolvePath };
});

vi.mock("../../../core/src/managed.js", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return {
		...actual,
		isEntitlementActive: mocked.isEntitlementActive,
		loadManagedState: mocked.loadManagedState,
		managedStatePath: () => "managed.json",
	};
});

vi.mock("../../../core/src/behavioral-orchestrator.js", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return {
		...actual,
		createBehavioralDetectionOrchestrator: mocked.createBehavioralDetectionOrchestrator,
	};
});

import {
	canonicalDetectorPolicyPayload,
	detectorPolicyPath,
	loadProvisionedDetectorContext,
} from "../../../core/src/detector-provisioning.js";
import {
	detectorPolicyPath as claudeCodeDetectorPolicyPath,
	loadProvisionedDetectorContext as loadClaudeCodeProvisionedDetectorContext,
} from "../detector-provisioning.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const tenantId = "tenant-a";
let stateDir: string;
let realHome: string | undefined;

function payload(overrides: Record<string, unknown> = {}) {
	return {
		schema_version: 1,
		tenant_id: tenantId,
		issued_at: new Date(Date.now() - 60_000).toISOString(),
		expires_at: new Date(Date.now() + 60_000).toISOString(),
		dlp: {
			enabled: true,
			policy: {
				version: 1,
				tenantId,
				labels: [
					{ id: "business-secret", tenantId, name: "Business secret", sensitivity: "restricted" },
				],
				rules: [
					{
						id: "block-secret",
						tenantId,
						labelId: "business-secret",
						name: "Block secret",
						action: "block",
						matchers: [{ type: "keyword", values: ["customer secret"] }],
					},
				],
			},
		},
		...overrides,
	};
}

async function installPolicy(value: Record<string, unknown>, signingKey = privateKey) {
	const signature = sign(
		null,
		Buffer.from(canonicalDetectorPolicyPayload(value)),
		signingKey,
	).toString("base64");
	await mkdir(dirname(detectorPolicyPath("claude-code")), { recursive: true });
	await writeFile(
		detectorPolicyPath("claude-code"),
		JSON.stringify({ alg: "ed25519", payload: value, sig_b64: signature }),
	);
}

beforeEach(async () => {
	stateDir = await mkdtemp(join(tmpdir(), "aidr-detector-provisioning-"));
	mocked.resolvePath.mockReturnValue(stateDir);
	vi.stubEnv("HOME", stateDir);
	mocked.loadConfig.mockResolvedValue({
		mode: "managed",
		licensing: { public_keys_pem: [publicKeyPem] },
	});
	mocked.loadManagedState.mockResolvedValue({
		entitlement_alg: "ed25519",
		entitlement_sig: "verified-by-core",
		entitlement: { schema_version: 2, tenant_id: tenantId, premium_modules: [] },
	});
	mocked.isEntitlementActive.mockReturnValue(true);
	mocked.createBehavioralDetectionOrchestrator.mockReturnValue({ evaluate: vi.fn() });
});

afterEach(async () => {
	vi.clearAllMocks();
	await rm(stateDir, { recursive: true, force: true });
	if (realHome) {
		await rm(realHome, { recursive: true, force: true });
		realHome = undefined;
	}
});

describe("Claude Code detector provisioning", () => {
	it("passes a signed tenant-bound DLP policy to the evaluator context", async () => {
		await installPolicy(payload());
		const context = await loadProvisionedDetectorContext("claude-code");
		expect(context.runtimeDetectors?.tenantId).toBe(tenantId);
		expect(context.runtimeDetectors?.dlp?.enabled).toBe(true);
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.id).toBe("block-secret");
	});

	it("passes a signed feed keyring and behavioral opt-in with fixed local storage", async () => {
		await installPolicy(
			payload({
				behavioral: { enabled: true },
				reputation_feed: { feed_id: "enterprise-feed", trusted_keys: { publisher: publicKeyPem } },
			}),
		);
		const context = await loadProvisionedDetectorContext("claude-code");
		expect(context.runtimeDetectors?.behavioral?.enabled).toBe(true);
		expect(context.runtimeDetectors?.behavioral?.learningAllowed).toBe(false);
		expect(context.reputationFeed).toEqual(
			expect.objectContaining({
				feedId: "enterprise-feed",
				storeDir: join(stateDir, "reputation-feeds", "enterprise-feed"),
				trustedKeys: { publisher: publicKeyPem },
			}),
		);
	});

	it("does not let a tool or another tenant select the detector policy", async () => {
		await installPolicy(payload({ tenant_id: "tenant-b" }));
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects a DLP policy whose tenant differs from the signed bundle", async () => {
		const mixed = payload();
		(mixed.dlp.policy as Record<string, unknown>).tenantId = "tenant-b";
		await installPolicy(mixed);
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow();
	});

	it.each([
		["legacy v1 learning", 1, { enabled: true, learning_allowed: true }],
		[
			"v1 with a v2 capability",
			1,
			{ enabled: true, learning_allowed: true, learning_capability: "durable_baseline_v1" },
		],
		["v2 learning without an explicit capability", 2, { enabled: true, learning_allowed: true }],
		[
			"v2 with an unsupported capability",
			2,
			{ enabled: true, learning_allowed: true, learning_capability: "unsupported" },
		],
		["v1 inline corpus", 1, { enabled: true, threat_corpus: syntheticThreatCorpus(tenantId) }],
	])("rejects %s rather than treating it as an authorized durable workflow", async (_, version, behavioral) => {
		mocked.loadManagedState.mockResolvedValue({
			entitlement_alg: "ed25519",
			entitlement_sig: "verified-by-core",
			entitlement: entitlementSnapshot({
				tenantId,
				premiumModules: ["runtime_detectors", "behavioral_learning_v1"],
			}),
		});
		await installPolicy(payload({ schema_version: version, behavioral }));
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow("invalid");
		expect(mocked.createBehavioralDetectionOrchestrator).not.toHaveBeenCalled();
	});

	it("requires the verified entitlement capability even for an explicit signed v2 workflow", async () => {
		await installPolicy(behavioralPolicyPayload(tenantId));
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"behavioral learning capability is unavailable",
		);
		expect(mocked.createBehavioralDetectionOrchestrator).not.toHaveBeenCalled();
	});

	it("rejects a signed feed configuration with an untrusted key format", async () => {
		await installPolicy(
			payload({
				reputation_feed: { feed_id: "enterprise-feed", trusted_keys: { publisher: "not-a-key" } },
			}),
		);
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"keyring is invalid",
		);
	});

	it("rejects tampered signatures and expired policies", async () => {
		const signed = payload();
		await installPolicy(signed);
		const tampered = { ...signed, tenant_id: "tenant-b" };
		await writeFile(
			detectorPolicyPath("claude-code"),
			JSON.stringify({
				alg: "ed25519",
				payload: tampered,
				sig_b64: sign(
					null,
					Buffer.from(canonicalDetectorPolicyPayload(signed)),
					privateKey,
				).toString("base64"),
			}),
		);
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow();

		await installPolicy(payload({ expires_at: new Date(Date.now() - 1000).toISOString() }));
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("fails closed when signed entitlement requires a missing detector bundle", async () => {
		mocked.loadManagedState.mockResolvedValue({
			entitlement_alg: "ed25519",
			entitlement_sig: "verified-by-core",
			entitlement: {
				schema_version: 2,
				tenant_id: tenantId,
				premium_modules: ["runtime_detectors"],
			},
		});
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow("unavailable");
	});

	it("keeps optional detectors absent when none were provisioned", async () => {
		await expect(loadProvisionedDetectorContext("claude-code")).resolves.toEqual({});
	});

	it("provisions a behavioral baseline that persists between hook processes", async () => {
		const corpus = syntheticThreatCorpus(tenantId);
		await installPolicy(behavioralPolicyPayload(tenantId, { threat_corpus: corpus }));
		mocked.loadManagedState.mockResolvedValue({
			entitlement_alg: "ed25519",
			entitlement_sig: "verified-by-core",
			entitlement: entitlementSnapshot({
				tenantId,
				premiumModules: ["runtime_detectors", "behavioral_learning_v1"],
			}),
		});
		// Keep the real provisioning dependencies, including the signed corpus's
		// LocalEmbeddingModel and durable store, rather than replacing the model.
		mocked.createBehavioralDetectionOrchestrator.mockImplementation(
			(config: ConstructorParameters<typeof BehavioralDetectionOrchestrator>[0], deps) =>
				new BehavioralDetectionOrchestrator(config, deps),
		);
		const first = await loadProvisionedDetectorContext("claude-code");
		const dependencies = mocked.createBehavioralDetectionOrchestrator.mock.calls.at(
			-1,
		)?.[1] as BehavioralOrchestratorDependencies;
		expect(dependencies.mlModel).toBeInstanceOf(LocalEmbeddingModel);
		expect(dependencies.baselineStore).toBeDefined();
		expect(first.runtimeDetectors?.behavioral?.learningAllowed).toBe(true);
		const firstProcess = first.runtimeDetectors?.behavioral?.orchestrator;
		if (!firstProcess) throw new Error("Provisioning did not construct an orchestrator");
		for (let index = 0; index < 10; index++) {
			const result = await firstProcess.evaluate(
				syntheticBehavioralInput(index, {
					learningAllowed: first.runtimeDetectors?.behavioral?.learningAllowed,
				}),
			);
			expect(result.learning.accepted).toBe(true);
			expect(result.explanations).toContainEqual(
				expect.objectContaining({ leg: "ml", status: "ready", score: 0 }),
			);
		}
		expect(firstProcess.getStats().totalBaselineSamples).toBe(10);
		const sessionId = syntheticBehavioralInput().sessionId;
		expect((await dependencies.baselineStore?.load(tenantId, sessionId))?.baselineSamples).toBe(10);

		// Corpus-bound records remain under the fixed tenant/session storage root.
		const records = await readdir(join(stateDir, "behavioral-baseline"), {
			recursive: true,
		});
		expect(records.filter((entry) => entry.endsWith(".json"))).toHaveLength(1);

		// A fresh hook context imports the same signed corpus and restores learning.
		const second = await loadProvisionedDetectorContext("claude-code");
		expect(second.runtimeDetectors?.behavioral?.learningAllowed).toBe(true);
		const secondProcess = second.runtimeDetectors?.behavioral?.orchestrator;
		if (!secondProcess) throw new Error("Provisioning did not construct an orchestrator");
		expect(secondProcess).not.toBe(firstProcess);
		const result = await secondProcess.evaluate(
			syntheticBehavioralInput(10, {
				learningAllowed: second.runtimeDetectors?.behavioral?.learningAllowed,
			}),
		);

		expect(result.learning.baselineSamplesBefore).toBe(10);
		expect(result.outcome).toBe("normal");
		for (const leg of ["behavioral", "novelty", "ml"]) {
			expect(result.explanations).toContainEqual(expect.objectContaining({ leg, status: "ready" }));
		}
		await expect(
			secondProcess.evaluate(
				syntheticBehavioralInput(0, {
					tenantId: "tenant-b",
					learningAllowed: true,
				}),
			),
		).rejects.toThrow("different tenant");
		expect(await dependencies.baselineStore?.load("tenant-b", sessionId)).toBeNull();
	});

	it.each([
		undefined,
		false,
	])("keeps legacy learning %s compatible without a baseline store", async (learningAllowed) => {
		await installPolicy(
			payload({
				behavioral: {
					enabled: true,
					...(learningAllowed === undefined ? {} : { learning_allowed: learningAllowed }),
				},
			}),
		);
		const context = await loadProvisionedDetectorContext("claude-code");
		expect(context.runtimeDetectors?.behavioral?.learningAllowed).toBe(false);
		expect(
			mocked.createBehavioralDetectionOrchestrator.mock.calls.at(-1)?.[1].baselineStore,
		).toBeUndefined();
	});

	it("does not let event consent override signed learning false with a ready corpus", async () => {
		await installPolicy(behavioralPolicyPayload(tenantId, { learning_allowed: false }));
		mocked.createBehavioralDetectionOrchestrator.mockImplementation(
			(config: ConstructorParameters<typeof BehavioralDetectionOrchestrator>[0], deps) =>
				new BehavioralDetectionOrchestrator(config, deps),
		);
		const context = await loadProvisionedDetectorContext("claude-code");
		const orchestrator = context.runtimeDetectors?.behavioral?.orchestrator;
		if (!orchestrator) throw new Error("Provisioning did not construct an orchestrator");
		const result = await orchestrator.evaluate(
			syntheticBehavioralInput(0, { learningAllowed: true }),
		);
		expect(result.explanations).toContainEqual(
			expect.objectContaining({ leg: "ml", status: "ready", score: 0 }),
		);
		expect(result.learning).toMatchObject({
			accepted: false,
			reason: "explicitly_disabled",
			baselineSamplesAfter: 0,
		});
		expect(orchestrator.getStats().totalBaselineSamples).toBe(0);
	});
});

describe("Claude Code consumes the shared helper", () => {
	it("reads the core helper's claude-code policy location and applies it", async () => {
		// Real files, real signatures and the published core build: this pins the
		// façade to the one implementation instead of a Claude-only copy.
		realHome = await mkdtemp(join(tmpdir(), "aidr-claude-code-provisioning-"));
		vi.stubEnv("HOME", realHome);
		await provisionTenantDetectorPolicy({ homeDir: realHome, agentRuntime: "claude-code" });

		expect(claudeCodeDetectorPolicyPath()).toBe(
			join(realHome, ".singularity-aidr", "detectors", "claude-code.json"),
		);

		const context = await loadClaudeCodeProvisionedDetectorContext();
		expect(context.runtimeDetectors?.tenantId).toBe(TEST_TENANT_ID);
		expect(context.runtimeDetectors?.dlp?.enabled).toBe(true);
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.id).toBe("tenant-restricted-rule");
	});

	it("restores a signed v2 baseline and matches its real corpus through the Claude facade", async () => {
		realHome = await mkdtemp(join(tmpdir(), "aidr-claude-code-behavioral-"));
		vi.stubEnv("HOME", realHome);
		const corpus = syntheticThreatCorpus();
		const installed = await provisionTenantDetectorPolicy({
			homeDir: realHome,
			agentRuntime: "claude-code",
			payload: behavioralPolicyPayload(TEST_TENANT_ID, { threat_corpus: corpus }),
			entitlement: entitlementSnapshot({
				premiumModules: ["runtime_detectors", "behavioral_learning_v1"],
			}),
		});

		// The facade consumes built core, so config, entitlement signature, model
		// import and baseline persistence all run without the source-module mocks.
		for (let index = 0; index < 10; index++) {
			const context = await loadClaudeCodeProvisionedDetectorContext();
			expect(context.runtimeDetectors?.tenantId).toBe(TEST_TENANT_ID);
			expect(context.runtimeDetectors?.behavioral?.learningAllowed).toBe(true);
			const orchestrator = context.runtimeDetectors?.behavioral?.orchestrator;
			if (!orchestrator) throw new Error("Claude facade did not construct an orchestrator");
			const input = syntheticBehavioralInput(index);
			const verdict = await evaluateToolCall(
				{
					sessionId: input.sessionId,
					toolName: input.toolName,
					toolInput: { file_path: input.path },
					artifacts: [],
				},
				{
					...context,
					configPath: installed.configPath,
					threatsDir: join(realHome, "empty-threats"),
					allowlistsDir: join(realHome, "empty-allowlists"),
				},
			);
			expect(verdict).toMatchObject({ decision: "ask", source: "behavioral" });
			expect(orchestrator.getStats().totalBaselineSamples).toBe(index + 1);
		}

		const restored = await loadClaudeCodeProvisionedDetectorContext();
		const orchestrator = restored.runtimeDetectors?.behavioral?.orchestrator;
		if (!orchestrator) throw new Error("Claude facade did not construct an orchestrator");
		const normal = await orchestrator.evaluate(
			syntheticBehavioralInput(10, { learningAllowed: false }),
		);
		expect(normal.learning.baselineSamplesBefore).toBe(10);
		expect(normal.outcome).toBe("normal");
		for (const leg of ["behavioral", "novelty", "ml"]) {
			expect(normal.explanations).toContainEqual(expect.objectContaining({ leg, status: "ready" }));
		}
		const matched = await orchestrator.evaluate(
			syntheticBehavioralInput(10, {
				classificationText: TEST_SYNTHETIC_THREAT_TEXT,
				learningAllowed: restored.runtimeDetectors?.behavioral?.learningAllowed,
			}),
		);
		expect(matched.outcome).toBe("anomalous");
		expect(matched.explanations).toContainEqual(
			expect.objectContaining({
				leg: "ml",
				status: "ready",
				score: 100,
				summary: expect.stringContaining(TEST_SYNTHETIC_THREAT_ID),
			}),
		);
		expect(matched.learning).toMatchObject({
			accepted: false,
			reason: "anomaly_detected",
			baselineSamplesAfter: 10,
		});
		const verdict = await evaluateToolCall(
			{
				sessionId: syntheticBehavioralInput().sessionId,
				toolName: "Read",
				toolInput: JSON.parse(TEST_SYNTHETIC_THREAT_TEXT),
				artifacts: [],
			},
			{
				...restored,
				configPath: installed.configPath,
				threatsDir: join(realHome, "empty-threats"),
				allowlistsDir: join(realHome, "empty-allowlists"),
			},
		);
		expect(verdict).toMatchObject({ decision: "ask", source: "behavioral" });
		expect(verdict.reasons).toContainEqual(expect.stringContaining("Behavioral anomaly detected"));
		expect(orchestrator.getStats().totalBaselineSamples).toBe(10);
		const records = await readdir(join(realHome, ".singularity-aidr", "behavioral-baseline"), {
			recursive: true,
		});
		expect(records.filter((entry) => entry.endsWith(".json"))).toHaveLength(1);
		expect(mocked.createBehavioralDetectionOrchestrator).not.toHaveBeenCalled();
	});
});
