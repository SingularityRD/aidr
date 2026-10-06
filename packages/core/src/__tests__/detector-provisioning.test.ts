import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
	BehavioralDetectionInput,
	BehavioralDetectionResult,
} from "../behavioral-orchestrator.js";
import { detectorPolicyPath, loadProvisionedDetectorContext } from "../detector-provisioning.js";
import { evaluateToolCall } from "../evaluator.js";
import { LocalEmbeddingModel } from "../ml-model.js";
import type { AgentRuntime } from "../types.js";
import {
	behavioralPolicyPayload,
	detectorPolicyPathFor,
	detectorPolicyPayload,
	entitlementSnapshot,
	provisionTenantDetectorPolicy,
	syntheticBehavioralInput,
	syntheticDlpPolicy,
	syntheticThreatCorpus,
	TEST_DLP_MARKER,
	TEST_SYNTHETIC_THREAT_ID,
	TEST_SYNTHETIC_THREAT_TEXT,
	TEST_TENANT_ID,
} from "./detector-provisioning-fixtures.js";

let home: string;
let subprocessModulePath: string | null = null;

async function buildSubprocessModule(): Promise<string> {
	if (subprocessModulePath) return subprocessModulePath;
	const buildDir = join(home, "core-subprocess-build");
	await mkdir(buildDir, { recursive: true });
	await writeFile(join(buildDir, "package.json"), '{"type":"module"}\n', "utf8");
	await symlink(
		fileURLToPath(new URL("../../node_modules", import.meta.url)),
		join(buildDir, "node_modules"),
		"junction",
	);
	const compiler = fileURLToPath(
		new URL("../../../../node_modules/typescript/lib/tsc.js", import.meta.url),
	);
	const tsconfig = fileURLToPath(new URL("../../tsconfig.json", import.meta.url));
	execFileSync(
		process.execPath,
		[
			compiler,
			"-p",
			tsconfig,
			"--outDir",
			buildDir,
			"--composite",
			"false",
			"--declaration",
			"false",
			"--declarationMap",
			"false",
			"--sourceMap",
			"false",
		],
		{ cwd: fileURLToPath(new URL("../../../../", import.meta.url)), stdio: "inherit" },
	);
	subprocessModulePath = join(buildDir, "detector-provisioning.js");
	return subprocessModulePath;
}

function firstCorpusEntry(corpus = syntheticThreatCorpus()) {
	const entry = corpus.entries[0];
	if (!entry) throw new Error("Synthetic corpus fixture must have an entry");
	return entry;
}

async function provisionBehavioral(payload = behavioralPolicyPayload()) {
	return provisionTenantDetectorPolicy({
		homeDir: home,
		agentRuntime: "opencode",
		payload,
		entitlement: entitlementSnapshot({
			premiumModules: ["runtime_detectors", "behavioral_learning_v1"],
		}),
	});
}

async function freshBehavioral() {
	const context = await loadProvisionedDetectorContext("opencode");
	const behavioral = context.runtimeDetectors?.behavioral;
	expect(behavioral?.enabled).toBe(true);
	if (!behavioral) throw new Error("Signed behavioral detector was not provisioned");
	return behavioral;
}

async function evaluateFresh(input = syntheticBehavioralInput()) {
	return (await freshBehavioral()).orchestrator.evaluate(input);
}

async function evaluateInSeparateProcess(input: BehavioralDetectionInput) {
	const outputPath = join(home, "process-result.json");
	const detectorModulePath = await buildSubprocessModule();
	execFileSync(
		process.execPath,
		[
			fileURLToPath(new URL("./detector-provisioning-process.mjs", import.meta.url)),
			JSON.stringify(input),
			outputPath,
			detectorModulePath,
		],
		{
			cwd: fileURLToPath(new URL("../../../../", import.meta.url)),
			env: { ...process.env, HOME: home, USERPROFILE: home },
			stdio: ["ignore", "inherit", "inherit"],
			timeout: 15_000,
		},
	);
	return JSON.parse(await readFile(outputPath, "utf8")) as {
		pid: number;
		result: BehavioralDetectionResult;
	};
}

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-detector-provisioning-"));
	subprocessModulePath = null;
	vi.stubEnv("HOME", home);
});

afterEach(async () => {
	vi.unstubAllEnvs();
	await rm(home, { recursive: true, force: true });
});

describe("shared tenant detector provisioning", () => {
	it("provisions a signed, tenant-bound DLP policy for a connector runtime", async () => {
		await provisionTenantDetectorPolicy({ homeDir: home, agentRuntime: "opencode" });

		// The read is pinned to a fixed, non-tool-selectable location named after
		// the agent runtime.
		expect(detectorPolicyPath("opencode")).toBe(detectorPolicyPathFor(home, "opencode"));
		expect(detectorPolicyPath("opencode")).toBe(
			join(home, ".singularity-aidr", "detectors", "opencode.json"),
		);

		const context = await loadProvisionedDetectorContext("opencode");
		expect(context.runtimeDetectors?.tenantId).toBe(TEST_TENANT_ID);
		expect(context.runtimeDetectors?.dlp?.enabled).toBe(true);
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.id).toBe("tenant-restricted-rule");
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.matchers[0]).toMatchObject({
			values: [TEST_DLP_MARKER],
		});
	});

	it("keeps one runtime's provisioned policy away from another runtime", async () => {
		// Without the `runtime_detectors` premium module the bundle is optional, so
		// a runtime that was never provisioned stays unprovisioned.
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "codex",
			entitlement: entitlementSnapshot({ premiumModules: [] }),
		});

		const provisioned = await loadProvisionedDetectorContext("codex");
		expect(provisioned.runtimeDetectors?.tenantId).toBe(TEST_TENANT_ID);
		await expect(loadProvisionedDetectorContext("opencode")).resolves.toEqual({});
	});

	it("returns an empty context when no policy was issued", async () => {
		// Nothing on disk at all: an unenrolled installation is not provisioned.
		await expect(loadProvisionedDetectorContext("openclaw")).resolves.toEqual({});

		// A verified entitlement that does not require the runtime_detectors
		// module, with no bundle installed, is also simply unprovisioned.
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "openclaw",
			skipPolicy: true,
			entitlement: entitlementSnapshot({ premiumModules: [] }),
		});
		await expect(loadProvisionedDetectorContext("openclaw")).resolves.toEqual({});
	});

	it("rejects a tampered detector policy", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "claude-code",
			tamperPolicy: "signature",
		});
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"trust or tenant binding failed",
		);

		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "claude-code",
			tamperPolicy: "payload",
		});
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects a policy bound to a different tenant than the signed entitlement", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			entitlement: entitlementSnapshot({ tenantId: "tenant-b" }),
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects an expired entitlement and an expired policy", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			entitlement: entitlementSnapshot({ expired: true }),
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
			"trust or tenant binding failed",
		);

		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			payload: detectorPolicyPayload(TEST_TENANT_ID, {
				issued_at: new Date(Date.now() - 120_000).toISOString(),
				expires_at: new Date(Date.now() - 60_000).toISOString(),
			}),
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects a DLP policy whose tenant differs from the signed bundle", async () => {
		// The policy is internally consistent for `tenant-b`, so only the binding
		// to the signed bundle's tenant can reject it.
		const payload = detectorPolicyPayload(TEST_TENANT_ID, {
			dlp: { enabled: true, policy: syntheticDlpPolicy("tenant-b") },
		});
		await provisionTenantDetectorPolicy({ homeDir: home, agentRuntime: "opencode", payload });

		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
			"belongs to a different tenant",
		);
	});

	it("refuses signed behavioral learning in a one-shot hook contract", async () => {
		// V1 remains invalid even with the premium entitlement and the new capability.
		for (const behavioral of [
			{ enabled: true, learning_allowed: true },
			{ enabled: true, learning_allowed: true, learning_capability: "durable_baseline_v1" },
			{ enabled: true, unavailable_action: "skip" },
		]) {
			await provisionTenantDetectorPolicy({
				homeDir: home,
				agentRuntime: "opencode",
				entitlement: entitlementSnapshot({
					premiumModules: ["runtime_detectors", "behavioral_learning_v1"],
				}),
				payload: detectorPolicyPayload(TEST_TENANT_ID, { behavioral }),
			});
			await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow("invalid");
		}
	});

	describe("signed durable behavioral capability and corpus", () => {
		it("defaults baseline absence to ask and allows only a signed, visible skip", async () => {
			const defaultInstalled = await provisionBehavioral();
			const defaultContext = await loadProvisionedDetectorContext("opencode");
			expect(defaultContext.runtimeDetectors?.behavioral?.unavailableAction).toBe("ask");
			const defaultVerdict = await evaluateToolCall(
				{
					sessionId: "cold-behavior-session",
					toolName: "Read",
					toolInput: { file_path: "/synthetic-workspace/ordinary.txt" },
					artifacts: [],
				},
				{
					...defaultContext,
					configPath: defaultInstalled.configPath,
					threatsDir: join(home, "empty-threats"),
					allowlistsDir: join(home, "empty-allowlists"),
				},
			);
			expect(defaultVerdict).toMatchObject({
				decision: "ask",
				category: "behavioral_unavailable",
				source: "behavioral",
			});

			const skipPayload = {
				...behavioralPolicyPayload(TEST_TENANT_ID, { unavailable_action: "skip" }),
				dlp: { enabled: true, policy: syntheticDlpPolicy() },
			};
			const installed = await provisionBehavioral(skipPayload);
			const signedContext = await loadProvisionedDetectorContext("opencode");
			const behavioral = signedContext.runtimeDetectors?.behavioral;
			expect(behavioral?.unavailableAction).toBe("skip");
			const evalContext = {
				...signedContext,
				configPath: installed.configPath,
				threatsDir: join(home, "empty-threats"),
				allowlistsDir: join(home, "empty-allowlists"),
			};
			const skipped = await evaluateToolCall(
				{
					sessionId: "cold-behavior-session",
					toolName: "Read",
					toolInput: { file_path: "/synthetic-workspace/ordinary.txt" },
					artifacts: [],
				},
				evalContext,
			);
			expect(skipped).toMatchObject({
				decision: "allow",
				category: "behavioral_unavailable",
				severity: "warning",
				source: "behavioral",
			});
			expect(skipped.reasons.join(" ")).toContain("not ready");
			expect(skipped.source).not.toBe("no_artifacts");

			const dlp = await evaluateToolCall(
				{
					sessionId: "cold-behavior-session",
					toolName: "Read",
					toolInput: { body: TEST_DLP_MARKER },
					artifacts: [],
				},
				evalContext,
			);
			expect(dlp).toMatchObject({ decision: "deny", source: "dlp" });

			const knownThreatInput = JSON.parse(TEST_SYNTHETIC_THREAT_TEXT) as Record<string, unknown>;
			const knownThreat = await evaluateToolCall(
				{
					sessionId: "cold-behavior-session",
					toolName: "Read",
					toolInput: knownThreatInput,
					artifacts: [],
				},
				evalContext,
			);
			expect(knownThreat).toMatchObject({ decision: "ask", category: "behavioral_anomaly" });
			expect(behavioral?.orchestrator.getStats().totalBaselineSamples).toBe(0);
		});

		it("keeps direct observations cold within and across contexts despite a signed learning declaration", async () => {
			await provisionBehavioral();
			const detector = await freshBehavioral();
			expect(detector.learningAllowed).toBe(true);
			for (let index = 0; index < 10; index++) {
				const result = await detector.orchestrator.evaluate(syntheticBehavioralInput(index));
				expect(result).toMatchObject({
					outcome: "learning",
					modelVersion: "local-tinyhash-v1",
					learning: {
						accepted: false,
						reason: "explicitly_disabled",
						baselineSamplesBefore: 0,
						baselineSamplesAfter: 0,
					},
				});
			}
			// A signed policy flag and repeated caller assertions are not execution
			// or independent approval receipts. Real warm-up is covered by the native
			// signed lifecycle in behavioral-learning-lifecycle.test.ts.
			const cold = await detector.orchestrator.evaluate(syntheticBehavioralInput(10));
			expect(cold).toMatchObject({
				outcome: "learning",
				anomalyScore: 0,
				modelVersion: "local-tinyhash-v1",
				learning: {
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				},
			});
			expect(cold.explanations).toHaveLength(3);
			for (const leg of ["behavioral", "novelty"]) {
				expect(cold.explanations).toContainEqual(
					expect.objectContaining({ leg, status: "learning" }),
				);
			}
			expect(cold.explanations).toContainEqual(
				expect.objectContaining({ leg: "ml", status: "ready", score: 0 }),
			);
			expect(detector.orchestrator.getStats().totalBaselineSamples).toBe(0);

			const freshContext = await freshBehavioral();
			expect(freshContext.orchestrator.getStats().totalBaselineSamples).toBe(0);
			expect(await freshContext.orchestrator.evaluate(syntheticBehavioralInput(11))).toMatchObject({
				outcome: "learning",
				learning: {
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				},
			});
		});

		it("recognizes the exact synthetic fixture using the signed real embedding, without seeding it", async () => {
			await provisionBehavioral();
			const result = await evaluateFresh(
				syntheticBehavioralInput(0, {
					classificationText: TEST_SYNTHETIC_THREAT_TEXT,
				}),
			);
			expect(result).toMatchObject({
				outcome: "anomalous",
				anomalyScore: 100,
				modelVersion: "local-tinyhash-v1",
				learning: { accepted: false, reason: "explicitly_disabled", baselineSamplesAfter: 0 },
			});
			expect(result.explanations).toContainEqual(
				expect.objectContaining({
					leg: "ml",
					status: "ready",
					score: 100,
					summary: expect.stringContaining(TEST_SYNTHETIC_THREAT_ID),
				}),
			);
			expect((await evaluateFresh()).learning.baselineSamplesBefore).toBe(0);
		});

		it.each([false, "omitted"] as const)(
			"pins signed learning %s off despite per-event true",
			async (setting) => {
				const payload = behavioralPolicyPayload(TEST_TENANT_ID, { learning_allowed: false });
				if (setting === "omitted")
					delete (payload.behavioral as Record<string, unknown>).learning_allowed;
				await provisionBehavioral(payload);
				for (let index = 0; index < 11; index++) {
					const detector = await freshBehavioral();
					expect(detector.learningAllowed).toBe(false);
					const result = await detector.orchestrator.evaluate(
						syntheticBehavioralInput(index, {
							learningAllowed: true,
						}),
					);
					expect(result.learning).toMatchObject({
						accepted: false,
						reason: "explicitly_disabled",
						baselineSamplesBefore: 0,
						baselineSamplesAfter: 0,
					});
				}
			},
		);

		it("keeps missing caller consent disabled under the signed declaration", async () => {
			await provisionBehavioral();
			const result = await evaluateFresh(
				syntheticBehavioralInput(0, { learningAllowed: undefined }),
			);
			expect(result.learning).toMatchObject({
				accepted: false,
				reason: "explicitly_disabled",
				baselineSamplesBefore: 0,
				baselineSamplesAfter: 0,
			});
		});

		it("rejects unsigned model replacement on a provisioned orchestrator", async () => {
			await provisionBehavioral();
			const detector = await freshBehavioral();
			const unsignedModel = new LocalEmbeddingModel(LocalEmbeddingModel.createDefaultConfig());
			await unsignedModel.addThreat(firstCorpusEntry());
			// This is a rejection test, never a shortcut to provision the test model.
			await expect(
				detector.orchestrator.refreshModel(unsignedModel, "unsigned-model-v1"),
			).rejects.toThrow(/newly verified policy context/i);
			const result = await detector.orchestrator.evaluate(syntheticBehavioralInput());
			expect(result.modelVersion).toBe("local-tinyhash-v1");
		});

		it("never seeds explicitly denied or high-risk events", async () => {
			await provisionBehavioral();
			for (const overrides of [{ learningAllowed: false }, { riskScore: 90 }] as const) {
				const result = await evaluateFresh(syntheticBehavioralInput(0, overrides));
				expect(result.learning).toMatchObject({
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				});
			}
			const installed = await provisionBehavioral();
			const context = await loadProvisionedDetectorContext("opencode");
			const verdict = await evaluateToolCall(
				{
					sessionId: "synthetic-behavioral-session",
					toolName: "Read",
					toolInput: { body: TEST_DLP_MARKER },
					artifacts: [],
				},
				{
					...context,
					configPath: installed.configPath,
					threatsDir: join(home, "empty-threats"),
					allowlistsDir: join(home, "empty-allowlists"),
				},
			);
			expect(verdict).toMatchObject({ decision: "deny", source: "dlp" });
			expect(
				context.runtimeDetectors?.behavioral?.orchestrator.getStats().totalBaselineSamples,
			).toBe(0);
			expect((await evaluateFresh()).learning.baselineSamplesBefore).toBe(0);
		});

		it("refuses repeated unsigned fingerprints before they can consume learning counters", async () => {
			await provisionBehavioral();
			const detector = await freshBehavioral();
			for (let index = 0; index < 5; index++) {
				expect(await detector.orchestrator.evaluate(syntheticBehavioralInput())).toMatchObject({
					learning: {
						accepted: false,
						reason: "explicitly_disabled",
						baselineSamplesBefore: 0,
						baselineSamplesAfter: 0,
					},
				});
			}
			for (let index = 0; index < 3; index++) {
				expect(
					(await detector.orchestrator.evaluate(syntheticBehavioralInput())).learning,
				).toMatchObject({
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				});
			}

			const freshContext = await freshBehavioral();
			expect(freshContext.orchestrator.getStats().totalBaselineSamples).toBe(0);
			expect(await freshContext.orchestrator.evaluate(syntheticBehavioralInput())).toMatchObject({
				learning: {
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				},
			});
		});

		it("rejects evaluation for a different tenant before creating baseline state", async () => {
			await provisionBehavioral();
			const detector = await freshBehavioral();
			await expect(
				detector.orchestrator.evaluate(
					syntheticBehavioralInput(0, {
						tenantId: "tenant-b",
					}),
				),
			).rejects.toThrow(/tenant/i);
			expect(detector.orchestrator.getStats().totalBaselineSamples).toBe(0);
			expect((await evaluateFresh()).learning.baselineSamplesBefore).toBe(0);
		});

		it("cannot carry unsigned observations across signed corpus replacement", async () => {
			const original = behavioralPolicyPayload();
			await provisionBehavioral(original);
			await evaluateFresh();
			await evaluateFresh(syntheticBehavioralInput(1));
			await provisionBehavioral(
				behavioralPolicyPayload(TEST_TENANT_ID, {
					threat_corpus: syntheticThreatCorpus(TEST_TENANT_ID, { corpus_version: 2 }),
				}),
			);
			expect((await evaluateFresh()).learning).toMatchObject({
				baselineSamplesBefore: 0,
				baselineSamplesAfter: 0,
				accepted: false,
				reason: "explicitly_disabled",
			});
			await provisionBehavioral(original);
			expect(
				(await evaluateFresh(syntheticBehavioralInput(2))).learning.baselineSamplesBefore,
			).toBe(0);
		});

		it("requires both the signed capability and verified learning entitlement", async () => {
			const noCapability = behavioralPolicyPayload();
			delete (noCapability.behavioral as Record<string, unknown>).learning_capability;
			await provisionBehavioral(noCapability);
			await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow();
			await provisionBehavioral(
				behavioralPolicyPayload(TEST_TENANT_ID, { learning_capability: "future-v2" }),
			);
			await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow();
			await provisionTenantDetectorPolicy({
				homeDir: home,
				agentRuntime: "opencode",
				payload: behavioralPolicyPayload(),
				entitlement: entitlementSnapshot({ premiumModules: ["runtime_detectors"] }),
			});
			await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow();
			const installed = await provisionBehavioral();
			const state = JSON.parse(await readFile(installed.managedPath, "utf8"));
			state.entitlement.premium_modules.push("unsigned-extra-module");
			await writeFile(installed.managedPath, JSON.stringify(state));
			await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow();
		});

		it.each([1, 2])("keeps a missing corpus unavailable in schema v%s", async (schemaVersion) => {
			const payload = detectorPolicyPayload(TEST_TENANT_ID, {
				schema_version: schemaVersion,
				behavioral:
					schemaVersion === 2
						? { enabled: true, learning_allowed: true, learning_capability: "durable_baseline_v1" }
						: { enabled: true, learning_allowed: false },
			});
			await provisionBehavioral(payload);
			const result = await evaluateFresh();
			expect(result).toMatchObject({ outcome: "unavailable", modelVersion: null });
			expect(result.learning).toMatchObject({
				accepted: false,
				reason: "explicitly_disabled",
				baselineSamplesAfter: 0,
			});
			expect(result.explanations).toContainEqual(
				expect.objectContaining({
					leg: "ml",
					status: "unavailable",
					unavailableReason: "empty_corpus",
				}),
			);
		});

		it("requires schema v2 even for a valid corpus with learning disabled", async () => {
			await provisionBehavioral({
				...behavioralPolicyPayload(TEST_TENANT_ID, { learning_allowed: false }),
				schema_version: 1,
			});
			await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow();
		});

		it.each([
			["empty", (): unknown => syntheticThreatCorpus(TEST_TENANT_ID, { entries: [] })],
			["wrong tenant", () => syntheticThreatCorpus("tenant-b")],
			["wrong SHA", () => ({ ...syntheticThreatCorpus(), sha256: "0".repeat(64) })],
			[
				"uppercase SHA",
				() => {
					const corpus = syntheticThreatCorpus();
					return { ...corpus, sha256: corpus.sha256.toUpperCase() };
				},
			],
			[
				"incompatible model",
				() => syntheticThreatCorpus(TEST_TENANT_ID, { model_version: "other-model" }),
			],
			["incompatible dimension", () => syntheticThreatCorpus(TEST_TENANT_ID, { dimension: 99 })],
			["unknown corpus schema", () => syntheticThreatCorpus(TEST_TENANT_ID, { schema_version: 2 })],
			["zero version", () => syntheticThreatCorpus(TEST_TENANT_ID, { corpus_version: 0 })],
			["fractional version", () => syntheticThreatCorpus(TEST_TENANT_ID, { corpus_version: 1.5 })],
			[
				"unsafe corpus ID",
				() => syntheticThreatCorpus(TEST_TENANT_ID, { corpus_id: "../../escape" }),
			],
			[
				"duplicate threat IDs",
				() => {
					const corpus = syntheticThreatCorpus();
					return syntheticThreatCorpus(TEST_TENANT_ID, {
						entries: [...corpus.entries, ...corpus.entries],
					});
				},
			],
			[
				"oversized corpus",
				() =>
					syntheticThreatCorpus(TEST_TENANT_ID, {
						entries: Array.from({ length: 1025 }, (_, index) => ({
							...firstCorpusEntry(),
							threatId: `fixture-${index}`,
						})),
					}),
			],
			[
				"short embedding",
				() => {
					const corpus = syntheticThreatCorpus();
					firstCorpusEntry(corpus).embedding.pop();
					return syntheticThreatCorpus(TEST_TENANT_ID, { entries: corpus.entries });
				},
			],
			[
				"zero vector",
				() => {
					const corpus = syntheticThreatCorpus();
					firstCorpusEntry(corpus).embedding.fill(0);
					return syntheticThreatCorpus(TEST_TENANT_ID, { entries: corpus.entries });
				},
			],
			[
				"non-unit vector",
				() => {
					const corpus = syntheticThreatCorpus();
					firstCorpusEntry(corpus).embedding = firstCorpusEntry(corpus).embedding.map(
						(value) => value / 2,
					);
					return syntheticThreatCorpus(TEST_TENANT_ID, { entries: corpus.entries });
				},
			],
			[
				"out-of-range coordinate",
				() => {
					const corpus = syntheticThreatCorpus();
					firstCorpusEntry(corpus).embedding[0] = 2;
					return syntheticThreatCorpus(TEST_TENANT_ID, { entries: corpus.entries });
				},
			],
			[
				"snake-case entry",
				() => ({
					...syntheticThreatCorpus(),
					entries: [{ threat_id: "wrong-shape", embedding: [] }],
				}),
			],
			["malformed value", (): unknown => "not-a-corpus"],
			["null", (): unknown => null],
		] as const)(
			"rejects a supplied %s corpus rather than activating or silently dropping it",
			async (_name, makeCorpus) => {
				await provisionBehavioral(
					behavioralPolicyPayload(TEST_TENANT_ID, { threat_corpus: makeCorpus() }),
				);
				await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow();
			},
		);

		it("rejects a non-finite JSON coordinate before activating the corpus", async () => {
			const installed = await provisionBehavioral();
			const signed = await readFile(installed.policyPath, "utf8");
			// JSON permits this numeric spelling, but JavaScript decodes it as Infinity.
			const nonFinite = signed.replace(
				/("embedding":\[)[^,]+/,
				(_match, prefix: string) => `${prefix}1e999`,
			);
			expect(nonFinite).not.toBe(signed);
			await writeFile(installed.policyPath, nonFinite);
			await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow("invalid");
		});

		it("rejects corpus bytes edited after signing, even if their digest is recomputed", async () => {
			const installed = await provisionBehavioral();
			const signed = JSON.parse(await readFile(installed.policyPath, "utf8"));
			signed.payload.behavioral.threat_corpus = syntheticThreatCorpus(TEST_TENANT_ID, {
				corpus_version: 2,
			});
			await writeFile(installed.policyPath, JSON.stringify(signed));
			await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
				"trust or tenant binding failed",
			);
		});

		it("never promotes unsigned observations across separate Node processes", async () => {
			await provisionBehavioral();
			for (let index = 0; index < 10; index++) {
				const { pid, result } = await evaluateInSeparateProcess(syntheticBehavioralInput(index));
				expect(pid).not.toBe(process.pid);
				expect(result).toMatchObject({
					outcome: "learning",
					modelVersion: "local-tinyhash-v1",
					learning: {
						accepted: false,
						reason: "explicitly_disabled",
						baselineSamplesBefore: 0,
						baselineSamplesAfter: 0,
					},
				});
			}
			const { result } = await evaluateInSeparateProcess(syntheticBehavioralInput(10));
			expect(result).toMatchObject({
				outcome: "learning",
				anomalyScore: 0,
				modelVersion: "local-tinyhash-v1",
				learning: {
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				},
			});
			const matched = await evaluateInSeparateProcess(
				syntheticBehavioralInput(0, {
					classificationText: TEST_SYNTHETIC_THREAT_TEXT,
				}),
			);
			expect(matched.result).toMatchObject({
				outcome: "anomalous",
				anomalyScore: 100,
				modelVersion: "local-tinyhash-v1",
				learning: {
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				},
			});
			expect(matched.result.explanations).toContainEqual(
				expect.objectContaining({
					leg: "ml",
					status: "ready",
					score: 100,
					summary: expect.stringContaining(TEST_SYNTHETIC_THREAT_ID),
				}),
			);
		}, 120_000);
	});

	it("fails closed when the signed entitlement requires a missing bundle", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			skipPolicy: true,
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow("unavailable");
	});

	it("refuses an unknown runtime instead of following it out of the detector directory", async () => {
		expect(() => detectorPolicyPath("../../evil" as AgentRuntime)).toThrow(
			"agent runtime is not supported",
		);
		await expect(loadProvisionedDetectorContext("../../evil" as AgentRuntime)).rejects.toThrow(
			"agent runtime is not supported",
		);
	});
});
