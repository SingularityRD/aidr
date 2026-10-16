import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeLearningCommand } from "../../../cli/src/utils/learning-execution.js";
import {
	ingestBehavioralLearningReceipt,
	issueAuthorizedLearningExecution,
	prepareAuthorizedLearningExecution,
} from "../behavioral-learning.js";
import {
	createLearningApprovalReceipt,
	validateLearningAuthorities,
	verifyLearningExecutionReceipt,
} from "../behavioral-learning-receipt.js";
import { VerdictCache } from "../cache.js";
import {
	behavioralBaselineDir,
	canonicalDetectorPolicyPayload,
	exportBrokerLearningAuthority,
	loadProvisionedLearningApprovalContext,
	loadProvisionedLearningContext,
} from "../detector-provisioning.js";
import * as secretStore from "../secret-store.js";
import {
	behavioralPolicyPayload,
	entitlementSnapshot,
	type ProvisionedTenant,
	provisionTenantDetectorPolicy,
	syntheticDlpPolicy,
	TEST_DLP_MARKER,
} from "./detector-provisioning-fixtures.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

function key() {
	const pair = generateKeyPairSync("ed25519");
	return {
		privateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
}

let home: string;
let provisioned: ProvisionedTenant;
let executionKey: ReturnType<typeof key>;
let approvalKey: ReturnType<typeof key>;
let vault: Map<string, string>;
let resources: { threatsDir: string; allowlistsDir: string };

beforeEach(async () => {
	home = await makeTmpDir();
	vi.stubEnv("HOME", home);
	executionKey = key();
	approvalKey = key();
	vault = new Map();
	vi.spyOn(secretStore, "resolveSecretStore").mockReturnValue({
		kind: "windows-dpapi",
		location: "os-vault",
		osProtected: true,
		isAvailable: () => true,
		get: (id) => vault.get(id) ?? null,
		put: (id, value) => {
			vault.set(id, value);
		},
		revoke: (id) => {
			vault.delete(id);
		},
	});
	const dlp = syntheticDlpPolicy();
	dlp.supportedFormats = ["application/json", "text/plain"];
	const payload = behavioralPolicyPayload("tenant-a", {
		unavailable_action: "skip",
		learning_authorities: {
			execution: { broker: executionKey.publicKeyPem },
			approval: { operator: approvalKey.publicKeyPem },
		},
	});
	payload.dlp = { enabled: true, policy: dlp };
	provisioned = await provisionTenantDetectorPolicy({
		homeDir: home,
		agentRuntime: "codex",
		payload,
		entitlement: entitlementSnapshot({
			premiumModules: ["runtime_detectors", "behavioral_learning_v1"],
		}),
	});
	resources = { threatsDir: join(home, "threats"), allowlistsDir: join(home, "allowlists") };
	await mkdir(resources.threatsDir);
	await mkdir(resources.allowlistsDir);
});

afterEach(async () => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	await removeTmpDir(home);
});

function request(
	command = process.platform === "win32" ? "Write-Output 'completed'" : "printf completed",
) {
	return {
		sessionId: "approved-session",
		toolName: "Bash",
		artifacts: [],
		toolInput: {
			command,
			execution_shell: process.platform === "win32" ? "powershell.exe" : "/bin/sh",
		},
	};
}

async function proof(actualNative = false, value = request()) {
	const prepared = await prepareAuthorizedLearningExecution(
		"codex",
		value,
		{ keyId: "broker", ...executionKey },
		resources,
	);
	const startedAt = Date.now();
	const output = actualNative
		? await executeLearningCommand(String(prepared.request.toolInput.command))
		: "completed";
	const execution = await issueAuthorizedLearningExecution("codex", prepared.request, {
		keyId: "broker",
		...executionKey,
		startedAt,
		completedAt: Date.now(),
		output,
		receiptContext: prepared.receiptContext,
		inputDigest: prepared.inputDigest,
	});
	const approval = createLearningApprovalReceipt(
		execution,
		approvalKey.privateKeyPem,
		"operator",
		prepared.receiptContext,
	);
	return { prepared, execution, approval };
}

async function refreshGrant(extra: Record<string, unknown>) {
	const entitlement = { ...provisioned.entitlement, ...extra };
	const state = JSON.parse(await readFile(provisioned.managedPath, "utf8"));
	state.entitlement = entitlement;
	state.entitlement_sig = sign(
		null,
		Buffer.from(canonicalDetectorPolicyPayload(entitlement)),
		provisioned.keys.privateKey,
	).toString("base64");
	await writeFile(provisioned.managedPath, JSON.stringify(state));
}

describe("authorized signed behavioral learning lifecycle", () => {
	it("warms all actual detector legs with ten separately executed and approved operations, then stays read-only", async () => {
		for (let index = 0; index < 10; index += 1) {
			const command =
				process.platform === "win32"
					? `Write-Output 'document-${index}'`
					: `printf document-${index}`;
			const signed = await proof(true, request(command));
			const result = await ingestBehavioralLearningReceipt(
				"codex",
				{ execution: signed.execution, approval: signed.approval },
				signed.prepared.request.toolInput,
			);
			expect(result.learning).toMatchObject({ accepted: true, baselineSamplesAfter: index + 1 });
		}
		const fresh = await loadProvisionedLearningContext("codex");
		const command =
			process.platform === "win32" ? "Write-Output 'document-0'" : "printf document-0";
		const scored = await fresh.orchestrator.evaluate({
			tenantId: "tenant-a",
			sessionId: "approved-session",
			toolName: "Bash",
			command,
			riskScore: 0,
			timestamp: Date.now(),
			learningAllowed: true,
		});
		expect(scored.outcome).toBe("normal");
		expect(scored.explanations.map((leg) => leg.status)).toEqual(["ready", "ready", "ready"]);
		expect(scored.learning).toMatchObject({
			accepted: false,
			baselineSamplesBefore: 10,
			baselineSamplesAfter: 10,
		});
	});

	it("rejects private PEM and ASN.1 tails in declared-public authority and feed keys before handoff", async () => {
		const der = createPublicKey(executionKey.publicKeyPem).export({ type: "spki", format: "der" });
		const tailedDer = Buffer.concat([der, Buffer.from("private tail")]).toString("base64");
		for (const raw of [executionKey.publicKeyPem + executionKey.privateKeyPem, tailedDer]) {
			expect(() =>
				validateLearningAuthorities({
					execution: { broker: raw },
					approval: { operator: approvalKey.publicKeyPem },
				}),
			).toThrow(/exactly one/);
		}
		const publicPem = executionKey.publicKeyPem.replace(/\n/g, "\r\n");
		expect(
			validateLearningAuthorities({
				execution: { broker: publicPem },
				approval: { operator: approvalKey.publicKeyPem },
			}).execution.broker,
		).toBe(publicPem);
		const policy = JSON.parse(await readFile(provisioned.policyPath, "utf8"));
		policy.payload.behavioral.learning_authorities.execution.broker += executionKey.privateKeyPem;
		policy.sig_b64 = sign(
			null,
			Buffer.from(canonicalDetectorPolicyPayload(policy.payload)),
			provisioned.keys.privateKey,
		).toString("base64");
		await writeFile(provisioned.policyPath, JSON.stringify(policy));
		await expect(exportBrokerLearningAuthority("codex")).rejects.toThrow(/exactly one/);
		policy.payload.behavioral.learning_authorities.execution.broker = executionKey.publicKeyPem;
		policy.payload.reputation_feed = {
			feed_id: "test-feed",
			trusted_keys: { feed: executionKey.publicKeyPem + executionKey.privateKeyPem },
		};
		policy.sig_b64 = sign(
			null,
			Buffer.from(canonicalDetectorPolicyPayload(policy.payload)),
			provisioned.keys.privateKey,
		).toString("base64");
		await writeFile(provisioned.policyPath, JSON.stringify(policy));
		await expect(exportBrokerLearningAuthority("codex")).rejects.toThrow(/keyring/);
	});

	it("binds preflight to a fresh issuer grant renewed during local enforcement", async () => {
		const config = JSON.parse(await readFile(provisioned.configPath, "utf8"));
		config.cache.enabled = true;
		await writeFile(provisioned.configPath, JSON.stringify(config));
		vi.spyOn(VerdictCache.prototype, "load").mockImplementation(async () => {
			await refreshGrant({
				serial: "during-preflight-renewal",
				issued_at: new Date().toISOString(),
			});
		});
		// The verdict cache is opened only for calls that carry a URL or package,
		// so the renewal seam needs a URL in the command.
		const prepared = await prepareAuthorizedLearningExecution(
			"codex",
			request(
				process.platform === "win32"
					? "Write-Output 'https://example.com/completed'"
					: "printf https://example.com/completed",
			),
			{ keyId: "broker", ...executionKey },
			resources,
		);
		expect(prepared.receiptContext.entitlementSerial).toBe("during-preflight-renewal");
	});

	// AIDR-SKIP: AIDR-063 qa-owner - Actual current-user DPAPI is Windows-only; this case uses the real Windows vault rather than a mock
	it.skipIf(process.platform !== "win32")(
		"persists and restores with the real current-user DPAPI vault in an ephemeral home",
		async () => {
			vi.mocked(secretStore.resolveSecretStore).mockRestore();
			vi.stubEnv("AIDR_SECRET_STORE", "windows-dpapi");
			const signed = await proof(true);
			const accepted = await ingestBehavioralLearningReceipt(
				"codex",
				{ execution: signed.execution, approval: signed.approval },
				signed.prepared.request.toolInput,
			);
			expect(accepted.learning.accepted).toBe(true);
			const restored = await loadProvisionedLearningContext("codex");
			const result = await restored.orchestrator.evaluate({
				tenantId: "tenant-a",
				sessionId: "approved-session",
				toolName: "Bash",
				riskScore: 0,
				timestamp: Date.now(),
			});
			expect(result.learning.baselineSamplesBefore).toBe(1);
			const secretFiles = await readdir(join(home, ".singularity-aidr", "secrets"));
			expect(secretFiles).toHaveLength(1);
			const secretFile = secretFiles[0];
			if (!secretFile) throw new Error("Expected an ephemeral DPAPI ciphertext");
			expect(
				await readFile(join(home, ".singularity-aidr", "secrets", secretFile), "utf8"),
			).not.toMatch(/^-----BEGIN/);
		},
	);

	it("creates one authentication key under concurrent first initialization", async () => {
		const initializations = await Promise.allSettled([
			loadProvisionedLearningContext("codex"),
			loadProvisionedLearningContext("codex"),
		]);
		expect(initializations.some((result) => result.status === "fulfilled")).toBe(true);
		expect(vault.size).toBe(1);
		await expect(loadProvisionedLearningContext("codex")).resolves.toBeDefined();
	});

	it("executes the actual native foreground command, accepts once, and restores without raw input/output", async () => {
		const { prepared, execution, approval } = await proof(true);
		const result = await ingestBehavioralLearningReceipt(
			"codex",
			{ execution, approval },
			prepared.request.toolInput,
		);
		expect(result.learning).toMatchObject({ accepted: true, baselineSamplesAfter: 1 });
		await expect(
			ingestBehavioralLearningReceipt("codex", { execution, approval }, prepared.request.toolInput),
		).rejects.toThrow(/consumed/);
		const fresh = await loadProvisionedLearningContext("codex");
		const ordinary = await fresh.orchestrator.evaluate({
			tenantId: "tenant-a",
			sessionId: "approved-session",
			toolName: "Bash",
			riskScore: 0,
			timestamp: Date.now(),
			command: String(prepared.request.toolInput.command),
			learningAllowed: true,
		});
		expect(ordinary.learning).toMatchObject({ accepted: false, baselineSamplesBefore: 1 });
		const files = (await readdir(behavioralBaselineDir())).filter((name) =>
			name.endsWith(".v3.json"),
		);
		expect(files).toHaveLength(1);
		const journalFile = files[0];
		if (!journalFile) throw new Error("Expected the authenticated baseline journal");
		const journal = await readFile(join(behavioralBaselineDir(), journalFile), "utf8");
		expect(journal).not.toContain(String(prepared.request.toolInput.command));
		expect(journal).not.toContain("completed\\n");
	});

	it("survives ordinary issuer serial refresh but rejects stale pending receipt ingestion", async () => {
		const first = await proof();
		await ingestBehavioralLearningReceipt(
			"codex",
			{ execution: first.execution, approval: first.approval },
			first.prepared.request.toolInput,
		);
		const pending = await proof();
		await refreshGrant({ serial: "heartbeat-serial-2", issued_at: new Date().toISOString() });
		await expect(
			ingestBehavioralLearningReceipt(
				"codex",
				{ execution: pending.execution, approval: pending.approval },
				pending.prepared.request.toolInput,
			),
		).rejects.toThrow(/binding/);
		const current = await loadProvisionedLearningContext("codex");
		const scored = await current.orchestrator.evaluate({
			tenantId: "tenant-a",
			sessionId: "approved-session",
			toolName: "Bash",
			riskScore: 0,
			timestamp: Date.now(),
		});
		expect(scored.learning.baselineSamplesBefore).toBe(1);
	});

	it("requires distinct actual keys and rejects incorrect private key before execution", async () => {
		expect(() =>
			validateLearningAuthorities({
				execution: { one: executionKey.publicKeyPem },
				approval: { two: executionKey.publicKeyPem },
			}),
		).toThrow(/distinct/);
		await expect(
			prepareAuthorizedLearningExecution(
				"codex",
				request(),
				{ keyId: "broker", ...approvalKey },
				resources,
			),
		).rejects.toThrow(/Private key/);
	});

	it("rejects tampered input, missing independent consent and mismatched runtime/device", async () => {
		const signed = await proof();
		await expect(
			ingestBehavioralLearningReceipt(
				"codex",
				{ execution: signed.execution, approval: signed.approval },
				request("echo other").toolInput,
			),
		).rejects.toThrow(/input/);
		await expect(
			ingestBehavioralLearningReceipt(
				"codex",
				{ execution: signed.execution },
				signed.prepared.request.toolInput,
			),
		).rejects.toThrow();
		for (const field of [
			"tenantId",
			"deviceId",
			"agentRuntime",
			"policyDigest",
			"entitlementSerial",
		] as const) {
			expect(() =>
				verifyLearningExecutionReceipt(
					{ ...signed.execution, payload: { ...signed.execution.payload, [field]: "other" } },
					signed.prepared.receiptContext,
				),
			).toThrow();
		}
	});

	it("never issues a receipt for secret output, incomplete output or changed authority", async () => {
		const signed = await proof();
		const options = {
			keyId: "broker",
			...executionKey,
			startedAt: Date.now(),
			completedAt: Date.now(),
			output: "SSN: 123-45-6789",
			receiptContext: signed.prepared.receiptContext,
			inputDigest: signed.prepared.inputDigest,
		};
		await expect(
			issueAuthorizedLearningExecution("codex", signed.prepared.request, options),
		).rejects.toThrow(/output/);
		await expect(
			issueAuthorizedLearningExecution("codex", signed.prepared.request, {
				...options,
				output: "x".repeat(2 * 1024 * 1024 + 1),
			}),
		).rejects.toThrow(/output/);
		await refreshGrant({ serial: "replacement-grant" });
		await expect(
			issueAuthorizedLearningExecution("codex", signed.prepared.request, {
				...options,
				output: "completed",
			}),
		).rejects.toThrow(/changed/);
	});

	it("blocks signed tenant secret input at preflight", async () => {
		await expect(
			prepareAuthorizedLearningExecution(
				"codex",
				request(`echo ${TEST_DLP_MARKER}`),
				{ keyId: "broker", ...executionKey },
				resources,
			),
		).rejects.toThrow(/not permitted/);
	});

	it("validates target handoff on a separate account against fixed operator issuer roots", async () => {
		const signed = await proof();
		const handoff = await exportBrokerLearningAuthority("codex");
		const station = join(home, "independent-station");
		await mkdir(join(station, ".singularity-aidr"), { recursive: true });
		await writeFile(
			join(station, ".singularity-aidr/config.json"),
			await readFile(provisioned.configPath),
		);
		vi.stubEnv("HOME", station);
		const targetContext = await loadProvisionedLearningApprovalContext("codex", handoff);
		expect(targetContext.deviceId).toBe(signed.execution.payload.deviceId);
		const approval = createLearningApprovalReceipt(
			signed.execution,
			approvalKey.privateKeyPem,
			"operator",
			targetContext,
		);
		vi.stubEnv("HOME", home);
		expect(
			(
				await ingestBehavioralLearningReceipt(
					"codex",
					{ execution: signed.execution, approval },
					signed.prepared.request.toolInput,
				)
			).learning.accepted,
		).toBe(true);
		const unsafe = { ...handoff, managed: { ...handoff.managed, api_key: "should-never-travel" } };
		await expect(loadProvisionedLearningApprovalContext("codex", unsafe)).rejects.toThrow(
			/invalid/,
		);
	});

	it("disables learning on signed capability downgrade", async () => {
		const signed = await proof();
		await refreshGrant({ premium_modules: ["runtime_detectors"] });
		await expect(
			ingestBehavioralLearningReceipt(
				"codex",
				{ execution: signed.execution, approval: signed.approval },
				signed.prepared.request.toolInput,
			),
		).rejects.toThrow(/capability/);
	});
});
