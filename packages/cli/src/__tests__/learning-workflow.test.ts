import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

const custody = vi.hoisted(() => ({ secrets: new Map<string, string>(), forbidVault: false }));
const vaultModule = vi.hoisted(
	() => async (importOriginal: () => Promise<Record<string, unknown>>) => {
		const actual = await importOriginal();
		return {
			...actual,
			resolveSecretStore: (options?: { selection?: string }) => {
				if (options?.selection === "file-acl")
					return (actual.createFileAclStore as () => unknown)();
				if (custody.forbidVault)
					throw new Error("Independent approval must not need the broker vault.");
				return {
					kind: "windows-dpapi",
					location: "os-vault",
					osProtected: true,
					isAvailable: () => true,
					put: (id: string, secret: string) => custody.secrets.set(id, secret),
					get: (id: string) => custody.secrets.get(id) ?? null,
					revoke: (id: string) => custody.secrets.delete(id),
				};
			},
		};
	},
);
vi.mock("../../../core/src/secret-store.js", vaultModule);
vi.mock("../../../core/dist/secret-store.js", vaultModule);

const consent = vi.hoisted(() => ({ phrase: "" }));
vi.mock("node:readline/promises", () => ({
	createInterface: () => ({ once() {}, close() {}, question: async () => consent.phrase }),
}));

import { loadProvisionedLearningContext } from "@singularityrd/aidr-core";
import {
	learningApproveCommand,
	learningExecuteCommand,
	learningExportAuthorityCommand,
	learningIngestCommand,
} from "../commands/learning.js";
import { generateLearningAuthority, writePrivateNewJson } from "../utils/learning-authority.js";
import {
	behavioralPolicyPayload,
	entitlementSnapshot,
	provisionTenantDetectorPolicy,
	syntheticDlpPolicy,
} from "./learning-workflow-fixtures.js";

const roots: string[] = [];
const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
const stderrTty = Object.getOwnPropertyDescriptor(process.stderr, "isTTY");

afterEach(async () => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	if (stdinTty) Object.defineProperty(process.stdin, "isTTY", stdinTty);
	else delete (process.stdin as { isTTY?: boolean }).isTTY;
	if (stderrTty) Object.defineProperty(process.stderr, "isTTY", stderrTty);
	else delete (process.stderr as { isTTY?: boolean }).isTTY;
	custody.forbidVault = false;
	custody.secrets.clear();
	process.exitCode = 0;
	for (const path of roots.splice(0)) await rm(path, { recursive: true, force: true });
});

function station(home: string): void {
	vi.stubEnv("HOME", home);
	vi.stubEnv("USERPROFILE", home);
	vi.stubEnv("AIDR_BUILD_FLAVOR", "local");
	vi.stubEnv("AIDR_SECRET_STORE", "windows-dpapi");
}

it("runs the real signed broker, independent approval handoff and one-time durable learning workflow", async () => {
	const broker = await mkdtemp(join(tmpdir(), "aidr-learning-broker-"));
	const approving = await mkdtemp(join(tmpdir(), "aidr-learning-operator-"));
	roots.push(broker, approving);
	const logs = vi.spyOn(console, "log").mockImplementation(() => {});
	const errors = vi.spyOn(console, "error").mockImplementation(() => {});
	vi.spyOn(process.stderr, "write").mockImplementation(() => true);
	Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
	Object.defineProperty(process.stderr, "isTTY", { value: true, configurable: true });
	process.exitCode = 0;

	station(broker);
	const executionRef = join(broker, "execution-authority.json");
	const executionKey = await generateLearningAuthority({
		role: "execution",
		out: executionRef,
		secretStore: "file-acl",
	});
	station(approving);
	const approvalRef = join(approving, "approval-authority.json");
	const approvalKey = await generateLearningAuthority({
		role: "approval",
		out: approvalRef,
		secretStore: "file-acl",
	});
	station(broker);
	const installed = await provisionTenantDetectorPolicy({
		homeDir: broker,
		agentRuntime: "opencode",
		payload: {
			...(await behavioralPolicyPayload(undefined, {
				unavailable_action: "skip",
				learning_authorities: {
					execution: { [executionKey.key_id]: executionKey.public_key_pem },
					approval: { [approvalKey.key_id]: approvalKey.public_key_pem },
				},
			})),
			dlp: {
				enabled: true,
				policy: { ...syntheticDlpPolicy(), supportedFormats: ["application/json", "text/plain"] },
			},
		},
		entitlement: entitlementSnapshot({
			premiumModules: ["runtime_detectors", "behavioral_learning_v1"],
		}),
	});
	const requestPath = join(broker, "request.json");
	const command =
		process.platform === "win32"
			? "Write-Output 'ordinary document'"
			: "printf 'ordinary document\\n'";
	const toolInput = {
		command,
		execution_shell: process.platform === "win32" ? "powershell.exe" : "/bin/sh",
	};
	await writePrivateNewJson(requestPath, {
		sessionId: "learning-session",
		toolName: "Bash",
		toolInput,
	});
	const receiptPath = join(broker, "execution.json");
	const handoffPath = join(broker, "handoff.json");
	await learningExecuteCommand({
		runtime: "opencode",
		request: requestPath,
		keyRef: executionRef,
		out: receiptPath,
	} as Parameters<typeof learningExecuteCommand>[0]);
	expect(errors.mock.calls).toEqual([]);
	expect(process.exitCode).toBe(0);
	const execution = JSON.parse(await readFile(receiptPath, "utf8"));
	expect(execution.payload).toMatchObject({
		outcome: "success",
		outputInspection: "clean",
		toolName: "Bash",
	});
	expect(JSON.stringify(execution)).not.toContain(command);
	await learningExportAuthorityCommand({ runtime: "opencode", out: handoffPath });
	const handoff = JSON.parse(await readFile(handoffPath, "utf8"));
	expect(JSON.stringify(handoff)).not.toMatch(/privateKeyPem|api_key|PRIVATE KEY/);

	station(approving);
	await provisionTenantDetectorPolicy({
		homeDir: approving,
		agentRuntime: "opencode",
		keys: installed.keys,
		skipEntitlement: true,
		skipPolicy: true,
	});
	const approvingHandoff = join(approving, "handoff.json");
	await writePrivateNewJson(approvingHandoff, handoff);
	custody.forbidVault = true;
	consent.phrase = `APPROVE ${execution.payload.executionId}`;
	const approvalPath = join(approving, "approval.json");
	await learningApproveCommand({
		runtime: "opencode",
		request: requestPath,
		receipt: receiptPath,
		brokerAuthority: approvingHandoff,
		keyRef: approvalRef,
		out: approvalPath,
	} as Parameters<typeof learningApproveCommand>[0]);
	expect(errors.mock.calls).toEqual([]);
	expect(process.exitCode).toBe(0);
	expect(JSON.parse(await readFile(approvalPath, "utf8")).payload).toMatchObject({
		benign: true,
		consent: true,
	});

	station(broker);
	custody.forbidVault = false;
	const options = {
		runtime: "opencode",
		request: requestPath,
		receipt: receiptPath,
		approval: approvalPath,
	} as Parameters<typeof learningIngestCommand>[0];
	await learningIngestCommand(options);
	const accepted = JSON.parse(logs.mock.calls.at(-1)?.[0] as string).result;
	expect(accepted.learning).toMatchObject({
		accepted: true,
		baselineSamplesBefore: 0,
		baselineSamplesAfter: 1,
	});
	const reportsBeforeReplay = logs.mock.calls.length;
	await learningIngestCommand(options);
	expect(logs.mock.calls).toHaveLength(reportsBeforeReplay);
	expect(errors.mock.calls).toHaveLength(1);
	expect(process.exitCode).toBe(1);
	const fresh = await loadProvisionedLearningContext("opencode");
	const restored = await fresh.orchestrator.evaluate({
		tenantId: installed.tenantId,
		sessionId: "learning-session",
		toolName: "Bash",
		command,
		riskScore: 0,
		timestamp: Date.now(),
		learningAllowed: false,
	});
	expect(restored.learning.baselineSamplesBefore).toBe(1);
	const stateDir = join(broker, ".singularity-aidr", "behavioral-baseline");
	const saved = (await readdir(stateDir)).find((name) => name.endsWith(".v3.json"));
	expect(saved).toBeTruthy();
	expect(await readFile(join(stateDir, saved as string), "utf8")).not.toContain(command);
}, 120_000);
