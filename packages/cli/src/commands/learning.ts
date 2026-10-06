import { createPublicKey } from "node:crypto";
import { createInterface } from "node:readline/promises";
import {
	type AgentRuntime,
	type BrokerLearningAuthorityBundle,
	createLearningApprovalReceipt,
	exportBrokerLearningAuthority,
	ingestBehavioralLearningReceipt,
	issueAuthorizedLearningExecution,
	type LearningReceiptContext,
	learningInputDigest,
	loadProvisionedLearningApprovalContext,
	prepareAuthorizedLearningExecution,
	type SignedLearningExecutionReceipt,
	type ToolEvaluationRequest,
	verifyLearningExecutionReceipt,
} from "@singularityrd/aidr-core";
import {
	generateLearningAuthority,
	loadLearningAuthority,
	prepareLearningOutput,
	readJsonFile,
	writePrivateNewJson,
} from "../utils/learning-authority.js";
import { executeLearningCommand } from "../utils/learning-execution.js";
import { resolveBundledDataDirs } from "../utils/test-protection.js";

const RUNTIMES = ["claude-code", "cursor", "vscode", "openclaw", "opencode", "codex"] as const;
const SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

interface LearningOptions {
	runtime: string;
	request: string;
	keyRef: string;
	out: string;
	receipt: string;
	approval: string;
	brokerAuthority: string;
}

function runtime(value: string): AgentRuntime {
	if (!(RUNTIMES as readonly string[]).includes(value)) {
		throw new Error("Learning runtime is unsupported.");
	}
	return value as AgentRuntime;
}

function record(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("Learning request is invalid.");
	}
	return value as Record<string, unknown>;
}

/** Only this broker's concrete shell operation can receive an execution receipt. */
export function learningRequest(value: unknown, executing = false): ToolEvaluationRequest {
	const request = record(value);
	const input = record(request.toolInput);
	if (
		Object.keys(request).some((key) => !["sessionId", "toolName", "toolInput"].includes(key)) ||
		typeof request.sessionId !== "string" ||
		!SESSION_ID.test(request.sessionId) ||
		request.toolName !== "Bash" ||
		Object.keys(input).some((key) => !["command", "execution_shell"].includes(key)) ||
		typeof input.execution_shell !== "string" ||
		!["powershell.exe", "/bin/sh"].includes(input.execution_shell) ||
		typeof input.command !== "string" ||
		!input.command.trim() ||
		input.command.length > 32_768 ||
		input.command.includes("\0")
	) {
		throw new Error("Learning request must contain one bounded Bash command.");
	}
	if (
		executing &&
		input.execution_shell !== (process.platform === "win32" ? "powershell.exe" : "/bin/sh")
	) {
		throw new Error("Learning execution shell does not match this host.");
	}
	return {
		sessionId: request.sessionId,
		toolName: "Bash",
		toolInput: {
			command: input.command,
			execution_shell: input.execution_shell,
		},
		artifacts: [],
	};
}

function authorityAllowed(
	context: LearningReceiptContext,
	role: "execution" | "approval",
	authority: { keyId: string; publicKeyPem: string },
): void {
	const expected = context.authorities[role][authority.keyId];
	if (!expected) throw new Error("Learning authority is not authorized by the installed policy.");
	const actualDer = createPublicKey(authority.publicKeyPem).export({ format: "der", type: "spki" });
	const expectedKey = expected.trim().startsWith("-----BEGIN")
		? createPublicKey(expected)
		: createPublicKey({ key: Buffer.from(expected, "base64"), format: "der", type: "spki" });
	const expectedDer = expectedKey.export({ format: "der", type: "spki" });
	if (!actualDer.equals(expectedDer))
		throw new Error("Learning authority identity does not match.");
}

function assertMatchingExecution(
	request: ToolEvaluationRequest,
	execution: SignedLearningExecutionReceipt,
): void {
	if (
		request.sessionId !== execution.payload.sessionId ||
		request.toolName !== execution.payload.toolName ||
		learningInputDigest(request.toolInput) !== execution.payload.inputDigest
	) {
		throw new Error("Learning approval input does not match the executed request.");
	}
}

function failed(
	operation: string,
	guidance = "Check the signed policy, active entitlement, authority reference, input and output limits.",
): void {
	// Vault/crypto/output errors may contain private material; never echo their text.
	console.error(`Learning ${operation} failed. ${guidance} No baseline acceptance is reported.`);
	process.exitCode = 1;
}

export async function learningKeygenCommand(options: {
	role: string;
	out: string;
	secretStore?: string;
}): Promise<void> {
	try {
		if (options.role !== "execution" && options.role !== "approval") {
			throw new Error("Learning authority role is invalid.");
		}
		const reference = await generateLearningAuthority({ ...options, role: options.role });
		console.log(
			JSON.stringify({
				command: "learning keygen",
				role: reference.role,
				keyId: reference.key_id,
				publicKeyPem: reference.public_key_pem,
				reference: options.out,
				store: reference.private.store,
			}),
		);
	} catch {
		failed("key generation", "Check the role, new private destination and selected vault.");
	}
}

export async function learningExportAuthorityCommand(options: {
	runtime: string;
	out: string;
}): Promise<void> {
	try {
		const agentRuntime = runtime(options.runtime);
		await prepareLearningOutput(options.out);
		const bundle = await exportBrokerLearningAuthority(agentRuntime);
		await writePrivateNewJson(options.out, bundle);
		console.log(JSON.stringify({ command: "learning export-authority", authority: options.out }));
	} catch {
		failed("authority export");
	}
}

export async function learningExecuteCommand(options: LearningOptions): Promise<void> {
	try {
		const agentRuntime = runtime(options.runtime);
		await prepareLearningOutput(options.out);
		const request = learningRequest(await readJsonFile(options.request, 64 * 1024), true);
		const authority = await loadLearningAuthority(options.keyRef, "execution");
		const prepared = await prepareAuthorizedLearningExecution(
			agentRuntime,
			request,
			authority,
			resolveBundledDataDirs(),
		);
		const startedAt = Date.now();
		const output = await executeLearningCommand(String(prepared.request.toolInput.command));
		const completedAt = Date.now();
		const receipt = await issueAuthorizedLearningExecution(agentRuntime, prepared.request, {
			...authority,
			startedAt,
			completedAt,
			output,
			receiptContext: prepared.receiptContext,
			inputDigest: prepared.inputDigest,
		});
		await writePrivateNewJson(options.out, receipt);
		console.log(JSON.stringify({ command: "learning execute", receipt: options.out }));
	} catch {
		failed("execution or receipt publication");
	}
}

/** Explicit consent is interactive and bound to the verified execution identity. */
async function confirmBenignLearning(
	receipt: SignedLearningExecutionReceipt,
	request: ToolEvaluationRequest,
): Promise<boolean> {
	if (!process.stdin.isTTY || !process.stderr.isTTY) {
		throw new Error("Learning approval requires an interactive terminal.");
	}
	const summary = {
		tenant: receipt.payload.tenantId,
		device: receipt.payload.deviceId,
		session: receipt.payload.sessionId,
		tool: receipt.payload.toolName,
		execution: receipt.payload.executionId,
		completedAt: receipt.payload.completedAt,
		inputDigest: receipt.payload.inputDigest,
		command: request.toolInput.command,
		executionShell: request.toolInput.execution_shell,
	};
	process.stderr.write(
		`${JSON.stringify(summary).replace(/[\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "?")}\n`,
	);
	const phrase = `APPROVE ${receipt.payload.executionId}`;
	const terminal = createInterface({ input: process.stdin, output: process.stderr });
	const abort = new AbortController();
	terminal.once("close", () => abort.abort());
	terminal.once("SIGINT", () => abort.abort());
	try {
		const answer = await terminal.question(
			`Confirm this execution is benign and consent to pseudonymous baseline retention for up to 30 days. Type ${phrase}: `,
			{ signal: abort.signal },
		);
		return answer === phrase;
	} finally {
		terminal.close();
	}
}

export async function learningApproveCommand(options: LearningOptions): Promise<void> {
	try {
		const agentRuntime = runtime(options.runtime);
		await prepareLearningOutput(options.out);
		const rawExecution = await readJsonFile(options.receipt);
		const request = learningRequest(await readJsonFile(options.request, 64 * 1024));
		const authority = await loadLearningAuthority(options.keyRef, "approval");
		const handoff = (await readJsonFile(
			options.brokerAuthority,
			10 * 1024 * 1024,
			true,
		)) as BrokerLearningAuthorityBundle;
		const installed = await loadProvisionedLearningApprovalContext(agentRuntime, handoff);
		authorityAllowed(installed, "approval", authority);
		const execution = verifyLearningExecutionReceipt(rawExecution, installed);
		assertMatchingExecution(request, execution);
		if (!(await confirmBenignLearning(execution, request))) {
			throw new Error("Learning approval was not given.");
		}
		const freshHandoff = (await readJsonFile(
			options.brokerAuthority,
			10 * 1024 * 1024,
			true,
		)) as BrokerLearningAuthorityBundle;
		const fresh = await loadProvisionedLearningApprovalContext(agentRuntime, freshHandoff);
		authorityAllowed(fresh, "approval", authority);
		verifyLearningExecutionReceipt(execution, fresh);
		assertMatchingExecution(request, execution);
		const approval = createLearningApprovalReceipt(
			execution,
			authority.privateKeyPem,
			authority.keyId,
			fresh,
		);
		await writePrivateNewJson(options.out, approval);
		console.log(JSON.stringify({ command: "learning approve", approval: options.out }));
	} catch {
		failed("approval");
	}
}

export async function learningIngestCommand(options: LearningOptions): Promise<void> {
	try {
		const agentRuntime = runtime(options.runtime);
		const execution = await readJsonFile(options.receipt);
		const approval = await readJsonFile(options.approval);
		const request = learningRequest(await readJsonFile(options.request, 64 * 1024));
		const result = await ingestBehavioralLearningReceipt(
			agentRuntime,
			{ execution, approval },
			request.toolInput,
		);
		console.log(JSON.stringify({ command: "learning ingest", result }));
		if (!result.learning.accepted) process.exitCode = 1;
	} catch {
		failed("ingestion");
	}
}
