import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	generate: vi.fn(),
	load: vi.fn(),
	read: vi.fn(),
	write: vi.fn(),
	output: vi.fn(),
	prepare: vi.fn(),
	execute: vi.fn(),
	issue: vi.fn(),
	context: vi.fn(),
	export: vi.fn(),
	verify: vi.fn(),
	approve: vi.fn(),
	ingest: vi.fn(),
	question: vi.fn(),
	close: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", () => ({
	prepareAuthorizedLearningExecution: mocks.prepare,
	issueAuthorizedLearningExecution: mocks.issue,
	loadProvisionedLearningApprovalContext: mocks.context,
	exportBrokerLearningAuthority: mocks.export,
	verifyLearningExecutionReceipt: mocks.verify,
	createLearningApprovalReceipt: mocks.approve,
	ingestBehavioralLearningReceipt: mocks.ingest,
	learningInputDigest: (input: unknown) => JSON.stringify(input),
}));
vi.mock("../utils/learning-authority.js", () => ({
	generateLearningAuthority: mocks.generate,
	loadLearningAuthority: mocks.load,
	readJsonFile: mocks.read,
	writePrivateNewJson: mocks.write,
	prepareLearningOutput: mocks.output,
}));
vi.mock("../utils/learning-execution.js", () => ({ executeLearningCommand: mocks.execute }));
vi.mock("../utils/test-protection.js", () => ({
	resolveBundledDataDirs: () => ({
		threatsDir: "bundled/threats",
		allowlistsDir: "bundled/allowlists",
	}),
}));
vi.mock("node:readline/promises", () => ({
	createInterface: () => ({ once: () => {}, question: mocks.question, close: mocks.close }),
}));

import {
	learningApproveCommand,
	learningExecuteCommand,
	learningExportAuthorityCommand,
	learningIngestCommand,
	learningKeygenCommand,
	learningRequest,
} from "../commands/learning.js";

const { publicKey } = generateKeyPairSync("ed25519");
const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
const shell = process.platform === "win32" ? "powershell.exe" : "/bin/sh";
const request = {
	sessionId: "session-1",
	toolName: "Bash",
	toolInput: { command: "echo clean", execution_shell: shell },
};
const authority = { keyId: "approval-key", publicKeyPem: pem, privateKeyPem: "PRIVATE-SENTINEL" };
const receipt = {
	payload: {
		executionId: "ab4abfc5-4118-4d22-8a2f-85f77a526788",
		tenantId: "tenant-1",
		deviceId: "device-1",
		sessionId: "session-1",
		toolName: "Bash",
		completedAt: new Date().toISOString(),
		inputDigest: JSON.stringify(request.toolInput),
	},
};
const context = { authorities: { execution: {}, approval: { "approval-key": pem } } };
const options = {
	runtime: "opencode",
	request: "request.json",
	keyRef: "authority.json",
	out: "output.json",
	receipt: "execution.json",
	approval: "approval.json",
	brokerAuthority: "broker-authority.json",
};
const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
const stderrTty = Object.getOwnPropertyDescriptor(process.stderr, "isTTY");

beforeEach(() => {
	vi.clearAllMocks();
	process.exitCode = 0;
	Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
	Object.defineProperty(process.stderr, "isTTY", { value: true, configurable: true });
	vi.spyOn(console, "log").mockImplementation(() => {});
	vi.spyOn(console, "error").mockImplementation(() => {});
	vi.spyOn(process.stderr, "write").mockImplementation(() => true);
	mocks.output.mockResolvedValue(undefined);
	mocks.read.mockImplementation(async (path: string) =>
		path === "request.json" ? structuredClone(request) : structuredClone(receipt),
	);
	mocks.load.mockResolvedValue(authority);
	mocks.prepare.mockResolvedValue({
		request: learningRequest(request),
		receiptContext: context,
		inputDigest: "prepared-input-digest",
	});
	mocks.execute.mockResolvedValue("clean actual output");
	mocks.issue.mockResolvedValue({ signed: "execution" });
	mocks.context.mockResolvedValue(context);
	mocks.export.mockResolvedValue({ public: "signed handoff" });
	mocks.verify.mockImplementation((value) => value);
	mocks.question.mockResolvedValue(`APPROVE ${receipt.payload.executionId}`);
	mocks.approve.mockReturnValue({ signed: "approval" });
	mocks.ingest.mockResolvedValue({ learning: { accepted: true } });
	mocks.write.mockResolvedValue(undefined);
});

afterEach(() => {
	vi.restoreAllMocks();
	if (stdinTty) Object.defineProperty(process.stdin, "isTTY", stdinTty);
	else delete (process.stdin as { isTTY?: boolean }).isTTY;
	if (stderrTty) Object.defineProperty(process.stderr, "isTTY", stderrTty);
	else delete (process.stderr as { isTTY?: boolean }).isTTY;
	process.exitCode = 0;
});

describe("explicit learning commands", () => {
	it("exports only the verified public authority handoff to a new private file", async () => {
		await learningExportAuthorityCommand({ runtime: "opencode", out: "handoff.json" });
		expect(mocks.output).toHaveBeenCalledWith("handoff.json");
		expect(mocks.export).toHaveBeenCalledWith("opencode");
		expect(mocks.write).toHaveBeenCalledWith("handoff.json", { public: "signed handoff" });
		expect(mocks.load).not.toHaveBeenCalled();
	});

	it("rejects caller-controlled shell, environment and aliases before execution", () => {
		for (const invalid of [
			{ ...request, artifacts: [] },
			{ ...request, cwd: "/elsewhere" },
			{ ...request, toolInput: { ...request.toolInput, env: {} } },
			{ ...request, toolInput: { ...request.toolInput, execution_shell: [shell] } },
			{ ...request, toolName: "execute" },
		])
			expect(() => learningRequest(invalid, true)).toThrow();
		expect(() =>
			learningRequest(
				{
					...request,
					toolInput: {
						...request.toolInput,
						execution_shell: shell === "/bin/sh" ? "powershell.exe" : "/bin/sh",
					},
				},
				true,
			),
		).toThrow();
	});

	it("checks a new writable output before any supervised operation", async () => {
		mocks.output.mockRejectedValue(new Error("existing output"));
		await learningExecuteCommand(options);
		expect(mocks.prepare).not.toHaveBeenCalled();
		expect(mocks.execute).not.toHaveBeenCalled();
		expect(process.exitCode).toBe(1);
	});

	it("does not run when the installed signed grant refuses preflight", async () => {
		mocks.prepare.mockRejectedValue(new Error("policy denied"));
		await learningExecuteCommand(options);
		expect(mocks.execute).not.toHaveBeenCalled();
		expect(mocks.issue).not.toHaveBeenCalled();
	});

	it("does not issue a receipt after actual execution fails or output is incomplete", async () => {
		mocks.execute.mockRejectedValue(new Error("PRIVATE-SENTINEL"));
		await learningExecuteCommand(options);
		expect(mocks.issue).not.toHaveBeenCalled();
		expect(mocks.write).not.toHaveBeenCalled();
		expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain("PRIVATE-SENTINEL");
	});

	it("binds actual execution timing, output and preflight context before publication", async () => {
		await learningExecuteCommand(options);
		expect(mocks.issue).toHaveBeenCalledWith(
			"opencode",
			learningRequest(request),
			expect.objectContaining({
				output: "clean actual output",
				receiptContext: context,
				startedAt: expect.any(Number),
				completedAt: expect.any(Number),
			}),
		);
		expect(mocks.write).toHaveBeenCalledWith("output.json", { signed: "execution" });
		expect(JSON.stringify(vi.mocked(console.log).mock.calls)).not.toContain("PRIVATE-SENTINEL");
		expect(JSON.stringify(vi.mocked(console.log).mock.calls)).not.toContain("clean actual output");
	});

	it("refuses approval when the actual reviewed request differs from the receipt", async () => {
		mocks.read.mockImplementation(async (path: string) =>
			path === "request.json"
				? { ...request, toolInput: { ...request.toolInput, command: "echo different" } }
				: receipt,
		);
		await learningApproveCommand(options);
		expect(mocks.question).not.toHaveBeenCalled();
		expect(mocks.approve).not.toHaveBeenCalled();
	});

	it("refuses an approval role using an unauthorized real public key before prompting", async () => {
		mocks.load.mockResolvedValue({
			...authority,
			publicKeyPem: generateKeyPairSync("ed25519")
				.publicKey.export({ type: "spki", format: "pem" })
				.toString(),
		});
		await learningApproveCommand(options);
		expect(mocks.question).not.toHaveBeenCalled();
		expect(mocks.approve).not.toHaveBeenCalled();
	});

	it("requires interactive exact consent and does not accept a generic yes", async () => {
		mocks.question.mockResolvedValue("yes");
		await learningApproveCommand(options);
		expect(mocks.approve).not.toHaveBeenCalled();
		mocks.question.mockClear();
		Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
		await learningApproveCommand(options);
		expect(mocks.question).not.toHaveBeenCalled();
	});

	it("revalidates installed trust and expiry after explicit operator consent", async () => {
		mocks.verify.mockReturnValueOnce(receipt).mockImplementationOnce(() => {
			throw new Error("expired during consent");
		});
		await learningApproveCommand(options);
		expect(mocks.question).toHaveBeenCalledOnce();
		expect(mocks.approve).not.toHaveBeenCalled();
		expect(mocks.write).not.toHaveBeenCalled();
	});

	it("shows the actual request, signs only after consent and writes only public approval", async () => {
		await learningApproveCommand(options);
		expect(mocks.question).toHaveBeenCalledWith(
			expect.stringContaining("pseudonymous baseline retention for up to 30 days"),
			expect.any(Object),
		);
		expect(mocks.context).toHaveBeenCalledTimes(2);
		expect(vi.mocked(process.stderr.write).mock.calls[0]?.[0]).toContain("echo clean");
		expect(mocks.approve).toHaveBeenCalledOnce();
		expect(mocks.write).toHaveBeenCalledWith("output.json", { signed: "approval" });
	});

	it("ingests both proofs with the original execution shell and input snapshot", async () => {
		const otherShell = shell === "/bin/sh" ? "powershell.exe" : "/bin/sh";
		mocks.read.mockImplementation(async (path: string) =>
			path === "request.json"
				? { ...request, toolInput: { ...request.toolInput, execution_shell: otherShell } }
				: { path },
		);
		await learningIngestCommand(options);
		expect(mocks.ingest).toHaveBeenCalledWith(
			"opencode",
			{ execution: { path: "execution.json" }, approval: { path: "approval.json" } },
			{ ...request.toolInput, execution_shell: otherShell },
		);
	});

	it("reports only public key metadata on key generation", async () => {
		mocks.generate.mockResolvedValue({
			role: "execution",
			key_id: "key-1",
			public_key_pem: pem,
			private: { store: "windows-dpapi", id: "opaque-id" },
		});
		await learningKeygenCommand({ role: "execution", out: "authority.json" });
		expect(JSON.stringify(vi.mocked(console.log).mock.calls)).not.toContain("opaque-id");
	});
});
