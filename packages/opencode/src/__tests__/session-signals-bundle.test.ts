/**
 * Canary credentials and runaway failure tracking through the built plugin
 * (dist/index.js): `chat.message` blocks a prompt carrying a decoy value,
 * `tool.execute.after` records tool output carrying one as a canary incident,
 * and a bash result whose `metadata.exit` is non-zero counts towards the
 * repeated-failure signal of the next identical `tool.execute.before`.
 */

import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CanaryRecord, deployCanaries } from "../../../core/src/canary/index.js";
import { openCodeToolFailed } from "../output-handler.js";

const PLUGIN_DIST = resolve(__dirname, "..", "..", "dist", "index.js");

interface Hooks {
	"chat.message"?: (
		input: { sessionID: string; messageID?: string },
		output: { message: { id: string; sessionID: string; role: "user" }; parts: unknown[] },
	) => Promise<void>;
	"tool.execute.before"?: (
		input: { tool: string; sessionID: string; callID: string },
		output: { args: Record<string, unknown> },
	) => Promise<void>;
	"tool.execute.after"?: (
		input: { tool: string; sessionID: string; callID: string; args: unknown },
		output: Record<string, unknown>,
	) => Promise<void>;
}

const saved: Record<string, string | undefined> = {};
let home: string;
let aidrDir: string;
let hooks: Hooks;
let records: CanaryRecord[];

function token(kind: CanaryRecord["kind"], index = 0): string {
	const path = records.find((record) => record.kind === kind)?.path as string;
	return [...readFileSync(path, "utf8").matchAll(/[A-Za-z0-9]{20,}/g)][index]?.[0] as string;
}

async function auditEntries(): Promise<Array<Record<string, unknown>>> {
	try {
		return (await readFile(join(aidrDir, "audit.jsonl"), "utf8"))
			.split("\n")
			.filter((line) => line.trim())
			.map((line) => JSON.parse(line) as Record<string, unknown>);
	} catch {
		return [];
	}
}

beforeAll(async () => {
	for (const key of ["HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"]) {
		saved[key] = process.env[key];
	}
	home = await mkdtemp(join(tmpdir(), "aidr-opencode-signals-"));
	process.env.HOME = home;
	process.env.USERPROFILE = home;
	process.env.XDG_CONFIG_HOME = join(home, ".config");
	process.env.XDG_CACHE_HOME = join(home, ".cache");
	aidrDir = join(home, ".singularity-aidr");
	await mkdir(aidrDir, { recursive: true });
	await writeFile(
		join(aidrDir, "config.json"),
		JSON.stringify({ mode: "local", logging: { enabled: true, path: join(aidrDir, "audit.jsonl") } }),
	);
	records = deployCanaries({
		homeDir: home,
		projectDir: join(home, "project"),
		registryPath: join(aidrDir, "canary", "registry.json"),
	}).deployed;

	const mod = (await import(PLUGIN_DIST)) as {
		default: (input: Record<string, unknown>) => Promise<Hooks>;
	};
	hooks = await mod.default({
		client: {
			app: { log: async () => undefined },
			tui: { showToast: async () => true },
		},
		project: { id: "test-project" },
		directory: home,
		worktree: home,
		$: {},
	});
}, 30_000);

afterAll(async () => {
	for (const [key, value] of Object.entries(saved)) {
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
	await rm(home, { recursive: true, force: true });
});

describe("OpenCode canary credentials (built plugin)", () => {
	it("chat.message blocks a prompt carrying a decoy value and records it", async () => {
		const secret = token("aws");
		const parts = [
			{ id: "prt_1", sessionID: "ses_c", messageID: "msg_1", type: "text", text: `key ${secret}` },
		];
		const submit = hooks["chat.message"]?.(
			{ sessionID: "ses_c" },
			{ message: { id: "msg_1", sessionID: "ses_c", role: "user" }, parts },
		);
		await expect(submit).rejects.toThrow(/canary credential/);
		expect(JSON.stringify(parts)).not.toContain(secret);
		const entries = await auditEntries();
		expect(entries).toContainEqual(
			expect.objectContaining({ category: "canary_triggered", session_id: "ses_c" }),
		);
		expect(JSON.stringify(entries)).not.toContain(secret);
	});

	it("tool.execute.after records tool output carrying a decoy value", async () => {
		const secret = token("env", 1);
		const output = {
			title: "grep",
			output: `.env.backup:4:JWT_SECRET=${secret}`,
			metadata: { exit: 0 },
		};
		await hooks["tool.execute.after"]?.(
			{ tool: "bash", sessionID: "ses_out", callID: "call_1", args: { command: "grep -rn SECRET ." } },
			output,
		);
		// Output inspection quarantines it (OUT-CANARY-001); the incident is recorded.
		expect(output.output).not.toContain(secret);
		const entries = await auditEntries();
		expect(entries).toContainEqual(
			expect.objectContaining({
				category: "canary_triggered",
				source: "canary",
				tool_name: "bash",
				session_id: "ses_out",
			}),
		);
		expect(JSON.stringify(entries)).not.toContain(secret);
	});
});

describe("OpenCode runaway failure tracking (built plugin)", () => {
	it("reads only explicit failure markers", () => {
		expect(openCodeToolFailed({ output: "x", metadata: { exit: 1 } })).toBe(true);
		expect(openCodeToolFailed({ output: "x", metadata: { exit: 0 } })).toBe(false);
		expect(openCodeToolFailed({ output: "x", metadata: { exit: null } })).toBe(false);
		expect(openCodeToolFailed({ content: [], isError: true })).toBe(true);
		expect(openCodeToolFailed({ content: [], isError: false })).toBe(false);
		expect(openCodeToolFailed({ output: "failed", metadata: {} })).toBe(false);
	});

	it("pauses a bash command that failed three times on its next identical call", async () => {
		const args = { command: "npm run build", description: "build" };
		for (let attempt = 0; attempt < 3; attempt += 1) {
			await hooks["tool.execute.after"]?.(
				{ tool: "bash", sessionID: "ses_loop", callID: `call_${attempt}`, args },
				{ title: "build", output: "build failed", metadata: { exit: 1 } },
			);
		}
		await expect(
			hooks["tool.execute.before"]?.(
				{ tool: "bash", sessionID: "ses_loop", callID: "call_retry" },
				{ args: { ...args } },
			),
		).rejects.toThrow(/already failed 3 times/);

		// Successful runs in another session never count.
		for (let attempt = 0; attempt < 3; attempt += 1) {
			await hooks["tool.execute.after"]?.(
				{ tool: "bash", sessionID: "ses_ok", callID: `ok_${attempt}`, args },
				{ title: "build", output: "done", metadata: { exit: 0 } },
			);
		}
		await expect(
			hooks["tool.execute.before"]?.(
				{ tool: "bash", sessionID: "ses_ok", callID: "ok_retry" },
				{ args: { ...args } },
			),
		).resolves.toBeUndefined();
	});
});
