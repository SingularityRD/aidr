/**
 * Canary credentials through the BUILT OpenClaw plugin (dist/index.cjs): the
 * `before_agent_run` gate blocks a prompt that carries a decoy value, and
 * `after_tool_call` records tool output that carries one as a canary incident.
 * Both land in the audit log with canary ids only. The bundle also ships the
 * toxic-flow capability data next to its threat rules.
 */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CanaryRecord, deployCanaries } from "../../../core/src/canary/index.js";

const require = createRequire(import.meta.url);
const PACKAGE_ROOT = resolve(__dirname, "..", "..");
const PLUGIN_DIST = join(PACKAGE_ROOT, "dist", "index.cjs");

type Handler = (event: unknown, ctx?: unknown) => Promise<unknown>;

const handlers = new Map<string, Handler>();
const saved: Record<string, string | undefined> = {};
let home: string;
let records: CanaryRecord[];

function token(kind: CanaryRecord["kind"], index = 0): string {
	const path = records.find((record) => record.kind === kind)?.path as string;
	return [...readFileSync(path, "utf8").matchAll(/[A-Za-z0-9]{20,}/g)][index]?.[0] as string;
}

function auditEntries(): Array<Record<string, unknown>> {
	try {
		return readFileSync(join(home, ".singularity-aidr", "audit.jsonl"), "utf8")
			.split("\n")
			.filter((line) => line.trim())
			.map((line) => JSON.parse(line) as Record<string, unknown>);
	} catch {
		return [];
	}
}

function handler(event: string): Handler {
	const found = handlers.get(event);
	if (!found) throw new Error(`${event} was not registered`);
	return found;
}

beforeAll(() => {
	for (const key of ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"]) saved[key] = process.env[key];
	home = mkdtempSync(join(tmpdir(), "aidr-openclaw-canary-"));
	process.env.HOME = home;
	process.env.USERPROFILE = home;
	process.env.XDG_CONFIG_HOME = join(home, ".config");
	records = deployCanaries({
		homeDir: home,
		projectDir: join(home, "project"),
		registryPath: join(home, ".singularity-aidr", "canary", "registry.json"),
	}).deployed;
	const plugin = require(PLUGIN_DIST).default;
	plugin.register({
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		on(event: string, registered: Handler) {
			if (!handlers.has(event)) handlers.set(event, registered);
		},
		registerTool() {},
	});
});

afterAll(() => {
	for (const [key, value] of Object.entries(saved)) {
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
	rmSync(home, { recursive: true, force: true });
});

describe("OpenClaw bundle: canary credentials", { timeout: 60_000 }, () => {
	it("before_agent_run blocks a prompt carrying a decoy value and records it", async () => {
		const secret = token("aws");
		const decision = (await handler("before_agent_run")(
			{ prompt: `configure the CLI with ${secret}`, messages: [] },
			{ sessionKey: "agent:main:canary-prompt", trigger: "user" },
		)) as Record<string, unknown>;
		expect(decision).toMatchObject({
			outcome: "block",
			reason: "aidr_prompt_protection:canary",
			category: "prompt_protection",
		});
		expect(String(decision.message)).toContain("canary credential");
		expect(JSON.stringify(decision)).not.toContain(secret);
		expect(auditEntries()).toContainEqual(
			expect.objectContaining({
				category: "canary_triggered",
				tool_name: "before_agent_run",
				session_id: "agent:main:canary-prompt",
			}),
		);
		expect(JSON.stringify(auditEntries())).not.toContain(secret);
	});

	it("after_tool_call records tool output carrying a decoy value", async () => {
		const secret = token("env", 1);
		await handler("after_tool_call")(
			{
				toolName: "exec",
				params: { command: "grep -rn SECRET ." },
				result: { content: [{ type: "text", text: `.env.backup:4:JWT_SECRET=${secret}` }] },
			},
			{ sessionKey: "agent:main:canary-output" },
		);
		expect(auditEntries()).toContainEqual(
			expect.objectContaining({
				category: "canary_triggered",
				source: "canary",
				tool_name: "exec",
				session_id: "agent:main:canary-output",
			}),
		);
		expect(JSON.stringify(auditEntries())).not.toContain(secret);
	});
});

describe("OpenClaw bundle: toxic-flow capability data", () => {
	it("ships threats/flow/capabilities.yaml unchanged next to the threat rules", () => {
		const shipped = readFileSync(
			join(PACKAGE_ROOT, "dist", "resources", "threats", "flow", "capabilities.yaml"),
			"utf8",
		);
		const source = readFileSync(
			join(PACKAGE_ROOT, "..", "..", "threats", "flow", "capabilities.yaml"),
			"utf8",
		);
		expect(shipped).toBe(source);
	});
});
