/**
 * Pre-model tool-output quarantine through the BUILT OpenClaw plugin
 * (dist/index.cjs) and its shipped manifest: OpenClaw only accepts the
 * middleware from an installed plugin that declares
 * `contracts.agentToolResultMiddleware`, and the replacement the bundle returns
 * is what the embedded runner hands the model. Canary values in a quarantined
 * result are still recorded, since `after_tool_call` only sees the notice.
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
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5".repeat(4)}`;

type Handler = (event: unknown, ctx?: unknown) => Promise<unknown>;

const handlers = new Map<string, Handler>();
const middlewares: Array<{ handler: Handler; options: unknown }> = [];
const saved: Record<string, string | undefined> = {};
let home: string;
let records: CanaryRecord[];

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

function middleware(): Handler {
	const found = middlewares[0]?.handler;
	if (!found) throw new Error("tool-result middleware was not registered");
	return found;
}

beforeAll(() => {
	for (const key of ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"]) saved[key] = process.env[key];
	home = mkdtempSync(join(tmpdir(), "aidr-openclaw-quarantine-"));
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
		id: "aidr-openclaw",
		config: { plugins: { entries: { "aidr-openclaw": { enabled: true } } } },
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		on(event: string, registered: Handler) {
			if (!handlers.has(event)) handlers.set(event, registered);
		},
		registerTool() {},
		registerAgentToolResultMiddleware(handler: Handler, options: unknown) {
			middlewares.push({ handler, options });
		},
	});
});

afterAll(() => {
	for (const [key, value] of Object.entries(saved)) {
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
	rmSync(home, { recursive: true, force: true });
});

describe("OpenClaw bundle: pre-model tool-output quarantine", { timeout: 60_000 }, () => {
	it("ships the manifest contract OpenClaw requires for the middleware", () => {
		const manifest = JSON.parse(readFileSync(join(PACKAGE_ROOT, "openclaw.plugin.json"), "utf8"));
		expect(manifest.contracts.agentToolResultMiddleware).toEqual(["openclaw"]);
		expect(middlewares).toHaveLength(1);
		expect(middlewares[0]?.options).toEqual({ runtimes: ["openclaw"] });
	});

	it("returns AIDR's quarantine notice in place of a secret-bearing result", async () => {
		const replacement = (await middleware()(
			{
				toolCallId: "call-bundle-secret",
				toolName: "exec",
				args: { command: "cat notes.txt" },
				result: {
					content: [{ type: "text", text: `deploy token: ${GITHUB_TOKEN}\n` }],
					details: { status: "completed", aggregated: `deploy token: ${GITHUB_TOKEN}` },
				},
			},
			{ runtime: "openclaw", runId: "run-bundle", sessionKey: "agent:main:bundle" },
		)) as { result: { content: Array<{ type: string; text: string }>; details: unknown } };

		expect(replacement.result.content).toEqual([
			{
				type: "text",
				text: expect.stringContaining(
					"Singularity AIDR quarantined this tool output before it reached the model",
				),
			},
		]);
		expect(JSON.stringify(replacement)).not.toContain(GITHUB_TOKEN);
		expect(replacement.result.details).toEqual({
			aidr: expect.objectContaining({ boundary: "pre_model_tool_result" }),
		});
	});

	it("passes a benign result through unchanged", async () => {
		await expect(
			middleware()(
				{
					toolCallId: "call-bundle-benign",
					toolName: "exec",
					result: { content: [{ type: "text", text: "aidr-benign-ok" }] },
				},
				{ runtime: "openclaw" },
			),
		).resolves.toBeUndefined();
	});

	it("records a canary value in a quarantined result, which after_tool_call never sees", async () => {
		const path = records.find((record) => record.kind === "env")?.path as string;
		const secret = [...readFileSync(path, "utf8").matchAll(/[A-Za-z0-9]{20,}/g)][1]?.[0] as string;
		const replacement = await middleware()(
			{
				toolCallId: "call-bundle-canary",
				toolName: "exec",
				args: { command: "grep -rn SECRET ." },
				result: { content: [{ type: "text", text: `.env.backup:4:JWT_SECRET=${secret}` }] },
			},
			{ runtime: "openclaw", sessionKey: "agent:main:quarantine-canary" },
		);
		expect(JSON.stringify(replacement)).not.toContain(secret);
		expect(auditEntries()).toContainEqual(
			expect.objectContaining({
				category: "canary_triggered",
				tool_name: "exec",
				session_id: "agent:main:quarantine-canary",
			}),
		);
		const before = auditEntries().filter((entry) => entry.category === "canary_triggered").length;
		// The host then hands after_tool_call the notice: no duplicate record.
		await handlers.get("after_tool_call")?.(
			{
				toolName: "exec",
				params: { command: "grep -rn SECRET ." },
				toolCallId: "call-bundle-canary",
				result: replacement,
			},
			{ sessionKey: "agent:main:quarantine-canary" },
		);
		expect(auditEntries().filter((entry) => entry.category === "canary_triggered")).toHaveLength(
			before,
		);
		expect(JSON.stringify(auditEntries())).not.toContain(secret);
	});
});
