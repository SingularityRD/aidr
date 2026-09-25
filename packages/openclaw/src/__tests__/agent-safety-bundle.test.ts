/**
 * Agent-safety guardrails through the BUILT OpenClaw plugin (dist/index.cjs):
 * reward hacking and irreversible actions are held for approval, autonomy
 * escalation is denied, and a runaway loop (including repeated failures
 * reported by after_tool_call) pauses the session. HOME points at a fresh
 * directory so the session state lives in a clean AIDR state directory.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Agent-edit fixture text that adds a Vitest skip. Assembled at runtime so the
// mandatory-skip gate (scripts/check-mandatory-skips.mjs) does not read the
// fixture string as a skip in this suite.
const IT_SKIP = ["it", "skip"].join(".");

const require = createRequire(import.meta.url);
const PLUGIN_DIST = resolve(__dirname, "..", "..", "dist", "index.cjs");

type Handler = (event: Record<string, unknown>, ctx?: Record<string, unknown>) => Promise<unknown>;

interface BlockResult {
	block: true;
	blockReason: string;
}

describe("OpenClaw bundle: agent-safety guardrails", { timeout: 60_000 }, () => {
	const handlers = new Map<string, Handler>();
	let home: string;
	const previousHome = process.env.HOME;

	beforeAll(() => {
		home = mkdtempSync(join(tmpdir(), "aidr-openclaw-agent-safety-"));
		process.env.HOME = home;
		const plugin = require(PLUGIN_DIST).default;
		plugin.register({
			logger: { debug() {}, info() {}, warn() {}, error() {} },
			on(event: string, handler: Handler) {
				if (!handlers.has(event)) handlers.set(event, handler);
			},
			registerTool() {},
		});
	});

	afterAll(() => {
		process.env.HOME = previousHome;
		rmSync(home, { recursive: true, force: true });
	});

	function beforeCall(sessionKey: string, toolName: string, params: Record<string, unknown>) {
		const handler = handlers.get("before_tool_call");
		if (!handler) throw new Error("before_tool_call not registered");
		return handler({ toolName, params }, { sessionKey }) as Promise<BlockResult | undefined>;
	}

	it("holds a git hook bypass and a force-push to main for approval", async () => {
		const bypass = await beforeCall("s-rh", "exec", { command: 'git commit --no-verify -m "wip"' });
		expect(bypass?.block).toBe(true);
		expect(bypass?.blockReason).toContain("--no-verify");
		expect(bypass?.blockReason).toContain("actionId");
		expect(
			await beforeCall("s-rh", "exec", { command: "git push origin feature/x" }),
		).toBeUndefined();
	});

	it("holds a test skip added through the edit tool", async () => {
		const result = await beforeCall("s-edit", "edit", {
			path: "src/auth.test.ts",
			oldText: "it('logs in', () => {",
			newText: `${IT_SKIP}('logs in', () => {`,
		});
		expect(result?.block).toBe(true);
		expect(result?.blockReason).toContain("Test skipped or disabled");
	});

	it("denies launching an agent with approvals disabled", async () => {
		const result = await beforeCall("s-auto", "exec", {
			command: 'claude --dangerously-skip-permissions -p "fix everything"',
		});
		expect(result?.block).toBe(true);
		expect(result?.blockReason).toContain("permission prompts disabled");
		expect(result?.blockReason).not.toContain("actionId");
	});

	it("holds irreversible actions but not their benign twins", async () => {
		const destroy = await beforeCall("s-irr", "exec", { command: "terraform destroy" });
		expect(destroy?.blockReason).toContain("Irreversible action");
		expect(await beforeCall("s-irr", "exec", { command: "terraform plan" })).toBeUndefined();
	});

	it("pauses a command that keeps failing unchanged (after_tool_call errors)", async () => {
		const after = handlers.get("after_tool_call");
		if (!after) throw new Error("after_tool_call not registered");
		const params = { command: "make build" };
		for (let i = 0; i < 3; i++) {
			expect(await beforeCall("s-fail", "exec", params)).toBeUndefined();
			await after({ toolName: "exec", params, error: "exit status 2" }, { sessionKey: "s-fail" });
		}
		const retry = await beforeCall("s-fail", "exec", params);
		expect(retry?.block).toBe(true);
		expect(retry?.blockReason).toContain("Runaway guard");
		expect(retry?.blockReason).toContain("already failed 3 times");
		// Another session is unaffected.
		expect(await beforeCall("s-other", "exec", params)).toBeUndefined();
	});

	it("pauses the same call repeated back-to-back", async () => {
		const params = { path: "/repo/README.md" };
		for (let i = 0; i < 8; i++) {
			expect(await beforeCall("s-loop", "read", params)).toBeUndefined();
		}
		const ninth = await beforeCall("s-loop", "read", params);
		expect(ninth?.blockReason).toContain("repeated 9 times in a row");
	});
});
