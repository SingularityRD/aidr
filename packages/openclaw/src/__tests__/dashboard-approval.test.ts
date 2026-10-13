/**
 * Managed-mode dashboard approvals through the BUILT OpenClaw plugin bundle and
 * the real core pipeline: an `ask` is submitted to a loopback fake control plane,
 * the block reason carries the request id (and never an approval tool), the
 * administrator's signed approval releases exactly one identical retry, and the
 * next retry is blocked again.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	FakeControlPlane,
	type ManagedFixture,
	managedConfig,
	managedFixture,
	writeManagedHome,
} from "../../../core/src/__tests__/dashboard-approval-fixtures.js";

const require = createRequire(import.meta.url);
const PLUGIN_DIST = resolve(__dirname, "..", "..", "dist", "index.cjs");

interface BlockResult {
	block: true;
	blockReason: string;
}
type ToolCallHandler = (
	event: { toolName: string; params: Record<string, unknown> },
	ctx?: { sessionKey?: string },
) => Promise<BlockResult | undefined>;

function loadHandler(): { handler: ToolCallHandler; tools: string[] } {
	const plugin = require(PLUGIN_DIST).default;
	let handler: ToolCallHandler | undefined;
	const tools: string[] = [];
	plugin.register({
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		on(event: string, h: ToolCallHandler) {
			if (event === "before_tool_call") handler = h;
		},
		registerTool(tool: { name: string }) {
			tools.push(tool.name);
		},
	});
	if (!handler) throw new Error("before_tool_call handler was not registered");
	return { handler, tools };
}

// url_check disabled with unchecked_action "ask": a benign URL is not verified clean, so it is an `ask`.
const EVENT = { toolName: "web_fetch", params: { url: "https://example.com" } };
const CTX = { sessionKey: "openclaw-dashboard-session" };

let home: string;
let fixture: ManagedFixture;
let cp: FakeControlPlane;

beforeEach(async () => {
	home = await mkdtemp(resolve(tmpdir(), "aidr-openclaw-dashboard-"));
	fixture = managedFixture();
	cp = new FakeControlPlane(fixture);
	const endpoint = await cp.listen();
	await writeManagedHome(home, fixture, {
		...managedConfig(fixture, endpoint),
		url_check: { enabled: false, unchecked_action: "ask" },
	});
	vi.stubEnv("HOME", home);
	vi.stubEnv("USERPROFILE", home);
	// The single-use ledger needs an anchor; there is no OS vault in CI.
	vi.stubEnv("AIDR_OPERATOR_APPROVAL_KEY_STORAGE", "file");
});

afterEach(async () => {
	vi.unstubAllEnvs();
	await cp.close();
	await rm(home, { recursive: true, force: true });
});

describe("OpenClaw plugin with managed dashboard approvals", { timeout: 60_000 }, () => {
	it("requests approval, releases exactly one retry after it, then blocks again", async () => {
		const { handler, tools } = loadHandler();
		expect(tools.some((name) => /approv/i.test(name))).toBe(false);

		const blocked = await handler(EVENT, CTX);
		expect(blocked?.block).toBe(true);
		const requestId = cp.onlyRequestId();
		expect(blocked?.blockReason).toContain(
			`Approval requested in the AIDR dashboard: ${requestId}`,
		);
		expect(blocked?.blockReason).toContain("no tool available to you can approve it");
		expect(cp.requests.get(requestId)?.body.agent_runtime).toBe("openclaw");

		// Undecided: still blocked.
		expect((await handler(EVENT, CTX))?.block).toBe(true);

		cp.approve(requestId);
		expect(await handler(EVENT, CTX)).toBeUndefined();

		expect((await handler(EVENT, CTX))?.block).toBe(true);
		const replay = await handler(EVENT, CTX);
		expect(replay?.block).toBe(true);
		expect(replay?.blockReason).toContain("could not be verified (replayed)");
	});

	it("keeps the call blocked when the dashboard denies it", async () => {
		const { handler } = loadHandler();
		await handler(EVENT, CTX);
		cp.deny(cp.onlyRequestId());
		const denied = await handler(EVENT, CTX);
		expect(denied?.block).toBe(true);
		expect(denied?.blockReason).toContain("was denied");
	});
});
