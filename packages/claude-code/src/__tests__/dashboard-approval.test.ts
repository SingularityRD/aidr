/**
 * Managed-mode dashboard approvals through the BUILT Claude Code PreToolUse hook.
 *
 * Every hook call is a separate process, so this proves the persisted state
 * works across processes: the request id remembered by one call is polled by the
 * next, the approval token (signed with a key published in the signed
 * entitlement) releases exactly one retry, and its spent nonce blocks the next.
 */

import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	FakeControlPlane,
	type ManagedFixture,
	managedConfig,
	managedFixture,
	writeManagedHome,
} from "../../../core/src/__tests__/dashboard-approval-fixtures.js";

const PRE_TOOL_USE = resolve(__dirname, "..", "..", "dist", "pre-tool-use.cjs");

// url_check disabled with unchecked_action "ask": a benign URL is not verified clean, so it is an `ask`.
const CALL = {
	tool_name: "WebFetch",
	tool_input: { url: "https://example.com" },
	session_id: "dashboard-session",
	tool_use_id: "toolu_dashboard_1",
};

let home: string;
let fixture: ManagedFixture;
let cp: FakeControlPlane;

function runHook(): Promise<Record<string, unknown>> {
	const env: Record<string, string | undefined> = {
		...process.env,
		HOME: home,
		USERPROFILE: home,
		XDG_CONFIG_HOME: join(home, ".config"),
		XDG_STATE_HOME: join(home, ".local", "state"),
		XDG_CACHE_HOME: join(home, ".cache"),
	};
	for (const key of Object.keys(env)) {
		if (key.startsWith("AIDR_")) delete env[key];
	}
	// The single-use ledger needs an anchor; there is no OS vault in CI.
	env.AIDR_OPERATOR_APPROVAL_KEY_STORAGE = "file";
	return new Promise((done, fail) => {
		const child = execFile("node", [PRE_TOOL_USE], { timeout: 30_000, env }, (error, stdout) => {
			if (error && !stdout) {
				fail(error);
				return;
			}
			done(JSON.parse(stdout.trim() || "{}") as Record<string, unknown>);
		});
		child.stdin?.end(JSON.stringify(CALL));
	});
}

function hookOutput(response: Record<string, unknown>): Record<string, unknown> {
	return (response.hookSpecificOutput ?? {}) as Record<string, unknown>;
}

async function setupHome(extra: Record<string, unknown> = {}): Promise<void> {
	const endpoint = await cp.listen();
	await writeManagedHome(home, fixture, {
		...managedConfig(fixture, endpoint),
		url_check: { enabled: false, unchecked_action: "ask" },
		...extra,
	});
}

beforeEach(() => {
	home = mkdtempSync(join(tmpdir(), "aidr-cc-dashboard-"));
	fixture = managedFixture();
	cp = new FakeControlPlane(fixture);
});

afterEach(async () => {
	await cp.close();
	rmSync(home, { recursive: true, force: true });
});

describe("Claude Code PreToolUse with managed dashboard approvals", () => {
	it("requests approval, releases exactly one retry after it, then blocks again", async () => {
		// approvals_mode: host_dialog keeps the native dialog next to the dashboard.
		await setupHome({ operator_approvals: { approvals_mode: "host_dialog" } });

		const first = await runHook();
		expect(hookOutput(first).permissionDecision).toBe("ask");
		const requestId = cp.onlyRequestId();
		expect(hookOutput(first).permissionDecisionReason).toContain(
			`Approval requested in the AIDR dashboard: ${requestId}`,
		);
		expect(cp.requests.get(requestId)?.body.agent_runtime).toBe("claude-code");

		cp.approve(requestId);
		const released = await runHook();
		expect(released).toEqual({});

		// The idempotent control plane returns the spent approval; it cannot release again.
		expect(hookOutput(await runHook()).permissionDecision).toBe("ask");
		const replay = await runHook();
		expect(hookOutput(replay).permissionDecision).toBe("ask");
		expect(hookOutput(replay).permissionDecisionReason).toContain(
			"could not be verified (replayed)",
		);
	}, 90_000);

	it("managed default: blocks instead of the native dialog and links the approval page", async () => {
		cp.consoleUrl = (id) => `https://console.example.test/approvals?request=${id}`;
		await setupHome();

		const blocked = await runHook();
		expect(hookOutput(blocked).permissionDecision).toBe("deny");
		const requestId = cp.onlyRequestId();
		expect(String(blocked.systemMessage)).toContain(
			`https://console.example.test/approvals?request=${requestId}`,
		);
		expect(hookOutput(blocked).permissionDecisionReason).toContain("You cannot approve it");

		cp.approve(requestId);
		expect(await runHook()).toEqual({});
	}, 60_000);

	it("dashboard_only blocks instead of opening the native dialog", async () => {
		await setupHome({ operator_approvals: { dashboard_only: true } });

		const blocked = await runHook();
		expect(hookOutput(blocked).permissionDecision).toBe("deny");
		const requestId = cp.onlyRequestId();
		// The person reads the request id; the agent is told it cannot approve.
		expect(String(blocked.systemMessage)).toContain(
			`Approval requested in the AIDR dashboard: ${requestId}`,
		);
		expect(hookOutput(blocked).permissionDecisionReason).toContain("You cannot approve it");

		cp.approve(requestId);
		expect(await runHook()).toEqual({});
	}, 60_000);
});
