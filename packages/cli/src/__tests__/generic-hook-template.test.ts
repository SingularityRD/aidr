/**
 * The generic hook entry point must fail CLOSED: when the AIDR hook bundle is
 * missing, crashes, prints nothing or hangs, the host receives an explicit deny
 * verdict (exit 0) instead of an empty pass-through.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
	GENERIC_HOOK_TIMEOUT_MS,
	renderGenericHookTemplate,
	writeGenericHookTemplate,
} from "../utils/install-hooks.js";

const dir = mkdtempSync(join(tmpdir(), "aidr-generic-hook-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function bundle(name: string, source: string): string {
	const path = join(dir, name);
	writeFileSync(path, source);
	return path;
}

function runHook(bundlePath: string, timeoutMs = 2_000, input = '{"tool_name":"Bash"}') {
	const hook = join(dir, `hook-${Math.random().toString(36).slice(2)}.cjs`);
	writeFileSync(hook, renderGenericHookTemplate(bundlePath, timeoutMs));
	const started = Date.now();
	const result = spawnSync(process.execPath, [hook], { input, timeout: 20_000 });
	return {
		status: result.status,
		elapsed: Date.now() - started,
		verdict: JSON.parse(result.stdout.toString("utf8")) as Record<string, unknown>,
	};
}

function expectDeny(verdict: Record<string, unknown>, detail: string) {
	expect(verdict).toMatchObject({ decision: "deny", permission: "deny" });
	expect(String(verdict.reason)).toContain(detail);
}

describe("generic hook template", () => {
	it("stays below a 10 s host hook budget", () => {
		expect(GENERIC_HOOK_TIMEOUT_MS).toBeLessThan(10_000);
	});

	it("passes the bundle's verdict through unchanged", () => {
		const ok = bundle(
			"ok.cjs",
			'process.stdin.resume();process.stdin.on("end",()=>process.stdout.write(JSON.stringify({decision:"allow",permission:"allow"})));',
		);
		const { status, verdict } = runHook(ok);
		expect(status).toBe(0);
		expect(verdict).toEqual({ decision: "allow", permission: "allow" });
	});

	it("denies when the bundle is missing", () => {
		const { status, verdict } = runHook(join(dir, "does-not-exist.cjs"));
		expect(status).toBe(0);
		expectDeny(verdict, "exited with status");
	});

	it("denies when the bundle crashes, even after printing an allow", () => {
		const crash = bundle(
			"crash.cjs",
			'process.stdout.write(JSON.stringify({decision:"allow",permission:"allow"}));process.exit(3);',
		);
		const { status, verdict } = runHook(crash);
		expect(status).toBe(0);
		expectDeny(verdict, "exited with status 3");
	});

	it("denies when the bundle prints nothing", () => {
		const silent = bundle("silent.cjs", "process.exit(0);");
		expectDeny(runHook(silent).verdict, "no verdict");
	});

	it("denies when the bundle prints something that is not a verdict object", () => {
		const garbage = bundle("garbage.cjs", 'process.stdout.write("not json");');
		expectDeny(runHook(garbage).verdict, "unreadable verdict");
	});

	it("denies a hanging bundle within its time budget", () => {
		const hang = bundle("hang.cjs", "setInterval(() => {}, 1000);");
		const { status, verdict, elapsed } = runHook(hang, 1_000);
		expect(status).toBe(0);
		expectDeny(verdict, "timed out");
		expect(elapsed).toBeLessThan(8_000);
	});

	it("writes the template into the requested hooks directory", () => {
		const target = writeGenericHookTemplate("/opt/aidr/pre-tool-use.cjs", join(dir, "hooks"));
		expect(target).toBe(join(dir, "hooks", "generic-hook.cjs"));
	});
});
