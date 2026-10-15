import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { MANAGED_HOOK_MARKER } from "../../../cli/src/utils/install-hooks.js";
import { runFile } from "../main/exec.js";
import { parseHookCommand } from "../main/hooks.js";
import { BENIGN_COMMAND, CANARY_COMMAND, runSelfTest } from "../main/selftest.js";
import { tempDir } from "./fixtures.js";

const cleanup: string[] = [];
afterEach(() => {
	for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

const quote = (path: string) => `"${path.replaceAll("\\", "/")}"`;

/** A stand-in hook with Claude Code's I/O contract: JSON in, verdict JSON out. */
const HOOK_SOURCE = `
let input = "";
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
	const call = JSON.parse(input);
	if (call.hook_event_name !== "PreToolUse" || call.tool_name !== "Bash") process.exit(3);
	if (!String(call.session_id).startsWith("aidr-desktop-self-test-")) process.exit(4);
	if (/curl .*\\| *bash/.test(call.tool_input.command)) {
		process.stdout.write(JSON.stringify({
			systemMessage: "blocked (rule CLT-CMD-001)",
			hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "Singularity AIDR blocked this" },
		}) + "\\n");
	} else process.stdout.write("{}\\n");
});`;

function homeWithHook(command: string | null): string {
	const home = tempDir("selftest");
	cleanup.push(home);
	mkdirSync(join(home, ".claude"), { recursive: true });
	const settings =
		command === null
			? { hooks: {} }
			: {
					hooks: {
						PreToolUse: [
							{ matcher: "*", hooks: [{ type: "command", command, timeout: 15, statusMessage: MANAGED_HOOK_MARKER }] },
						],
					},
				};
	writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify(settings));
	return home;
}

describe("runSelfTest", () => {
	it("runs the registered hook without a shell, with Claude Code's payload, and reports both verdicts", async () => {
		const scripts = tempDir("hook");
		cleanup.push(scripts);
		const script = join(scripts, "aidr hook.cjs");
		writeFileSync(script, HOOK_SOURCE);
		const home = homeWithHook(`${quote(process.execPath)} ${quote(script)}`);
		const result = await runSelfTest({ home, run: runFile });
		expect(result.error).toBeNull();
		expect(result.ok).toBe(true);
		const [benign, canary] = result.cases;
		expect(benign).toMatchObject({ command: BENIGN_COMMAND, expected: "allow", decision: "allow", pass: true });
		expect(canary).toMatchObject({ command: CANARY_COMMAND, expected: "deny", decision: "deny", pass: true, ruleId: "CLT-CMD-001" });
		expect(canary?.latencyMs).toBeGreaterThanOrEqual(0);
	});

	it("fails visibly when a hook answers wrongly", async () => {
		const scripts = tempDir("hook");
		cleanup.push(scripts);
		const script = join(scripts, "allow-all.cjs");
		writeFileSync(script, 'process.stdin.resume(); process.stdin.on("end", () => process.stdout.write("{}"));');
		const home = homeWithHook(`${quote(process.execPath)} ${quote(script)}`);
		const result = await runSelfTest({ home, run: runFile });
		expect(result.ok).toBe(false);
		expect(result.cases.find((entry) => entry.name === "canary")).toMatchObject({ decision: "allow", pass: false });
	});

	it("fails visibly when no hook is registered", async () => {
		const result = await runSelfTest({ home: homeWithHook(null), run: runFile });
		expect(result.ok).toBe(false);
		expect(result.error).toMatch(/No AIDR PreToolUse hook/);
	});

	it("fails visibly when the hook program is missing", async () => {
		const home = homeWithHook(`"C:/does/not/exist/aidr.exe" hook pre-tool-use`);
		const result = await runSelfTest({ home, run: runFile });
		expect(result.ok).toBe(false);
		expect(result.error).toMatch(/missing/);
	});

	it("never runs a hook command that needs a shell", async () => {
		let ran = false;
		const home = homeWithHook('node "${CLAUDE_PLUGIN_ROOT}/dist/pre-tool-use.cjs"');
		const result = await runSelfTest({
			home,
			run: async () => {
				ran = true;
				throw new Error("must not run");
			},
		});
		expect(ran).toBe(false);
		expect(result.error).toMatch(/without a shell/);
	});
});

describe("parseHookCommand", () => {
	it.each([
		['"C:/Users/a b/.singularity-aidr/desktop/runtime/x/bin/aidr.exe" hook pre-tool-use', "C:/Users/a b/.singularity-aidr/desktop/runtime/x/bin/aidr.exe", ["hook", "pre-tool-use"]],
		['"C:/Program Files/nodejs/node.exe" "C:/x/dist/pre-tool-use.cjs"', "C:/Program Files/nodejs/node.exe", ["C:/x/dist/pre-tool-use.cjs"]],
	])("splits %s", (command, file, args) => {
		if (process.platform !== "win32") return;
		expect(parseHookCommand(command)).toEqual({ file, args });
	});

	it.each([
		'node "${CLAUDE_PLUGIN_ROOT}/x.cjs"',
		'"C:/aidr.exe" hook pre-tool-use && calc',
		'"C:/aidr.exe" hook pre-tool-use | more',
		'"C:/aidr.exe" %PATH%',
		'"C:/aidr.exe" $(whoami)',
		"aidr-codex-hook",
		'"C:/aidr.exe" "unterminated',
		"",
	])("refuses %s", (command) => {
		expect(parseHookCommand(command)).toBeNull();
	});
});
