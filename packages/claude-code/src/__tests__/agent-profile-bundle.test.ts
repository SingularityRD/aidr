/**
 * Agent permission profiles through the built Claude Code PreToolUse bundle:
 * the hook reads the operator's local profile file, selects the profile by the
 * host-reported `cwd`, and denies with a reason naming the profile and rule.
 */
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const PRE_TOOL_USE = resolve(__dirname, "..", "..", "dist", "pre-tool-use.cjs");

let home: string;
let workspace: string;

function runHook(input: Record<string, unknown>): Promise<Record<string, unknown>> {
	const env: NodeJS.ProcessEnv = {
		...process.env,
		HOME: home,
		USERPROFILE: home,
		XDG_CONFIG_HOME: join(home, ".config"),
	};
	for (const key of Object.keys(env)) if (key.startsWith("AIDR_")) delete env[key];
	return new Promise((resolvePromise, reject) => {
		const child = execFile("node", [PRE_TOOL_USE], { timeout: 30_000, env }, (error, stdout) => {
			if (error && !stdout) return reject(error);
			try {
				resolvePromise(JSON.parse(stdout.trim()) as Record<string, unknown>);
			} catch (parseError) {
				reject(parseError);
			}
		});
		child.stdin?.end(JSON.stringify(input));
	});
}

function hookOutput(response: Record<string, unknown>) {
	return (response.hookSpecificOutput ?? {}) as Record<string, unknown>;
}

beforeEach(() => {
	home = mkdtempSync(join(tmpdir(), "aidr-claude-profile-"));
	workspace = join(home, "work", "reviewed-repo");
	mkdirSync(workspace, { recursive: true });
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
	writeFileSync(
		join(home, ".singularity-aidr", "agent-profiles.json"),
		JSON.stringify({
			version: 1,
			profiles: [
				{ name: "open", default: "allow" },
				{
					name: "reviewer",
					applies_to: { connectors: ["claude-code"], repositories: ["~/work/reviewed-repo"] },
					default: "deny",
					tools: { shell: "allow", file_read: "allow" },
					commands: { allow_prefixes: ["git status", "git diff"], unmatched: "deny" },
				},
			],
		}),
	);
});

afterEach(() => {
	rmSync(home, { recursive: true, force: true });
});

describe("Claude Code bundle enforces agent permission profiles", () => {
	it("denies a clean command outside the repository profile's allowed prefixes", async () => {
		const response = await runHook({
			session_id: "profile-bundle",
			tool_use_id: "t1",
			cwd: workspace,
			tool_name: "Bash",
			tool_input: { command: "npm install left-pad" },
		});
		const output = hookOutput(response);
		expect(output.permissionDecision).toBe("deny");
		expect(String(output.permissionDecisionReason)).toMatch(
			/^🛡️ Singularity AIDR blocked this action: Agent permission profile "reviewer"/,
		);
		expect(String(response.systemMessage)).toContain('Agent permission profile "reviewer" (local)');
		expect(String(response.systemMessage)).toContain("commands.unmatched");
	});

	it("allows an allowed prefix and applies the unscoped profile elsewhere", async () => {
		const allowed = await runHook({
			session_id: "profile-bundle",
			tool_use_id: "t2",
			cwd: workspace,
			tool_name: "Bash",
			tool_input: { command: "git status" },
		});
		expect(hookOutput(allowed).permissionDecision).not.toBe("deny");

		const write = await runHook({
			session_id: "profile-bundle",
			tool_use_id: "t3",
			cwd: workspace,
			tool_name: "Write",
			tool_input: { file_path: join(workspace, "notes.md"), content: "hello" },
		});
		expect(hookOutput(write).permissionDecision).toBe("deny");

		const elsewhere = await runHook({
			session_id: "profile-bundle",
			tool_use_id: "t4",
			cwd: home,
			tool_name: "Write",
			tool_input: { file_path: join(home, "notes.md"), content: "hello" },
		});
		expect(hookOutput(elsewhere).permissionDecision).not.toBe("deny");
	});
});
