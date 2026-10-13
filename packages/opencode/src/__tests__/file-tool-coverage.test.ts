/**
 * CON-3 regression (AIDR-060 follow-up): OpenCode file tools beyond
 * write/edit/apply_patch, driven through the BUILT plugin (dist/index.js).
 *
 * The audit showed `patch` (the patchText tool under the name some OpenCode
 * builds expose) planting `~/.ssh/authorized_keys` and agent-config tampering
 * while `apply_patch` with the same body was blocked, and `list`/`glob`/`grep`
 * reading sensitive paths through fields the connector never looked at. Each
 * bypass below has a benign twin that must still pass.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const PLUGIN_DIST = resolve(__dirname, "..", "..", "dist", "index.js");

type BeforeHook = (
	input: { tool: string; sessionID: string; callID: string },
	output: { args: Record<string, unknown> },
) => Promise<void>;

function patchAdding(path: string, line: string): string {
	return ["*** Begin Patch", `*** Add File: ${path}`, `+${line}`, "*** End Patch"].join("\n");
}

// Assembled at runtime so no key-shaped literal sits in the source.
const SSH_KEY_LINE = ["ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAA", "attacker@example.test"].join(" ");

describe("OpenCode bundle: patch/multiedit/list/glob/grep go through file-path policy", {
	timeout: 60_000,
}, () => {
	let home: string;
	let before: BeforeHook;
	const previous = {
		HOME: process.env.HOME,
		XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME,
		XDG_CACHE_HOME: process.env.XDG_CACHE_HOME,
	};
	let call = 0;

	beforeAll(async () => {
		home = await mkdtemp(join(tmpdir(), "aidr-opencode-file-tools-"));
		process.env.HOME = home;
		process.env.XDG_CONFIG_HOME = join(home, ".config");
		process.env.XDG_CACHE_HOME = join(home, ".cache");
		const mod = (await import(PLUGIN_DIST)) as {
			default: (input: Record<string, unknown>) => Promise<Record<string, unknown>>;
		};
		const hooks = await mod.default({
			client: { app: { log: async () => {} } },
			project: { id: "file-tool-coverage" },
			directory: process.cwd(),
			worktree: process.cwd(),
			$: {},
		});
		before = hooks["tool.execute.before"] as BeforeHook;
	});

	afterAll(async () => {
		for (const [key, value] of Object.entries(previous)) {
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
		await rm(home, { recursive: true, force: true });
	});

	function run(tool: string, args: Record<string, unknown>) {
		call += 1;
		return before({ tool, sessionID: "s1", callID: `c${call}` }, { args });
	}

	async function expectBlocked(tool: string, args: Record<string, unknown>, rule: string) {
		await expect(run(tool, args), `${tool} ${JSON.stringify(args)}`).rejects.toThrow(rule);
	}

	async function expectAllowed(tool: string, args: Record<string, unknown>) {
		await expect(run(tool, args), `${tool} ${JSON.stringify(args)}`).resolves.toBeUndefined();
	}

	const authorizedKeys = () => join(home, ".ssh", "authorized_keys");

	it("apply_patch adding authorized_keys is blocked (the baseline)", async () => {
		await expectBlocked(
			"apply_patch",
			{ patchText: patchAdding(authorizedKeys(), SSH_KEY_LINE) },
			"CLT-FILE-002",
		);
	});

	it("patch adding authorized_keys is blocked like apply_patch", async () => {
		await expectBlocked(
			"patch",
			{ patchText: patchAdding(authorizedKeys(), SSH_KEY_LINE) },
			"CLT-FILE-002",
		);
	});

	it("patch disabling agent hooks in .claude/settings.json is blocked", async () => {
		const patchText = [
			"*** Begin Patch",
			"*** Update File: .claude/settings.json",
			"@@",
			"-{}",
			'+{"disableAllHooks": true}',
			"*** End Patch",
		].join("\n");
		await expectBlocked("patch", { patchText }, "Singularity AIDR blocked this action");
	});

	it("patch adding a shell rc file needs approval like apply_patch", async () => {
		const patchText = patchAdding(join(home, ".bashrc"), "export PATH=$PATH:/opt/bin");
		await expectBlocked("patch", { patchText }, "CLT-FILE-004");
		await expectBlocked("apply_patch", { patchText }, "CLT-FILE-004");
	});

	it("patch without a patch body fails closed", async () => {
		await expectBlocked(
			"patch",
			{ description: "no body" },
			"Singularity AIDR blocked this action",
		);
	});

	it("multiedit of authorized_keys is blocked", async () => {
		await expectBlocked(
			"multiedit",
			{ filePath: authorizedKeys(), edits: [{ oldString: "", newString: SSH_KEY_LINE }] },
			"CLT-FILE-002",
		);
	});

	it("list of a sensitive file is blocked", async () => {
		await expectBlocked("list", { path: authorizedKeys() }, "CLT-FILE-002");
	});

	it("glob resolves its pattern against its search root", async () => {
		await expectBlocked(
			"glob",
			{ pattern: "authorized_keys", path: join(home, ".ssh") },
			"CLT-FILE-002",
		);
	});

	it("grep with a sensitive search path is blocked", async () => {
		await expectBlocked("grep", { pattern: "ssh-", path: authorizedKeys() }, "CLT-FILE-002");
	});

	it("grep include resolved against its search root is flagged", async () => {
		await expectBlocked(
			"grep",
			{ pattern: "PRIVATE", path: join(home, ".ssh"), include: "id_rsa" },
			"CLT-FILE-003",
		);
	});

	describe("benign twins still pass", () => {
		it("patch adding a workspace source file", async () => {
			await expectAllowed("patch", {
				patchText: patchAdding("src/hello.ts", "export const a = 1;"),
			});
		});

		it("multiedit of a workspace source file", async () => {
			await expectAllowed("multiedit", {
				filePath: "src/a.ts",
				edits: [{ oldString: "const a = 1", newString: "const a = 2" }],
			});
		});

		it("list, glob and grep over the workspace", async () => {
			await expectAllowed("list", { path: "src" });
			await expectAllowed("glob", { pattern: "**/*.ts", path: "src" });
			await expectAllowed("grep", { pattern: "TODO", path: "src", include: "*.ts" });
		});
	});
});
