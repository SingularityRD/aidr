/**
 * Integration tests: the response layer through the real `guardToolCall`.
 *
 * The unit tests cover `runResponseActions`; these prove the wiring is
 * default-OFF and that a blocking verdict still stands no matter what the
 * response layer does.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ApprovalStore } from "../approval-store.js";
import { guardToolCall } from "../guard.js";
import { extractFromWrite } from "../extractors.js";

let home: string;
let vault: string;
let configPath: string;
let target: string;
/**
 * The evaluator does not discover rules on its own: connectors pass the bundle
 * they ship. Without this the runtime loads zero rules and allows everything
 * (the silent-degradation path), which would make these tests vacuously pass.
 */
let threatsDir: string;
let allowlistsDir: string;

const SUSPICIOUS_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB injected";

async function writeConfig(mode: "off" | "on") {
	const config = {
		mode: "local",
		response: {
			actions: {
				snapshot_on_deny: mode === "on",
				snapshot_dir: vault,
				snapshot_min_severity: "warning",
			},
		},
		url_check: { enabled: false },
		file_check: { enabled: false },
		package_check: { enabled: false },
		cache: { enabled: false, path: join(home, "cache.json") },
		allowlist: { path: join(home, "allowlist.json") },
		logging: { enabled: false, path: join(home, "audit.jsonl") },
		control_plane: { enabled: false },
	};
	await writeFile(configPath, JSON.stringify(config), "utf8");
}

async function guard() {
	const toolInput = { file_path: target, content: SUSPICIOUS_KEY };
	return guardToolCall(
		{
			sessionId: "s1",
			toolName: "Write",
			toolInput,
			artifacts: extractFromWrite(toolInput),
		},
		{ configPath, threatsDir, allowlistsDir },
		new ApprovalStore(),
	);
}

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-guard-response-"));
	vault = join(home, "vault");
	configPath = join(home, "config.json");
	target = join(home, ".ssh", "authorized_keys");
	await mkdir(join(home, ".ssh"), { recursive: true });
	await writeFile(target, "ssh-rsa AAAA the legitimate key\n", "utf8");
	// Use a module-relative URL rather than `__dirname`: the package is ESM
	// ("type": "module"), so `__dirname` is not reliably defined and
	// `resolve(undefined, ...)` silently produces a wrong path - which made this
	// suite assert against zero loaded rules.
	const testDir = dirname(fileURLToPath(import.meta.url));
	threatsDir = resolve(testDir, "..", "..", "..", "claude-code", "resources", "threats");
	allowlistsDir = resolve(testDir, "..", "..", "..", "claude-code", "resources", "allowlists");
	expect(existsSync(threatsDir), "connector rule bundle must exist").toBe(true);
});

afterEach(async () => {
	await rm(home, { recursive: true, force: true });
});

describe("guardToolCall response wiring", () => {
	it("blocks and takes no action when snapshot_on_deny is off", async () => {
		await writeConfig("off");
		const result = await guard();

		expect(result.verdict.decision).not.toBe("allow");
		expect(result.responseActions ?? []).toEqual([]);
		expect(existsSync(vault)).toBe(false);
		// The user's file is exactly as it was.
		expect(await readFile(target, "utf8")).toBe("ssh-rsa AAAA the legitimate key\n");
	});

	it("blocks AND snapshots when snapshot_on_deny is on", async () => {
		await writeConfig("on");
		const result = await guard();

		// The block is unchanged by the response.
		expect(result.verdict.decision).not.toBe("allow");
		const actions = result.responseActions ?? [];
		expect(actions).toHaveLength(1);
		expect(actions[0]?.outcome).toBe("success");
		expect(actions[0]?.target).toBe(target);

		// The prior contents are recoverable from the vault...
		const vaulted = await readFile(actions[0]?.vaultPath as string, "utf8");
		expect(vaulted).toBe("ssh-rsa AAAA the legitimate key\n");
		// ...and the original is untouched.
		expect(await readFile(target, "utf8")).toBe("ssh-rsa AAAA the legitimate key\n");
	});

	it("keeps the verdict blocking even if the response cannot run", async () => {
		// Point the vault at a path that cannot be a directory.
		const blocker = join(home, "blocker");
		await writeFile(blocker, "file", "utf8");
		await writeConfig("on");
		await writeFile(
			configPath,
			JSON.stringify({
				mode: "local",
				response: { actions: { snapshot_on_deny: true, snapshot_dir: join(blocker, "v") } },
				url_check: { enabled: false },
				file_check: { enabled: false },
				package_check: { enabled: false },
				cache: { enabled: false, path: join(home, "cache.json") },
				allowlist: { path: join(home, "allowlist.json") },
				logging: { enabled: false, path: join(home, "audit.jsonl") },
				control_plane: { enabled: false },
			}),
			"utf8",
		);

		const result = await guard();
		expect(result.verdict.decision).not.toBe("allow");
		expect(result.responseActions?.[0]?.outcome).toBe("failure");
	});

	it("does not snapshot for an allowed tool call", async () => {
		await writeConfig("on");
		// A path in the OS temp dir that matches no threat rule. Note the target
		// must be genuinely benign: a dotfile or config-looking name is flagged by
		// the rule set (correctly), which would make this test assert nothing.
		const toolInput = { file_path: join(tmpdir(), "aidr-benign-notes.txt"), content: "just notes" };
		const result = await guardToolCall(
			{
				sessionId: "s1",
				toolName: "Write",
				toolInput,
				artifacts: extractFromWrite(toolInput),
			},
			// The rules must be supplied here too: without them the evaluator loads
			// zero threats and reports `detection_unavailable`, which is the guard
			// working correctly - but it would make this test assert the wrong thing.
			{ configPath, threatsDir, allowlistsDir },
			new ApprovalStore(),
		);

		expect(result.verdict.decision).toBe("allow");
		expect(result.responseActions ?? []).toEqual([]);
		expect(existsSync(vault)).toBe(false);
	});
});
