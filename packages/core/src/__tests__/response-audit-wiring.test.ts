/**
 * Integration test: a response action must leave an audit trail.
 *
 * A response with no record is worse than no response: the operator cannot tell
 * whether the runtime touched anything, and cannot find what it preserved. This
 * test drives the real `guardToolCall` and then reads the audit log back.
 *
 * NOTE ON PATHS: `logging.path` is deliberately confined to `~/.singularity-aidr`
 * by `normalizeStateFilePath` - a config that points a state file outside that
 * directory is rejected and reset to the default (with a warning). That is a real
 * security control, so this test does not try to place the log elsewhere: it
 * redirects HOME to a temp directory and reads the log from its default location,
 * which is exactly what a real install does.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ApprovalStore } from "../approval-store.js";
import { extractFromWrite } from "../extractors.js";
import { guardToolCall } from "../guard.js";

let home: string;
let previousHome: string | undefined;
let previousUserProfile: string | undefined;
let vault: string;
let configPath: string;
let auditPath: string;
let target: string;
let threatsDir: string;
let allowlistsDir: string;

const SECRET_CONTENT = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ injected-key-marker";
const PRIOR_CONTENT = "ssh-rsa AAAA the legitimate key\n";

async function writeConfig(snapshotOnDeny: boolean, snapshotDir = vault) {
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			response: {
				actions: {
					snapshot_on_deny: snapshotOnDeny,
					snapshot_dir: snapshotDir,
					snapshot_min_severity: "warning",
				},
			},
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			allowlist: {},
			logging: { enabled: true, log_clean: false },
			control_plane: { enabled: false },
		}),
		"utf8",
	);
}

function run() {
	const toolInput = { file_path: target, content: SECRET_CONTENT };
	return guardToolCall(
		{ sessionId: "s-audit", toolName: "Write", toolInput, artifacts: extractFromWrite(toolInput) },
		{ configPath, threatsDir, allowlistsDir },
		new ApprovalStore(),
	);
}

async function auditEntries(): Promise<Array<Record<string, unknown>>> {
	if (!existsSync(auditPath)) return [];
	const raw = await readFile(auditPath, "utf8");
	return raw
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-resp-audit-"));
	previousHome = process.env.HOME;
	previousUserProfile = process.env.USERPROFILE;
	// The default audit path resolves from HOME, so redirecting it is what places
	// the log inside the temp directory on both POSIX and Windows.
	process.env.HOME = home;
	process.env.USERPROFILE = home;

	vault = join(home, "vault");
	configPath = join(home, "config.json");
	auditPath = join(home, ".singularity-aidr", "audit.jsonl");
	target = join(home, ".ssh", "authorized_keys");
	await mkdir(join(home, ".ssh"), { recursive: true });
	await writeFile(target, PRIOR_CONTENT, "utf8");
	threatsDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "claude-code", "resources", "threats");
	allowlistsDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "claude-code", "resources", "allowlists");
});

afterEach(async () => {
	if (previousHome === undefined) delete process.env.HOME;
	else process.env.HOME = previousHome;
	if (previousUserProfile === undefined) delete process.env.USERPROFILE;
	else process.env.USERPROFILE = previousUserProfile;
	await rm(home, { recursive: true, force: true });
});

describe("response actions are auditable", () => {
	it("writes a response_action entry when a snapshot is taken", async () => {
		await writeConfig(true);
		const result = await run();
		expect(result.verdict.decision).not.toBe("allow");

		const entries = await auditEntries();
		const responseEntries = entries.filter((e) => e.type === "response_action");
		expect(responseEntries).toHaveLength(1);

		const entry = responseEntries[0];
		expect(entry?.verdict).toBe(result.verdict.decision);
		expect(entry?.session_id).toBe("s-audit");
		expect(entry?.tool_name).toBe("Write");
		const actions = entry?.actions as Array<Record<string, unknown>>;
		expect(actions).toHaveLength(1);
		expect(actions[0]?.action).toBe("snapshot");
		expect(actions[0]?.outcome).toBe("success");
		expect(actions[0]?.vault_path).toBe(result.responseActions?.[0]?.vaultPath);
	});

	it("never writes file contents into the audit log", async () => {
		await writeConfig(true);
		await run();
		const raw = await readFile(auditPath, "utf8");
		expect(raw).not.toContain(SECRET_CONTENT);
		expect(raw).not.toContain("injected-key-marker");
		// The prior content is preserved in the vault, not in the log.
		expect(raw).not.toContain("the legitimate key");
	});

	it("writes no response_action entry when the action is disabled", async () => {
		await writeConfig(false);
		await run();
		const entries = await auditEntries();
		expect(entries.filter((e) => e.type === "response_action")).toEqual([]);
	});

	it("records a failed response action so the operator knows it did not work", async () => {
		const blocker = join(home, "blocker");
		await writeFile(blocker, "not a dir", "utf8");
		// Vault inside a path that cannot be a directory -> the snapshot fails.
		await writeConfig(true, join(blocker, "vault"));

		const result = await run();
		expect(result.responseActions?.[0]?.outcome).toBe("failure");

		const entries = await auditEntries();
		const responseEntries = entries.filter((e) => e.type === "response_action");
		expect(responseEntries).toHaveLength(1);
		const actions = responseEntries[0]?.actions as Array<Record<string, unknown>>;
		expect(actions[0]?.outcome).toBe("failure");
		expect(actions[0]?.reason).toBe("snapshot_failed");
	});

	it("does not break the block when the audit log cannot be written", async () => {
		// Make the audit log's parent path unusable by placing a FILE where the
		// `~/.singularity-aidr` directory needs to be.
		await rm(join(home, ".singularity-aidr"), { recursive: true, force: true });
		await writeFile(join(home, ".singularity-aidr"), "not a directory", "utf8");

		await writeConfig(true);
		const result = await run();

		// The verdict is unchanged and the snapshot still succeeded: a logging
		// failure must never weaken the block or undo the response.
		expect(result.verdict.decision).not.toBe("allow");
		expect(result.responseActions?.[0]?.outcome).toBe("success");
	});
});
