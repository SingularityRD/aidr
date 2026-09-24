/**
 * AIDR-030 (rollback half): a destructive operation that is ALLOWED must have its
 * target snapshotted FIRST, so the operation can genuinely be rolled back.
 *
 * These tests drive the real `guardToolCall` — no mocked verdicts — against the
 * connector's shipped threat bundle, because the whole point of the finding is
 * that the response layer must hang off the *detection path*, not beside it.
 *
 * `logging.path` and `response.audit.path` are deliberately left at their defaults:
 * `normalizeStateFilePath` confines both to `~/.singularity-aidr`, so HOME is
 * redirected to a temp directory and the files are read from where a real install
 * puts them.
 */

import { existsSync, realpathSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ApprovalStore } from "../approval-store.js";
import { loadConfig } from "../config.js";
import { extractFromDelete, extractFromWrite } from "../extractors.js";
import {
	executeWithRollback,
	guardToolCall,
	resolveGuardResponseSettings,
	rollbackSnapshotFromGuardResult,
} from "../guard.js";
import { ResponseAuditor } from "../response-audit.js";

let home: string;
let previousHome: string | undefined;
let previousUserProfile: string | undefined;
let configPath: string;
let auditPath: string;
let chainPath: string;
let protectDir: string;
let sshDir: string;
let target: string;
let threatsDir: string;
let allowlistsDir: string;

const PRIOR_CONTENT = "irreplaceable source of truth\n";

interface ActionsConfig {
	snapshot_before_destructive?: boolean;
	protect_paths?: string[];
	snapshot_on_deny?: boolean;
	snapshot_max_bytes?: number;
	snapshot_retention_days?: number;
}

async function writeConfig(actions: ActionsConfig, signedChain?: boolean) {
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			response: {
				actions,
				...(signedChain === undefined ? {} : { audit: { signed_chain: signedChain } }),
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

/** A real guard call for `Delete target` — a destructive, normally-allowed tool. */
function guard() {
	const toolInput = { file_path: target };
	return guardToolCall(
		{
			sessionId: "s-rollback",
			toolName: "Delete",
			toolInput,
			artifacts: extractFromDelete(toolInput),
		},
		{ configPath, threatsDir, allowlistsDir },
		new ApprovalStore(),
	);
}

/** A real guard call for `Write target` with attacker-supplied content. */
function guardWrite(content: string, filePath = target) {
	const toolInput = { file_path: filePath, content };
	return guardToolCall(
		{
			sessionId: "s-rollback",
			toolName: "Write",
			toolInput,
			artifacts: extractFromWrite(toolInput),
		},
		{ configPath, threatsDir, allowlistsDir },
		new ApprovalStore(),
	);
}

async function jsonl(path: string): Promise<Array<Record<string, unknown>>> {
	if (!existsSync(path)) return [];
	const raw = await readFile(path, "utf8");
	return raw
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-prerollback-"));
	previousHome = process.env.HOME;
	previousUserProfile = process.env.USERPROFILE;
	process.env.HOME = home;
	process.env.USERPROFILE = home;

	configPath = join(home, "config.json");
	// Canonicalise before deriving paths to read back: on Windows `tmpdir()` can
	// return an 8.3 short name (`ANL~1`) while `homedir()` returns the long one, so
	// a path built here would not be the path the runtime actually wrote to.
	auditPath = join(realpathSync.native(home), ".singularity-aidr", "audit.jsonl");
	chainPath = join(realpathSync.native(home), ".singularity-aidr", "response-audit.jsonl");
	await mkdir(dirname(auditPath), { recursive: true });
	protectDir = join(home, "work", "deploy");
	target = join(protectDir, "artifact.bin");
	await mkdir(protectDir, { recursive: true });
	await writeFile(target, PRIOR_CONTENT, "utf8");

	// The deny-path tests need a target the shipped rules actually block: the same
	// `.ssh/authorized_keys` shape the existing guard-response suite uses, so a
	// pass here cannot be a "nothing matched" accident.
	sshDir = join(home, ".ssh");
	await mkdir(sshDir, { recursive: true });
	await writeFile(join(sshDir, "authorized_keys"), "ssh-rsa AAAA the legitimate key\n", "utf8");

	const testDir = dirname(fileURLToPath(import.meta.url));
	// src/__tests__ -> src -> core -> packages, then into the connector bundle.
	threatsDir = resolve(testDir, "..", "..", "..", "claude-code", "resources", "threats");
	allowlistsDir = resolve(testDir, "..", "..", "..", "claude-code", "resources", "allowlists");
	// The evaluator does not discover rules on its own: without the bundle it loads
	// zero threats and reports `detection_unavailable` (an `ask`), which would make
	// every assertion below test the wrong path. Fail loudly instead.
	expect(existsSync(join(threatsDir, "threats.yaml")) || existsSync(threatsDir)).toBe(true);
});

afterEach(async () => {
	if (previousHome === undefined) delete process.env.HOME;
	else process.env.HOME = previousHome;
	if (previousUserProfile === undefined) delete process.env.USERPROFILE;
	else process.env.USERPROFILE = previousUserProfile;
	await rm(home, { recursive: true, force: true });
});

describe("pre-operation snapshots are OFF by default", () => {
	it("takes no snapshot when snapshot_before_destructive is absent", async () => {
		await writeConfig({});
		const result = await guard();

		expect(result.verdict.decision).toBe("allow");
		expect(result.responseActions ?? []).toEqual([]);
		// Nothing was preserved and nothing was promised.
		expect(result.snapshot).toBeUndefined();
		expect(result.finalizeSnapshot).toBeUndefined();
		expect(existsSync(join(home, ".singularity-aidr", "snapshots"))).toBe(false);
	});
});

describe("pre-operation snapshots are doubly gated when enabled", () => {
	it("still snapshots nothing when protect_paths is empty", async () => {
		await writeConfig({ snapshot_before_destructive: true, protect_paths: [] });
		const result = await guard();

		expect(result.verdict.decision).toBe("allow");
		expect(result.responseActions ?? []).toEqual([]);
		expect(result.snapshot).toBeUndefined();
	});

	it("skips an unprotected target and says so instead of implying protection", async () => {
		await writeConfig({
			snapshot_before_destructive: true,
			protect_paths: [join(home, "elsewhere")],
		});
		const result = await guard();

		expect(result.verdict.decision).toBe("allow");
		expect(result.snapshot).toBeUndefined();
		expect(result.responseActions).toHaveLength(1);
		expect(result.responseActions?.[0]).toMatchObject({
			action: "snapshot",
			outcome: "skipped",
			reason: "not_protected",
			target,
		});
	});

	it("reports a target too large to preserve instead of pretending it is recoverable", async () => {
		await writeConfig({
			snapshot_before_destructive: true,
			protect_paths: [protectDir],
			snapshot_max_bytes: 8,
		});
		const result = await guard();

		expect(result.verdict.decision).toBe("allow");
		expect(result.snapshot).toBeUndefined();
		expect(result.responseActions?.[0]).toMatchObject({
			action: "snapshot",
			outcome: "skipped",
			reason: "too_large",
			target,
		});
	});
});

describe("an allowed destructive operation is snapshotted and can be rolled back", () => {
	beforeEach(async () => {
		await writeConfig({ snapshot_before_destructive: true, protect_paths: [protectDir] }, true);
	});

	it("records no rollback promise for a multi-file patch", async () => {
		const second = join(protectDir, "second.bin");
		await writeFile(second, "second original\n", "utf8");
		const patch = [
			"*** Begin Patch",
			`*** Update File: ${target.replaceAll("\\", "/")}`,
			"@@",
			"-irreplaceable source of truth",
			"+first changed",
			`*** Update File: ${second.replaceAll("\\", "/")}`,
			"@@",
			"-second original",
			"+second changed",
			"*** End Patch",
		].join("\n");
		const result = await guardToolCall(
			{ sessionId: "s-rollback", toolName: "apply_patch", toolInput: { patch }, artifacts: [] },
			{ configPath, threatsDir, allowlistsDir },
			new ApprovalStore(),
		);

		expect(result.verdict.decision).toBe("allow");
		expect(result.snapshot).toBeUndefined();
		expect(result.responseActions?.[0]).toMatchObject({
			outcome: "failure",
			reason: "multi_file_patch_not_snapshot_safe",
		});
		expect(result.signedChain?.written).toBe(true);
		expect((await jsonl(chainPath))[0]).toMatchObject({ action: "snapshot", outcome: "failure" });
	});

	it("uses canonical tool and input names for connector aliases", async () => {
		const result = await guardToolCall(
			{
				sessionId: "s-rollback",
				toolName: "write_file",
				toolInput: { filePath: target, content: "replacement" },
				artifacts: [],
			},
			{ configPath, threatsDir, allowlistsDir },
			new ApprovalStore(),
		);

		expect(result.verdict.decision).toBe("allow");
		expect(result.snapshot?.target).toBe(target);
		expect(result.responseActions?.[0]).toMatchObject({
			action: "snapshot",
			outcome: "success",
			target,
		});
	});

	it("denies conflicting paths instead of selecting one for protected-file handling", async () => {
		const result = await guardToolCall(
			{
				sessionId: "conflicting-paths",
				toolName: "Write",
				toolInput: {
					file_path: join(home, "elsewhere", "notes.txt"),
					filePath: target,
					content: "replacement",
				},
				artifacts: [],
			},
			{ configPath, threatsDir, allowlistsDir },
			new ApprovalStore(),
		);

		expect(result.verdict).toMatchObject({
			decision: "deny",
			category: "input_ambiguous",
			matchedThreatId: "POL-INPUT-001",
		});
		expect(result.snapshot).toBeUndefined();
		expect(await readFile(target, "utf8")).toBe(PRIOR_CONTENT);
	});

	it("snapshots the target, records it in the signed chain and restores it", async () => {
		const result = await guard();

		// 1. The call was ALLOWED — this is not a block path.
		expect(result.verdict.decision).toBe("allow");

		// 2. The target was preserved before it could be destroyed.
		expect(result.snapshot?.target).toBe(target);
		expect(result.snapshot?.bytes).toBe(Buffer.byteLength(PRIOR_CONTENT));
		expect(result.responseActions?.[0]).toMatchObject({
			action: "snapshot",
			outcome: "success",
			target,
		});
		expect(result.finalizeSnapshot).toBeTypeOf("function");

		// 3. The response reached the tamper-evident chain.
		expect(result.signedChain?.written).toBe(true);

		// 4. Now the destructive operation actually happens (a real delete).
		await unlink(target);
		expect(existsSync(target)).toBe(false);

		// 5. Roll back and prove the contents are byte-identical to before.
		const record = await rollbackSnapshotFromGuardResult(result, {
			toolName: "Delete",
			toolInput: { file_path: target },
			sessionId: "s-rollback",
			configPath,
		});
		expect(record).toMatchObject({ action: "rollback", outcome: "success", target });
		expect(await readFile(target, "utf8")).toBe(PRIOR_CONTENT);
	});

	it("does not claim a failed rollback succeeded and permits a safe retry", async () => {
		const result = await guard();
		const vaultPath = result.responseActions?.[0]?.vaultPath;
		if (!vaultPath || !result.finalizeSnapshot) throw new Error("Expected a restorable snapshot");
		await unlink(target);
		await unlink(vaultPath);

		expect(await result.finalizeSnapshot("failure")).toEqual({ rolledBack: false });
		expect(existsSync(target)).toBe(false);
		await writeFile(vaultPath, PRIOR_CONTENT, "utf8");
		expect(await result.finalizeSnapshot("failure")).toEqual({ rolledBack: true });
		expect(await readFile(target, "utf8")).toBe(PRIOR_CONTENT);
		expect(await result.finalizeSnapshot("failure")).toEqual({ rolledBack: false });
	});

	it("does not roll back a successful allowed operation", async () => {
		const result = await guard();
		if (!result.finalizeSnapshot) throw new Error("Expected a restorable snapshot");
		await unlink(target);

		expect(await result.finalizeSnapshot("success")).toEqual({ rolledBack: false });
		expect(existsSync(target)).toBe(false);
		expect(await result.finalizeSnapshot("failure")).toEqual({ rolledBack: false });
	});

	it("writes both the plain audit entry and the signed chain entry for the snapshot", async () => {
		const result = await guard();
		expect(result.signedChain?.written).toBe(true);

		// Plain log: filed as an ALLOWED response so it cannot be confused with a block.
		const entries = await jsonl(auditPath);
		const allowed = entries.filter((entry) => entry.type === "response_action_allowed");
		expect(allowed).toHaveLength(1);
		expect(allowed[0]?.verdict).toBe("allow");
		const actions = allowed[0]?.actions as Array<Record<string, unknown>>;
		expect(actions[0]).toMatchObject({ action: "snapshot", outcome: "success", target });
		expect(actions[0]?.snapshot_id).toBe(result.snapshot?.id);

		// Signed chain: a real signed record, not an unsigned line claiming to be one.
		// Exactly one record for one decision — the allowed path must not double-log.
		const chain = await jsonl(chainPath);
		expect(chain).toHaveLength(1);
		expect(chain[0]).toMatchObject({
			action: "snapshot",
			response_taken: "contain",
			tool: "Delete",
			outcome: "success",
		});
		expect(chain[0]?._prev_hash).toBe("GENESIS");
		expect(chain[0]?._entry_hash).toMatch(/^[0-9a-f]{64}$/);
		expect(chain[0]?._signature).toEqual(expect.any(String));
	});

	it("never writes file contents into either record", async () => {
		await guard();
		const plain = await readFile(auditPath, "utf8");
		const chain = await readFile(chainPath, "utf8");

		expect(plain).not.toContain("irreplaceable");
		expect(chain).not.toContain("irreplaceable");
	});
});

describe("the allowed call is never weakened by the response layer", () => {
	it("still allows the call when the snapshot cannot be written", async () => {
		// A FILE where the snapshot root needs to be a directory.
		const blocker = join(home, "blocker");
		await writeFile(blocker, "not a directory", "utf8");
		await writeConfig({
			snapshot_before_destructive: true,
			protect_paths: [protectDir],
		});
		await writeFile(
			configPath,
			JSON.stringify({
				mode: "local",
				response: {
					actions: {
						snapshot_before_destructive: true,
						protect_paths: [protectDir],
						snapshot_root_dir: join(blocker, "snapshots"),
					},
					audit: { signed_chain: true },
				},
				url_check: { enabled: false },
				file_check: { enabled: false },
				package_check: { enabled: false },
				cache: { enabled: false },
				allowlist: {},
				logging: { enabled: true },
				control_plane: { enabled: false },
			}),
			"utf8",
		);

		const result = await guard();

		// The allow stands. A response failure must not turn into a block...
		expect(result.verdict.decision).toBe("allow");
		// ...and must not be reported as protection that did not happen.
		expect(result.snapshot).toBeUndefined();
		expect(result.responseActions?.[0]).toMatchObject({
			action: "snapshot",
			outcome: "failure",
			reason: "snapshot_failed",
		});
	});

	it("still allows the call when no signed chain is configured, and says the record is missing", async () => {
		// The default: no chain. The snapshot still happens (it is a file copy), but
		// the tamper-evident record does not, and the result must not imply it does.
		await writeConfig({ snapshot_before_destructive: true, protect_paths: [protectDir] });
		const result = await guard();

		expect(result.verdict.decision).toBe("allow");
		expect(result.snapshot).toBeDefined();
		expect(result.signedChain?.written).toBe(false);
		expect(result.signedChain?.reason).toBe("signed_chain_disabled");
		expect(existsSync(chainPath)).toBe(false);
	});
});

describe("the signed chain is verifiable, not just written", () => {
	it("verifies the chain a real guard call produced", async () => {
		await writeConfig({ snapshot_before_destructive: true, protect_paths: [protectDir] }, true);
		const result = await guard();
		expect(result.signedChain?.written).toBe(true);

		// Independent verification: a fresh auditor with only the log and the key file.
		const verifier = new ResponseAuditor(chainPath, { signEntries: true });
		expect(await verifier.verifyIntegrity()).toEqual({ valid: true });

		// Tamper with the recorded outcome and the chain must notice.
		const [record] = await jsonl(chainPath);
		await writeFile(chainPath, `${JSON.stringify({ ...record, outcome: "failure" })}\n`, "utf8");
		const tampered = await verifier.verifyIntegrity();
		expect(tampered.valid).toBe(false);
		expect(tampered.tamperedEntries).toEqual([record?.id]);
	});

	it("confines the signed chain path to ~/.singularity-aidr", async () => {
		// A config that tries to point security evidence at an attacker-chosen
		// location must be rejected, exactly like cache/allowlist/logging paths.
		await writeConfig({}, true);
		const raw = JSON.parse(await readFile(configPath, "utf8")) as Record<string, unknown>;
		(raw.response as Record<string, unknown>).audit = {
			signed_chain: true,
			path: join(home, "elsewhere", "chain.jsonl"),
		};
		await writeFile(configPath, JSON.stringify(raw), "utf8");

		const config = await loadConfig(configPath);
		// Compare canonically: on Windows the same file can be spelled with an 8.3
		// short name, so a raw string comparison would be a false negative. The chain
		// file itself does not exist yet, so canonicalise its parent directory.
		expect(
			join(
				realpathSync.native(dirname(config.response?.audit?.path ?? "")),
				"response-audit.jsonl",
			),
		).toBe(chainPath);
	});
});

describe("the deny path keeps its own guarantees", () => {
	it("blocks, snapshots and chains the response when signing is on", async () => {
		await writeConfig({ snapshot_on_deny: true }, true);
		// The same shape the existing guard-response tests use: an authorized_keys
		// overwrite carrying an injected key, which the shipped rules must block.
		const result = await guardWrite(
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB injected",
			join(sshDir, "authorized_keys"),
		);

		expect(result.verdict.decision).not.toBe("allow");
		expect(result.responseActions?.[0]?.outcome).toBe("success");
		expect(result.signedChain?.written).toBe(true);

		const chain = await jsonl(chainPath);
		expect(chain).toHaveLength(1);
		expect(chain[0]).toMatchObject({ action: "snapshot", outcome: "success" });
		expect(chain[0]?._signature).toEqual(expect.any(String));
	});
});

describe("executeWithRollback", () => {
	beforeEach(async () => {
		await writeConfig({ snapshot_before_destructive: true, protect_paths: [protectDir] }, true);
	});

	it("rolls the target back when the allowed operation fails", async () => {
		const result = await guard();
		const settings = await resolveGuardResponseSettings(configPath);

		await expect(
			executeWithRollback(
				result,
				{ toolName: "Delete", toolInput: { file_path: target }, sessionId: "s-rollback" },
				async () => {
					await unlink(target);
					throw new Error("deployment script failed halfway");
				},
				settings,
			),
		).rejects.toThrow("deployment script failed halfway");

		// The operation's failure did not cost the user their file.
		expect(await readFile(target, "utf8")).toBe(PRIOR_CONTENT);

		// And the rollback is on the record: one entry for the snapshot, then one for
		// the restore, correctly chained onto it.
		const chain = await jsonl(chainPath);
		expect(chain.map((entry) => entry.action)).toEqual(["snapshot", "rollback"]);
		expect(chain[1]).toMatchObject({ action: "rollback", outcome: "success" });
		expect(chain[1]?._prev_hash).toBe(chain[0]?._entry_hash);
	});

	it("does not roll back when onFailure is notify", async () => {
		const result = await guard();
		const settings = await resolveGuardResponseSettings(configPath);

		await expect(
			executeWithRollback(
				result,
				{ toolName: "Delete", toolInput: { file_path: target }, sessionId: "s-rollback" },
				async () => {
					await unlink(target);
					throw new Error("failed");
				},
				{ ...settings, onFailure: "notify" },
			),
		).rejects.toThrow("failed");

		expect(existsSync(target)).toBe(false);
	});

	it("does not attempt a rollback when no snapshot was taken", async () => {
		await writeConfig({ snapshot_before_destructive: true, protect_paths: [] }, true);
		const result = await guard();
		expect(result.snapshot).toBeUndefined();

		await expect(
			executeWithRollback(
				result,
				{ toolName: "Delete", toolInput: {}, sessionId: "s" },
				async () => {
					throw new Error("boom");
				},
			),
		).rejects.toThrow("boom");
	});
});
