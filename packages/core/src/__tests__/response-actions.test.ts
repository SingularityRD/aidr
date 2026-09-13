/**
 * Tests for the response layer — what the runtime does AFTER it blocks something.
 *
 * The product is named "Detection & Response" but previously only produced a
 * verdict: quarantine/contain/rollback existed as a closed island no verdict
 * could reach. These tests pin the delivered behaviour and, just as importantly,
 * the boundaries that make it safe to enable.
 */

import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	anyActionSucceeded,
	runResponseActions,
	summarizeResponseActions,
	targetPathFor,
} from "../response-actions.js";
import type { Verdict } from "../types.js";

let dir: string;
let vault: string;

function verdict(overrides: Partial<Verdict> = {}): Verdict {
	return {
		decision: "deny",
		category: "credential_access",
		confidence: 0.95,
		severity: "critical",
		source: "heuristic",
		artifacts: [],
		matchedThreatId: "CLT-CRED-004",
		reasons: ["reading credential files"],
		...overrides,
	};
}

beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "aidr-response-"));
	vault = join(dir, "vault");
});

afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

describe("response layer is off by default", () => {
	it("does nothing when no action is configured", async () => {
		const target = join(dir, "id_rsa");
		await writeFile(target, "PRIVATE KEY", "utf8");

		const records = await runResponseActions(verdict(), {
			toolName: "Write",
			toolInput: { file_path: target },
		});

		expect(records).toEqual([]);
		expect(existsSync(vault)).toBe(false);
	});

	it("does not act on an allowed verdict even when configured", async () => {
		const target = join(dir, "notes.txt");
		await writeFile(target, "hello", "utf8");

		const records = await runResponseActions(
			verdict({ decision: "allow", severity: "info" }),
			{ toolName: "Write", toolInput: { file_path: target } },
			{ snapshotOnDeny: true, snapshotDir: vault },
		);

		expect(records).toEqual([]);
		expect(existsSync(vault)).toBe(false);
	});
});

describe("snapshot on deny", () => {
	it("preserves a copy of the blocked target and leaves the original byte-identical", async () => {
		const target = join(dir, "authorized_keys");
		const original = "ssh-rsa AAAA original contents\n";
		await writeFile(target, original, "utf8");

		const records = await runResponseActions(
			verdict(),
			{ toolName: "Write", toolInput: { file_path: target } },
			{ snapshotOnDeny: true, snapshotDir: vault },
		);

		expect(records).toHaveLength(1);
		const [record] = records;
		expect(record?.action).toBe("snapshot");
		expect(record?.outcome).toBe("success");
		expect(record?.bytes).toBe(Buffer.byteLength(original));

		// The vault holds the prior contents...
		expect(record?.vaultPath && existsSync(record.vaultPath)).toBe(true);
		expect(await readFile(record?.vaultPath as string, "utf8")).toBe(original);

		// ...and the ORIGINAL is untouched, because the blocked write never ran.
		expect(existsSync(target)).toBe(true);
		expect(await readFile(target, "utf8")).toBe(original);
	});

	it("reports running the action so a caller can tell the user", async () => {
		const target = join(dir, "secrets.env");
		await writeFile(target, "TOKEN=abc", "utf8");

		const records = await runResponseActions(
			verdict(),
			{ toolName: "Write", toolInput: { file_path: target } },
			{ snapshotOnDeny: true, snapshotDir: vault },
		);

		expect(anyActionSucceeded(records)).toBe(true);
		const summary = summarizeResponseActions(records);
		expect(summary).toContain("snapshot");
		expect(summary).toContain(target);
	});

	it("is idempotent-safe: two snapshots both survive", async () => {
		const target = join(dir, "config.json");
		await writeFile(target, '{"a":1}', "utf8");

		for (let i = 0; i < 2; i++) {
			const records = await runResponseActions(
				verdict(),
				{ toolName: "Edit", toolInput: { file_path: target } },
				{ snapshotOnDeny: true, snapshotDir: vault },
			);
			expect(records[0]?.outcome).toBe("success");
		}
		const files = readdirSync(vault).filter((f) => f.includes("config.json"));
		expect(files.length).toBe(2);
	});
});

describe("snapshot boundaries are reported, never silent", () => {
	it("skips a target that does not exist and says why", async () => {
		const records = await runResponseActions(
			verdict(),
			{ toolName: "Write", toolInput: { file_path: join(dir, "brand-new.txt") } },
			{ snapshotOnDeny: true, snapshotDir: vault },
		);
		expect(records[0]?.outcome).toBe("skipped");
		expect(records[0]?.reason).toBe("target_absent");
	});

	it("skips a non-file tool and says why", async () => {
		const records = await runResponseActions(
			verdict(),
			{ toolName: "Bash", toolInput: { command: "rm -rf /" } },
			{ snapshotOnDeny: true, snapshotDir: vault },
		);
		expect(records[0]?.outcome).toBe("skipped");
		expect(records[0]?.reason).toBe("not_a_file_target");
	});

	it("honours the severity floor", async () => {
		const target = join(dir, "low.txt");
		await writeFile(target, "x", "utf8");

		const records = await runResponseActions(
			verdict({ severity: "info" }),
			{ toolName: "Write", toolInput: { file_path: target } },
			{ snapshotOnDeny: true, snapshotDir: vault, snapshotMinSeverity: "critical" },
		);
		expect(records[0]?.outcome).toBe("skipped");
		expect(records[0]?.reason).toBe("below_severity_floor");
	});

	it("honours the size ceiling", async () => {
		const target = join(dir, "big.bin");
		await writeFile(target, Buffer.alloc(2048));

		const records = await runResponseActions(
			verdict(),
			{ toolName: "Write", toolInput: { file_path: target } },
			{ snapshotOnDeny: true, snapshotDir: vault, snapshotMaxBytes: 1024 },
		);
		expect(records[0]?.outcome).toBe("skipped");
		expect(records[0]?.reason).toBe("too_large");
	});

	it("does not fail the block when the vault cannot be written", async () => {
		// A path whose parent is an existing FILE cannot be created as a directory.
		const blocker = join(dir, "blocker");
		await writeFile(blocker, "not a directory", "utf8");
		const target = join(dir, "target.txt");
		await writeFile(target, "content", "utf8");

		const records = await runResponseActions(
			verdict(),
			{ toolName: "Write", toolInput: { file_path: target } },
			{ snapshotOnDeny: true, snapshotDir: join(blocker, "vault") },
		);

		expect(records[0]?.outcome).toBe("failure");
		expect(records[0]?.reason).toBe("snapshot_failed");
		// The original is still intact and the caller still has the deny verdict.
		expect(await readFile(target, "utf8")).toBe("content");
	});

	it("never records file contents in the record", async () => {
		const target = join(dir, "secret.txt");
		const secret = "SUPER_SECRET_VALUE_12345";
		await writeFile(target, secret, "utf8");

		const records = await runResponseActions(
			verdict(),
			{ toolName: "Write", toolInput: { file_path: target } },
			{ snapshotOnDeny: true, snapshotDir: vault },
		);

		const serialized = JSON.stringify(records);
		expect(serialized).not.toContain(secret);
	});

	it("creates the vault with owner-only permissions", async () => {
		const target = join(dir, "perm.txt");
		await writeFile(target, "x", "utf8");
		await runResponseActions(
			verdict(),
			{ toolName: "Write", toolInput: { file_path: target } },
			{ snapshotOnDeny: true, snapshotDir: vault },
		);
		const mode = (await stat(vault)).mode & 0o777;
		// On Windows the mode bits are synthetic; assert only on POSIX semantics.
		if (process.platform !== "win32") expect(mode).toBe(0o700);
		else expect(mode).toBeGreaterThan(0);
	});
});

describe("target path extraction", () => {
	it("recognises the file-tool key variants the connectors send", () => {
		expect(targetPathFor("Write", { file_path: "/a/b" })).toBe("/a/b");
		expect(targetPathFor("Edit", { path: "/c/d" })).toBe("/c/d");
		expect(targetPathFor("Write", { filePath: "/e/f" })).toBe("/e/f");
		expect(targetPathFor("Delete", { target_file: "/g/h" })).toBe("/g/h");
	});

	it("returns null for non-file tools and for a missing path", () => {
		expect(targetPathFor("Bash", { command: "ls" })).toBeNull();
		expect(targetPathFor("WebFetch", { url: "http://x" })).toBeNull();
		expect(targetPathFor("Write", {})).toBeNull();
	});
});
